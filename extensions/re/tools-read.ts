/**
 * T0 read-only r2 tools. Port of internal/re/r2tools.go (11 native tools) +
 * internal/re/hashtools.go (hash_binary).
 *
 * Unlike the Go daemon — which sends the model only a short count string and
 * keeps the actual JSON in a side-channel evidence blob (agentloop.go:662,
 * `Content: result.Text` where Text is "12 functions") — every tool here
 * returns the real data as tool content. A model that never sees function
 * names or addresses has nothing to ground claims on.
 *
 * Because the full list is now visible to the model (not just a count), list
 * tools default to a bounded page (DEFAULT_LIMIT, capped at MAX_LIMIT) and
 * jsonResult applies pi's standard truncation as a defense-in-depth backstop,
 * always telling the model explicitly when a view is partial.
 */
import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import type { ExtensionAPI } from "@oh-my-pi/pi-coding-agent";
import { ensureR2, getState, requireBinary } from "./state.ts";
import { addrOf, eaFromOffset, resolveNumericAddr, validateAddr } from "./r2.ts";
import { jsonResult, prefixedTextResult, textResult } from "./format.ts";
import { decompileAt, DISASM_ONLY_PREFIX } from "./decompile.ts";

const DEFAULT_LIMIT = 200;
const MAX_LIMIT = 1000;

/** Clamp a user-supplied limit: unset/invalid/non-positive falls back to DEFAULT_LIMIT; everything else caps at MAX_LIMIT. */
function clampLimit(limit: number | undefined): number {
	if (limit === undefined || !Number.isFinite(limit) || limit <= 0) return DEFAULT_LIMIT;
	return Math.min(limit, MAX_LIMIT);
}

/** offset<0 clamps to 0; offset>=len returns an empty page (never null). Always reports total so callers can tell the model the view is partial. */
function paginate<T>(items: T[], offset: number | undefined, limit: number | undefined): { page: T[]; total: number } {
	const start = Math.max(0, offset ?? 0);
	const total = items.length;
	if (start >= total) return { page: [], total };
	return { page: items.slice(start, start + clampLimit(limit)), total };
}

function pageHeader(label: string, page: unknown[], total: number, offset: number | undefined): string {
	if (page.length >= total) return `${page.length} ${label}`;
	return `${page.length} of ${total} ${label} (offset=${offset ?? 0}; use offset/limit to page through the rest)`;
}

/** r2 6.x reports functions (aflj/afij) with `addr`; r2 5.x used `offset`. Both are optional here — resolve via `addrOf`, never assume either is present. */
interface R2Func {
	addr?: number;
	offset?: number;
	name: string;
	size: number;
}

interface R2FuncInfo extends R2Func {
	[key: string]: unknown;
}

/** pdfj's address field — at the function-start level and on each per-instruction op — is `addr`; there is no `offset` field anywhere in pdfj's JSON, despite the previous assumption here (verified against live r2 5.5.0 and 6.1.8 processes on both an ELF and the WannaCry PE fixture; r2 6.x also renamed aflj/afij's `offset` to `addr`, hence addrOf). Ops also carry `comment` (base64), `flags` (attached symbol/label names), and `xrefs` (incoming references) when r2 has them. */
interface PdfjOp {
	addr: number;
	disasm: string;
	/** Base64-encoded; decode before display. */
	comment?: string;
	/** Flag/symbol names attached at this address. */
	flags?: string[];
	/** Other locations that reference (jump/call to) this instruction's address. */
	xrefs?: { addr: number; type: string }[];
}

interface PdfjResult {
	addr: number;
	ops: PdfjOp[];
}

/** axtj rows carry only `from` (the queried address is the implicit `to`); axfj rows carry both. Never fabricate the missing side. */
interface R2Xref {
	from?: number;
	to?: number;
	type: string;
	opcode?: string;
	name?: string;
	refname?: string;
}

/** iij: no `offset` field — `plt` is the PLT stub address, 0/absent for symbols with no stub (weak/unresolved). */
interface R2Import {
	ordinal: number;
	bind: string;
	type: string;
	name: string;
	plt?: number;
}

/** iEj: address lives in `vaddr`/`paddr`, not `offset`. */
interface R2Export {
	name: string;
	flagname?: string;
	realname?: string;
	ordinal: number;
	bind: string;
	size: number;
	type: string;
	vaddr?: number;
	paddr?: number;
}

/** izj: address lives in `vaddr`/`paddr`, not `offset`. */
interface R2String {
	vaddr?: number;
	paddr?: number;
	ordinal: number;
	size: number;
	length: number;
	section: string;
	type: string;
	string: string;
}

/** iSj: address lives in `vaddr`/`paddr`, not `offset`. */
interface R2Segment {
	name: string;
	size: number;
	vsize: number;
	perm: string;
	paddr?: number;
	vaddr?: number;
}

/** Annotate each row with a hex `ea` field so the model quotes the address rzx computed, not one it derived itself from a decimal offset. r2 6.x reports functions (aflj/afij) with `addr`; r2 5.x used `offset`. Resolve via `addrOf` and omit `ea` entirely rather than fabricate when neither is present. */
function withEa<T extends { addr?: number; offset?: number }>(items: T[]): (T & { ea?: string })[] {
	return items.map((item) => {
		const addr = addrOf(item);
		return addr === undefined ? { ...item } : { ...item, ea: eaFromOffset(addr) };
	});
}

/** iEj/izj/iSj carry `vaddr`/`paddr`, never `offset`. Omit `ea` entirely rather than fabricate when neither is present. */
function withVaddrEa<T extends { vaddr?: number; paddr?: number }>(items: T[]): (T & { ea?: string })[] {
	return items.map((item) => {
		const addr = item.vaddr ?? item.paddr;
		return addr === undefined ? { ...item } : { ...item, ea: eaFromOffset(addr) };
	});
}

/** iij carries `plt`, not `offset`; plt 0/absent means no PLT stub (weak/unresolved symbol) — omit `ea` rather than emit "0x0". */
function withPltEa(items: R2Import[]): (R2Import & { ea?: string })[] {
	return items.map((item) => (item.plt ? { ...item, ea: eaFromOffset(item.plt) } : { ...item }));
}

/** Only annotate whichever side (`from`/`to`) the row actually carries — never fabricate the implicit side. */
function withXrefEa(items: R2Xref[]): (R2Xref & { fromEa?: string; toEa?: string })[] {
	return items.map((item) => {
		const out: R2Xref & { fromEa?: string; toEa?: string } = { ...item };
		if (typeof item.from === "number") out.fromEa = eaFromOffset(item.from);
		if (typeof item.to === "number") out.toEa = eaFromOffset(item.to);
		return out;
	});
}

/** Render one pdfj op as 1-2 plain-text lines: an optional flag/label line ahead of the instruction it marks, then the address-prefixed instruction with any comment/xrefs folded in as a trailing annotation. Keeps output compact — this feeds an LLM context window. */
function formatPdfOp(op: PdfjOp): string[] {
	const lines: string[] = [];
	if (op.flags && op.flags.length > 0) lines.push(`${op.flags.join(", ")}:`);

	const annotations: string[] = [];
	if (op.comment) {
		try {
			const decoded = Buffer.from(op.comment, "base64").toString("utf8").trim();
			if (decoded.length > 0) annotations.push(decoded);
		} catch {
			// Malformed base64 in a pdfj comment must never crash the tool; just omit the annotation.
		}
	}
	if (op.xrefs && op.xrefs.length > 0) {
		annotations.push(`xrefs: ${op.xrefs.map((xref) => `${xref.type} ${eaFromOffset(addrOf(xref)!)}`).join(", ")}`);
	}
	const suffix = annotations.length > 0 ? `  ; ${annotations.join(" | ")}` : "";
	lines.push(`${eaFromOffset(addrOf(op)!)}  ${op.disasm}${suffix}`);
	return lines;
}

export function registerReadTools(pi: ExtensionAPI): void {
	const z = pi.zod;
	const offsetLimit = {
		offset: z.number().int().optional().describe("Skip this many results (default 0)."),
		limit: z.number().int().optional().describe(`Max results to return (default ${DEFAULT_LIMIT}, capped at ${MAX_LIMIT}).`),
	};

	pi.registerTool({
		name: "list_functions",
		label: "List Functions",
		description: "List all functions detected in the open binary.",
		approval: "read",
		loadMode: "essential",
		parameters: z.object(offsetLimit),
		async execute(_id, params, _signal, _onUpdate, ctx) {
			const r2 = await ensureR2(getState(ctx));
			const fns = (await r2.cmdj<R2Func[]>("aflj")) ?? [];
			const { page, total } = paginate(fns, params.offset, params.limit);
			return jsonResult(pageHeader("functions", page, total, params.offset), withEa(page));
		},
	});

	pi.registerTool({
		name: "search_functions",
		label: "Search Functions",
		description: "Search functions in the open binary by substring match on name.",
		approval: "read",
		loadMode: "essential",
		parameters: z.object({
			query: z.string().describe("Substring to match against function names."),
			...offsetLimit,
		}),
		async execute(_id, params, _signal, _onUpdate, ctx) {
			const r2 = await ensureR2(getState(ctx));
			const fns = (await r2.cmdj<R2Func[]>("aflj")) ?? [];
			const filtered = fns.filter((fn) => fn.name.includes(params.query));
			const { page, total } = paginate(filtered, params.offset, params.limit);
			return jsonResult(
				pageHeader(`functions matching ${JSON.stringify(params.query)}`, page, total, params.offset),
				withEa(page),
			);
		},
	});

	pi.registerTool({
		name: "get_function",
		label: "Get Function",
		description: "Get detailed info for a single function by name or address.",
		approval: "read",
		loadMode: "essential",
		parameters: z.object({
			target: z.string().describe("Function name or address (e.g. sym.main, 0x1000)."),
		}),
		async execute(_id, params, _signal, _onUpdate, ctx) {
			const r2 = await ensureR2(getState(ctx));
			const target = validateAddr(params.target);
			const fns = (await r2.cmdj<R2FuncInfo[]>(`afij @ ${target}`)) ?? [];
			if (fns.length === 0) throw new Error(`omp-re: function not found: ${params.target}`);
			const fn = fns[0]!;
			const addr = addrOf(fn);
			if (addr === undefined) throw new Error(`omp-re: function not found: ${params.target}`);
			const ea = eaFromOffset(addr);
			return jsonResult(`${fn.name} at ${ea} (size ${fn.size})`, { ...fn, ea }, ea);
		},
	});

	pi.registerTool({
		name: "decompile_function",
		label: "Decompile Function",
		description:
			"Decompile a function to pseudo-C, preferring a real decompiler plugin (r2ghidra's pdg or r2dec's pdd) when one is loaded. Falls back to r2's native pdc — register-level pseudo-C, not a real decompile — when no plugin is available, and flags that fallback in the output.",
		approval: "read",
		loadMode: "essential",
		parameters: z.object({ addr: z.string().describe("Function address or name.") }),
		async execute(_id, params, _signal, _onUpdate, ctx) {
			const r2 = await ensureR2(getState(ctx));
			const addr = validateAddr(params.addr);
			const ea = eaFromOffset(await resolveNumericAddr(r2, addr));

			const outcome = await decompileAt(r2, ea);
			if (!outcome) {
				throw new Error(`omp-re: decompile_function: no decompiler (pdg/pdd/pdc) produced output for ${params.addr}`);
			}
			if (outcome.kind === "pdc") {
				return prefixedTextResult(DISASM_ONLY_PREFIX, `pseudo-C for ${ea}\n${outcome.code}`, ea);
			}
			return textResult(`decompiled ${ea} (${outcome.kind})`, outcome.code, ea);
		},
	});

	pi.registerTool({
		name: "disassemble_function",
		label: "Disassemble Function",
		description:
			"Disassemble a function to annotated instructions: comments, flags/labels, and cross-references are folded in where pdfj reports them.",
		approval: "read",
		loadMode: "essential",
		parameters: z.object({ addr: z.string().describe("Function address or name.") }),
		async execute(_id, params, _signal, _onUpdate, ctx) {
			const r2 = await ensureR2(getState(ctx));
			const addr = validateAddr(params.addr);
			const ea = eaFromOffset(await resolveNumericAddr(r2, addr));
			const pdf = await r2.cmdj<PdfjResult>(`pdfj @ ${addr}`);
			if (!pdf) throw new Error(`omp-re: disassemble_function: no instructions at ${params.addr}`);
			const lines = pdf.ops.flatMap(formatPdfOp);
			return textResult(`${pdf.ops.length} instructions at ${ea}`, lines.join("\n"), ea);
		},
	});

	const xrefParams = z.object({
		addr: z.string().describe("Address to query cross-references for."),
		...offsetLimit,
	});

	pi.registerTool({
		name: "get_xrefs_to",
		label: "Get Xrefs To",
		description: "List cross-references pointing to an address.",
		approval: "read",
		loadMode: "essential",
		parameters: xrefParams,
		async execute(_id, params, _signal, _onUpdate, ctx) {
			const r2 = await ensureR2(getState(ctx));
			const addr = validateAddr(params.addr);
			const xrefs = (await r2.cmdj<R2Xref[]>(`axtj @ ${addr}`)) ?? [];
			const { page, total } = paginate(xrefs, params.offset, params.limit);
			return jsonResult(pageHeader(`xrefs to ${params.addr}`, page, total, params.offset), withXrefEa(page));
		},
	});

	pi.registerTool({
		name: "get_xrefs_from",
		label: "Get Xrefs From",
		description: "List cross-references originating from an address.",
		approval: "read",
		loadMode: "essential",
		parameters: xrefParams,
		async execute(_id, params, _signal, _onUpdate, ctx) {
			const r2 = await ensureR2(getState(ctx));
			const addr = validateAddr(params.addr);
			const xrefs = (await r2.cmdj<R2Xref[]>(`axfj @ ${addr}`)) ?? [];
			const { page, total } = paginate(xrefs, params.offset, params.limit);
			return jsonResult(pageHeader(`xrefs from ${params.addr}`, page, total, params.offset), withXrefEa(page));
		},
	});

	pi.registerTool({
		name: "list_imports",
		label: "List Imports",
		description: "List imported symbols in the open binary.",
		approval: "read",
		loadMode: "essential",
		parameters: z.object(offsetLimit),
		async execute(_id, params, _signal, _onUpdate, ctx) {
			const r2 = await ensureR2(getState(ctx));
			const items = (await r2.cmdj<R2Import[]>("iij")) ?? [];
			const { page, total } = paginate(items, params.offset, params.limit);
			return jsonResult(pageHeader("imports", page, total, params.offset), withPltEa(page));
		},
	});

	pi.registerTool({
		name: "list_exports",
		label: "List Exports",
		description: "List exported symbols in the open binary.",
		approval: "read",
		loadMode: "essential",
		parameters: z.object(offsetLimit),
		async execute(_id, params, _signal, _onUpdate, ctx) {
			const r2 = await ensureR2(getState(ctx));
			const items = (await r2.cmdj<R2Export[]>("iEj")) ?? [];
			const { page, total } = paginate(items, params.offset, params.limit);
			return jsonResult(pageHeader("exports", page, total, params.offset), withVaddrEa(page));
		},
	});

	pi.registerTool({
		name: "list_strings",
		label: "List Strings",
		description: "List strings found in the open binary, optionally filtered by substring.",
		approval: "read",
		loadMode: "essential",
		parameters: z.object({
			...offsetLimit,
			filter: z.string().optional().describe("Only include strings containing this substring."),
		}),
		async execute(_id, params, _signal, _onUpdate, ctx) {
			const r2 = await ensureR2(getState(ctx));
			const items = (await r2.cmdj<R2String[]>("izj")) ?? [];
			const filtered = params.filter ? items.filter((s) => s.string.includes(params.filter as string)) : items;
			const { page, total } = paginate(filtered, params.offset, params.limit);
			return jsonResult(pageHeader("strings", page, total, params.offset), withVaddrEa(page));
		},
	});

	pi.registerTool({
		name: "list_segments",
		label: "List Segments",
		description: "List memory segments/sections in the open binary.",
		approval: "read",
		loadMode: "essential",
		parameters: z.object(offsetLimit),
		async execute(_id, params, _signal, _onUpdate, ctx) {
			const r2 = await ensureR2(getState(ctx));
			const items = (await r2.cmdj<R2Segment[]>("iSj")) ?? [];
			const { page, total } = paginate(items, params.offset, params.limit);
			return jsonResult(pageHeader("segments", page, total, params.offset), withVaddrEa(page));
		},
	});

	pi.registerTool({
		name: "hash_binary",
		label: "Hash Binary",
		description: "Compute SHA-256, SHA-1, and MD5 digests of the session's bound binary.",
		approval: "read",
		loadMode: "essential",
		parameters: z.object({}),
		async execute(_id, _params, _signal, _onUpdate, ctx) {
			const binaryPath = requireBinary(getState(ctx));
			const digest = await hashFile(binaryPath);
			const text = `sha256=${digest.sha256}\nsha1=${digest.sha1}\nmd5=${digest.md5}\nsize=${digest.size}`;
			return {
				content: [{ type: "text" as const, text }],
				details: { ea: "0x0", summary: text },
			};
		},
	});
}

interface FileDigest {
	sha256: string;
	sha1: string;
	md5: string;
	size: number;
}

function hashFile(path: string): Promise<FileDigest> {
	const { promise, resolve, reject } = Promise.withResolvers<FileDigest>();
	const sha256 = createHash("sha256");
	const sha1 = createHash("sha1");
	const md5 = createHash("md5");
	let size = 0;
	const stream = createReadStream(path);
	stream.on("data", (chunk: Buffer) => {
		size += chunk.length;
		sha256.update(chunk);
		sha1.update(chunk);
		md5.update(chunk);
	});
	stream.on("end", () => {
		resolve({ sha256: sha256.digest("hex"), sha1: sha1.digest("hex"), md5: md5.digest("hex"), size });
	});
	stream.on("error", (err) => reject(new Error(`omp-re: hash_binary: read failed: ${err.message}`)));
	return promise;
}
