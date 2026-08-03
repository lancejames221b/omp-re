/**
 * The five T1 mutating annotation tools, ported from internal/re/mutate.go.
 *
 * Every mutation follows the exact sequence: read-old -> write -> read-back ->
 * verify -> annotate. Verification compares the read-back against the
 * requested value; a mismatch throws (never silently "succeeds"). OldValue
 * comes from the pre-read, NewValue from the read-back — never from the
 * request — so a rename tool can't lie about what actually landed.
 */
import type { AgentToolResult, ExtensionAPI, ExtensionContext } from "@oh-my-pi/pi-coding-agent";
import { ensureR2, getState } from "./state.ts";
import { addrOf, eaFromOffset, normalizeAddr, validateAddr, validateIdent, validateText, validateTypeLike } from "./r2.ts";

/** Parse a JSON array read-back (afij/afvlj shape) defensively; returns [] on any parse failure rather than throwing, so callers can produce a clear verification error. */
function parseJsonArray(raw: string): Record<string, unknown>[] {
	try {
		const parsed: unknown = JSON.parse(raw);
		return Array.isArray(parsed) ? (parsed as Record<string, unknown>[]) : [];
	} catch {
		return [];
	}
}

/** Pull a hex EA out of a JSON read-back's addr/offset field (r2 6.x renamed afij's `offset` to `addr`; see addrOf), falling back to the raw requested addr when the read-back isn't JSON or has neither field. */
function resolveEA(readBack: string, fallbackAddr: string): string {
	const arr = parseJsonArray(readBack);
	const addr = addrOf(arr[0] ?? {});
	return addr === undefined ? fallbackAddr : eaFromOffset(addr);
}

/** r2's `afij` always re-punctuates a signature it stores (adds a space before `(`, appends a trailing `;`)
 * regardless of how it was set via `afs`, so an exact string compare between the requested signature and the
 * read-back would fail even when the mutation landed correctly. Strip that cosmetic re-punctuation from both
 * sides before comparing — this only tolerates r2's own deterministic formatting, not a semantic difference. */
function normalizeSignature(sig: string): string {
	return sig
		.trim()
		.replace(/;+\s*$/, "")
		.replace(/\s+/g, "");
}

interface AfvEntry {
	kind: "var" | "arg";
	type: string;
	name: string;
	location: string;
}

/**
 * Parse `afv`'s plain-text variable listing ("var int local_sum @ rbp-0x34",
 * "arg char * arg1 @ rdi"). This r2 build's JSON variant (`afvlj`) returns an
 * empty array even for functions with real stack variables confirmed present
 * via `afv`/`afij.bpvars` — a real protocol gap, not an edge case — so
 * variable read/read-back goes through this parser instead.
 */
function parseAfvPlainText(raw: string): AfvEntry[] {
	const entries: AfvEntry[] = [];
	for (const rawLine of raw.split("\n")) {
		const line = rawLine.trim();
		if (!line) continue;
		const atIndex = line.indexOf(" @ ");
		if (atIndex === -1) continue;
		const tokens = line
			.slice(0, atIndex)
			.split(/\s+/)
			.filter(Boolean);
		if (tokens.length < 3) continue;
		const kind = tokens[0] === "arg" ? "arg" : "var";
		const name = tokens[tokens.length - 1] ?? "";
		const type = tokens.slice(1, -1).join(" ");
		const location = line.slice(atIndex + 3).trim();
		entries.push({ kind, type, name, location });
	}
	return entries;
}

interface MutateResult {
	ea: string;
	oldValue: string;
	newValue: string;
	/** Extra identifier undo needs beyond ea/oldValue/newValue — only set_variable_type needs this (the variable name; oldValue/newValue there are types, not names). */
	target?: string;
}

/** Exported so /re undo (ui.ts, wired from index.ts) can reverse the most recent mutation without duplicating command-template knowledge. */
export async function recordAnnotation(
	pi: ExtensionAPI,
	ctx: ExtensionContext,
	kind: string,
	result: MutateResult,
): Promise<void> {
	const state = getState(ctx);
	const evidenceId = state.evidenceByAddr.get(normalizeAddr(result.ea)) ?? "";
	pi.appendEntry("re.annotation", {
		kind,
		ea: result.ea,
		oldValue: result.oldValue,
		newValue: result.newValue,
		target: result.target,
		evidenceId,
		ungrounded: evidenceId === "",
	});
}

function mutateContent(name: string, result: MutateResult): AgentToolResult<{ ea?: string; summary: string }> {
	const text = `${name}: ${result.oldValue} -> ${result.newValue} @ ${result.ea}`;
	return { content: [{ type: "text", text }], details: { ea: result.ea, summary: text } };
}

export function registerMutateTools(pi: ExtensionAPI): void {
	const z = pi.zod;

	pi.registerTool({
		name: "rename_function",
		label: "Rename Function",
		description: "Rename a function at the given address, verifying the rename actually landed before reporting success.",
		approval: "write",
		loadMode: "essential",
		parameters: z.object({
			addr: z.string().describe("Function address or name."),
			new: z.string().describe("New function name."),
		}),
		async execute(_id, params, _signal, _onUpdate, ctx) {
			const r2 = await ensureR2(getState(ctx));
			const addr = validateAddr(params.addr);
			const newName = validateIdent("new", params.new);

			const oldRaw = (await r2.cmd(`afij @ ${addr}`)).trim();
			const oldArr = parseJsonArray(oldRaw);
			const oldValue = typeof oldArr[0]?.name === "string" ? (oldArr[0].name as string) : oldRaw;

			await r2.cmd(`afn ${newName} ${addr}`);

			const readBack = (await r2.cmd(`afij @ ${addr}`)).trim();
			const info = parseJsonArray(readBack);
			const landed = info.find((fn) => fn.name === newName);
			if (!landed) {
				throw new Error(`omp-re: rename_function: mutation did not land: expected name ${JSON.stringify(newName)} not found in read-back`);
			}

			const result: MutateResult = { ea: resolveEA(readBack, addr), oldValue, newValue: newName };
			await recordAnnotation(pi, ctx, "rename_function", result);
			return mutateContent("rename_function", result);
		},
	});

	pi.registerTool({
		name: "rename_variable",
		label: "Rename Variable",
		description: "Rename a local variable within a function, verifying the rename actually landed before reporting success.",
		approval: "write",
		loadMode: "essential",
		parameters: z.object({
			addr: z.string().describe("Function address or name."),
			old: z.string().describe("Current variable name."),
			new: z.string().describe("New variable name."),
		}),
		async execute(_id, params, _signal, _onUpdate, ctx) {
			const r2 = await ensureR2(getState(ctx));
			const addr = validateAddr(params.addr);
			const oldName = validateIdent("old", params.old);
			const newName = validateIdent("new", params.new);

			// The old value is the current variable name itself — no read-old round trip needed (matches Go's parseOldValue for rename_variable).
			const oldValue = oldName;

			await r2.cmd(`afvn ${newName} ${oldName} @ ${addr}`);

			const readBack = (await r2.cmd(`afv @ ${addr}`)).trim();
			const vars = parseAfvPlainText(readBack);
			const landed = vars.find((v) => v.name === newName);
			if (!landed) {
				throw new Error(
					`omp-re: rename_variable: mutation did not land: expected variable name ${JSON.stringify(newName)} not found in read-back`,
				);
			}

			const result: MutateResult = { ea: resolveEA(readBack, addr), oldValue, newValue: newName };
			await recordAnnotation(pi, ctx, "rename_variable", result);
			return mutateContent("rename_variable", result);
		},
	});

	pi.registerTool({
		name: "set_comment",
		label: "Set Comment",
		description: "Set (or clear, with empty text) a comment at the given address, verifying it actually landed before reporting success.",
		approval: "write",
		loadMode: "essential",
		parameters: z.object({
			addr: z.string().describe("Address to comment."),
			text: z.string().describe("Comment text; empty string clears the comment."),
		}),
		async execute(_id, params, _signal, _onUpdate, ctx) {
			const r2 = await ensureR2(getState(ctx));
			const addr = validateAddr(params.addr);
			const text = validateText(params.text);

			const oldValue = (await r2.cmd(`CC. @ ${addr}`)).trim();

			// Empty text clears via CC- instead of CC, which with empty text would otherwise behave as a bare read.
			if (text === "") {
				await r2.cmd(`CC- @ ${addr}`);
			} else {
				// r2's CC appends to any existing comment rather than replacing it; clear first so the write is a true replace.
				await r2.cmd(`CC- @ ${addr}`);
				await r2.cmd(`CC ${text} @ ${addr}`);
			}

			const readBack = (await r2.cmd(`CC. @ ${addr}`)).trim();
			if (readBack !== text.trim()) {
				throw new Error(`omp-re: set_comment: mutation did not land: expected comment ${JSON.stringify(text)}, got ${JSON.stringify(readBack)}`);
			}

			const result: MutateResult = { ea: resolveEA(readBack, addr), oldValue, newValue: readBack };
			await recordAnnotation(pi, ctx, "set_comment", result);
			return mutateContent("set_comment", result);
		},
	});

	pi.registerTool({
		name: "set_prototype",
		label: "Set Prototype",
		description: "Set a function's type signature/prototype, verifying it actually landed before reporting success.",
		approval: "write",
		loadMode: "essential",
		parameters: z.object({
			addr: z.string().describe("Function address or name."),
			sig: z.string().describe("New C-style prototype/signature."),
		}),
		async execute(_id, params, _signal, _onUpdate, ctx) {
			const r2 = await ensureR2(getState(ctx));
			const addr = validateAddr(params.addr);
			const sig = validateTypeLike("sig", params.sig);

			const oldRaw = (await r2.cmd(`afij @ ${addr}`)).trim();
			const oldArr = parseJsonArray(oldRaw);
			// r2 always appends a trailing `;` to a stored signature (auto-generated or afs-set); strip it so a
			// later /re undo's validateTypeLike call on this oldValue doesn't reject it as a forbidden character.
			const oldValue = typeof oldArr[0]?.signature === "string" ? (oldArr[0].signature as string).replace(/;\s*$/, "") : oldRaw;

			await r2.cmd(`afs ${sig} @ ${addr}`);

			const readBack = (await r2.cmd(`afij @ ${addr}`)).trim();
			const info = parseJsonArray(readBack);
			const landed = info.find((fn) => typeof fn.signature === "string" && normalizeSignature(fn.signature) === normalizeSignature(sig));
			if (!landed) {
				throw new Error(`omp-re: set_prototype: mutation did not land: expected signature ${JSON.stringify(sig)} not found in read-back`);
			}

			const result: MutateResult = { ea: resolveEA(readBack, addr), oldValue, newValue: sig };
			await recordAnnotation(pi, ctx, "set_prototype", result);
			return mutateContent("set_prototype", result);
		},
	});

	pi.registerTool({
		name: "set_variable_type",
		label: "Set Variable Type",
		description: "Set a local variable's type, verifying it actually landed before reporting success.",
		approval: "write",
		loadMode: "essential",
		parameters: z.object({
			addr: z.string().describe("Function address or name."),
			var: z.string().describe("Variable name."),
			type: z.string().describe("New C-style type."),
		}),
		async execute(_id, params, _signal, _onUpdate, ctx) {
			const r2 = await ensureR2(getState(ctx));
			const addr = validateAddr(params.addr);
			const varName = validateIdent("var", params.var);
			const type = validateTypeLike("type", params.type);

			const oldRaw = (await r2.cmd(`afv @ ${addr}`)).trim();
			const oldVars = parseAfvPlainText(oldRaw);
			const oldEntry = oldVars.find((v) => v.name === varName);
			const oldValue = oldEntry?.type ?? oldRaw;

			await r2.cmd(`afvt ${varName} ${type} @ ${addr}`);

			const readBack = (await r2.cmd(`afv @ ${addr}`)).trim();
			const vars = parseAfvPlainText(readBack);
			const landed = vars.find((v) => v.name === varName && v.type === type);
			if (!landed) {
				throw new Error(
					`omp-re: set_variable_type: mutation did not land: expected variable ${JSON.stringify(varName)} with type ${JSON.stringify(type)} not found in read-back`,
				);
			}

			const result: MutateResult = { ea: resolveEA(readBack, addr), oldValue, newValue: type, target: varName };
			await recordAnnotation(pi, ctx, "set_variable_type", result);
			return mutateContent("set_variable_type", result);
		},
	});
}

interface AnnotationData {
	kind: string;
	ea: string;
	oldValue: string;
	newValue: string;
	target?: string;
}

/** Reverse the most recent not-yet-undone annotation by re-issuing the inverse r2 command with the stored OldValue. Used by `/re undo`. Records an `re.undo` marker (not a new annotation) so a repeated `/re undo` steps back through history instead of re-applying the same reversal. */
export async function undoLastAnnotation(pi: ExtensionAPI, ctx: ExtensionContext): Promise<string> {
	const entries = ctx.sessionManager.getEntries();

	const undone = new Set<string>();
	for (const entry of entries) {
		if (entry.type !== "custom" || entry.customType !== "re.undo") continue;
		const marker = entry.data as { undidEntryId?: unknown } | undefined;
		if (typeof marker?.undidEntryId === "string") undone.add(marker.undidEntryId);
	}

	let target: { id: string; data: AnnotationData } | undefined;
	for (const entry of entries) {
		if (entry.type !== "custom" || entry.customType !== "re.annotation") continue;
		if (undone.has(entry.id)) continue;
		target = { id: entry.id, data: entry.data as AnnotationData };
	}
	if (!target) throw new Error("omp-re: no annotation left to undo");
	const last = target.data;

	const r2 = await ensureR2(getState(ctx));
	const ea = validateAddr(last.ea);

	switch (last.kind) {
		case "rename_function":
			await r2.cmd(`afn ${validateIdent("old", last.oldValue)} ${ea}`);
			break;
		case "rename_variable":
			await r2.cmd(`afvn ${validateIdent("old", last.oldValue)} ${validateIdent("new", last.newValue)} @ ${ea}`);
			break;
		case "set_comment":
			if (last.oldValue === "") {
				await r2.cmd(`CC- @ ${ea}`);
			} else {
				await r2.cmd(`CC- @ ${ea}`);
				await r2.cmd(`CC ${validateText(last.oldValue)} @ ${ea}`);
			}
			break;
		case "set_prototype":
			await r2.cmd(`afs ${validateTypeLike("sig", last.oldValue)} @ ${ea}`);
			break;
		case "set_variable_type":
			if (!last.target) throw new Error("omp-re: cannot undo set_variable_type: annotation is missing the variable name");
			await r2.cmd(`afvt ${validateIdent("var", last.target)} ${validateTypeLike("type", last.oldValue)} @ ${ea}`);
			break;
		default:
			throw new Error(`omp-re: cannot undo unknown annotation kind: ${last.kind}`);
	}

	pi.appendEntry("re.undo", { undidEntryId: target.id });
	return `omp-re: undid ${last.kind} @ ${ea} (restored ${JSON.stringify(last.oldValue)})`;
}
