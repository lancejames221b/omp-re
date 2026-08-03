/**
 * Deterministic unit coverage for the 11 read-tier tool wrappers registered
 * by registerReadTools() (tools-read.ts) that are never invoked by name
 * anywhere else in the codebase: list_functions, search_functions,
 * get_function, decompile_function, disassemble_function, get_xrefs_to,
 * get_xrefs_from, list_imports, list_exports, list_strings, list_segments.
 *
 * Setup mirrors r2-integration.test.ts (spawn a real R2Session against the
 * fixture, skip the whole suite when r2 or the fixture is unavailable), but
 * instead of talking to R2Session directly, this file builds a stub
 * ExtensionAPI that records every registerTool() call and then invokes each
 * recorded ToolDefinition's execute() directly — the same 5-argument shape
 * (toolCallId, params, signal, onUpdate, ctx) the real pi runtime uses.
 *
 * "Valid argument" assertions are checked against ground truth fetched
 * independently (via raw session.cmd/cmdj calls in beforeAll, never by
 * calling into tools-read.ts), so a broken r2 command template inside a tool
 * — not a coincidence of this file mirroring it — is what makes a test fail.
 * "Invalid argument" assertions exercise whichever validation path is real
 * for that tool: the app-level ADDR_CHARS regex (validateAddr, for the 5
 * tools that take an address/name) or the Zod parameter schema itself (for
 * the other 6, which have no runtime argument validation of their own).
 */
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { existsSync } from "node:fs";
import type { ExtensionAPI, ExtensionContext, ToolDefinition } from "@oh-my-pi/pi-coding-agent";
import { zod } from "@oh-my-pi/pi-coding-agent";
import { R2Session, addrOf, eaFromOffset, resolveR2Path } from "../extensions/re/r2.ts";
import { getState } from "../extensions/re/state.ts";
import { registerReadTools } from "../extensions/re/tools-read.ts";

const TEST_BINARY = process.env.OMPRE_TEST_BINARY ?? "/tmp/rzx-dogfood/wannacry.bin";
const r2Path = resolveR2Path();
const r2Available = Bun.which(r2Path) !== null;
const binaryAvailable = existsSync(TEST_BINARY);

if (!r2Available || !binaryAvailable) {
	console.log(
		`omp-re: skipping tools-registry tests — ${!r2Available ? `radare2 ("${r2Path}") not on PATH` : ""}${!r2Available && !binaryAvailable ? "; " : ""}${!binaryAvailable ? `test binary not found at ${TEST_BINARY} (set OMPRE_TEST_BINARY)` : ""}`,
	);
}

/** An address string that fails r2.ts's ADDR_CHARS allowlist (the ';' makes r2 command-injection intent obvious) — used to exercise validateAddr's throw path. */
const BAD_ADDR = "main;whoami";
function expectedInvalidAddrMessage(addr: string): string {
	return `omp-re: invalid address or expression: ${JSON.stringify(addr)}`;
}

/** Mirrors tools-read.ts's own (unexported) pageHeader() so header assertions test real behavior without importing a private helper. */
function expectedPageHeader(label: string, pageLen: number, total: number, offset = 0): string {
	if (pageLen >= total) return `${pageLen} ${label}`;
	return `${pageLen} of ${total} ${label} (offset=${offset}; use offset/limit to page through the rest)`;
}

function textOf(result: { content: { type: string; text?: string }[] }): string {
	const block = result.content[0];
	if (!block || block.type !== "text" || typeof block.text !== "string") {
		throw new Error("expected a text content block");
	}
	return block.text;
}

/** Splits a tool result's rendered text into its header line and the remaining body (JSON payload for jsonResult, raw text for textResult). */
function splitHeaderBody(text: string): { header: string; body: string } {
	const nl = text.indexOf("\n");
	if (nl === -1) return { header: text, body: "" };
	return { header: text.slice(0, nl), body: text.slice(nl + 1) };
}

async function captureError(promise: Promise<unknown>): Promise<Error> {
	try {
		await promise;
	} catch (err) {
		if (err instanceof Error) return err;
		throw new Error(`expected an Error to be thrown, got ${String(err)}`);
	}
	throw new Error("expected the promise to reject, but it resolved");
}

function mustFind<T>(items: T[], pred: (item: T) => boolean, label: string): T {
	const found = items.find(pred);
	if (!found) {
		throw new Error(
			`tools-registry.test setup: fixture is missing ${label} — these tests assume the default WannaCry fixture (OMPRE_TEST_BINARY overrides at your own risk)`,
		);
	}
	return found;
}

/** r2 6.x renamed aflj/afij's address field from `offset` to `addr` (and dropped `callrefs` entirely); accept either via addrOf(). */
interface GroundFn {
	addr?: number;
	offset?: number;
	name: string;
	size?: number;
}
interface GroundImport {
	name: string;
	libname?: string;
	plt?: number;
}
interface GroundString {
	vaddr?: number;
	paddr?: number;
	string: string;
}
interface GroundSegment {
	name: string;
	perm: string;
	vaddr?: number;
	paddr?: number;
}
interface GroundXref {
	from?: number;
	to?: number;
	type: string;
}
interface GroundPdc {
	code: string;
}
/** r2 6.x renamed pdfj ops' address field from `offset` to `addr` too; accept either via addrOf(). */
interface GroundPdfOp {
	addr?: number;
	offset?: number;
	type: string;
	disasm: string;
}
interface GroundPdf {
	addr?: number;
	offset?: number;
	ops: GroundPdfOp[];
}

const registered = new Map<string, ToolDefinition<any, any>>();

function tool(name: string): ToolDefinition<any, any> {
	const def = registered.get(name);
	if (!def) throw new Error(`tools-registry.test setup: "${name}" was never registered by registerReadTools()`);
	return def;
}

let session: R2Session;
let ctx: ExtensionContext;

let groundFns: GroundFn[];
let mainFn: GroundFn;
let mainAddr: number;
let mainCallSite: number;
let groundImports: GroundImport[];
let waitForSingleObject: GroundImport;
let groundExports: unknown[];
let groundStrings: GroundString[];
let killSwitchString: GroundString;
let groundSegments: GroundSegment[];
let textSegment: GroundSegment;
let groundAxt: GroundXref[];
let groundAxf: GroundXref[];
let groundPdc: GroundPdc;
let groundPdf: GroundPdf;
/** decompile_function prefers a real decompiler plugin (r2ghidra's pdg, then r2dec's pdd) over r2's native pdc pseudo-decompiler when one is loaded; mirror decompile.ts's own probe-and-prefer order so the test asserts whichever branch the tool actually takes on this host. */
let expectedDecompileKind: "pdg" | "pdd" | "pdc";
let groundDecompileCode: string;

const KILL_SWITCH_FRAGMENT = "iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea";

describe.skipIf(!r2Available || !binaryAvailable)("registerReadTools (T0 read-only r2 tool wrappers)", () => {
	beforeAll(async () => {
		session = await R2Session.spawn(r2Path, TEST_BINARY);

		ctx = {
			sessionManager: { getSessionId: () => "tools-registry-test-session" },
		} as unknown as ExtensionContext;
		const state = getState(ctx);
		state.r2 = session;
		state.binaryPath = TEST_BINARY;

		const stubApi = {
			zod,
			registerTool(def: ToolDefinition<any, any>) {
				registered.set(def.name, def);
			},
		} as unknown as ExtensionAPI;
		registerReadTools(stubApi);

		groundFns = JSON.parse((await session.cmd("aflj")).trim()) as GroundFn[];
		mainFn = mustFind(groundFns, (f) => f.name === "main", "a function named 'main'");
		const resolvedMainAddr = addrOf(mainFn);
		if (resolvedMainAddr === undefined) {
			throw new Error("tools-registry.test setup: 'main' has neither 'addr' nor 'offset' in aflj output");
		}
		mainAddr = resolvedMainAddr;

		// r2 6.x's aflj carries no `callrefs` field at all, so a real CALL site
		// inside 'main' is found by disassembling it and picking the first op
		// whose `type` is "call" (verified live against r2 6.1.8).
		groundPdf = JSON.parse((await session.cmd("pdfj @ main")).trim()) as GroundPdf;
		const mainCallOp = mustFind(groundPdf.ops, (op) => op.type === "call", "a CALL instruction in 'main' (pdfj ops)");
		const resolvedCallSite = addrOf(mainCallOp);
		if (resolvedCallSite === undefined) {
			throw new Error("tools-registry.test setup: the CALL instruction in 'main' has neither 'addr' nor 'offset' in pdfj output");
		}
		mainCallSite = resolvedCallSite;

		groundImports = JSON.parse((await session.cmd("iij")).trim()) as GroundImport[];
		waitForSingleObject = mustFind(groundImports, (i) => i.name === "WaitForSingleObject", "import 'WaitForSingleObject'");

		groundExports = JSON.parse((await session.cmd("iEj")).trim()) as unknown[];

		groundStrings = JSON.parse((await session.cmd("izj")).trim()) as GroundString[];
		killSwitchString = mustFind(
			groundStrings,
			(s) => s.string.includes(KILL_SWITCH_FRAGMENT),
			`a string containing "${KILL_SWITCH_FRAGMENT}"`,
		);

		groundSegments = JSON.parse((await session.cmd("iSj")).trim()) as GroundSegment[];
		textSegment = mustFind(groundSegments, (s) => s.name === ".text", "segment '.text'");

		groundAxt = JSON.parse((await session.cmd("axtj @ main")).trim()) as GroundXref[];
		if (groundAxt.length === 0) throw new Error("tools-registry.test setup: expected at least one xref to 'main'");

		groundAxf = JSON.parse((await session.cmd(`axfj @ ${mainCallSite}`)).trim()) as GroundXref[];
		if (groundAxf.length === 0) throw new Error("tools-registry.test setup: expected at least one outgoing xref from the chosen call site");

		groundPdc = JSON.parse((await session.cmd("pdcj @ main")).trim()) as GroundPdc;

		const isDecompilerUnavailable = (reply: string): boolean => {
			const trimmed = reply.trim();
			return trimmed.length === 0 || trimmed.includes("r2pm -ci") || trimmed.includes("Unknown command") || trimmed.includes("Cannot find");
		};
		const pdgHelp = await session.cmd("pdg?");
		const pddHelp = await session.cmd("pdd?");
		if (!isDecompilerUnavailable(pdgHelp)) {
			expectedDecompileKind = "pdg";
			groundDecompileCode = (await session.cmd("pdg @ main")).trim();
		} else if (!isDecompilerUnavailable(pddHelp)) {
			expectedDecompileKind = "pdd";
			groundDecompileCode = (await session.cmd("pdd @ main")).trim();
		} else {
			expectedDecompileKind = "pdc";
			groundDecompileCode = groundPdc.code;
		}
	});

	afterAll(() => {
		session.close();
	});

	describe("list_functions", () => {
		test("valid: limit=1 returns the first function page-shaped, with matching total and hex ea", async () => {
			const result = await tool("list_functions").execute("t-list_functions-valid", { limit: 1 }, undefined, undefined, ctx);
			const { header, body } = splitHeaderBody(textOf(result));
			expect(header).toBe(expectedPageHeader("functions", 1, groundFns.length));
			const parsed = JSON.parse(body) as { name: string; addr?: number; offset?: number; ea: string }[];
			expect(Array.isArray(parsed)).toBe(true);
			expect(parsed.length).toBe(1);
			expect(parsed[0]?.name).toBe(groundFns[0]?.name);
			expect(addrOf(parsed[0]!)).toBe(addrOf(groundFns[0]!));
			expect(parsed[0]?.ea).toBe(eaFromOffset(addrOf(groundFns[0]!)!));
		});

		test("invalid: non-numeric limit is rejected by the parameter schema", () => {
			const result = tool("list_functions").parameters.safeParse({ limit: "nope" });
			expect(result.success).toBe(false);
			if (!result.success) {
				expect(result.error.issues[0]?.message).toBe("Invalid input: expected number, received string");
				expect(result.error.issues[0]?.path).toEqual(["limit"]);
			}
		});
	});

	describe("search_functions", () => {
		test("valid: query 'main' returns only name-matching functions, page-shaped", async () => {
			const groundMatches = groundFns.filter((f) => f.name.includes("main"));
			const result = await tool("search_functions").execute(
				"t-search_functions-valid",
				{ query: "main", limit: 5 },
				undefined,
				undefined,
				ctx,
			);
			const { header, body } = splitHeaderBody(textOf(result));
			const pageLen = Math.min(5, groundMatches.length);
			expect(header).toBe(expectedPageHeader(`functions matching ${JSON.stringify("main")}`, pageLen, groundMatches.length));
			const parsed = JSON.parse(body) as { name: string; ea: string }[];
			expect(Array.isArray(parsed)).toBe(true);
			expect(parsed.length).toBe(pageLen);
			expect(parsed.length).toBeGreaterThan(0);
			for (const fn of parsed) expect(fn.name).toContain("main");
		});

		test("invalid: missing required query is rejected by the parameter schema", () => {
			const result = tool("search_functions").parameters.safeParse({});
			expect(result.success).toBe(false);
			if (!result.success) {
				expect(result.error.issues[0]?.message).toBe("Invalid input: expected string, received undefined");
				expect(result.error.issues[0]?.path).toEqual(["query"]);
			}
		});
	});

	describe("get_function", () => {
		test("valid: target 'main' returns its name, size, and hex ea", async () => {
			const ea = eaFromOffset(mainAddr);
			const result = await tool("get_function").execute("t-get_function-valid", { target: "main" }, undefined, undefined, ctx);
			const text = textOf(result);
			expect(text.startsWith(`main at ${ea} (size ${mainFn.size})\n`)).toBe(true);
			const { body } = splitHeaderBody(text);
			const parsed = JSON.parse(body) as { name: string; addr?: number; offset?: number; size: number; ea: string };
			expect(parsed.name).toBe("main");
			expect(addrOf(parsed)).toBe(mainAddr);
			expect(parsed.size).toBe(mainFn.size!);
			expect(parsed.ea).toBe(ea);
			const { details: fnDetails } = result;
			const fnDetailsEa = fnDetails && typeof fnDetails === "object" && "ea" in fnDetails ? fnDetails.ea : undefined;
			expect(fnDetailsEa).toBe(ea);
		});

		test("invalid: a target containing forbidden characters throws validateAddr's exact message", async () => {
			const err = await captureError(
				tool("get_function").execute("t-get_function-invalid", { target: BAD_ADDR }, undefined, undefined, ctx),
			);
			expect(err.message).toBe(expectedInvalidAddrMessage(BAD_ADDR));
		});
	});

	describe("decompile_function", () => {
		test("valid: addr 'main' returns real decompiled output — pdg/pdd if a real decompiler plugin is loaded, else pdc's pseudo-C — containing the WannaCry kill-switch domain", async () => {
			const ea = eaFromOffset(mainAddr);
			const result = await tool("decompile_function").execute(
				"t-decompile_function-valid",
				{ addr: "main" },
				undefined,
				undefined,
				ctx,
			);
			const text = textOf(result);
			const expectedPrefix =
				expectedDecompileKind === "pdc" ? `pseudo-C for ${ea}\n` : `decompiled ${ea} (${expectedDecompileKind})\n`;
			expect(text.startsWith(expectedPrefix)).toBe(true);
			expect(text).toContain("main");
			expect(text).toContain(KILL_SWITCH_FRAGMENT);
			expect(text).toContain(groundDecompileCode.slice(0, 40));
			const { details: decompileDetails } = result;
			const decompileDetailsEa =
				decompileDetails && typeof decompileDetails === "object" && "ea" in decompileDetails ? decompileDetails.ea : undefined;
			expect(decompileDetailsEa).toBe(ea);
		});

		test("invalid: an addr containing forbidden characters throws validateAddr's exact message", async () => {
			const err = await captureError(
				tool("decompile_function").execute("t-decompile_function-invalid", { addr: BAD_ADDR }, undefined, undefined, ctx),
			);
			expect(err.message).toBe(expectedInvalidAddrMessage(BAD_ADDR));
		});
	});

	describe("disassemble_function", () => {
		test("valid: addr 'main' returns the real disassembly with matching instruction count and first line", async () => {
			const ea = eaFromOffset(mainAddr);
			const result = await tool("disassemble_function").execute(
				"t-disassemble_function-valid",
				{ addr: "main" },
				undefined,
				undefined,
				ctx,
			);
			const text = textOf(result);
			const firstOp = groundPdf.ops[0]!;
			expect(text.startsWith(`${groundPdf.ops.length} instructions at ${ea}\n`)).toBe(true);
			expect(text).toContain(`${eaFromOffset(addrOf(firstOp)!)}  ${firstOp.disasm}`);
		});

		test("invalid: an addr containing forbidden characters throws validateAddr's exact message", async () => {
			const err = await captureError(
				tool("disassemble_function").execute("t-disassemble_function-invalid", { addr: BAD_ADDR }, undefined, undefined, ctx),
			);
			expect(err.message).toBe(expectedInvalidAddrMessage(BAD_ADDR));
		});
	});

	describe("get_xrefs_to", () => {
		test("valid: addr 'main' returns entry0's real call xref with matching hex fromEa", async () => {
			const result = await tool("get_xrefs_to").execute("t-get_xrefs_to-valid", { addr: "main" }, undefined, undefined, ctx);
			const { header, body } = splitHeaderBody(textOf(result));
			expect(header).toBe(expectedPageHeader("xrefs to main", groundAxt.length, groundAxt.length));
			const parsed = JSON.parse(body) as { from?: number; type: string; fromEa?: string }[];
			expect(parsed.length).toBe(groundAxt.length);
			expect(parsed[0]?.from).toBe(groundAxt[0]?.from);
			expect(parsed[0]?.type).toBe(groundAxt[0]?.type);
			expect(parsed[0]?.fromEa).toBe(eaFromOffset(groundAxt[0]!.from!));
		});

		test("invalid: an addr containing forbidden characters throws validateAddr's exact message", async () => {
			const err = await captureError(
				tool("get_xrefs_to").execute("t-get_xrefs_to-invalid", { addr: BAD_ADDR }, undefined, undefined, ctx),
			);
			expect(err.message).toBe(expectedInvalidAddrMessage(BAD_ADDR));
		});
	});

	describe("get_xrefs_from", () => {
		test("valid: addr at a real call site returns its outgoing xref with matching hex toEa", async () => {
			const addr = String(mainCallSite);
			const result = await tool("get_xrefs_from").execute("t-get_xrefs_from-valid", { addr }, undefined, undefined, ctx);
			const { header, body } = splitHeaderBody(textOf(result));
			expect(header).toBe(expectedPageHeader(`xrefs from ${addr}`, groundAxf.length, groundAxf.length));
			const parsed = JSON.parse(body) as { to?: number; type: string; toEa?: string }[];
			expect(parsed.length).toBe(groundAxf.length);
			expect(parsed[0]?.to).toBe(groundAxf[0]?.to);
			expect(parsed[0]?.type).toBe(groundAxf[0]?.type);
			expect(parsed[0]?.toEa).toBe(eaFromOffset(groundAxf[0]!.to!));
		});

		test("invalid: an addr containing forbidden characters throws validateAddr's exact message", async () => {
			const err = await captureError(
				tool("get_xrefs_from").execute("t-get_xrefs_from-invalid", { addr: BAD_ADDR }, undefined, undefined, ctx),
			);
			expect(err.message).toBe(expectedInvalidAddrMessage(BAD_ADDR));
		});
	});

	describe("list_imports", () => {
		test("valid: default page includes the real WaitForSingleObject/KERNEL32.dll import with matching plt-derived ea", async () => {
			const result = await tool("list_imports").execute("t-list_imports-valid", {}, undefined, undefined, ctx);
			const { header, body } = splitHeaderBody(textOf(result));
			expect(header).toBe(expectedPageHeader("imports", groundImports.length, groundImports.length));
			const parsed = JSON.parse(body) as { name: string; libname?: string; plt?: number; ea?: string }[];
			expect(Array.isArray(parsed)).toBe(true);
			expect(parsed.length).toBe(groundImports.length);
			const found = mustFind(parsed, (i) => i.name === "WaitForSingleObject", "WaitForSingleObject in tool output");
			expect(found.libname).toBe(waitForSingleObject.libname);
			expect(found.ea).toBe(eaFromOffset(waitForSingleObject.plt!));
		});

		test("invalid: non-numeric offset is rejected by the parameter schema", () => {
			const result = tool("list_imports").parameters.safeParse({ offset: "nope" });
			expect(result.success).toBe(false);
			if (!result.success) {
				expect(result.error.issues[0]?.message).toBe("Invalid input: expected number, received string");
				expect(result.error.issues[0]?.path).toEqual(["offset"]);
			}
		});
	});

	describe("list_exports", () => {
		test("valid: default page matches the real (empty, for this non-DLL PE) export table", async () => {
			const result = await tool("list_exports").execute("t-list_exports-valid", {}, undefined, undefined, ctx);
			const { header, body } = splitHeaderBody(textOf(result));
			expect(header).toBe(expectedPageHeader("exports", groundExports.length, groundExports.length));
			const parsed = JSON.parse(body) as unknown[];
			expect(Array.isArray(parsed)).toBe(true);
			expect(parsed.length).toBe(groundExports.length);
		});

		test("invalid: non-numeric limit is rejected by the parameter schema", () => {
			const result = tool("list_exports").parameters.safeParse({ limit: "nope" });
			expect(result.success).toBe(false);
			if (!result.success) {
				expect(result.error.issues[0]?.message).toBe("Invalid input: expected number, received string");
				expect(result.error.issues[0]?.path).toEqual(["limit"]);
			}
		});
	});

	describe("list_strings", () => {
		test("valid: default page is capped at 200 of the real total, and the first row's known content survives", async () => {
			const result = await tool("list_strings").execute("t-list_strings-valid", {}, undefined, undefined, ctx);
			const text = textOf(result);
			const { header } = splitHeaderBody(text);
			expect(header).toBe(expectedPageHeader("strings", 200, groundStrings.length));
			// The body may be display-truncated at 200 rows, so assert on the
			// (always head-preserved) first row's exact known fields via
			// substring checks rather than a full JSON.parse.
			const first = groundStrings[0]!;
			expect(text).toContain(`"string": ${JSON.stringify(first.string)}`);
			if (first.vaddr !== undefined) {
				expect(text).toContain(`"ea": ${JSON.stringify(eaFromOffset(first.vaddr))}`);
			}
		});

		test("valid: filtering for the WannaCry kill-switch domain fragment returns exactly that string", async () => {
			const result = await tool("list_strings").execute(
				"t-list_strings-filter-valid",
				{ filter: KILL_SWITCH_FRAGMENT },
				undefined,
				undefined,
				ctx,
			);
			const { body } = splitHeaderBody(textOf(result));
			const parsed = JSON.parse(body) as { string: string; ea?: string }[];
			expect(parsed.length).toBe(1);
			expect(parsed[0]?.string).toBe(killSwitchString.string);
			if (killSwitchString.vaddr !== undefined) {
				expect(parsed[0]?.ea).toBe(eaFromOffset(killSwitchString.vaddr));
			}
		});

		test("invalid: non-string filter is rejected by the parameter schema", () => {
			const result = tool("list_strings").parameters.safeParse({ filter: 42 });
			expect(result.success).toBe(false);
			if (!result.success) {
				expect(result.error.issues[0]?.message).toBe("Invalid input: expected string, received number");
				expect(result.error.issues[0]?.path).toEqual(["filter"]);
			}
		});
	});

	describe("list_segments", () => {
		test("valid: default page includes the real executable .text segment with matching hex ea", async () => {
			const result = await tool("list_segments").execute("t-list_segments-valid", {}, undefined, undefined, ctx);
			const { header, body } = splitHeaderBody(textOf(result));
			expect(header).toBe(expectedPageHeader("segments", groundSegments.length, groundSegments.length));
			const parsed = JSON.parse(body) as { name: string; perm: string; vaddr?: number; ea?: string }[];
			expect(Array.isArray(parsed)).toBe(true);
			expect(parsed.length).toBe(groundSegments.length);
			const found = mustFind(parsed, (s) => s.name === ".text", ".text segment in tool output");
			expect(found.perm).toContain("x");
			expect(found.vaddr).toBe(textSegment.vaddr);
			if (textSegment.vaddr !== undefined) {
				expect(found.ea).toBe(eaFromOffset(textSegment.vaddr));
			}
		});

		test("invalid: non-numeric offset is rejected by the parameter schema", () => {
			const result = tool("list_segments").parameters.safeParse({ offset: "nope" });
			expect(result.success).toBe(false);
			if (!result.success) {
				expect(result.error.issues[0]?.message).toBe("Invalid input: expected number, received string");
				expect(result.error.issues[0]?.path).toEqual(["offset"]);
			}
		});
	});
});

