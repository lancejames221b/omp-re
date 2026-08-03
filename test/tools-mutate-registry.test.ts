/**
 * Deterministic unit coverage for the 5 MUTATE-tier tool wrappers and the
 * `/re undo` switch (tools-mutate.ts:315-341).
 *
 * v0.1.0 note: this file previously pinned four command-template defects
 * (rename_variable/set_variable_type never seeking to the target address,
 * set_prototype sending the function-rename command `af` instead of the
 * set-signature command `afs`, and set_comment's non-idempotent append via
 * plain `CC`) as expected failures. All four are fixed in
 * `extensions/re/tools-mutate.ts`, verified directly against real radare2
 * (5.5.0 and 6.1.8) — see `test/QA-FINDINGS.md` §2 for the historical
 * record. Every case below now asserts real success plus an independent
 * read-back via `session.cmd`, bypassing the tool's own verification so a
 * regression back to any of the old command templates fails this suite.
 *
 * Tests within each `describe` block run in declaration order and share one
 * long-lived `R2Session` (spawned once in the outer `beforeAll`), so a test
 * that mutates state undoes it before the next `describe` block runs
 * anything against the same address/variable.
 */
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { existsSync } from "node:fs";
import * as zod from "zod/v4";
import type { ExtensionAPI, ExtensionContext, ToolDefinition } from "@oh-my-pi/pi-coding-agent";
import { R2Session, resolveR2Path } from "../extensions/re/r2.ts";
import { getState } from "../extensions/re/state.ts";
import { recordAnnotation, registerMutateTools, undoLastAnnotation } from "../extensions/re/tools-mutate.ts";

const TEST_BINARY = process.env.OMPRE_TEST_BINARY ?? "/tmp/rzx-dogfood/wannacry.bin";
const r2Path = resolveR2Path();
const r2Available = Bun.which(r2Path) !== null;
const binaryAvailable = existsSync(TEST_BINARY);

if (!r2Available || !binaryAvailable) {
	console.log(
		`omp-re: skipping tools-mutate-registry tests — ${!r2Available ? `radare2 ("${r2Path}") not on PATH` : ""}${!r2Available && !binaryAvailable ? "; " : ""}${!binaryAvailable ? `test binary not found at ${TEST_BINARY} (set OMPRE_TEST_BINARY)` : ""}`,
	);
}

interface StubEntry {
	type: "custom";
	id: string;
	customType: string;
	data: unknown;
}

/** Awaits a promise expected to reject and returns the rejection as an Error, for exact `.message` assertions (stricter than jest/bun's substring-matching `.toThrow(string)`). */
async function captureError(promise: Promise<unknown>): Promise<Error> {
	try {
		await promise;
	} catch (err) {
		return err instanceof Error ? err : new Error(String(err));
	}
	throw new Error("expected promise to reject, but it resolved");
}

describe.skipIf(!r2Available || !binaryAvailable)("mutate tool registry + undo coverage", () => {
	let session: R2Session;
	let entryCounter = 0;
	const entries: StubEntry[] = [];
	const tools = new Map<string, ToolDefinition<any, any>>();

	const pi = {
		zod,
		appendEntry: (customType: string, data?: unknown) => {
			entries.push({ type: "custom", id: `entry-${entryCounter++}`, customType, data });
		},
		registerTool: (def: ToolDefinition<any, any>) => {
			tools.set(def.name, def);
		},
	} as unknown as ExtensionAPI;

	const ctx = {
		ui: { notify: () => {} },
		sessionManager: {
			getSessionId: () => "omp-re-tools-mutate-registry-test",
			getEntries: () => entries,
		},
	} as unknown as ExtensionContext;

	registerMutateTools(pi);

	function tool(name: string): ToolDefinition<any, any> {
		const def = tools.get(name);
		if (!def) throw new Error(`omp-re test setup: tool "${name}" was never registered`);
		return def;
	}

	beforeAll(async () => {
		session = await R2Session.spawn(r2Path, TEST_BINARY);
		const state = getState(ctx);
		state.binaryPath = TEST_BINARY;
		state.r2 = session;
	});

	afterAll(() => {
		session.close();
	});

	describe("rename_variable", () => {
		test("a malformed new name throws the validateIdent literal before touching r2", async () => {
			const err = await captureError(
				tool("rename_variable").execute("call-rv-invalid", { addr: "main", old: "var_14h", new: "1bad" }, undefined, undefined, ctx),
			);
			expect(err.message).toBe('omp-re: invalid new: "1bad"');
		});

		test("well-formed args land, independently verified, and /re undo reverts it", async () => {
			const before = await session.cmd("afv @ main");
			expect(before).toContain("var_14h");

			const result = await tool("rename_variable").execute(
				"call-rv-valid",
				{ addr: "main", old: "var_14h", new: "renamedVar" },
				undefined,
				undefined,
				ctx,
			);
			const expectedSummary = "rename_variable: var_14h -> renamedVar @ main";
			expect(result.content).toEqual([{ type: "text", text: expectedSummary }]);
			expect(result.details).toEqual({ ea: "main", summary: expectedSummary });

			const after = await session.cmd("afv @ main");
			expect(after).toContain("renamedVar");
			expect(after).not.toContain("var_14h");

			const message = await undoLastAnnotation(pi, ctx);
			expect(message).toBe('omp-re: undid rename_variable @ main (restored "var_14h")');

			const reverted = await session.cmd("afv @ main");
			expect(reverted).toContain("var_14h");
			expect(reverted).not.toContain("renamedVar");
		});
	});

	describe("set_comment", () => {
		let entryOriginalComment = "";

		test("valid text lands (verified independently via CC.) and returns a meaningful success shape", async () => {
			entryOriginalComment = (await session.cmd("CC. @ entry0")).trim();
			const result = await tool("set_comment").execute("call-sc-valid", { addr: "entry0", text: "qa probe comment" }, undefined, undefined, ctx);
			const expectedSummary = `set_comment: ${entryOriginalComment} -> qa probe comment @ entry0`;
			expect(result.content).toEqual([{ type: "text", text: expectedSummary }]);
			expect(result.details).toEqual({ ea: "entry0", summary: expectedSummary });
			const after = (await session.cmd("CC. @ entry0")).trim();
			expect(after).toBe("qa probe comment");
		});

		test("a second call at the same address also succeeds — CC no longer appends", async () => {
			const result = await tool("set_comment").execute(
				"call-sc-second",
				{ addr: "entry0", text: "second qa probe comment" },
				undefined,
				undefined,
				ctx,
			);
			const expectedSummary = "set_comment: qa probe comment -> second qa probe comment @ entry0";
			expect(result.content).toEqual([{ type: "text", text: expectedSummary }]);
			const after = (await session.cmd("CC. @ entry0")).trim();
			expect(after).toBe("second qa probe comment");
		});

		test("a newline in the comment throws the validateText literal before touching r2", async () => {
			const err = await captureError(
				tool("set_comment").execute("call-sc-invalid", { addr: "entry0", text: "bad\ntext" }, undefined, undefined, ctx),
			);
			expect(err.message).toBe("omp-re: invalid text: contains forbidden character");
		});

		test("undo reverts the second call through the real tool and returns the exact literal", async () => {
			const message = await undoLastAnnotation(pi, ctx);
			expect(message).toBe('omp-re: undid set_comment @ entry0 (restored "qa probe comment")');
			const after = (await session.cmd("CC. @ entry0")).trim();
			expect(after).toBe("qa probe comment");
		});

		test("undoing again reverts the first call back to the original comment", async () => {
			// The "valid text" test's annotation is still on the stack; this undo steps back through it.
			const message = await undoLastAnnotation(pi, ctx);
			expect(message).toBe(`omp-re: undid set_comment @ entry0 (restored ${JSON.stringify(entryOriginalComment)})`);
			const after = (await session.cmd("CC. @ entry0")).trim();
			expect(after).toBe(entryOriginalComment);
		});

	});

	describe("set_prototype", () => {
		test("a forbidden shell character throws the validateTypeLike literal before touching r2", async () => {
			const err = await captureError(
				tool("set_prototype").execute("call-sp-invalid", { addr: "entry0", sig: "bad;sig" }, undefined, undefined, ctx),
			);
			expect(err.message).toBe('omp-re: invalid sig: forbidden character ";"');
		});

		test("a well-formed signature lands, independently verified, and /re undo reverts it", async () => {
			const before = (await session.cmd("afij @ entry0")).trim();

			const result = await tool("set_prototype").execute("call-sp-valid", { addr: "entry0", sig: "int probe(int a)" }, undefined, undefined, ctx);
			expect(result.content).toEqual([
				{ type: "text", text: expect.stringContaining("set_prototype:") as unknown as string },
			]);

			const after = (await session.cmd("afij @ entry0")).trim();
			expect(after).toContain('"signature":"int probe (int a);"');

			const message = await undoLastAnnotation(pi, ctx);
			expect(message).toStartWith("omp-re: undid set_prototype @ 0x");

			const reverted = (await session.cmd("afij @ entry0")).trim();
			expect(reverted).toBe(before);
		});
	});

	describe("set_variable_type", () => {
		test("a malformed variable name throws the validateIdent literal before touching r2", async () => {
			const err = await captureError(
				tool("set_variable_type").execute("call-svt-invalid", { addr: "main", var: "1bad", type: "int" }, undefined, undefined, ctx),
			);
			expect(err.message).toBe('omp-re: invalid var: "1bad"');
		});

		test("a well-formed type lands, independently verified, and /re undo reverts it", async () => {
			const before = await session.cmd("afv @ main");
			expect(before).toMatch(/var\s+\S+\s+var_14h\s+@/);

			const result = await tool("set_variable_type").execute(
				"call-svt-valid",
				{ addr: "main", var: "var_14h", type: "uint32_t" },
				undefined,
				undefined,
				ctx,
			);
			expect(result.details).toMatchObject({ ea: "main" });

			const after = await session.cmd("afv @ main");
			expect(after).toMatch(/var\s+uint32_t\s+var_14h\s+@/);

			const message = await undoLastAnnotation(pi, ctx);
			expect(message).toStartWith("omp-re: undid set_variable_type @ main (restored ");

			const reverted = await session.cmd("afv @ main");
			expect(reverted).toBe(before);
		});

		test("undo throws its own guard literal when the annotation is missing the variable name", async () => {
			await recordAnnotation(pi, ctx, "set_variable_type", { ea: "0x6666", oldValue: "int32_t", newValue: "uint32_t" });
			const err = await captureError(undoLastAnnotation(pi, ctx));
			expect(err.message).toBe("omp-re: cannot undo set_variable_type: annotation is missing the variable name");
		});
	});
});
