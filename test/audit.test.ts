import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { createHmac } from "node:crypto";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { ExtensionAPI, ExtensionContext } from "@oh-my-pi/pi-coding-agent";
import { getAgentDir, setAgentDir } from "@oh-my-pi/pi-utils";
import {
	RE_ALL_TOOL_NAMES,
	RE_MUTATE_TOOL_NAMES,
	RE_READ_TOOL_NAMES,
	RE_SESSION_TOOL_NAMES,
	RE_TRIAGE_TOOL_NAMES,
	registerAuditLog,
} from "../extensions/re/audit.ts";

describe("RE_ALL_TOOL_NAMES", () => {
	test("contains exactly 22 names and is the union of read (12), mutate (5), triage (4), and session (1)", () => {
		expect(Object.keys(RE_READ_TOOL_NAMES)).toHaveLength(12);
		expect(Object.keys(RE_MUTATE_TOOL_NAMES)).toHaveLength(5);
		expect(Object.keys(RE_TRIAGE_TOOL_NAMES)).toHaveLength(4);
		expect(Object.keys(RE_SESSION_TOOL_NAMES)).toHaveLength(1);

		const allNames = Object.keys(RE_ALL_TOOL_NAMES);
		expect(allNames).toHaveLength(22);

		const expectedUnion = new Set([
			...Object.keys(RE_READ_TOOL_NAMES),
			...Object.keys(RE_MUTATE_TOOL_NAMES),
			...Object.keys(RE_TRIAGE_TOOL_NAMES),
			...Object.keys(RE_SESSION_TOOL_NAMES),
		]);
		expect(new Set(allNames)).toEqual(expectedUnion);
	});
});

/** Captures the "tool_call" handler registered by registerAuditLog without a real ExtensionAPI. */
function captureToolCallHandler(): (event: { type: "tool_call"; toolCallId: string; toolName: string; input: unknown }, ctx: ExtensionContext) => Promise<void> {
	let captured: ((event: unknown, ctx: unknown) => unknown) | undefined;
	const fakePi = {
		on: (event: string, handler: (event: unknown, ctx: unknown) => unknown) => {
			if (event === "tool_call") captured = handler;
		},
	} as unknown as ExtensionAPI;
	registerAuditLog(fakePi);
	if (!captured) throw new Error("registerAuditLog did not register a tool_call handler");
	return captured as (event: { type: "tool_call"; toolCallId: string; toolName: string; input: unknown }, ctx: ExtensionContext) => Promise<void>;
}

function makeCtx(sessionId: string, notifications: { message: string; type?: string }[]): ExtensionContext {
	return {
		hasUI: false,
		ui: {
			notify: (message: string, type?: string) => {
				notifications.push({ message, type });
			},
		},
		sessionManager: {
			getSessionId: () => sessionId,
		},
	} as unknown as ExtensionContext;
}

async function readAuditLines(sessionId: string): Promise<string[]> {
	const path = join(getAgentDir(), "re", "audit", `${sessionId}.log`);
	const raw = await readFile(path, "utf8");
	return raw
		.split("\n")
		.map((l) => l.trim())
		.filter((l) => l.length > 0);
}

describe("audit log", () => {
	let tempDir: string;
	let originalAgentDir: string;
	const originalHmacKey = process.env.OMPRE_AUDIT_HMAC_KEY;

	beforeEach(async () => {
		originalAgentDir = getAgentDir();
		tempDir = await mkdtemp(join(tmpdir(), "omp-re-audit-test-"));
		setAgentDir(tempDir);
	});

	afterEach(async () => {
		setAgentDir(originalAgentDir);
		await rm(tempDir, { recursive: true, force: true });
		if (originalHmacKey === undefined) delete process.env.OMPRE_AUDIT_HMAC_KEY;
		else process.env.OMPRE_AUDIT_HMAC_KEY = originalHmacKey;
	});

	test("with OMPRE_AUDIT_HMAC_KEY set, an appended line carries a non-empty hmac field that verifies", async () => {
		process.env.OMPRE_AUDIT_HMAC_KEY = "test-hmac-key";
		const sessionId = "audit-signed-session";
		const handler = captureToolCallHandler();
		const notifications: { message: string; type?: string }[] = [];
		const ctx = makeCtx(sessionId, notifications);

		await handler({ type: "tool_call", toolCallId: "call-1", toolName: "hash_binary", input: { path: "/tmp/x" } }, ctx);

		const lines = await readAuditLines(sessionId);
		expect(lines).toHaveLength(1);
		const parsed = JSON.parse(lines[0]!) as { hmac?: string; [key: string]: unknown };
		expect(typeof parsed.hmac).toBe("string");
		expect(parsed.hmac!.length).toBeGreaterThan(0);

		const { hmac, ...rest } = parsed;
		const expectedHmac = createHmac("sha256", "test-hmac-key").update(JSON.stringify(rest)).digest("base64");
		expect(hmac).toBe(expectedHmac);
	});

	test("with the key unset, lines are still written and the warning fires exactly once per session", async () => {
		delete process.env.OMPRE_AUDIT_HMAC_KEY;
		const sessionId = "audit-unsigned-session";
		const handler = captureToolCallHandler();
		const notifications: { message: string; type?: string }[] = [];
		const ctx = makeCtx(sessionId, notifications);

		const originalConsoleError = console.error;
		const errorCalls: unknown[][] = [];
		console.error = (...args: unknown[]) => {
			errorCalls.push(args);
		};
		try {
			await handler({ type: "tool_call", toolCallId: "call-1", toolName: "hash_binary", input: {} }, ctx);
			await handler({ type: "tool_call", toolCallId: "call-2", toolName: "list_functions", input: {} }, ctx);
			await handler({ type: "tool_call", toolCallId: "call-3", toolName: "list_imports", input: {} }, ctx);
		} finally {
			console.error = originalConsoleError;
		}

		const lines = await readAuditLines(sessionId);
		expect(lines).toHaveLength(3);
		for (const line of lines) {
			const parsed = JSON.parse(line) as { hmac?: string };
			expect(parsed.hmac).toBeUndefined();
		}

		const warnCalls = errorCalls.filter((args) => typeof args[0] === "string" && args[0].includes("OMPRE_AUDIT_HMAC_KEY not configured"));
		expect(warnCalls).toHaveLength(1);
	});
});
