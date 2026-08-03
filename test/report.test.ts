import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { access, mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { ExtensionContext } from "@oh-my-pi/pi-coding-agent";
import { writeReport } from "../extensions/re/report.ts";

interface StubEntry {
	type: string;
	customType?: string;
	data?: unknown;
}

function makeCtx(entries: StubEntry[], notifications: { message: string; type?: string }[]): ExtensionContext {
	return {
		ui: {
			notify: (message: string, type?: string) => {
				notifications.push({ message, type });
			},
		},
		hasUI: false,
		sessionManager: {
			getSessionId: () => "test-session",
			getEntries: () => entries,
		},
	} as unknown as ExtensionContext;
}

let tempDir: string;
let consoleErrorCalls: unknown[][];
let consoleLogCalls: unknown[][];
let originalConsoleError: typeof console.error;
let originalConsoleLog: typeof console.log;

beforeEach(async () => {
	tempDir = await mkdtemp(join(tmpdir(), "omp-re-report-test-"));
	process.exitCode = 0;
	consoleErrorCalls = [];
	consoleLogCalls = [];
	originalConsoleError = console.error;
	originalConsoleLog = console.log;
	console.error = (...args: unknown[]) => {
		consoleErrorCalls.push(args);
	};
	console.log = (...args: unknown[]) => {
		consoleLogCalls.push(args);
	};
});

afterEach(async () => {
	console.error = originalConsoleError;
	console.log = originalConsoleLog;
	process.exitCode = 0;
	await rm(tempDir, { recursive: true, force: true });
});

async function fileExists(path: string): Promise<boolean> {
	try {
		await access(path);
		return true;
	} catch {
		return false;
	}
}

describe("writeReport", () => {
	test("ungrounded: an IOC-shaped claim with no evidence id withholds the report", async () => {
		const entries: StubEntry[] = [
			{
				type: "custom",
				customType: "re.annotation",
				data: {
					kind: "comment",
					ea: "0x401000",
					oldValue: "",
					newValue: "http://evil-test.example/payload",
					evidenceId: "",
				},
			},
		];
		const notifications: { message: string; type?: string }[] = [];
		const ctx = makeCtx(entries, notifications);
		const outputPath = join(tempDir, "withheld.md");

		await writeReport(ctx, outputPath);

		expect(process.exitCode).toBe(1);
		expect(await fileExists(outputPath)).toBe(false);

		const errorText = consoleErrorCalls.map((args) => args.join(" ")).join("\n");
		expect(errorText).toContain("omp-re: report withheld");
		expect(errorText).toContain("hxxp://evil-test[.]example/payload");
	});

	test("grounded: an evidence-backed IOC claim writes the report with an anchor", async () => {
		const entries: StubEntry[] = [
			{
				type: "custom",
				customType: "re.evidence",
				data: {
					id: "ev-1",
					tool: "list_strings",
					summary: "found string: http://185.220.101.99/update.php in .data section",
				},
			},
		];
		const notifications: { message: string; type?: string }[] = [];
		const ctx = makeCtx(entries, notifications);
		const outputPath = join(tempDir, "grounded.md");

		await writeReport(ctx, outputPath);

		expect(process.exitCode).not.toBe(1);
		expect(await fileExists(outputPath)).toBe(true);

		const markdown = await readFile(outputPath, "utf8");
		expect(markdown).toContain("ev-1");
		expect(markdown).toContain("hxxp://185[.]220[.]101[.]99/update[.]php");
	});

	test("empty: no entries writes a trivial report without tripping the gate", async () => {
		const notifications: { message: string; type?: string }[] = [];
		const ctx = makeCtx([], notifications);
		const outputPath = join(tempDir, "empty.md");

		await writeReport(ctx, outputPath);

		expect(process.exitCode).not.toBe(1);
		expect(await fileExists(outputPath)).toBe(true);
		const markdown = await readFile(outputPath, "utf8");
		expect(markdown).toContain("Conclusion");
	});
});
