import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { getAgentDir, setAgentDir } from "@oh-my-pi/pi-utils";
import { readBlob, writeBlob } from "../extensions/re/evidence.ts";

let tempDir: string;
let originalAgentDir: string;

beforeEach(async () => {
	originalAgentDir = getAgentDir();
	tempDir = await mkdtemp(join(tmpdir(), "omp-re-evidence-test-"));
	setAgentDir(tempDir);
});

afterEach(async () => {
	setAgentDir(originalAgentDir);
	await rm(tempDir, { recursive: true, force: true });
});

describe("writeBlob / readBlob", () => {
	test("round-trips content and returns a stable content-addressed hash", async () => {
		const content = "some evidence text";
		const hash = await writeBlob(content);
		expect(hash).toMatch(/^[0-9a-f]{64}$/);
		const read = await readBlob(hash);
		expect(read).toBe(content);
	});

	test("writing identical content twice is idempotent and yields the same hash", async () => {
		const content = "duplicate blob content";
		const hash1 = await writeBlob(content);
		const hash2 = await writeBlob(content);
		expect(hash1).toBe(hash2);
		expect(await readBlob(hash1)).toBe(content);
	});

	test("readBlob on an unknown hash returns null and does not throw", async () => {
		const unknownHash = "0".repeat(64);
		await expect(readBlob(unknownHash)).resolves.toBeNull();
	});
});
