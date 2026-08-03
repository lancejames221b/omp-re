import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { existsSync } from "node:fs";
import { R2ProtocolError, R2Session, resolveBinaryPath, resolveR2Path } from "../extensions/re/r2.ts";
import type { ReSessionState } from "../extensions/re/state.ts";
import { ensureR2 } from "../extensions/re/state.ts";

const TEST_BINARY = process.env.OMPRE_TEST_BINARY ?? "/tmp/rzx-dogfood/wannacry.bin";
const r2Path = resolveR2Path();
const r2Available = Bun.which(r2Path) !== null;
const binaryAvailable = existsSync(TEST_BINARY);

if (!r2Available || !binaryAvailable) {
	console.log(
		`omp-re: skipping r2-integration tests — ${!r2Available ? `radare2 ("${r2Path}") not on PATH` : ""}${!r2Available && !binaryAvailable ? "; " : ""}${!binaryAvailable ? `test binary not found at ${TEST_BINARY} (set OMPRE_TEST_BINARY)` : ""}`,
	);
}

describe.skipIf(!r2Available || !binaryAvailable)("R2Session (radare2 integration)", () => {
	let session: R2Session;

	beforeAll(async () => {
		session = await R2Session.spawn(r2Path, TEST_BINARY);
	});

	afterAll(() => {
		session.close();
	});

	test("spawn + ij returns parseable JSON identifying an x86 PE binary", async () => {
		const raw = await session.cmd("ij");
		const parsed = JSON.parse(raw.trim()) as { core?: { format?: string }; bin?: { arch?: string } };
		expect(parsed.bin?.arch).toBe("x86");
		expect(String(parsed.core?.format).toLowerCase()).toBe("pe");
	});

	test("50 sequential commands in one session all return their own output", async () => {
		for (let i = 0; i < 50; i++) {
			const marker = `omp-re-seq-${i}`;
			const raw = await session.cmd(`?e ${marker}`);
			expect(raw.trim()).toBe(marker);
		}
	});

	test("a tiny-timeout command rejects with R2ProtocolError mentioning a timeout", async () => {
		const slowSession = await R2Session.spawn(r2Path, TEST_BINARY);
		let caught: unknown;
		try {
			await slowSession.cmd("!sleep 2", 200);
		} catch (err) {
			caught = err;
		}
		expect(caught).toBeInstanceOf(R2ProtocolError);
		expect((caught as Error).message).toMatch(/timed out/);
		// The timeout path already closes the session (see r2.ts withTimeout); this is idempotent either way.
		slowSession.close();
		expect(slowSession.isClosed).toBe(true);
	});

	test("close() sets isClosed, and ensureR2 transparently respawns against the same binary", async () => {
		const respawnSession = await R2Session.spawn(r2Path, TEST_BINARY);
		expect(respawnSession.isClosed).toBe(false);
		respawnSession.close();
		expect(respawnSession.isClosed).toBe(true);

		const state: ReSessionState = {
			sessionId: "r2-integration-respawn-test",
			r2: respawnSession,
			binaryPath: TEST_BINARY,
			auditHmacWarned: false,
			evidenceCount: 0,
			findingCount: 0,
			evidenceByAddr: new Map(),
		};

		const respawned = await ensureR2(state);
		expect(respawned).not.toBe(respawnSession);
		expect(respawned.isClosed).toBe(false);
		expect(state.r2).toBe(respawned);

		const raw = await respawned.cmd("?e alive");
		expect(raw.trim()).toBe("alive");
		respawned.close();
	});
});

describe("resolveBinaryPath", () => {
	test("rejects a nonexistent path", async () => {
		await expect(resolveBinaryPath("/tmp/omp-re-does-not-exist-ever.bin")).rejects.toThrow("omp-re: no such binary:");
	});
});
