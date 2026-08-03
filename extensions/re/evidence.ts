/**
 * Evidence store, ported from rzx-re's extensions/re/evidence.ts (itself
 * from internal/re/evidence.go + blob/).
 *
 * A SHA-256 content-addressed blob store (temp-file-then-rename, idempotent)
 * plus a central `tool_result` hook that appends a `re.evidence` custom
 * entry after every successful read-tier RE tool call. `pi.appendEntry()`
 * persists the entry to the session JSONL but explicitly does NOT send it to
 * the LLM (see its doc comment on ExtensionAPI), so the model sees a tool
 * result once and never re-reads its own evidence log — the RE advisor and
 * report.ts do, via `ctx.sessionManager.getEntries()` scans (see report.ts
 * and ui.ts's showEvidencePanel, both of which filter session entries by
 * `customType` directly rather than rendering anything live).
 *
 * Unlike the source package's old-fork `registerEntryRenderer`, omp's
 * `registerMessageRenderer` fires only for CustomMessageEntry objects
 * created through `pi.sendMessage(...)` (role "custom") — never for the
 * `appendEntry`-created CustomEntry objects this module writes. There is no
 * live, inline, transcript-visible rendering path for evidence entries in
 * omp, and adding one via `sendMessage` would defeat the entire point of
 * `appendEntry` (it would re-inject every read-tool's full output into LLM
 * context on every single call). So this module registers no renderer at
 * all — that visual affordance from the old fork has no omp equivalent and
 * is not reintroduced.
 */
import { createHash, randomUUID } from "node:crypto";
import { mkdir, readFile, rename, stat, writeFile } from "node:fs/promises";
import { join } from "node:path";
import type { ExtensionAPI } from "@oh-my-pi/pi-coding-agent";
import { getAgentDir } from "@oh-my-pi/pi-utils";
import { RE_READ_TOOL_NAMES } from "./audit.ts";
import { normalizeAddr } from "./r2.ts";
import { getState } from "./state.ts";

/** Write content to the content-addressed blob store, returning its SHA-256 hex hash. Idempotent: skips the write if the target already exists. Atomic: writes to a temp file in the same directory, then renames. */
export async function writeBlob(content: string): Promise<string> {
	const hash = createHash("sha256").update(content, "utf8").digest("hex");
	const dir = join(getAgentDir(), "re", "blobs", hash.slice(0, 2), hash.slice(2, 4));
	const target = join(dir, hash);

	try {
		await stat(target);
		return hash; // already stored
	} catch {
		// not yet stored — fall through and write it
	}

	await mkdir(dir, { recursive: true, mode: 0o700 });
	const tmp = join(dir, `.${hash}.${process.pid}.${randomUUID()}.tmp`);
	await writeFile(tmp, content, { mode: 0o600 });
	await rename(tmp, target);
	return hash;
}

/** Read a previously written blob by its SHA-256 hash. Returns null when the blob is missing (never throws) — a missing blob must degrade to "no evidence" for the adviser, not crash it. */
export async function readBlob(hash: string): Promise<string | null> {
	const target = join(getAgentDir(), "re", "blobs", hash.slice(0, 2), hash.slice(2, 4), hash);
	try {
		return await readFile(target, "utf8");
	} catch {
		return null;
	}
}

/** Truncate to at most maxBytes, cutting on a UTF-8 character boundary (never mid-codepoint, and — since maxBytes comfortably exceeds the disassembly-only prefix's length — never mid-prefix either). */
function truncateUtf8Safe(text: string, maxBytes: number): string {
	const buf = Buffer.from(text, "utf8");
	if (buf.length <= maxBytes) return text;
	let end = maxBytes;
	// Back off while we're in the middle of a multi-byte UTF-8 sequence (continuation bytes are 10xxxxxx).
	while (end > 0 && (buf[end]! & 0xc0) === 0x80) end--;
	return buf.subarray(0, end).toString("utf8");
}

const EVIDENCE_SUMMARY_MAX_BYTES = 512;

/** Join every text content block into one string; image blocks contribute nothing. */
function extractText(content: readonly { type: string; text?: string }[]): string {
	return content
		.filter((part) => part.type === "text" && typeof part.text === "string")
		.map((part) => part.text)
		.join("\n");
}

export function registerEvidenceStore(pi: ExtensionAPI): void {
	// state.evidenceByAddr is in-memory only. On --continue / session reload, the
	// process restarts with an empty state even though re.evidence entries
	// already exist on disk — rebuild the index from them before anything else
	// can run, or every mutate tool's evidence lookup after a reload silently
	// reports "ungrounded" for addresses that really were observed.
	pi.on("session_start", (_event, ctx) => {
		const state = getState(ctx);
		state.evidenceByAddr.clear();
		state.evidenceCount = 0;
		for (const entry of ctx.sessionManager.getEntries()) {
			if (entry.type !== "custom" || entry.customType !== "re.evidence") continue;
			const data = entry.data as { id?: unknown; ea?: unknown } | undefined;
			if (!data || typeof data.id !== "string") continue;
			state.evidenceCount++;
			if (typeof data.ea === "string" && data.ea) {
				state.evidenceByAddr.set(normalizeAddr(data.ea), data.id);
			}
		}
	});

	pi.on("tool_result", async (event, ctx) => {
		if (event.isError) return undefined;
		if (RE_READ_TOOL_NAMES[event.toolName] !== true) return undefined;

		try {
			const state = getState(ctx);
			const rawText = extractText(event.content);
			const outputHash = await writeBlob(rawText);
			const summary = truncateUtf8Safe(rawText, EVIDENCE_SUMMARY_MAX_BYTES);

			const details = event.details;
			const ea =
				details && typeof details === "object" && "ea" in details && typeof details.ea === "string"
					? details.ea
					: undefined;

			const id = randomUUID();
			state.evidenceCount++;
			if (ea) state.evidenceByAddr.set(normalizeAddr(ea), id);

			pi.appendEntry("re.evidence", {
				id,
				tool: event.toolName,
				args: event.input,
				ea,
				outputHash,
				summary,
			});
		} catch (err) {
			// A blob-store failure (disk full, EACCES, ...) must degrade to "no evidence
			// recorded" for this call, not crash the tool_result pipeline.
			const msg = `omp-re: evidence recording failed: ${err instanceof Error ? err.message : String(err)}`;
			if (ctx.hasUI) ctx.ui.notify(msg, "error");
			else console.error(msg);
		}

		return undefined;
	});
}
