/**
 * Decompiler capability probing and invocation.
 *
 * r2's native `pdc` is a built-in pseudo-decompiler: register-level annotated
 * disassembly (`rsp -= 0x28`, `ebp = 0`, truncated mnemonics like `endbr6`),
 * not real decompilation. Real decompilers are r2ghidra (`pdg`) and r2dec
 * (`pdd`), loaded as optional plugins that may or may not be present at
 * runtime. When a plugin isn't loaded, r2's help form for its command
 * (`pdg?`/`pdd?`) replies with an error containing the literal substring
 * "r2pm -ci" (e.g. "Error: r2pm -ci r2ghidra") — that is the reliable "not
 * available" signature this file probes for. Never assume a plugin exists;
 * always probe at runtime and degrade honestly to `pdc`.
 */
import type { R2Session } from "./r2.ts";

export type DecompilerKind = "pdg" | "pdd" | "pdc";

export interface DecompileOutcome {
	kind: DecompilerKind;
	code: string;
}

/** Exact formatting matters (em dash U+2014, one trailing space): prefixedTextResult keeps this at byte 0 of the content. No consumer currently matches on that literal. */
export const DISASM_ONLY_PREFIX = "(disassembly only — no decompiler plugin available) ";

/** A real decompile (pdg especially — full Ghidra Sleigh analysis) can run far longer than a plain r2 command; give it a much larger budget than cmd/cmdj's 60s default. */
const DECOMPILE_TIMEOUT_MS = 180_000;

/** r2's reply when a plugin-backed command's help form is invoked without the plugin loaded. Also treat empty output or r2's generic unknown-command replies as unavailable — never infer presence from anything short of real output. */
function isUnavailableReply(reply: string): boolean {
	const trimmed = reply.trim();
	if (trimmed.length === 0) return true;
	if (trimmed.includes("r2pm -ci")) return true;
	if (trimmed.includes("Unknown command")) return true;
	if (trimmed.includes("Cannot find")) return true;
	return false;
}

/** Ordered probe table: try r2ghidra's `pdg` first, then r2dec's `pdd`. Each entry's help form (`pdg?`/`pdd?`) reveals whether the plugin is actually loaded. */
const DECOMPILER_PROBES: readonly { kind: DecompilerKind; helpCommand: string }[] = [
	{ kind: "pdg", helpCommand: "pdg?" },
	{ kind: "pdd", helpCommand: "pdd?" },
];

/** Per-session decompiler tier, probed once and cached. A WeakMap drops a closed/GC'd session's entry for free (so it never leaks), and a fresh R2Session — a new spawn, e.g. after ensureR2 respawns a dead process — always re-probes rather than trusting a stale tier. */
const kindBySession = new WeakMap<R2Session, DecompilerKind>();

async function resolveKind(r2: R2Session): Promise<DecompilerKind> {
	const cached = kindBySession.get(r2);
	if (cached) return cached;

	let kind: DecompilerKind = "pdc";
	for (const probe of DECOMPILER_PROBES) {
		try {
			if (!isUnavailableReply(await r2.cmd(probe.helpCommand))) {
				kind = probe.kind;
				break;
			}
		} catch {
			// A throw (timeout, closed session, protocol desync) means "not available", never a crash.
		}
	}
	kindBySession.set(r2, kind);
	return kind;
}

/** pdcj has NO top-level `offset` field — only `code` and `annotations`. Kept local (not exported) since only the pdc branch below needs it. */
interface PdcjResult {
	code: string;
}

/**
 * Decompile the function at `ea`, preferring a real decompiler plugin.
 * Probes pdg (r2ghidra), then pdd (r2dec), then falls back to native pdc.
 * The probe result is cached per R2Session. Returns null when nothing
 * produced usable output.
 */
export async function decompileAt(r2: R2Session, ea: string): Promise<DecompileOutcome | null> {
	const kind = await resolveKind(r2);

	if (kind === "pdc") {
		const pdc = await r2.cmdj<PdcjResult>(`pdcj @ ${ea}`, DECOMPILE_TIMEOUT_MS);
		const code = pdc?.code ?? "";
		return code.trim().length > 0 ? { kind, code } : null;
	}

	// pdg/pdd also support a JSON variant (pdgj/pddj), but their shapes differ
	// and are version-dependent; the plain text form is what a human/model
	// actually wants, and it's stable across versions.
	const code = await r2.cmd(`${kind} @ ${ea}`, DECOMPILE_TIMEOUT_MS);
	return code.trim().length > 0 ? { kind, code } : null;
}
