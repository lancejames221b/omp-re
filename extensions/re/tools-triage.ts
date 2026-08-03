/**
 * External triage tools (capa/floss/yara/die), ported from internal/re/triage.go.
 *
 * Each wraps an external binary invoked via argv (never a shell). A tool is
 * registered only when its binary is found on PATH at factory time — an
 * offered tool that always fails is worse than an absent one. On this
 * machine that means only `yara` registers; capa/floss/diec are absent.
 *
 * Like tools-read.ts, every tool returns the real findings (rule names,
 * matched capabilities, detections) as content, not just a count — Go's
 * agentloop.go:662 sent the model only `result.Text`, and Go's own summarize*
 * functions produced counts, not names.
 */
import { access, realpath as fsRealpath } from "node:fs/promises";
import { constants as fsConstants } from "node:fs";
import type { ExtensionAPI } from "@oh-my-pi/pi-coding-agent";
import { getState, requireBinary } from "./state.ts";
import { jsonResult, textResult } from "./format.ts";

interface PlainTriageDef {
	/** External tool key (also the summarizer lookup key). */
	name: string;
	/** Executable name resolved on PATH — differs from `name` only for "die" (binary is `diec`). */
	bin: string;
	description: string;
	timeoutMs: number;
}

/** capa/floss/die all take a bare `{{file}}` argv and emit real JSON via `-j`; yara has no JSON mode and is handled separately below. */
const PLAIN_TRIAGE_TOOLS: PlainTriageDef[] = [
	{
		name: "capa",
		bin: "capa",
		description: "Run capa rules against the binary to detect capabilities and ATT&CK techniques.",
		timeoutMs: 300_000,
	},
	{
		name: "floss",
		bin: "floss",
		description: "Extract obfuscated strings (stack, decoded, static) from the binary using FLOSS.",
		timeoutMs: 600_000,
	},
	{
		name: "die",
		bin: "diec",
		description: "Detect packers, compilers, and file types using Detect It Easy.",
		timeoutMs: 60_000,
	},
];

const YARA_TIMEOUT_MS = 120_000;

async function isOnPath(bin: string): Promise<boolean> {
	const dirs = (process.env.PATH ?? "").split(":").filter(Boolean);
	for (const dir of dirs) {
		try {
			await access(`${dir}/${bin}`, fsConstants.X_OK);
			return true;
		} catch {
			// keep scanning
		}
	}
	return false;
}

/** Resolve and validate an existing, readable file path (used for both the session binary and yara's rules file). */
async function resolveExistingFile(label: string, value: string): Promise<string> {
	let real: string;
	try {
		real = await fsRealpath(value);
	} catch {
		throw new Error(`omp-re: invalid ${label}: ${value}`);
	}
	try {
		await access(real, fsConstants.R_OK);
	} catch {
		throw new Error(`omp-re: invalid ${label}: ${value}`);
	}
	return real;
}

/** capa: pull rule name + ATT&CK/MBC mapping out of each matched rule's `meta`, not just a count. */
function capaFindings(parsed: unknown): unknown {
	if (typeof parsed !== "object" || parsed === null || !("rules" in parsed)) return null;
	const { rules } = parsed;
	if (rules === null || typeof rules !== "object") return null;
	// capa's top-level `rules` is a map keyed by rule name, not an array.
	return Object.entries(rules as Record<string, unknown>).map(([name, rule]) => {
		const meta = typeof rule === "object" && rule !== null && "meta" in rule ? (rule as Record<string, unknown>).meta : undefined;
		return { name, meta };
	});
}

/** floss: return the actual decoded/stack/static strings, not just totals. */
function flossFindings(parsed: unknown): unknown {
	if (typeof parsed !== "object" || parsed === null || !("strings" in parsed)) return null;
	const { strings } = parsed;
	if (typeof strings !== "object" || strings === null) return null;
	const out: Record<string, unknown> = {};
	for (const key of ["stack_strings", "decoded_strings", "static_strings"]) {
		if (key in strings) out[key] = (strings as Record<string, unknown>)[key];
	}
	return out;
}

/** die: return the actual per-scan detections, not just a count. */
function dieFindings(parsed: unknown): unknown {
	if (typeof parsed !== "object" || parsed === null || !("scans" in parsed)) return null;
	const { scans } = parsed;
	if (!Array.isArray(scans)) return null;
	return scans;
}

const FINDERS: Record<string, (parsed: unknown) => unknown> = {
	capa: capaFindings,
	floss: flossFindings,
	die: dieFindings,
};

/** One matched YARA rule, parsed from real plain-text CLI output (`<rule> <file>` per line — yara has no JSON output mode). */
interface YaraMatch {
	rule: string;
	file: string;
}

function parseYaraPlainText(stdout: string): YaraMatch[] {
	const matches: YaraMatch[] = [];
	for (const rawLine of stdout.split("\n")) {
		const line = rawLine.trim();
		if (!line) continue;
		const spaceIndex = line.indexOf(" ");
		if (spaceIndex === -1) continue; // malformed line (e.g. a warning) — skip rather than misparse
		matches.push({ rule: line.slice(0, spaceIndex), file: line.slice(spaceIndex + 1).trim() });
	}
	return matches;
}

export async function registerTriageTools(pi: ExtensionAPI): Promise<void> {
	const z = pi.zod;
	const [plainAvailability, yaraAvailable] = await Promise.all([
		Promise.all(PLAIN_TRIAGE_TOOLS.map((def) => isOnPath(def.bin))),
		isOnPath("yara"),
	]);

	for (const [index, def] of PLAIN_TRIAGE_TOOLS.entries()) {
		if (!plainAvailability[index]) continue; // absent binary — skip silently, never register a tool that always fails

		pi.registerTool({
			name: `triage_${def.name}`,
			label: `Triage: ${def.name}`,
			description: def.description,
			approval: "exec",
			loadMode: "essential",
			parameters: z.object({}),
			async execute(_id, _params, _signal, _onUpdate, ctx) {
				const file = await resolveExistingFile("file", requireBinary(getState(ctx)));
				const result = await pi.exec(def.bin, ["-j", file], { timeout: def.timeoutMs });
				// Exit code is advisory, not failure: capa signals "no matches" with a non-zero exit.
				// But empty stdout + non-zero exit means it never ran at all — that must not read as "0 findings".
				if (result.code !== 0 && result.stdout.trim() === "") {
					throw new Error(`omp-re: ${def.name} failed (exit ${result.code}): ${result.stderr.trim() || "no output"}`);
				}
				let parsed: unknown;
				try {
					parsed = JSON.parse(result.stdout);
				} catch {
					return textResult(`${def.name}: output was not valid JSON (schema not recognized)`, result.stdout);
				}
				const findings = FINDERS[def.name]?.(parsed);
				if (findings === null || findings === undefined) {
					return textResult(`${def.name}: expected JSON shape not found`, result.stdout);
				}
				const count = Array.isArray(findings) ? findings.length : Object.keys(findings as object).length;
				return jsonResult(`${def.name}: ${count} finding group(s)`, findings);
			},
		});
	}

	if (yaraAvailable) {
		pi.registerTool({
			name: "triage_yara",
			label: "Triage: yara",
			description: "Scan the binary with user-supplied YARA rules.",
			approval: "exec",
			loadMode: "essential",
			parameters: z.object({
				rules_path: z.string().describe("Path to a YARA rules file."),
			}),
			async execute(_id, params, _signal, _onUpdate, ctx) {
				if (params.rules_path.trim() === "") {
					throw new Error("omp-re: yara: rules_path argument is required (no default ruleset ships)");
				}
				const file = await resolveExistingFile("file", requireBinary(getState(ctx)));
				const rules = await resolveExistingFile("rules_path", params.rules_path);
				const result = await pi.exec("yara", [rules, file], { timeout: YARA_TIMEOUT_MS });
				// Exit code is advisory, not failure: yara exits non-zero on zero matches. But empty
				// stdout + non-zero exit (e.g. a rules file that failed to compile) must not read as
				// "0 rules matched" — that would be a false all-clear from a security tool.
				if (result.code !== 0 && result.stdout.trim() === "") {
					throw new Error(`omp-re: yara failed (exit ${result.code}): ${result.stderr.trim() || "no output"}`);
				}
				const matches = parseYaraPlainText(result.stdout);
				return jsonResult(`yara: ${matches.length} rule(s) matched`, matches);
			},
		});
	}
}
