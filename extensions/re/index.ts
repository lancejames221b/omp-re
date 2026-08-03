/**
 * omp-re wiring hub. This is the sole auto-loaded extension for the `re/`
 * subdirectory (omp's directory-with-index.ts convention); every sibling
 * file here is a plain module imported below, never a separate extension.
 */
import type { ExtensionAPI, ExtensionContext } from "@oh-my-pi/pi-coding-agent";
import { Text } from "@oh-my-pi/pi-tui";
import { R2Session, assertR2Available, resolveBinaryPath, resolveR2Path } from "./r2.ts";
import { getState, shutdownState } from "./state.ts";
import { registerReadTools } from "./tools-read.ts";
import { registerMutateTools, undoLastAnnotation } from "./tools-mutate.ts";
import { registerTriageTools } from "./tools-triage.ts";
import { registerEvidenceStore } from "./evidence.ts";
import { RE_ALL_TOOL_NAMES, registerAuditLog } from "./audit.ts";
import { registerUI, refreshStatusBand, findEvidence, showEvidencePanel, showFunctionsPanel, showImportsPanel, showStringsPanel } from "./ui.ts";
import { writeReport } from "./report.ts";
import { textResult } from "./format.ts";

/** Open a binary for the given session: resolve the path, verify r2 is on PATH, spawn a fresh R2Session, and persist the choice so a later `--continue`/`--session` reload can restore it (re.evidence/re.annotation entries are meaningless without the binary they refer to). */
async function openBinary(pi: ExtensionAPI, ctx: ExtensionContext, inputPath: string): Promise<string> {
	const resolved = await resolveBinaryPath(inputPath);
	await assertR2Available();
	const state = getState(ctx);
	state.r2?.close();
	state.r2 = await R2Session.spawn(resolveR2Path(), resolved);
	state.binaryPath = resolved;
	// Two writes, deliberately: appendEntry persists a CustomEntry for lastRecordedBinaryPath()
	// to scan on a later --continue (never sent to the LLM); sendMessage is what actually feeds
	// the "re.binary" renderer below, since registerMessageRenderer only fires for role:"custom"
	// messages created via sendMessage, never for appendEntry's CustomEntry.
	pi.appendEntry("re.binary", { path: resolved });
	pi.sendMessage({ customType: "re.binary", content: `[re: opened ${resolved}]`, display: true, details: { path: resolved } });
	await refreshStatusBand(ctx);
	return resolved;
}

/** Find the most recently opened binary path recorded for this session, if any. */
function lastRecordedBinaryPath(ctx: ExtensionContext): string | undefined {
	let last: string | undefined;
	for (const entry of ctx.sessionManager.getEntries()) {
		if (entry.type !== "custom" || entry.customType !== "re.binary") continue;
		const data = entry.data as { path?: unknown } | undefined;
		if (typeof data?.path === "string") last = data.path;
	}
	return last;
}

export default async function (pi: ExtensionAPI) {
	pi.registerMessageRenderer<{ path?: string }>("re.binary", (message, _options, theme) => {
		const path = message.details?.path;
		return new Text(theme.fg("accent", `[re: opened ${typeof path === "string" ? path : "?"}]`), 0, 0);
	});

	registerReadTools(pi);
	registerMutateTools(pi);
	registerEvidenceStore(pi);
	registerAuditLog(pi);
	registerUI(pi);
	await registerTriageTools(pi);

	const z = pi.zod;
	const openBinaryParams = z.object({ path: z.string().describe("Path to the binary file to open.") });
	pi.registerTool({
		name: "open_binary",
		label: "Open binary",
		description:
			"Open a binary file for analysis in this session's radare2 backend. Every other RE tool (hash_binary, list_functions, decompile_function, etc.) acts on whichever binary was most recently opened here — call this first, especially in a delegated/subagent session that has no --binary flag or /re open command available.",
		approval: "read",
		loadMode: "essential",
		parameters: openBinaryParams,
		execute: async (_toolCallId, params, _signal, _onUpdate, ctx) => {
			try {
				const resolved = await openBinary(pi, ctx, params.path);
				return textResult("Binary opened.", resolved);
			} catch (err) {
				return { content: [{ type: "text", text: err instanceof Error ? err.message : String(err) }], isError: true };
			}
		},
	});

	pi.registerFlag("binary", {
		description: "Path to the binary to analyse",
		type: "string",
	});

	pi.on("session_start", async (_event, ctx) => {
		const flagValue = pi.getFlag("binary");
		const toOpen = typeof flagValue === "string" && flagValue.length > 0 ? flagValue : lastRecordedBinaryPath(ctx);
		if (!toOpen) return;
		try {
			await openBinary(pi, ctx, toOpen);
		} catch (err) {
			ctx.ui.notify(err instanceof Error ? err.message : String(err), "error");
		}
	});

	pi.on("session_shutdown", (_event, ctx) => {
		shutdownState(ctx.sessionManager.getSessionId());
	});

	pi.registerCommand("re", {
		description:
			"re reverse-engineering commands: open <path> | functions | strings | imports | evidence [id] | cite <id> | undo | report [path] | on | off | help",
		handler: async (args, ctx) => {
			const [sub, ...rest] = args.trim().split(/\s+/).filter(Boolean);

			if (sub === "open") {
				const path = rest.join(" ");
				if (!path) {
					ctx.ui.notify("Usage: /re open <path>", "error");
					return;
				}
				try {
					await openBinary(pi, ctx, path);
				} catch (err) {
					ctx.ui.notify(err instanceof Error ? err.message : String(err), "error");
				}
				return;
			}

			if (sub === "functions") {
				await showFunctionsPanel(ctx);
				return;
			}

			if (sub === "strings") {
				await showStringsPanel(ctx);
				return;
			}

			if (sub === "imports") {
				await showImportsPanel(ctx);
				return;
			}

			if (sub === "evidence") {
				await showEvidencePanel(ctx, rest[0]);
				return;
			}

			if (sub === "cite") {
				const id = rest[0];
				if (!id) {
					ctx.ui.notify("Usage: /re cite <id>", "error");
					return;
				}
				const rec = findEvidence(ctx, id);
				if (!rec) {
					ctx.ui.notify(`omp-re: no evidence found with id ${id}`, "error");
					return;
				}
				ctx.ui.setEditorText(
					`Re: evidence ${rec.id.slice(0, 8)} (${rec.tool} @ ${rec.ea ?? "?"})\n\n${rec.summary}\n\n`,
				);
				return;
			}

			if (sub === "undo") {
				try {
					const message = await undoLastAnnotation(pi, ctx);
					ctx.ui.notify(message, "info");
				} catch (err) {
					ctx.ui.notify(err instanceof Error ? err.message : String(err), "error");
				}
				return;
			}

			if (sub === "report") {
				try {
					await writeReport(ctx, rest.join(" ") || undefined);
				} catch (err) {
					ctx.ui.notify(err instanceof Error ? err.message : String(err), "error");
				}
				return;
			}

			if (sub === "off") {
				const active = pi.getActiveTools();
				await pi.setActiveTools(active.filter((name) => !RE_ALL_TOOL_NAMES[name]));
				ctx.ui.notify("omp-re: RE tools disabled for this session — /re on to re-enable", "info");
				return;
			}

			if (sub === "on") {
				const all = new Set(pi.getAllTools());
				const active = new Set(pi.getActiveTools());
				for (const name of Object.keys(RE_ALL_TOOL_NAMES)) {
					if (all.has(name)) active.add(name);
				}
				await pi.setActiveTools([...active]);
				ctx.ui.notify("omp-re: RE tools enabled for this session", "info");
				return;
			}

			if (sub === "help") {
				ctx.ui.notify([
					"/re open <path>      open a binary        alt+g  function navigator",
					"/re functions        function navigator   alt+s  strings",
					"/re strings          string list          in code view:",
					"/re imports          import list             d  toggle decompile",
					"/re evidence [id]    evidence log            x  follow xrefs",
					"/re cite <id>        cite evidence in chat",
					"/re undo             revert annotation       a  ask the model",
					"/re report [path]    write report",
					"/re on               enable RE tools",
					"/re off              disable RE tools (quick toggle, no restart)",
				].join("\n"), "info");
				return;
			}

			ctx.ui.notify(`omp-re: unknown /re subcommand ${JSON.stringify(sub ?? "")} — try /re help`, "error");
		},
	});
}
