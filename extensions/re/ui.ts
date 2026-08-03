/**
 * RE surface: an always-visible binary-facts status band plus transient,
 * dismissable overlays opened by slash commands. `binaryFacts()` is this
 * package's single source of truth for reverser-relevant state (format,
 * arch, entry, protections, counts); `refreshStatusBand` mounts it via
 * `ctx.ui.setWidget` above the editor. omp exposes no sidebar/rail
 * primitive for extensions, so the band is the only status surface.
 */
import { basename } from "node:path";
import { getSymbolTheme, type CustomEntry, type ExtensionAPI, type ExtensionContext, type Theme } from "@oh-my-pi/pi-coding-agent";
import {
	matchesKey,
	SelectList,
	truncateToWidth,
	type Component,
	type KeybindingsManager,
	type SelectItem,
	type SelectListTheme,
	type TUI,
} from "@oh-my-pi/pi-tui";
import { DISASM_ONLY_PREFIX, decompileAt } from "./decompile.ts";
import { addrOf, eaFromOffset, type R2Session } from "./r2.ts";
import { getState } from "./state.ts";

async function functionCount(ctx: ExtensionContext): Promise<number> {
	const state = getState(ctx);
	if (!state.r2 || state.r2.isClosed) return 0;
	try {
		const fns = await state.r2.cmdj<unknown[]>("aflj");
		return fns?.length ?? 0;
	} catch {
		return 0;
	}
}

/** Static facts an `ij`/`iej` pair always answers for a given r2 process — genuinely invariant for the lifetime of one R2Session, unlike function count (which `set_prototype`'s `af` can grow mid-session). */
interface BinInfo {
	core: { size: number; format: string };
	bin: {
		arch: string;
		bits: number;
		os: string;
		bintype: string;
		class: string;
		endian: string;
		stripped: boolean;
		static: boolean;
		pic: boolean;
		nx: boolean;
		canary: boolean;
		lang: string;
		baddr: number;
		subsys: string;
	};
}

const binInfoCache = new WeakMap<R2Session, { info: BinInfo | null; entry: number | null }>();

async function loadBinInfo(r2: R2Session): Promise<{ info: BinInfo | null; entry: number | null }> {
	const cached = binInfoCache.get(r2);
	if (cached) return cached;
	let info: BinInfo | null = null;
	try {
		info = await r2.cmdj<BinInfo>("ij");
	} catch {
		info = null;
	}
	let entry: number | null = null;
	try {
		const iej = await r2.cmdj<Array<{ vaddr: number }>>("iej");
		entry = iej?.[0]?.vaddr ?? null;
	} catch {
		entry = null;
	}
	const result = { info, entry };
	binInfoCache.set(r2, result);
	return result;
}

/** Reverser-relevant facts about the currently open binary, plus live counts. Single source of truth for the status-band presenter — never derive display strings anywhere else. */
export interface BinaryFacts {
	name: string;
	path: string | null;
	size: number | null;
	format: string | null;
	arch: string | null;
	os: string | null;
	entry: string | null;
	prot: string[];
	fnCount: number;
	findings: number;
	evidence: number;
}

export async function binaryFacts(ctx: ExtensionContext): Promise<BinaryFacts> {
	const state = getState(ctx);
	const facts: BinaryFacts = {
		name: state.binaryPath ? basename(state.binaryPath) : "no binary",
		path: state.binaryPath,
		size: null,
		format: null,
		arch: null,
		os: null,
		entry: null,
		prot: [],
		fnCount: await functionCount(ctx),
		findings: state.findingCount,
		evidence: state.evidenceCount,
	};

	if (!state.r2 || state.r2.isClosed) return facts;

	const { info, entry } = await loadBinInfo(state.r2);
	if (info?.bin) {
		const bin = info.bin;
		facts.format = bin.class ?? null;
		facts.arch = bin.arch ? `${bin.arch}/${bin.bits}` : null;
		facts.os = bin.os ?? null;
		const prot: string[] = [];
		if (bin.stripped) prot.push("stripped");
		if (bin.static) prot.push("static");
		if (bin.pic) prot.push("pic");
		if (bin.nx) prot.push("nx");
		if (bin.canary) prot.push("canary");
		facts.prot = prot;
	}
	facts.size = info?.core?.size ?? null;
	facts.entry = entry != null ? `0x${entry.toString(16)}` : null;
	return facts;
}

function formatSize(bytes: number): string {
	if (bytes < 1024) return `${bytes}B`;
	const units = ["K", "M", "G", "T"];
	let value = bytes;
	let unitIndex = -1;
	while (value >= 1024 && unitIndex < units.length - 1) {
		value /= 1024;
		unitIndex++;
	}
	return `${value.toFixed(1).replace(/\.0$/, "")}${units[unitIndex]}`;
}

function renderBand(f: BinaryFacts, theme: Theme, width: number): string[] {
	const info = [f.format, f.arch, f.os].filter(Boolean).join(" ");
	const groups = [f.name, info, f.entry ? `entry ${f.entry}` : null, f.size != null ? formatSize(f.size) : null].filter(Boolean);
	const line1 = theme.fg("accent", groups.join("  "));
	const metrics = [`${f.fnCount} fn`, `${f.findings} findings`, `${f.evidence} evidence`].join(" \u00b7 ");
	const line2 = theme.fg("muted", metrics);
	return [truncateToWidth(line1, width), truncateToWidth(line2, width)];
}

/** The widget factory closes over one already-computed BinaryFacts snapshot; render() never re-fetches, so it stays a pure, synchronous presenter as the Component contract requires. */
function makeHud(facts: BinaryFacts): (tui: TUI, theme: Theme) => Component {
	return (_tui: TUI, theme: Theme) => ({
		render(width: number): string[] {
			return renderBand(facts, theme, width);
		},
		invalidate() {},
	});
}

/**
 * Exported so index.ts can force an immediate refresh right after openBinary() — session_start handlers across
 * extensions are not guaranteed to run in a particular order, so waiting for this module's own session_start hook
 * could render "no binary" if it fires before the binary finishes opening.
 */
export async function refreshStatusBand(ctx: ExtensionContext): Promise<void> {
	try {
		const facts = await binaryFacts(ctx);
		ctx.ui.setWidget("re.hud", makeHud(facts), { placement: "aboveEditor" });
	} catch {
		// best-effort: a stale ctx or dead r2 process must never crash the primary flow
	}
}

const MAX_VISIBLE_ROWS = 12;
const DEFAULT_HINT = "enter select \u00b7 esc close";

function selectListTheme(theme: Theme): SelectListTheme {
	return {
		selectedPrefix: (t) => theme.fg("accent", t),
		selectedText: (t) => theme.fg("accent", t),
		description: (t) => theme.fg("dim", t),
		scrollInfo: (t) => theme.fg("dim", t),
		noMatch: (t) => theme.fg("muted", t),
		symbols: getSymbolTheme(),
	};
}

interface PickerOptions {
	title: string;
	items: SelectItem[];
	/** Invoked on Enter. Return "close" to dismiss the panel, "keep" to leave it open. */
	onChoose?: (item: SelectItem) => "close" | "keep" | Promise<"close" | "keep">;
	/** Extra key handling, tried before the SelectList. Return true if consumed. */
	onKey?: (data: string, selected: SelectItem | null) => boolean;
	/** Right-hand hint text, e.g. "enter open \u00b7 x xrefs \u00b7 esc back". */
	hint?: string;
	done: (result: undefined) => void;
}

/** A scrollable, filterable list: SelectList plus an externally-driven text filter that matches on `label`
 * (not `value` — SelectList's built-in setFilter matches value by prefix, which is useless when value is an
 * address). Rebuilds the SelectList on each filter change since it exposes no setItems. */
function makePickerPanel(theme: Theme, opts: PickerOptions): Component {
	const allItems = opts.items;
	let filter = "";
	let selectList = buildSelectList();

	function buildSelectList(): SelectList {
		const filtered = filter !== ""
			? allItems.filter((item) => item.label.toLowerCase().includes(filter.toLowerCase()))
			: allItems;
		const sl = new SelectList(filtered, MAX_VISIBLE_ROWS, selectListTheme(theme));
		sl.onSelect = async (item) => {
			if ((await opts.onChoose?.(item)) !== "keep") opts.done(undefined);
		};
		sl.onCancel = () => opts.done(undefined);
		return sl;
	}

	return {
		render(width: number): string[] {
			const filterLine = filter !== "" ? `${theme.fg("dim", "/")}${filter}` : theme.fg("dim", "(type to filter)");
			const lines = [theme.fg("accent", opts.title), filterLine, ...selectList.render(width), theme.fg("dim", opts.hint ?? DEFAULT_HINT)];
			return lines.map((l) => truncateToWidth(l, width));
		},
		handleInput(data: string) {
			if (opts.onKey?.(data, selectList.getSelectedItem())) return;
			if (matchesKey(data, "escape")) {
				if (filter !== "") {
					filter = "";
					selectList = buildSelectList();
				} else {
					opts.done(undefined);
				}
				return;
			}
			if (data === "\x7f" || data === "\b") {
				filter = filter.slice(0, -1);
				selectList = buildSelectList();
				return;
			}
			if (data.length === 1 && data >= " " && data <= "~") {
				filter += data;
				selectList = buildSelectList();
				return;
			}
			selectList.handleInput(data);
		},
		invalidate() {
			selectList.invalidate();
		},
	};
}

/**
 * Overlay when the interactive TUI is available; falls back to a plain notification otherwise
 * (headless/print/RPC modes, where `ctx.ui.custom` is a no-op that would otherwise hang the
 * command indefinitely).
 */
async function showPanel(ctx: ExtensionContext, opts: Omit<PickerOptions, "done">): Promise<void> {
	if (!ctx.hasUI) {
		const body = opts.items.length > 0 ? opts.items.map((item) => item.label).join("\n") : "(nothing to show)";
		ctx.ui.notify(`${opts.title}\n${body}`.slice(0, 4000), "info");
		return;
	}
	await ctx.ui.custom<undefined>((_tui, theme, _keybindings, done) => makePickerPanel(theme, { ...opts, done }), { overlay: true });
}

export async function showFunctionsPanel(ctx: ExtensionContext): Promise<void> {
	const state = getState(ctx);
	if (!state.r2 || state.r2.isClosed) {
		ctx.ui.notify("omp-re: no binary open — use /re open <path> first", "error");
		return;
	}
	interface Fn {
		addr?: number;
		offset?: number;
		name: string;
	}
	let fns: Fn[] = [];
	try {
		fns = (await state.r2.cmdj<Fn[]>("aflj")) ?? [];
	} catch {
		// leave fns empty — panel shows "(nothing to show)"
	}
	const items: SelectItem[] = fns.flatMap((fn) => {
		const addr = addrOf(fn);
		if (addr === undefined) return [];
		const value = eaFromOffset(addr);
		return [{ value, label: fn.name, description: value }];
	});
	await showPanel(ctx, {
		title: "omp-re: functions",
		items,
		onChoose: async (item) => {
			await showCodeView(ctx, item.value, item.label);
			return "keep" as const;
		},
		hint: "enter open \u00b7 type to filter \u00b7 esc close",
	});
}

interface PdfjResult {
	ops: { addr?: number; offset?: number; disasm: string }[];
}

interface R2XrefRow {
	from: number;
	type: string;
	fcn_name?: string;
}

type CodeViewMode = "disasm" | "decompile";

/**
 * Fixed-width addressed-text viewer with a scroll offset — deliberately not SelectList, whose
 * primary/description column layout and truncation would reflow disassembly and pseudo-C alike.
 */
function makeCodeView(opts: {
	title: string;
	disasmLines: string[];
	decompileLines: string[] | null;
	theme: Theme;
	keybindings: KeybindingsManager;
	onToggle: () => boolean;
	onXrefs: () => void;
	onAsk: () => void;
	done: (result: undefined) => void;
}): Component {
	let mode: CodeViewMode = "disasm";
	let offset = 0;

	function clamp(): void {
		const lines = mode === "decompile" && opts.decompileLines ? opts.decompileLines : opts.disasmLines;
		const max = Math.max(0, lines.length - 1);
		offset = Math.min(Math.max(0, offset), max);
	}

	return {
		render(width: number): string[] {
			const theme = opts.theme;
			const lines = mode === "decompile" && opts.decompileLines ? opts.decompileLines : opts.disasmLines;
			const window = lines.slice(offset, offset + MAX_VISIBLE_ROWS);
			const rendered = [
				theme.fg("accent", `${opts.title} \u00b7 ${mode}`),
				...(window.length > 0 ? window.map((l) => theme.fg("text", l)) : [theme.fg("dim", "(nothing to show)")]),
				theme.fg("dim", "d decomp \u00b7 x xrefs \u00b7 a ask \u00b7 esc back"),
			];
			return rendered.map((l) => truncateToWidth(l, width));
		},
		handleInput(data: string) {
			if (matchesKey(data, "escape")) {
				opts.done(undefined);
				return;
			}
			if (data === "d") {
				if (opts.onToggle()) {
					mode = mode === "disasm" ? "decompile" : "disasm";
					offset = 0;
				}
				return;
			}
			if (data === "x") {
				opts.onXrefs();
				return;
			}
			if (data === "a") {
				opts.onAsk();
				return;
			}
			const kb = opts.keybindings;
			if (kb.matches(data, "tui.select.up")) {
				offset -= 1;
				clamp();
				return;
			}
			if (kb.matches(data, "tui.select.down")) {
				offset += 1;
				clamp();
				return;
			}
			if (kb.matches(data, "tui.select.pageUp")) {
				offset -= MAX_VISIBLE_ROWS;
				clamp();
				return;
			}
			if (kb.matches(data, "tui.select.pageDown")) {
				offset += MAX_VISIBLE_ROWS;
				clamp();
				return;
			}
		},
		invalidate() {},
	};
}

/**
 * The code-view surface: disassembly (default) or decompiled pseudo-C, with xref following and a
 * model hand-off key. Writes no `re.evidence` entry — evidence means "the agent observed this";
 * recording a human's browsing would let a claim be credited to something the model never actually saw.
 */
export async function showCodeView(ctx: ExtensionContext, addr: string, name?: string, depth = 0): Promise<void> {
	const state = getState(ctx);
	if (!state.r2 || state.r2.isClosed) {
		ctx.ui.notify("omp-re: no binary open — use /re open <path> first", "error");
		return;
	}
	if (depth > 8) {
		ctx.ui.notify("omp-re: xref chain too deep — stopping to avoid an unbounded loop", "info");
		return;
	}
	const r2 = state.r2;

	let decompileLines: string[] | null = null;
	try {
		const outcome = await decompileAt(r2, addr);
		if (outcome) {
			const codeLines = outcome.code.split("\n");
			decompileLines =
				outcome.kind === "pdc" ? [DISASM_ONLY_PREFIX, ...codeLines] : [`// decompiled with ${outcome.kind}`, ...codeLines];
		}
	} catch {
		decompileLines = null;
	}
	let disasmLines: string[] = [];
	try {
		const pdf = await r2.cmdj<PdfjResult>(`pdfj @ ${addr}`);
		if (pdf?.ops)
			disasmLines = pdf.ops.flatMap((op) => {
				const opAddr = addrOf(op);
				return opAddr === undefined ? [] : [`${eaFromOffset(opAddr)}  ${op.disasm}`];
			});
	} catch {
		disasmLines = [];
	}
	if (disasmLines.length === 0 && !decompileLines) {
		ctx.ui.notify(`omp-re: no code at ${addr}`, "error");
		return;
	}

	if (!ctx.hasUI) {
		const lines = disasmLines.length > 0 ? disasmLines : (decompileLines ?? []);
		ctx.ui.notify(`${name ?? addr}\n${lines.join("\n")}`.slice(0, 4000), "info");
		return;
	}

	async function followXrefs(): Promise<void> {
		let xrefs: R2XrefRow[] = [];
		try {
			xrefs = ((await r2.cmdj<R2XrefRow[]>(`axtj @ ${addr}`)) ?? []).filter((row) => typeof row.from === "number");
		} catch {
			xrefs = [];
		}
		if (xrefs.length === 0) {
			ctx.ui.notify(`omp-re: no xrefs to ${addr}`, "info");
			return;
		}
		const items: SelectItem[] = xrefs.map((row) => ({
			value: eaFromOffset(row.from),
			label: row.fcn_name ?? eaFromOffset(row.from),
			description: row.type,
		}));
		await showPanel(ctx, {
			title: `omp-re: xrefs to ${addr}`,
			items,
			onChoose: async (item) => {
				await showCodeView(ctx, item.value, item.label, depth + 1);
				return "keep" as const;
			},
			hint: "enter open \u00b7 esc back",
		});
	}

	await ctx.ui.custom<undefined>(
		(_tui, theme, keybindings, done) =>
			makeCodeView({
				title: name ?? addr,
				disasmLines,
				decompileLines,
				theme,
				keybindings,
				onToggle: () => {
					if (!decompileLines) {
						ctx.ui.notify("omp-re: no decompiler output (pdc unavailable)", "info");
						return false;
					}
					return true;
				},
				onXrefs: () => {
					void followXrefs();
				},
				onAsk: () => {
					ctx.ui.setEditorText(
						`Analyze function ${name ?? addr} at ${addr}. Use the RE tools to gather evidence first; report only what the evidence supports.`,
					);
					done(undefined);
				},
				done,
			}),
		{ overlay: true },
	);
}

export interface EvidenceRecord {
	id: string;
	tool: string;
	ea?: string;
	summary: string;
}

function isEvidenceEntry(entry: { type: string; customType?: string }): entry is CustomEntry<EvidenceRecord> & { customType: string } {
	return entry.type === "custom" && entry.customType === "re.evidence";
}

/** Prefix match: the picker only ever displays an 8-char slice of the UUID, so retyping what's
 * shown could never satisfy an exact-equality lookup. Shared by `showEvidencePanel` and `/re cite`
 * so there is exactly one lookup rule. */
export function findEvidence(ctx: ExtensionContext, id: string): EvidenceRecord | undefined {
	const all = ctx.sessionManager
		.getEntries()
		.filter(isEvidenceEntry)
		.map((entry) => entry.data as EvidenceRecord);
	return all.find((e) => e.id === id || e.id.startsWith(id));
}

export async function showEvidencePanel(ctx: ExtensionContext, id?: string): Promise<void> {
	const all = ctx.sessionManager
		.getEntries()
		.filter(isEvidenceEntry)
		.map((entry) => entry.data as EvidenceRecord);

	function showDetail(match: EvidenceRecord | undefined, lookupId: string): void {
		if (match) {
			ctx.ui.notify(`[${match.tool}:${match.ea ?? "?"}]\n\n${match.summary}`, "info");
		} else {
			ctx.ui.notify(`omp-re: no evidence found with id ${lookupId}`, "error");
		}
	}

	if (id) {
		showDetail(findEvidence(ctx, id), id);
		return;
	}

	const items: SelectItem[] = all.map((e) => ({
		value: e.id,
		label: `[${e.id.slice(0, 8)}] ${e.tool} @ ${e.ea ?? "?"}`,
		description: e.summary?.slice(0, 80),
	}));
	await showPanel(ctx, {
		title: "omp-re: evidence",
		items,
		onChoose: (item) => {
			showDetail(
				all.find((e) => e.id === item.value),
				item.value,
			);
			return "keep" as const;
		},
		hint: "enter detail \u00b7 type to filter \u00b7 esc close",
	});
}

interface R2String {
	vaddr: number;
	string: string;
}

export async function showStringsPanel(ctx: ExtensionContext): Promise<void> {
	const state = getState(ctx);
	if (!state.r2 || state.r2.isClosed) {
		ctx.ui.notify("omp-re: no binary open — use /re open <path> first", "error");
		return;
	}
	const r2 = state.r2;
	let strings: R2String[] = [];
	try {
		strings = ((await r2.cmdj<R2String[]>("izj")) ?? []).filter((s) => typeof s.vaddr === "number");
	} catch {
		strings = [];
	}
	const items: SelectItem[] = strings.map((s) => ({ value: eaFromOffset(s.vaddr), label: s.string, description: eaFromOffset(s.vaddr) }));
	await showPanel(ctx, {
		title: "omp-re: strings",
		items,
		onChoose: async (item) => {
			let xrefs: { from: number; fcn_name?: string }[] = [];
			try {
				xrefs = ((await r2.cmdj<{ from: number; fcn_name?: string }[]>(`axtj @ ${item.value}`)) ?? []).filter(
					(row) => typeof row.from === "number",
				);
			} catch {
				xrefs = [];
			}
			if (xrefs.length === 0) {
				ctx.ui.notify("omp-re: no xrefs to that string", "info");
				return "keep" as const;
			}
			const target = xrefs[0]!;
			await showCodeView(ctx, eaFromOffset(target.from), target.fcn_name);
			return "keep" as const;
		},
		hint: "enter open \u00b7 type to filter \u00b7 esc close",
	});
}

interface R2Import {
	name: string;
	plt?: number;
}

export async function showImportsPanel(ctx: ExtensionContext): Promise<void> {
	const state = getState(ctx);
	if (!state.r2 || state.r2.isClosed) {
		ctx.ui.notify("omp-re: no binary open — use /re open <path> first", "error");
		return;
	}
	const r2 = state.r2;
	let imports: R2Import[] = [];
	try {
		imports = (await r2.cmdj<R2Import[]>("iij")) ?? [];
	} catch {
		imports = [];
	}
	const items: SelectItem[] = imports.map((imp) => ({
		value: imp.plt ? eaFromOffset(imp.plt) : "",
		label: imp.name,
		description: imp.plt ? eaFromOffset(imp.plt) : "(no PLT)",
	}));
	await showPanel(ctx, {
		title: "omp-re: imports",
		items,
		onChoose: async (item) => {
			if (item.value === "") {
				ctx.ui.notify("omp-re: no PLT stub for that import", "info");
				return "keep" as const;
			}
			await showCodeView(ctx, item.value, item.label);
			return "keep" as const;
		},
		hint: "enter open \u00b7 type to filter \u00b7 esc close",
	});
}

export function registerUI(pi: ExtensionAPI): void {
	pi.on("session_start", async (_event, ctx) => {
		await refreshStatusBand(ctx);
	});
	pi.on("tool_result", async (_event, ctx) => {
		await refreshStatusBand(ctx);
	});

	pi.registerShortcut("alt+g", {
		description: "omp-re: function navigator",
		handler: async (ctx) => {
			await showFunctionsPanel(ctx);
		},
	});
	pi.registerShortcut("alt+s", {
		description: "omp-re: strings panel",
		handler: async (ctx) => {
			await showStringsPanel(ctx);
		},
	});
}
