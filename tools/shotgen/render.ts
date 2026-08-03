// Converts each tools/shotgen/out/<scene>.ansi capture (raw truecolor ANSI
// from `tmux capture-pane -ep`) into a styled tools/shotgen/out/<scene>.html
// page that reads as a real terminal window screenshot.
//
// Two passes, deliberately kept separate: ansi-to-html turns SGR codes into
// color spans, then a second pass wraps every character in its own
// fixed-width cell span *inside* those color spans (never replacing them —
// dropping the color spans would make every screenshot monochrome). The
// cell grid is what keeps box-drawing borders aligned: without it, emoji and
// fallback-font glyphs carry non-monospace advance widths and the right-hand
// borders drift out of column (verified by screenshot during this pass).
//
// Not part of the plugin: standalone dev tool under tools/shotgen/, isolated
// from the root package.json.
import { readdir } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import Convert from "ansi-to-html";

const SHOTGEN_DIR = dirname(fileURLToPath(import.meta.url));
const OUT_DIR = join(SHOTGEN_DIR, "out");

const FONT_STACK = "'Hack','DejaVu Sans Mono','Noto Sans Symbols2','Noto Color Emoji',monospace";

// --- East Asian Width, just enough of it -----------------------------------
// Full ranges for the standard Wide/Fullwidth categories (CJK, Hangul, full-
// width forms) plus the emoji/pictograph blocks the East Asian Width UCD
// property also classifies as Wide as of current Unicode data — real
// terminals render both classes at two cells. Combining marks are 0-width so
// they compose onto the preceding cell instead of claiming one of their own.
const WIDE_RANGES: Array<[number, number]> = [
	[0x1100, 0x115f], // Hangul Jamo
	[0x2e80, 0x303e], // CJK Radicals .. CJK Symbols and Punctuation
	[0x3041, 0x33ff], // Hiragana .. CJK Compatibility
	[0x3400, 0x4dbf], // CJK Unified Ideographs Extension A
	[0x4e00, 0x9fff], // CJK Unified Ideographs
	[0xa000, 0xa4cf], // Yi Syllables/Radicals
	[0xac00, 0xd7a3], // Hangul Syllables
	[0xf900, 0xfaff], // CJK Compatibility Ideographs
	[0xfe30, 0xfe4f], // CJK Compatibility Forms
	[0xff00, 0xff60], // Fullwidth Forms
	[0xffe0, 0xffe6],
	[0x1f000, 0x1f0ff], // Mahjong / dominoes / playing cards
	[0x1f300, 0x1faff], // Misc symbols & pictographs .. Symbols and Pictographs Extended-A
	[0x20000, 0x3fffd], // CJK Unified Ideographs Extension B+
];

const COMBINING_RANGES: Array<[number, number]> = [
	[0x0300, 0x036f],
	[0x1ab0, 0x1aff],
	[0x1dc0, 0x1dff],
	[0x20d0, 0x20ff],
	[0xfe20, 0xfe2f],
];

function inRanges(cp: number, ranges: Array<[number, number]>): boolean {
	return ranges.some(([lo, hi]) => cp >= lo && cp <= hi);
}

/** 0 for combining marks (compose onto the previous cell), 2 for East Asian Wide/Fullwidth, else 1. */
function charWidth(cp: number): 0 | 1 | 2 {
	if (inRanges(cp, COMBINING_RANGES)) return 0;
	if (inRanges(cp, WIDE_RANGES)) return 2;
	return 1;
}

// --- entity-aware per-character cell wrapping -------------------------------
// ansi-to-html (escapeXML: true) delegates to the `entities` package's
// encodeXML, which escapes `& < > "` as named entities but any other
// non-ASCII character — including every emoji this TUI renders — as a
// numeric character reference (`&#x1F5FA;`), not a named entity. Decoding
// only the five named forms would leave a literal `&#x1F5FA;` in the text
// stream, which then gets split into 9 separate one-column cells instead of
// composing back into one emoji (confirmed by a synthetic-input smoke test
// during this pass). Decode both named and numeric forms.
const NAMED_ENTITY_TO_CHAR: Record<string, string> = {
	amp: "&",
	lt: "<",
	gt: ">",
	quot: '"',
	apos: "'",
};
const CHAR_TO_ENTITY: Record<string, string> = {
	"&": "&amp;",
	"<": "&lt;",
	">": "&gt;",
	'"': "&quot;",
	"'": "&#39;",
};

function decodeEntities(text: string): string {
	return text.replace(/&(#x[0-9A-Fa-f]+|#[0-9]+|[A-Za-z]+);/g, (whole, body: string) => {
		if (body[0] === "#") {
			const isHex = body[1] === "x" || body[1] === "X";
			const codePoint = Number.parseInt(isHex ? body.slice(2) : body.slice(1), isHex ? 16 : 10);
			return Number.isFinite(codePoint) ? String.fromCodePoint(codePoint) : whole;
		}
		return NAMED_ENTITY_TO_CHAR[body] ?? whole;
	});
}

function wrapTextRun(text: string): string {
	const decoded = decodeEntities(text);
	let out = "";
	for (const ch of decoded) {
		if (ch === "\n" || ch === "\r") {
			out += ch; // real line breaks, never a cell
			continue;
		}
		const cp = ch.codePointAt(0) ?? 0;
		const width = charWidth(cp);
		const safe = CHAR_TO_ENTITY[ch] ?? ch;
		if (width === 0) {
			// Combining mark: compose without claiming a cell of its own.
			out += safe;
			continue;
		}
		const emStyle = width === 2 ? ";font-size:0.75em" : "";
		out += `<span style="display:inline-block;width:${width}ch;overflow:hidden;text-align:center${emStyle}">${safe}</span>`;
	}
	return out;
}

/** Splits `html` into tag/text tokens and wraps only the text tokens — tags (the ansi-to-html color spans) pass through untouched, so color survives. */
function applyCellGrid(html: string): string {
	return html
		.split(/(<[^>]+>)/)
		.map((token) => (token.startsWith("<") ? token : wrapTextRun(token)))
		.join("");
}

function renderPage(bodyHtml: string): string {
	return `<!doctype html>
<html>
<head>
<meta charset="utf-8">
<style>
  html, body { margin: 0; padding: 0; background: #0f1216; }
  #shot {
    display: inline-block;
    background: #0f1216;
    color: #d4c090;
    font-family: ${FONT_STACK};
    font-size: 16px;
    line-height: 1.35;
    padding: 20px;
    white-space: pre;
    border-radius: 10px;
  }
</style>
</head>
<body>
<pre id="shot">${bodyHtml}</pre>
</body>
</html>
`;
}

async function main(): Promise<void> {
	const entries = await readdir(OUT_DIR, { withFileTypes: true });
	const ansiFiles = entries.filter((e) => e.isFile() && e.name.endsWith(".ansi")).map((e) => e.name);
	if (ansiFiles.length === 0) {
		console.error(`render.ts: no .ansi captures found in ${OUT_DIR} — run capture.sh first`);
		process.exit(1);
	}
	for (const name of ansiFiles) {
		const scene = name.slice(0, -".ansi".length);
		const raw = await Bun.file(join(OUT_DIR, name)).text();
		const convert = new Convert({ fg: "#d4c090", bg: "#0f1216", newline: false, escapeXML: true });
		const colored = convert.toHtml(raw) as string;
		const gridded = applyCellGrid(colored);
		const page = renderPage(gridded);
		const outPath = join(OUT_DIR, `${scene}.html`);
		await Bun.write(outPath, page);
		console.log(`render.ts: wrote ${outPath}`);
	}
}

await main();
