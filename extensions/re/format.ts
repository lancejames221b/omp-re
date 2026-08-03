/**
 * Shared tool-result formatting: every read/triage tool sends the model the
 * real data (not just a count — see tools-read.ts header comment for why),
 * truncated defensively via a local port of pi's truncation semantics.
 *
 * `truncateHead`/`formatSize`/`DEFAULT_MAX_LINES`/`DEFAULT_MAX_BYTES` are not
 * confirmed to exist on @oh-my-pi/pi-coding-agent, so the truncate-from-head
 * algorithm (two independent limits, whichever is hit first wins; never
 * returns a partial line) is ported locally instead of imported.
 */
import type { AgentToolResult } from "@oh-my-pi/pi-coding-agent";

const MAX_LINES = 2000;
const MAX_BYTES = 50 * 1024;

interface TruncationResult {
	content: string;
	truncated: boolean;
	totalLines: number;
	totalBytes: number;
	outputLines: number;
	outputBytes: number;
}

interface TruncationOptions {
	maxLines?: number;
	maxBytes?: number;
}

function splitLinesForCounting(content: string): string[] {
	if (content.length === 0) return [];
	const lines = content.split("\n");
	if (content.endsWith("\n")) lines.pop();
	return lines;
}

/** Format bytes as human-readable size. */
function formatSize(bytes: number): string {
	if (bytes < 1024) return `${bytes}B`;
	if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)}KB`;
	return `${(bytes / (1024 * 1024)).toFixed(1)}MB`;
}

/**
 * Truncate content from the head (keep first N lines/bytes). Never returns a
 * partial line; if the first line alone exceeds the byte limit, returns empty
 * content rather than a fragment.
 */
function truncateHead(content: string, options: TruncationOptions = {}): TruncationResult {
	const maxLines = options.maxLines ?? MAX_LINES;
	const maxBytes = options.maxBytes ?? MAX_BYTES;
	const totalBytes = Buffer.byteLength(content, "utf-8");
	const lines = splitLinesForCounting(content);
	const totalLines = lines.length;

	if (totalLines <= maxLines && totalBytes <= maxBytes) {
		return { content, truncated: false, totalLines, totalBytes, outputLines: totalLines, outputBytes: totalBytes };
	}

	const firstLineBytes = Buffer.byteLength(lines[0] ?? "", "utf-8");
	if (firstLineBytes > maxBytes) {
		return { content: "", truncated: true, totalLines, totalBytes, outputLines: 0, outputBytes: 0 };
	}

	const outputLinesArr: string[] = [];
	let outputBytesCount = 0;
	for (let i = 0; i < lines.length && i < maxLines; i++) {
		const line = lines[i] ?? "";
		const lineBytes = Buffer.byteLength(line, "utf-8") + (i > 0 ? 1 : 0); // +1 for the joining newline
		if (outputBytesCount + lineBytes > maxBytes) break;
		outputLinesArr.push(line);
		outputBytesCount += lineBytes;
	}

	const outputContent = outputLinesArr.join("\n");
	return {
		content: outputContent,
		truncated: true,
		totalLines,
		totalBytes,
		outputLines: outputLinesArr.length,
		outputBytes: Buffer.byteLength(outputContent, "utf-8"),
	};
}

/** Build a tool result whose content is the real JSON payload (not just a count), truncated defensively for huge outputs. */
export function jsonResult(header: string, data: unknown, ea?: string): AgentToolResult<{ ea?: string; summary: string }> {
	const body = JSON.stringify(data, null, 2);
	const truncation = truncateHead(body, { maxLines: MAX_LINES, maxBytes: MAX_BYTES });
	let text = `${header}\n${truncation.content}`;
	if (truncation.truncated) {
		text += `\n\n[Output truncated: ${truncation.outputLines} of ${truncation.totalLines} lines (${formatSize(truncation.outputBytes)} of ${formatSize(truncation.totalBytes)}). Narrow with offset/limit or filter.]`;
	}
	return {
		content: [{ type: "text", text }],
		details: { ea, summary: text.slice(0, 512) },
	};
}

/** Same idea for plain-text output (e.g. triage tool stdout) that isn't structured JSON. */
export function textResult(header: string, body: string, ea?: string): AgentToolResult<{ ea?: string; summary: string }> {
	const truncation = truncateHead(body, { maxLines: MAX_LINES, maxBytes: MAX_BYTES });
	let text = `${header}\n${truncation.content}`;
	if (truncation.truncated) {
		text += `\n\n[Output truncated: ${truncation.outputLines} of ${truncation.totalLines} lines (${formatSize(truncation.outputBytes)} of ${formatSize(truncation.totalBytes)}). Full output was larger.]`;
	}
	return {
		content: [{ type: "text", text }],
		details: { ea, summary: text.slice(0, 512) },
	};
}

/** Like textResult, but keeps `prefix` at byte 0 of the content. No consumer currently matches on that literal. */
export function prefixedTextResult(prefix: string, body: string, ea?: string): AgentToolResult<{ ea?: string; summary: string }> {
	const truncation = truncateHead(body, { maxLines: MAX_LINES, maxBytes: MAX_BYTES });
	let text = `${prefix}${truncation.content}`;
	if (truncation.truncated) {
		text += `\n\n[Output truncated: ${truncation.outputLines} of ${truncation.totalLines} lines (${formatSize(truncation.outputBytes)} of ${formatSize(truncation.totalBytes)}). Full output was larger.]`;
	}
	return {
		content: [{ type: "text", text }],
		details: { ea, summary: text.slice(0, 512) },
	};
}
