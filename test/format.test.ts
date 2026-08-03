import { describe, expect, test } from "bun:test";
import { jsonResult, prefixedTextResult, textResult } from "../extensions/re/format.ts";

const MAX_LINES = 2000;
const MAX_BYTES = 50 * 1024;

function textOf(result: { content: { type: string; text?: string }[] }): string {
	const block = result.content[0];
	if (!block || block.type !== "text" || typeof block.text !== "string") {
		throw new Error("expected a text content block");
	}
	return block.text;
}

describe("textResult", () => {
	test("passes an under-cap body through unchanged", () => {
		const result = textResult("header", "line1\nline2\nline3");
		const text = textOf(result);
		expect(text).toBe("header\nline1\nline2\nline3");
		expect(text).not.toContain("[Output truncated");
	});

	test("head-truncates a body exceeding MAX_LINES and carries the truncation notice", () => {
		const lines = Array.from({ length: MAX_LINES + 500 }, (_, i) => `line${i}`);
		const body = lines.join("\n");
		const result = textResult("header", body);
		const text = textOf(result);
		expect(text).toContain("[Output truncated");
		expect(text).toContain(`${MAX_LINES} of ${MAX_LINES + 500} lines`);
		// Head-truncated: keeps the first line, drops the last.
		expect(text).toContain("line0");
		expect(text).not.toContain(`line${MAX_LINES + 499}`);
	});

	test("head-truncates a body exceeding MAX_BYTES and carries the truncation notice", () => {
		const body = "x".repeat(MAX_BYTES + 10_000);
		const result = textResult("header", body);
		const text = textOf(result);
		expect(text).toContain("[Output truncated");
		expect(text.length).toBeLessThan(body.length);
	});

	test("details.summary never exceeds 512 bytes even for a far larger body", () => {
		const body = "y".repeat(MAX_BYTES * 2);
		const result = textResult("header", body);
		expect(Buffer.byteLength(result.details!.summary, "utf-8")).toBeLessThanOrEqual(512);
	});
});

describe("prefixedTextResult", () => {
	test("places the prefix at byte 0 with no injected newline", () => {
		const prefix = "(disassembly only — no decompiler plugin available) ";
		const result = prefixedTextResult(prefix, "mov eax, ebx");
		const text = textOf(result);
		expect(text.startsWith(prefix)).toBe(true);
		expect(text).toBe(`${prefix}mov eax, ebx`);
	});

	test("still truncates and appends the notice when the body is oversized", () => {
		const prefix = "PFX ";
		const body = "z".repeat(MAX_BYTES + 5000);
		const result = prefixedTextResult(prefix, body);
		const text = textOf(result);
		expect(text.startsWith(prefix)).toBe(true);
		expect(text).toContain("[Output truncated");
	});
});

describe("jsonResult", () => {
	test("round-trips an object and sets ea when supplied", () => {
		const data = { foo: "bar", n: 42 };
		const result = jsonResult("header", data, "0x401d80");
		const text = textOf(result);
		expect(text).toContain('"foo": "bar"');
		expect(text).toContain('"n": 42');
		expect(result.details!.ea).toBe("0x401d80");
	});

	test("omits ea when not supplied", () => {
		const result = jsonResult("header", { a: 1 });
		expect(result.details!.ea).toBeUndefined();
	});
});
