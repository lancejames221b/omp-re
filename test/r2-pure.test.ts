import { describe, expect, test } from "bun:test";
import { eaFromOffset, normalizeAddr, validateAddr, validateIdent, validateText, validateTypeLike } from "../extensions/re/r2.ts";

describe("validateAddr", () => {
	test("accepts a hex address and a symbol name", () => {
		expect(validateAddr("0x401d80")).toBe("0x401d80");
		expect(validateAddr("main")).toBe("main");
	});

	test("rejects a command-injection payload with a semicolon", () => {
		expect(() => validateAddr("0x401d80; rm -rf /")).toThrow();
	});

	test("rejects backticks", () => {
		expect(() => validateAddr("`whoami`")).toThrow();
	});

	test("rejects newlines", () => {
		expect(() => validateAddr("0x401d80\nrm -rf /")).toThrow();
	});

	test("rejects command substitution", () => {
		expect(() => validateAddr("$(whoami)")).toThrow();
	});
});

describe("normalizeAddr", () => {
	test("lowercases and zero-normalizes 0x-prefixed values consistently", () => {
		expect(normalizeAddr("0x1100")).toBe("0x1100");
		expect(normalizeAddr("0X01100")).toBe("0x1100");
		expect(normalizeAddr("0x1100 ")).toBe("0x1100");
		expect(normalizeAddr("0x001100")).toBe("0x1100");
	});

	test("preserves a single zero digit", () => {
		expect(normalizeAddr("0x0")).toBe("0x0");
		expect(normalizeAddr("0x00000")).toBe("0x0");
	});

	test("lowercases a non-0x-prefixed value unchanged otherwise", () => {
		expect(normalizeAddr("MAIN")).toBe("main");
	});
});

describe("validateIdent / validateTypeLike / validateText", () => {
	test("validateIdent passes ordinary identifiers", () => {
		expect(validateIdent("name", "sub_401000")).toBe("sub_401000");
		expect(validateIdent("name", "_leading")).toBe("_leading");
	});

	test("validateIdent rejects identifiers starting with a digit or containing spaces", () => {
		expect(() => validateIdent("name", "1abc")).toThrow();
		expect(() => validateIdent("name", "a b")).toThrow();
		expect(() => validateIdent("name", "a;b")).toThrow();
	});

	test("validateTypeLike passes ordinary type strings", () => {
		expect(validateTypeLike("type", "int *")).toBe("int *");
		expect(validateTypeLike("type", "struct Foo *")).toBe("struct Foo *");
	});

	test("validateTypeLike rejects each documented forbidden character", () => {
		for (const c of [";", "|", "&", "`", "$", "\n", "\0"]) {
			expect(() => validateTypeLike("type", `int${c}x`)).toThrow();
		}
	});

	test("validateText passes ordinary comment bodies", () => {
		expect(validateText("this looks like a decoder loop")).toBe("this looks like a decoder loop");
	});

	test("validateText rejects newline and NUL", () => {
		expect(() => validateText("line one\nline two")).toThrow();
		expect(() => validateText("has\0nul")).toThrow();
	});
});

describe("eaFromOffset", () => {
	test("formats to the 0x… form the evidence store keys on", () => {
		expect(eaFromOffset(0)).toBe("0x0");
		expect(eaFromOffset(4201856)).toBe("0x401d80");
	});
});
