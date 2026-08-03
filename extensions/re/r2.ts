/**
 * NUL-framed radare2 pipe protocol (r2 -q0) and per-session lifecycle.
 *
 * Port of internal/re/r2frame.go + r2backend.go: no npm dependency, direct
 * child_process framing. Frames are terminated by a single 0x00 byte; the
 * banner frame (emitted once at startup) is consumed before issuing `aaa`.
 * Every command is serialized through a promise chain because r2 answers
 * exactly one request at a time over the pipe.
 */
import { spawn, type ChildProcess } from "node:child_process";
import { access, realpath as fsRealpath } from "node:fs/promises";
import { constants as fsConstants } from "node:fs";

/** Allowed characters in any value interpolated into an r2 command: addresses,
 * flag names, math expressions (sym.main+0x10, @@, $$, etc). Rejecting
 * everything else makes r2's ';' command-separator injection impossible. */
const ADDR_CHARS = /^[0-9a-zA-Z_.:@$+-]+$/;

export function validateAddr(addr: string): string {
	if (!ADDR_CHARS.test(addr)) {
		throw new Error(`omp-re: invalid address or expression: ${JSON.stringify(addr)}`);
	}
	return addr;
}

/** Canonicalize an EA to "0x" + lowercase hex with no leading zeros (except "0x0"), or the lowercased raw value when it isn't 0x-prefixed. Used to key evidence/annotation lookups so "0x1100", "0X01100", and "0x1100 " all match. */
export function normalizeAddr(raw: string): string {
	let s = raw.trim().toLowerCase();
	if (!s.startsWith("0x")) return s;
	s = s.slice(2);
	if (s.length === 0) return "0x";
	while (s.length > 1 && s[0] === "0") s = s.slice(1);
	return `0x${s}`;
}

/** Identifiers for rename targets (function/variable names). */
const IDENT_CHARS = /^[A-Za-z_][A-Za-z0-9_.]*$/;

export function validateIdent(key: string, value: string): string {
	if (!IDENT_CHARS.test(value)) {
		throw new Error(`omp-re: invalid ${key}: ${JSON.stringify(value)}`);
	}
	return value;
}
/** Format a numeric offset as a lowercase `0x` hex string. */
export function eaFromOffset(offset: number): string {
	return `0x${offset.toString(16)}`;
}

/** r2 6.x renamed the address field on aflj/afij/pdfj from `offset` to `addr`. Accept both. */
export function addrOf(item: { addr?: number; offset?: number }): number | undefined {
	return item.addr ?? item.offset;
}

/**
 * Resolve a name/expression to a concrete numeric address via r2's `?v`, which
 * (unlike direct `@ <expr>` addressing on pdcj/pdfj) never hangs or errors on an
 * unresolvable input — it just prints "0x0". Failing fast here, before
 * pdcj/pdfj, avoids trusting either command's own (sometimes absent) address
 * field and gives a clear error instead of treating base address 0 as real.
 */
export async function resolveNumericAddr(r2: R2Session, addr: string): Promise<number> {
	const raw = (await r2.cmd(`?v ${addr}`)).trim();
	const value = Number.parseInt(raw, 16);
	if (!Number.isFinite(value) || value === 0) {
		throw new Error(`omp-re: could not resolve address: ${addr}`);
	}
	return value;
}

const FORBIDDEN_SHELL_CHARS = [";", "|", "&", "`", "$", "\n", "\0"];

/** Loose validation for type/signature strings: reject shell/r2 metacharacters, allow everything else. */
export function validateTypeLike(key: string, value: string): string {
	for (const c of FORBIDDEN_SHELL_CHARS) {
		if (value.includes(c)) {
			throw new Error(`omp-re: invalid ${key}: forbidden character ${JSON.stringify(c)}`);
		}
	}
	return value;
}

/** Validation for free-text comment bodies: only newline and NUL are forbidden. */
export function validateText(value: string): string {
	if (value.includes("\n") || value.includes("\0")) {
		throw new Error("omp-re: invalid text: contains forbidden character");
	}
	return value;
}

export class R2ProtocolError extends Error {}

const COMMAND_TIMEOUT_MS = 60_000;
const ANALYSIS_TIMEOUT_MS = Number(process.env.OMPRE_R2_ANALYSIS_TIMEOUT_MS) || 300_000;
const STDERR_TAIL_MAX = 4096;

/** One radare2 subprocess speaking the NUL-framed pipe protocol. */
export class R2Session {
	private buf = Buffer.alloc(0);
	private queue: Promise<void> = Promise.resolve();
	private pending: { resolve: (frame: string) => void; reject: (err: Error) => void } | null = null;
	private closedFlag = false;
	private stderrTail = "";
	private cmdCounter = 0;

	private constructor(
		private readonly proc: ChildProcess,
		readonly binaryPath: string,
	) {
		this.proc.stdout?.on("data", (chunk: Buffer) => {
			this.buf = Buffer.concat([this.buf, chunk]);
			this.drain();
		});
		// Drain stderr unconditionally: an unread pipe fills its OS buffer and
		// blocks the child mid-write on a noisy binary, wedging every command.
		this.proc.stderr?.on("data", (chunk: Buffer) => {
			this.stderrTail = (this.stderrTail + chunk.toString("utf8")).slice(-STDERR_TAIL_MAX);
		});
		this.proc.on("exit", () => {
			this.closedFlag = true;
			this.pending?.reject(new R2ProtocolError("omp-re: radare2 process exited"));
			this.pending = null;
		});
		this.proc.on("error", (err) => {
			this.closedFlag = true;
			this.pending?.reject(new R2ProtocolError(`omp-re: radare2 spawn failed: ${err.message}`));
			this.pending = null;
		});
	}

	/** Whether the underlying r2 process has exited or been closed. Callers should respawn rather than reuse. */
	get isClosed(): boolean {
		return this.closedFlag;
	}

	private drain(): void {
		if (!this.pending) return;
		const nul = this.buf.indexOf(0x00);
		if (nul === -1) return;
		const frame = this.buf.subarray(0, nul).toString("utf8");
		this.buf = this.buf.subarray(nul + 1);
		const { resolve } = this.pending;
		this.pending = null;
		resolve(frame);
	}

	private readFrame(): Promise<string> {
		if (this.closedFlag) {
			return Promise.reject(new R2ProtocolError("omp-re: radare2 process exited"));
		}
		const { promise, resolve, reject } = Promise.withResolvers<string>();
		this.pending = { resolve, reject };
		this.drain();
		return promise;
	}

	/** Race a frame read against a hard timeout. A stuck r2 (e.g. waiting on
	 * stdin it will never get) must never wedge the caller's tool call forever;
	 * on timeout the process is killed so the next command starts clean. */
	private withTimeout(framePromise: Promise<string>, command: string, timeoutMs: number): Promise<string> {
		const { promise: timeoutPromise, reject } = Promise.withResolvers<string>();
		const timer = setTimeout(() => {
			const detail = this.stderrTail.trim();
			this.close();
			reject(
				new R2ProtocolError(
					`omp-re: radare2 command timed out after ${timeoutMs}ms: ${command}${detail ? ` (stderr: ${detail})` : ""}`,
				),
			);
		}, timeoutMs);
		return Promise.race([framePromise, timeoutPromise]).finally(() => clearTimeout(timer));
	}

	/**
	 * Run a raw r2 command, returning its unparsed output.
	 *
	 * r2 -q0 does not always terminate a command's response with a frame: an
	 * invalid `@ <expr>` addressing argument (e.g. a flag name r2 can't
	 * resolve) prints only to stderr and emits ZERO stdout bytes — not even an
	 * empty NUL-terminated frame. Waiting for "the" response frame in that
	 * case would hang until the timeout fires on every single bad address.
	 *
	 * Fix: pipeline a unique `?e <marker>` echo immediately after the real
	 * command in one write. r2 processes stdin lines strictly in order, so the
	 * marker's own frame is guaranteed to arrive (it can never fail). Read
	 * frames until the marker appears; everything read before it — zero frames
	 * for the no-output case, one frame for the normal case — is the real
	 * command's response. This bounds a bad address to one instant round trip
	 * instead of the full command timeout, and keeps the frame stream aligned
	 * either way.
	 */
	cmd(command: string, timeoutMs: number = COMMAND_TIMEOUT_MS): Promise<string> {
		const task = this.queue.then(async () => {
			if (this.closedFlag) throw new R2ProtocolError("omp-re: radare2 process exited");
			const marker = `__RZX_SYNC_${(this.cmdCounter++).toString(36)}_${process.hrtime.bigint().toString(36)}__`;
			const deadline = Date.now() + timeoutMs;
			this.proc.stdin?.write(`${command}\n?e ${marker}\n`);

			const collected: string[] = [];
			// A well-behaved command produces 0 (no output) or 1 (JSON/text) frames before the marker.
			// The loop bound is a defensive ceiling against a genuinely desynced stream, not the expected path.
			for (let i = 0; i < 8; i++) {
				const remaining = deadline - Date.now();
				if (remaining <= 0) {
					const detail = this.stderrTail.trim();
					this.close();
					throw new R2ProtocolError(
						`omp-re: radare2 command timed out after ${timeoutMs}ms: ${command}${detail ? ` (stderr: ${detail})` : ""}`,
					);
				}
				const frame = await this.withTimeout(this.readFrame(), command, remaining);
				if (frame.trim() === marker) return collected.join("");
				collected.push(frame);
			}
			const detail = this.stderrTail.trim();
			this.close();
			throw new R2ProtocolError(
				`omp-re: radare2 protocol desync waiting for sync marker after: ${command}${detail ? ` (stderr: ${detail})` : ""}`,
			);
		});
		this.queue = task.then(
			() => undefined,
			() => undefined,
		);
		return task;
	}

	/** Run a command expecting a JSON frame. Returns null for a legitimate no-result (matches Go's json.RawMessage("null")) or an invalid address that produced no output at all. */
	async cmdj<T>(command: string, timeoutMs: number = COMMAND_TIMEOUT_MS): Promise<T | null> {
		const raw = (await this.cmd(command, timeoutMs)).trim();
		if (!raw.startsWith("{") && !raw.startsWith("[")) return null;
		try {
			return JSON.parse(raw) as T;
		} catch {
			return null;
		}
	}

	close(): void {
		if (this.closedFlag) return;
		this.closedFlag = true;
		this.proc.kill();
	}

	/** Spawn r2 -q0 <binary>, consume the startup banner, run `aaa` synchronously, and return a ready session.
	 * `aaa` gets its own much larger budget: full analysis of a large or packed
	 * binary routinely runs minutes, well past the per-command default. */
	static async spawn(r2Path: string, binaryPath: string): Promise<R2Session> {
		const proc = spawn(r2Path, ["-q0", binaryPath], { stdio: ["pipe", "pipe", "pipe"] });
		const session = new R2Session(proc, binaryPath);
		await session.withTimeout(session.readFrame(), "<startup banner>", COMMAND_TIMEOUT_MS);
		await session.cmd("aaa", ANALYSIS_TIMEOUT_MS);
		return session;
	}
}

export function resolveR2Path(): string {
	return process.env.OMPRE_R2_PATH?.trim() || "r2";
}

async function isExecutableOnPath(name: string): Promise<boolean> {
	if (name.includes("/")) {
		try {
			await access(name, fsConstants.X_OK);
			return true;
		} catch {
			return false;
		}
	}
	const pathDirs = (process.env.PATH ?? "").split(":").filter(Boolean);
	for (const dir of pathDirs) {
		try {
			await access(`${dir}/${name}`, fsConstants.X_OK);
			return true;
		} catch {
			// keep scanning
		}
	}
	return false;
}

export async function assertR2Available(): Promise<void> {
	const r2Path = resolveR2Path();
	if (!(await isExecutableOnPath(r2Path))) {
		throw new Error(
			"omp-re: radare2 not found on PATH — install r2 (https://rada.re) or set OMPRE_R2_PATH",
		);
	}
}

/** Resolve a user-supplied binary path to an absolute, existing file path. */
export async function resolveBinaryPath(inputPath: string): Promise<string> {
	let real: string;
	try {
		real = await fsRealpath(inputPath);
	} catch {
		throw new Error(`omp-re: no such binary: ${inputPath}`);
	}
	try {
		await access(real, fsConstants.R_OK);
	} catch {
		throw new Error(`omp-re: no such binary: ${inputPath}`);
	}
	return real;
}
