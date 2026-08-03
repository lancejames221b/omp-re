/**
 * Per-omp-session state shared across the omp-re modules: the lazily-spawned
 * R2Session and the currently open binary. Keyed by ctx.sessionManager.getSessionId().
 */
import type { ExtensionContext } from "@oh-my-pi/pi-coding-agent";
import { R2Session, resolveR2Path } from "./r2.ts";

export interface ReSessionState {
	sessionId: string;
	r2: R2Session | null;
	binaryPath: string | null;
	auditHmacWarned: boolean;
	evidenceCount: number;
	findingCount: number;
	/** normalized addr -> most recent evidence id observed at that address (used by mutate tools' resolveEvidence and by report anchors) */
	evidenceByAddr: Map<string, string>;
}

const sessions = new Map<string, ReSessionState>();

function newState(sessionId: string): ReSessionState {
	return {
		sessionId,
		r2: null,
		binaryPath: null,
		auditHmacWarned: false,
		evidenceCount: 0,
		findingCount: 0,
		evidenceByAddr: new Map(),
	};
}

export function getState(ctx: ExtensionContext): ReSessionState {
	const sessionId = ctx.sessionManager.getSessionId();
	let state = sessions.get(sessionId);
	if (!state) {
		state = newState(sessionId);
		sessions.set(sessionId, state);
	}
	return state;
}

/** Idempotent teardown for session_shutdown: closes the r2 process and drops the state entry. */
export function shutdownState(sessionId: string): void {
	const state = sessions.get(sessionId);
	if (!state) return;
	state.r2?.close();
	sessions.delete(sessionId);
}

export function requireBinary(state: ReSessionState): string {
	if (!state.binaryPath) {
		throw new Error("omp-re: no binary open — use /re open <path> or --binary <path> first");
	}
	return state.binaryPath;
}

/** Returns a live R2Session for this state, transparently respawning against the same binary if the previous process died or timed out. */
export async function ensureR2(state: ReSessionState): Promise<R2Session> {
	if (state.r2 && !state.r2.isClosed) return state.r2;
	const binaryPath = requireBinary(state);
	state.r2 = await R2Session.spawn(resolveR2Path(), binaryPath);
	return state.r2;
}
