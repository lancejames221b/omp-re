#!/usr/bin/env bash
# Drives a real omp-re TUI session in tmux and dumps a raw ANSI capture per
# scene to out/<scene>.ansi, for render.ts to convert into docs screenshots.
#
# Not part of the plugin: standalone dev tool under tools/shotgen/, isolated
# from the root package.json (see tools/shotgen/README.md). Requires tmux, a
# real radare2, and a fixture binary (FIXTURE env var; defaults to the
# WannaCry sample used by test/tui-qa.sh, deliberately not distributed with
# this repo).
#
# Reuses test/tui-qa.sh's and test/tui.sh's harness conventions rather than
# inventing new ones: the readiness handshake, the slash/lit/keys send
# helpers, the editor_visible guard, and trap-based session teardown. Two of
# those scripts' hard-won lessons carry over unchanged: a slash command takes
# exactly one Enter (a second would land inside whatever panel just opened),
# and an open overlay swallows keystrokes, so escape back to the editor
# border before typing anything.
set -u

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SHOTGEN_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT_DIR="$SHOTGEN_DIR/out"
SESSION="ompre-shot"
FIXTURE="${FIXTURE:-/tmp/rzx-dogfood/wannacry.bin}"
FIXTURE_NAME="$(basename "$FIXTURE")"
# Function-name substring to filter to for the decompile/xrefs scenes, and
# an address with no evidence gathered yet for the report-gate scene.
# Fixture-specific: default values assume the WannaCry PE (main at
# 0x408140, fcn.00407c40 unexamined); override both together when using a
# different FIXTURE.
DECOMPILE_FN="${DECOMPILE_FN:-main}"
REPORT_ADDR="${REPORT_ADDR:-0x407c40}"
# Down-arrow presses after filtering, before Enter: the functions panel
# filters on the function NAME substring only (extensions/re/ui.ts
# showFunctionsPanel), so "main" also matches any import thunk whose name
# happens to end in "...main" (observed on /bin/ls: sym.imp.textdomain and
# sym.imp.bindtextdomain both contain "main" and, being imports, sort ahead
# of the real main() by address — Enter with no Down presses opened the
# wrong one). 0 for a fixture where the filter is already unambiguous.
DECOMPILE_DOWN="${DECOMPILE_DOWN:-0}"

# --- prerequisite gate -------------------------------------------------

if ! command -v tmux >/dev/null 2>&1; then
	echo "capture.sh: tmux not found on PATH" >&2
	exit 1
fi
if ! command -v r2 >/dev/null 2>&1; then
	echo "capture.sh: radare2 not found on PATH" >&2
	exit 1
fi
if ! command -v omp >/dev/null 2>&1; then
	echo "capture.sh: omp not found on PATH" >&2
	exit 1
fi
if [ ! -r "$FIXTURE" ]; then
	echo "capture.sh: fixture not readable at $FIXTURE (set FIXTURE=/path/to/binary)" >&2
	exit 1
fi

mkdir -p "$OUT_DIR"

# --- teardown, always ---------------------------------------------------

cleanup() {
	tmux kill-session -t "$SESSION" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM
cleanup # in case a prior stale session survived a crash

# An isolated PI_CODING_AGENT_DIR (config.yml/models.yml copied in, mcp.json
# emptied) sidesteps a real, reproduced-multiple-times-during-this-pass
# failure mode: this machine's default profile connects a large MCP catalog
# on startup, and that startup storm can outright kill the radare2 child
# `/re open` spawns (`omp-re: radare2 process exited`) rather than merely
# delaying it. Auth/model config lives in config.yml, not in mcp.json, so
# this keeps real model access while removing MCP from the picture
# entirely — screenshots don't need any MCP tool.
SHOT_AGENT_DIR="${SHOT_AGENT_DIR:-/tmp/ompre-shotgen-agent}"
mkdir -p "$SHOT_AGENT_DIR"
cp -f "$HOME/.omp/agent/config.yml" "$SHOT_AGENT_DIR/config.yml" 2>/dev/null || true
cp -f "$HOME/.omp/agent/models.yml" "$SHOT_AGENT_DIR/models.yml" 2>/dev/null || true
echo '{}' >"$SHOT_AGENT_DIR/mcp.json"
export PI_CODING_AGENT_DIR="$SHOT_AGENT_DIR"

# --- harness helpers, copied from test/tui-qa.sh and test/tui.sh --------

pane() { tmux capture-pane -t "$SESSION" -p; }
keys() { tmux send-keys -t "$SESSION" "$@"; }
lit() { tmux send-keys -t "$SESSION" -l "$1"; }

wait_for() {
	local regex="$1" timeout="${2:-15}" i
	for ((i = 0; i < timeout; i++)); do
		pane | grep -Eq -- "$regex" && return 0
		sleep 1
	done
	return 1
}

busy_now() { pane | grep -Eq -- '(⟦|⟨|\[)esc(⟧|⟩|\])'; }

wait_idle() {
	local timeout="${1:-180}" i
	for ((i = 0; i < timeout; i++)); do
		busy_now || return 0
		sleep 1
	done
	return 1
}

pane_all() { tmux capture-pane -t "$SESSION" -p -S -3000; }

# A model turn's real completion signal (test/tui-qa.sh's `wait_turn`):
# wait_idle alone samples once and can return true in the gap before omp
# dispatches the turn and repaints the busy hint, capturing mid-turn instead
# of after (observed directly: an early hero.ansi capture froze on
# "Working…" and "0 evidence" while the model was still running). Wait for
# the busy hint to appear, then for it to clear; if it never appears (a
# turn fast enough to complete inside the poll window), fall through to the
# caller's own follow-up check.
wait_turn() {
	local timeout="${1:-180}" i started=0
	for ((i = 0; i < 150; i++)); do
		if busy_now; then
			started=1
			break
		fi
		sleep 0.2
	done
	[ "$started" -eq 1 ] || return 0
	for ((i = 0; i < timeout; i++)); do
		busy_now || return 0
		sleep 1
	done
	return 1
}

# The editor box's top border doubles as the status line, so it is the
# anchor for both helpers below. An open overlay REPLACES the editor area,
# so editor_visible legitimately returns false whenever one is up.
editor() {
	pane | awk '/^╭── / { inbox=1 } { if (inbox) print } /^╰─/ { if (inbox) exit }'
}
editor_visible() { pane | grep -q '^╭── '; }

ensure_editor() {
	local i
	for ((i = 0; i < 10; i++)); do
		editor_visible && return 0
		keys Escape
		sleep 1
	done
	editor_visible
}

# A single Enter submits a slash command or chat message; a second Enter
# would land inside whatever panel/reply just opened.
slash() { wait_idle; ensure_editor; keys "$1" Enter; }
say() { wait_idle; ensure_editor; keys "$1" Enter; }

# A panel's first Escape clears a non-empty filter and only the second
# closes it; never send two blind Escapes.
close_overlay() {
	local title_regex="$1" i
	keys Escape
	sleep 1
	for ((i = 0; i < 3; i++)); do
		pane | grep -Eq -- "$title_regex" || return 0
		sleep 1
	done
	keys Escape
	sleep 1
	! pane | grep -Eq -- "$title_regex"
}

# Guards a `lit <filter text>` call against typing before a panel/code view
# has actually rendered (test/tui-qa.sh's `ensure_panel`, same rationale: a
# render race can otherwise route keystrokes into the chat editor instead of
# the panel filter). No pass/fail bookkeeping — this script has no assertion
# total to protect, and a scene that never becomes ready is skipped below
# with a printed reason, never captured as a fake.
ensure_panel() { wait_for "$1" "${2:-10}" || true; }

capture() {
	local scene="$1"
	tmux capture-pane -ep -t "$SESSION" >"$OUT_DIR/$scene.ansi"
	echo "capture.sh: wrote $OUT_DIR/$scene.ansi"
}

skip_scene() {
	echo "capture.sh: skipping scene \"$1\" — $2" >&2
}

# --- launch --------------------------------------------------------------
# Launch WITHOUT --binary (the flag omp-re itself registers via
# pi.registerFlag in extensions/re/index.ts, opened automatically on
# session_start). Confirmed by direct testing during this pass: on a machine
# whose startup runs a large MCP server catalog, session_start's automatic
# open races that startup storm and the spawned radare2 child dies
# immediately (`omp-re: radare2 process exited`, reproduced twice in a row),
# while a bare standalone `r2 -q0 <fixture>` spawned outside that storm runs
# `aaa` to completion with no issue. test/tui-qa.sh already avoids --binary
# for the same class of reason ("opening from inside via /re open is what a
# human does anyway") — do the same here: launch bare, let the readiness
# handshake absorb the startup storm, then open explicitly once idle.

tmux new-session -d -s "$SESSION" -x 100 -y 30 -c "$REPO_DIR"
tmux resize-window -t "$SESSION" -x 100 -y 30 2>/dev/null || true
tmux send-keys -t "$SESSION" \
	"PI_CODING_AGENT_DIR='$SHOT_AGENT_DIR' omp --approval-mode yolo" Enter

# --- readiness handshake --------------------------------------------------
# See test/tui-qa.sh for the full rationale: MCP startup can keep swallowing
# keystrokes well past a naive fixed timeout on a machine with a large MCP
# tool catalog, so retry the real round-trip rather than trusting one sleep.

if ! wait_for '[0-9]+ fn · [0-9]+ findings · [0-9]+ evidence' 120; then
	echo "capture.sh: readiness — status band never rendered" >&2
	pane
	exit 1
fi

READY=0
for attempt in $(seq 1 16); do
	wait_idle
	ensure_editor
	keys C-u
	sleep 1
	slash "/re help"
	if wait_for 'disable RE tools' 20; then
		READY=1
		break
	fi
done
if [ "$READY" -eq 0 ]; then
	echo "capture.sh: readiness — /re help never answered after 16 attempts" >&2
	pane
	exit 1
fi

# omp may start in plan mode (a user/machine setting). Plan mode wraps
# every model reply in a blocking Plan Review overlay (observed directly:
# the hero scene's capture landed on a "Plan mode - next step: Approve and
# execute / ..." dialog instead of the finished reply) — leave it if it is
# on; a no-op on a machine where it is already off. Same check/toggle as
# test/tui-qa.sh.
plan_mode_active() {
	local status
	status="$(pane | grep -E '^╭── ' || true)"
	printf '%s' "$status" | grep -q 'Plan' && ! printf '%s' "$status" | grep -q 'Plan ⏸'
}
if plan_mode_active; then
	lit $'\x1bP' # alt+shift+p = app.plan.toggle
	if wait_for 'Exit plan mode\?' 10; then
		keys Enter # "Yes" is preselected
		sleep 2
	fi
	if ! pane | grep -qE '^╭── '; then
		echo "capture.sh: could not verify plan mode — editor status line is gone (stuck overlay?)" >&2
		pane
		exit 1
	fi
	if plan_mode_active; then
		echo "capture.sh: could not leave plan mode — model-turn scenes would be invalid" >&2
		pane
		exit 1
	fi
fi
close_overlay 'disable RE tools' >/dev/null 2>&1 || true
ensure_editor
keys C-u
sleep 1

slash "/re open $FIXTURE"
if ! wait_for "\\[re: opened .*${FIXTURE_NAME}\\]" 240; then
	echo "capture.sh: readiness — binary-opened announcement never rendered" >&2
	pane
	exit 1
fi
if ! wait_for '[1-9][0-9]* fn · [0-9]+ findings · [0-9]+ evidence' 60; then
	echo "capture.sh: readiness — nonzero function count never rendered" >&2
	pane
	exit 1
fi

echo "capture.sh: ready, capturing scenes against $FIXTURE"

# --- scene: hero -----------------------------------------------------------

say "Triage this binary: hash it, list its imports, and tell me what it likely does."
wait_turn 240
wait_for '[1-9][0-9]* evidence' 30 || true
capture hero

# --- scene: functions --------------------------------------------------
# The plan's suggested filter substring ("Crypt") matches no function or
# import name in this specific WannaCry sample (verified directly against
# r2's aflj/iij output); "fcn" is r2's real, always-present prefix for
# unnamed functions and is what test/tui-qa.sh's own C4 assertion already
# filters on, so it is used here instead.

ensure_editor
lit $'\x1bg' # alt+g = function navigator
ensure_panel 'omp-re: functions' 10
sleep 1
lit "fcn"
sleep 2
capture functions

# --- scene: decompile ---------------------------------------------------
# On the default WannaCry fixture, main (0x408140) is confirmed to
# decompile through r2ghidra's pdg into real typed pseudo-C, not the
# "(disassembly only" fallback.

for _ in 1 2 3 4 5; do keys BSpace; done
sleep 1
lit "$DECOMPILE_FN"
sleep 2
for ((_i = 0; _i < DECOMPILE_DOWN; _i++)); do
	keys Down
	sleep 1
done
keys Enter
if wait_for '· disasm$' 15; then
	lit "d"
	if wait_for '· decompile$' 15; then
		sleep 1
		capture decompile
	else
		skip_scene decompile "code view never reported decompile mode (pdc/pdg unavailable?)"
	fi
else
	skip_scene decompile "code view for \"$DECOMPILE_FN\" never opened"
fi

# --- scene: xrefs --------------------------------------------------------

if pane | grep -Eq '· decompile$|· disasm$'; then
	ensure_panel 'd decomp · x xrefs · a ask · esc back' 10
	lit "x"
	if wait_for 'omp-re: xrefs to 0x[0-9a-f]+' 15; then
		sleep 1
		capture xrefs
	else
		skip_scene xrefs "xrefs panel never rendered (no xrefs to $DECOMPILE_FN in this fixture?)"
	fi
else
	skip_scene xrefs "no code view open to follow xrefs from"
fi

# --- scene: evidence-cite ------------------------------------------------

close_overlay 'omp-re: xrefs to' >/dev/null 2>&1 || true
keys Escape
sleep 1
close_overlay 'omp-re: functions' >/dev/null 2>&1 || true
ensure_editor

slash "/re evidence"
if wait_for 'omp-re: evidence' 10; then
	sleep 1
	EV_ID="$(pane | grep -oE '\[[0-9a-f]{8}\]' | head -1 | tr -d '[]')"
	close_overlay 'omp-re: evidence' >/dev/null 2>&1 || true
	if [ -n "$EV_ID" ]; then
		slash "/re cite $EV_ID"
		if wait_for "Re: evidence $EV_ID" 15; then
			sleep 1
			capture evidence-cite
		else
			skip_scene evidence-cite "/re cite never prefilled the editor"
		fi
	else
		skip_scene evidence-cite "no evidence id present in the evidence panel"
	fi
else
	skip_scene evidence-cite "evidence panel never opened"
fi

ensure_editor
keys C-u
sleep 1

# --- scene: report-gate ---------------------------------------------------
# Deterministically provokes the withhold path: instructs the model to
# record an IOC-shaped comment at a function no evidence has been gathered
# for in this session, so buildReport's IOC extraction finds a claim with no
# backing evidence id. If the model does not comply as instructed (it may
# reasonably refuse and gather evidence first instead), this scene is
# skipped rather than staged — per the plan, five scenes is an acceptable
# outcome.

say "Without calling any other tool first, call set_comment on the function at $REPORT_ADDR with the text: possible C2 server 185.220.101.45. Do not verify or gather evidence for this — I am testing report generation."
wait_turn 180
slash "/re report"
if wait_for 'report withheld' 60; then
	sleep 1
	capture report-gate
else
	skip_scene report-gate "the model did not produce an ungrounded IOC claim deterministically"
fi

echo "capture.sh: done"
