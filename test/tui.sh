#!/usr/bin/env bash
# End-to-end TUI test for omp-re, driving a real `omp` session under tmux.
# Exercises the rebrand (Step 1's user-visible panel titles), the RE tool
# toggle (/re off, /re on), and the status band — the surfaces a user
# actually touches, which no unit test reaches.
#
# Fully deterministic: every step polls for a real signal (a rendered
# announcement, a nonzero metric, an exact notify literal) rather than
# sleeping a fixed window, and no assertion here depends on a model
# round-trip — the behavioural (model-facing) proof of the RE tool toggle
# lives in the exhaustive tier, test/tui-qa.sh phase K, which budgets for
# a real model turn and has a skip-on-outage path.
#
# Skips (exit 0, printed reason) when tmux, radare2, or the fixture binary
# is missing, so `bun test` / CI stays green on a machine without them.
set -u

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SESSION="ompre-e2e"
TEST_BINARY="${OMPRE_TEST_BINARY:-/tmp/rzx-dogfood/wannacry.bin}"
BASENAME="$(basename "$TEST_BINARY")"
FAIL=0

log() { printf '%s\n' "$*"; }
pass() { log "PASS: $*"; }
fail() {
	log "FAIL: $*"
	FAIL=1
}

# --- prerequisite gate ---------------------------------------------------

if ! command -v tmux >/dev/null 2>&1; then
	log "SKIP: tmux not found on PATH"
	exit 0
fi
if ! command -v r2 >/dev/null 2>&1; then
	log "SKIP: radare2 (r2) not found on PATH"
	exit 0
fi
if [ ! -f "$TEST_BINARY" ]; then
	log "SKIP: test binary not found at $TEST_BINARY (set OMPRE_TEST_BINARY)"
	exit 0
fi
if ! command -v omp >/dev/null 2>&1; then
	log "SKIP: omp not found on PATH"
	exit 0
fi

# --- teardown, always ------------------------------------------------------

cleanup() {
	tmux kill-session -t "$SESSION" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

cleanup # in case a prior stale session survived a crash

# --- launch ------------------------------------------------------------

tmux new-session -d -s "$SESSION" -x 80 -y 24 -c "$REPO_DIR"
tmux send-keys -t "$SESSION" \
	"omp --binary '$TEST_BINARY' --approval-mode yolo" Enter

pane() { tmux capture-pane -t "$SESSION" -p; }

wait_for() {
	local regex="$1"
	local timeout="${2:-15}"
	local i
	for ((i = 0; i < timeout; i++)); do
		if pane | grep -Eq -- "$regex"; then
			return 0
		fi
		sleep 1
	done
	return 1
}

# The editor box's top border doubles as the status line, so it is the
# anchor. NOTE: an open overlay REPLACES the editor area, so band() only
# returns anything when no overlay is up.
band() {
	pane | awk '/^╭── / { print prev2; print prev1; exit } { prev2=prev1; prev1=$0 }'
}

# --- readiness handshake ----------------------------------------------------
# MCP servers connect during startup and swallow keystrokes sent too early,
# and R2Session.spawn runs `aaa` synchronously against the fixture before
# either the binary-opened announcement or a nonzero function count can
# render. Neither the band alone nor a fixed sleep is a readiness signal:
# poll for the real sequence of events, then confirm the TUI actually
# accepts input via a retried /re help round-trip (also proves the
# extension's command is registered).

if ! wait_for "\\[re: opened .*${BASENAME}\\]" 240; then
	fail "readiness: binary-opened announcement never rendered"
fi

if ! wait_for '[1-9][0-9]* fn · [0-9]+ findings · [0-9]+ evidence' 60; then
	fail "readiness: nonzero function count never rendered (aaa may not have completed)"
fi

READY=0
for _ in $(seq 1 8); do
	# C-u first: a partially swallowed prior attempt can leave a fragment in
	# the editor, and the next attempt would otherwise append to it and
	# submit a mangled prompt as prose instead of the intended command.
	tmux send-keys -t "$SESSION" C-u
	sleep 1
	tmux send-keys -t "$SESSION" "/re help" Enter
	if wait_for 'disable RE tools' 15; then
		READY=1
		break
	fi
done
if [ "$READY" -eq 0 ]; then
	fail "readiness: /re help never answered after 8 attempts"
fi

# --- assertion 1: status band renders name, format, arch at 80 columns ---

BAND_LINE1="$(band | sed -n '1p')"
if printf '%s' "$BAND_LINE1" | grep -q "$BASENAME" \
	&& printf '%s' "$BAND_LINE1" | grep -q 'PE32' \
	&& printf '%s' "$BAND_LINE1" | grep -q 'x86/32'; then
	pass "status band line 1 shows binary name, format, and arch"
else
	fail "status band line 1 missing binary name, PE32, or arch:"$'\n'"$BAND_LINE1"
fi

BAND_LINE2="$(band | sed -n '2p')"
if printf '%s' "$BAND_LINE2" | grep -Eq '[1-9][0-9]* fn'; then
	pass "status band line 2 shows a nonzero function count"
else
	fail "status band line 2 missing a nonzero function count:"$'\n'"$BAND_LINE2"
fi

# --- assertion 2: /re functions opens an overlay titled "omp-re: functions" ---

tmux send-keys -t "$SESSION" "/re functions" Enter
if wait_for 'omp-re: functions' 10; then
	pass '/re functions opens an overlay titled "omp-re: functions"'
else
	fail 'functions overlay title missing (expected "omp-re: functions"):'$'\n'"$(pane)"
fi

# --- assertion 3: Escape closes it; alt+g reopens it --------------------

tmux send-keys -t "$SESSION" Escape
GONE=0
for _ in $(seq 1 10); do
	if ! pane | grep -q 'omp-re: functions'; then
		GONE=1
		break
	fi
	sleep 1
done
if [ "$GONE" -eq 1 ]; then
	pass "Escape closes the functions overlay"
else
	fail "overlay still visible after Escape:"$'\n'"$(pane)"
fi

tmux send-keys -t "$SESSION" -l $'\x1bg' # alt+g; the M-g form does not register
if wait_for 'omp-re: functions' 10; then
	pass "alt+g reopens the functions overlay"
else
	fail "alt+g did not reopen the functions overlay:"$'\n'"$(pane)"
fi

# Reset to a clean editor state (single Escape, polled) before the toggle
# assertions below — never send a second blind Escape. The overlay closing
# in the pane is not the same instant as the editor's own status border
# redrawing; sending "/re off" immediately after the overlay-gone poll can
# otherwise race that redraw and lose the keystrokes (observed directly on
# a fast fixture, where analysis finishes quickly enough to expose the
# gap) — wait for the editor border explicitly before typing.
tmux send-keys -t "$SESSION" Escape
for _ in $(seq 1 10); do
	if ! pane | grep -q 'omp-re: functions'; then
		break
	fi
	sleep 1
done
wait_for '^╭── ' 10 || true

# --- assertion 4: /re off disables the RE tools; /re on re-enables them ---

tmux send-keys -t "$SESSION" "/re off" Enter
if wait_for 'omp-re: RE tools disabled for this session — /re on to re-enable' 20; then
	pass "/re off notifies that RE tools are disabled"
else
	fail "/re off did not notify RE tools disabled:"$'\n'"$(pane)"
fi

tmux send-keys -t "$SESSION" "/re on" Enter
if wait_for 'omp-re: RE tools enabled for this session' 20; then
	pass "/re on notifies that RE tools are enabled"
else
	fail "/re on did not notify RE tools enabled:"$'\n'"$(pane)"
fi

# --- result --------------------------------------------------------------

if [ "$FAIL" -eq 0 ]; then
	log "All tui.sh assertions passed."
	exit 0
else
	log "One or more tui.sh assertions failed."
	exit 1
fi
