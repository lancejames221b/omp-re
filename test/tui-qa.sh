#!/usr/bin/env bash
# Exhaustive TUI QA for omp-re: one continuous tmux session driving one live
# `omp` TUI process through a realistic reverse-engineering workflow, asserting
# every user-facing surface as it goes. The exhaustive tier (~5-8 min) that
# complements the fast smoke tier test/tui.sh (~55s, 7 assertions).
#
# Skips (exit 0, printed reason) when tmux, r2, omp, or the fixture binary is
# missing, so CI stays green on a machine without them. Model-dependent phases
# (G, H, K) degrade to SKIP on a provider outage; skips never fail the run.
set -u

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SESSION="ompre-qa"
PE_BINARY="${OMPRE_TEST_BINARY:-/tmp/rzx-dogfood/wannacry.bin}"
ALT_BINARY="${OMPRE_TEST_BINARY_ALT:-/tmp/rzx-dogfood/synth_malware}"
TMP="$(mktemp -d /tmp/ompre-qa-XXXXXX)"
PASS_COUNT=0
FAIL_COUNT=0
SKIP_COUNT=0
MODEL_OK=1
ALT_OK=1
SENTINEL_SEEN=0

# --- prerequisite gate ------------------------------------------------------

if ! command -v tmux >/dev/null 2>&1; then
	echo "SKIP: tmux not on PATH"
	exit 0
fi
if ! command -v r2 >/dev/null 2>&1; then
	echo "SKIP: r2 not on PATH"
	exit 0
fi
if ! command -v omp >/dev/null 2>&1; then
	echo "SKIP: omp not on PATH"
	exit 0
fi
if ! command -v sha256sum >/dev/null 2>&1; then
	echo "SKIP: sha256sum not on PATH"
	exit 0
fi
if ! command -v python3 >/dev/null 2>&1; then
	echo "SKIP: python3 not on PATH"
	exit 0
fi
if [ ! -r "$PE_BINARY" ]; then
	echo "SKIP: $PE_BINARY not readable (set OMPRE_TEST_BINARY)"
	exit 0
fi
if [ ! -r "$ALT_BINARY" ]; then
	ALT_OK=0
fi

PE_NAME="$(basename "$PE_BINARY")"
ALT_NAME="$(basename "$ALT_BINARY")"
# Phase L's branding guard greps the whole scrollback for "rzx". The fixture
# lives under /tmp/rzx-dogfood on this machine, so the fixture's own path would
# be a permanent false positive; strip the fixture path tokens before grepping.
PE_DIR_TOKEN="$(basename "$(dirname "$PE_BINARY")")"
ALT_DIR_TOKEN="$(basename "$(dirname "$ALT_BINARY")")"

# --- teardown, always ------------------------------------------------------

cleanup() {
	tmux kill-session -t "$SESSION" >/dev/null 2>&1 || true
	rm -rf "$TMP"
}
trap cleanup EXIT INT TERM
tmux kill-session -t "$SESSION" >/dev/null 2>&1 || true # in case a prior stale session survived a crash

# --- harness helpers -------------------------------------------------------

pane()     { tmux capture-pane -t "$SESSION" -p; }
pane_all() { tmux capture-pane -t "$SESSION" -p -S -3000; }

# The editor box's top border doubles as the status line, so it is the anchor
# for both helpers below. NOTE: an open overlay REPLACES the editor area, so
# band() and editor() only return anything when no overlay is up.
band() {
	wait_idle
	ensure_editor
	pane | awk '/^╭── / { print prev2; print prev1; exit } { prev2=prev1; prev1=$0 }'
}

# The editor box body, used to assert the code view's `a` key prefill. The
# closing border is "╰─" followed by padding, not "╰──". ("in" is reserved.)
editor() {
	pane | awk '/^╭── / { inbox=1 } { if (inbox) print } /^╰─/ { if (inbox) exit }'
}

keys()  { tmux send-keys -t "$SESSION" "$@"; }
lit()   { tmux send-keys -t "$SESSION" -l "$1"; }

# The busy hint's bracket glyphs are per-theme (⟦⟧ default, ⟨⟩ nerd-font, []
# ASCII), so all three pairs must match or the gate silently fails open.
busy_now() { pane | grep -Eq -- '(⟦|⟨|\[)esc(⟧|⟩|\])'; }

# Wait until the agent is not mid-generation. Typing into a running turn
# interleaves badly, and Escape (from ensure_editor) would cancel the turn.
wait_idle() {
	local i
	for ((i = 0; i < 90; i++)); do
		if busy_now; then
			SENTINEL_SEEN=1
			sleep 1
			continue
		fi
		return 0
	done
	return 1
}

# A model turn's COMPLETION signal. wait_idle alone is not one: its first
# sample is taken before omp can dispatch the turn and repaint the busy hint,
# so it returns 0 immediately and the caller ends up asserting against a pane
# captured at submit time. Wait for the busy edge to appear, then to clear.
#
# A reply marker is accepted as an alternative completion signal for turns too
# short for the appear edge to be sampled. It is counted against SCROLLBACK,
# not the visible pane: the prompt echo is occurrence 1 and scrolls off a
# 24-row pane as soon as the reply is long, which would stall a visible-pane
# count at 1 forever.
wait_turn() {
	local marker="$1"
	local timeout="${2:-180}"
	local i started=0
	# Poll the appear edge sub-second: a refusal turn (which is what K2 expects,
	# the tools being gated off) can start and finish inside a 1s gap, and a
	# missed edge would drop through to the weaker marker-only fallback.
	for ((i = 0; i < 150; i++)); do
		if busy_now; then
			started=1
			SENTINEL_SEEN=1
			break
		fi
		if [ -n "$marker" ] && [ $((i % 5)) -eq 0 ] \
			&& [ "$(pane_all | grep -Ec -- "$marker" || true)" -ge 2 ]; then
			return 0
		fi
		sleep 0.2
	done
	if [ "$started" -eq 0 ]; then
		# Never saw the turn start; the marker is the only remaining evidence.
		[ -n "$marker" ] || return 1
		for ((i = 0; i < timeout; i++)); do
			if [ "$(pane_all | grep -Ec -- "$marker" || true)" -ge 2 ]; then
				return 0
			fi
			sleep 1
		done
		return 1
	fi
	for ((i = 0; i < timeout; i++)); do
		if ! busy_now; then
			return 0
		fi
		sleep 1
	done
	return 1
}

# An open overlay REPLACES the editor area and swallows every keystroke, so a
# command typed while one is up silently becomes filter text instead of
# reaching the editor. The editor box's top border is the invariant that says
# "the editor has focus"; press Escape until it is back before typing anything.
ensure_editor() {
	local i
	for ((i = 0; i < 5; i++)); do
		if pane | grep -q '^╭── '; then
			return 0
		fi
		keys Escape
		sleep 1
	done
	return 1
}

# True when the editor box is actually on screen. Without this guard an
# assertion that greps editor() would "pass" on empty output whenever the box
# was hidden, which silently hides the very defect it is meant to catch.
editor_visible() {
	pane | grep -q '^╭── '
}

# Empty the editor and verify it. A leftover prefill is not cosmetic: the next
# slash command gets APPENDED to it and the whole thing submits as prose,
# which starts an unintended agent run and derails every later phase.
#
# "Cleared" means the editor box has no content row at all — checking for one
# specific prefill's text (as an earlier version of this helper did) silently
# passes for any OTHER prefill, since a check for text that was never present
# is trivially true on the very first no-op attempt. Content rows are the
# `editor()` lines that start with the box's left border glyph, `│`; the top
# (`╭──`) and bottom (`╰─`) border lines never do.
editor_has_content() {
	editor | grep -q '^│'
}

clear_editor() {
	editor_visible || return 1
	local i
	for ((i = 0; i < 3; i++)); do
		keys C-u
		sleep 1
		if ! editor_has_content; then
			return 0
		fi
	done
	# C-u alone does not clear a genuinely multi-line prefill (it only acts on
	# the current line, and a prefill built from real `\n` characters — as
	# `/re cite`'s is — leaves the cursor on an already-empty trailing line).
	# Fall back to plain backspacing with a time-bounded budget rather than a
	# fixed keypress count: an evidence summary can run past 500 bytes
	# (EVIDENCE_SUMMARY_MAX_BYTES), well beyond what a short fixed count
	# would cover, and a tight burst of BSpace keys can lose some to the
	# TUI's own render/input loop, so retry in batches against a wall-clock
	# deadline instead of trusting one pass of N keypresses to land.
	local deadline=$((SECONDS + 20))
	local j
	while ((SECONDS < deadline)); do
		for ((j = 0; j < 40; j++)); do
			keys BSpace
		done
		sleep 0.5
		if ! editor_has_content; then
			return 0
		fi
	done
	editor_visible || return 1
	! editor_has_content
}

# A single Enter submits a slash command; a second Enter would land INSIDE a
# panel the command just opened and select its first row (verified against a
# live session). Never send a speculative second Enter here.
slash() { wait_idle; ensure_editor; tmux send-keys -t "$SESSION" "$1" Enter; }
say()   { wait_idle; ensure_editor; tmux send-keys -t "$SESSION" "$1" Enter; }

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

# Poll until the scrollback holds at least <n> occurrences of <regex>. Needed
# whenever the prompt text itself echoes the string being waited on: the user's
# own message counts as occurrence 1, so a plain wait_for would return before
# the model has replied at all.
wait_for_count() {
	local regex="$1"
	local want="$2"
	local timeout="${3:-120}"
	local i seen
	for ((i = 0; i < timeout; i++)); do
		seen="$(pane | grep -Ec -- "$regex" || true)"
		if [ "${seen:-0}" -ge "$want" ]; then
			return 0
		fi
		sleep 1
	done
	return 1
}

diagnose() {
	echo "--- pane ---"
	pane
	echo "--- end pane ---"
}

pass() {
	echo "PASS: $1"
	PASS_COUNT=$((PASS_COUNT + 1))
}

fail() {
	echo "FAIL: $1"
	FAIL_COUNT=$((FAIL_COUNT + 1))
}

expect() {
	local label="$1"
	local regex="$2"
	local timeout="${3:-15}"
	if wait_for "$regex" "$timeout"; then
		pass "$label"
	else
		fail "$label"
		diagnose
	fi
}

expect_count() {
	local label="$1"
	local regex="$2"
	local want="$3"
	local timeout="${4:-15}"
	if wait_for_count "$regex" "$want" "$timeout"; then
		pass "$label"
	else
		fail "$label (wanted >= $want occurrences, saw $(pane | grep -Ec -- "$regex" || true))"
		diagnose
	fi
}

# Absence is checked against the visible pane only, never scrollback: a closed
# overlay's title stays in scrollback forever, so a scrollback check could never
# observe a close.
expect_gone() {
	local label="$1"
	local regex="$2"
	local timeout="${3:-10}"
	local i
	for ((i = 0; i < timeout; i++)); do
		if ! pane | grep -Eq -- "$regex"; then
			pass "$label"
			return
		fi
		sleep 1
	done
	fail "$label"
	diagnose
}

# For the genuinely environment-dependent branches (Phase E d/x, Phase F
# enter): passes if either outcome is observed, fails only if neither is.
expect_any() {
	local label="$1"
	local regexA="$2"
	local regexB="$3"
	local timeout="${4:-20}"
	local i
	for ((i = 0; i < timeout; i++)); do
		if pane | grep -Eq -- "$regexA" || pane | grep -Eq -- "$regexB"; then
			pass "$label"
			return
		fi
		sleep 1
	done
	fail "$label"
	diagnose
}

skip() {
	echo "SKIP: $1 ($2)"
	SKIP_COUNT=$((SKIP_COUNT + 1))
}

# A panel's first Escape clears a non-empty filter and only the second closes
# it (makePickerPanel handleInput, extensions/re/ui.ts). Never send two blind
# Escapes: the second would leak into whatever is underneath.
close_overlay() {
	local title_regex="$1"
	keys Escape
	sleep 1
	local i
	for ((i = 0; i < 3; i++)); do
		if ! pane | grep -Eq -- "$title_regex"; then
			return 0
		fi
		sleep 1
	done
	keys Escape
	sleep 1
	! pane | grep -Eq -- "$title_regex"
}

# Enter on a picker row has two possible outcomes, and they need different
# observation strategies: a code view is an overlay (visible immediately),
# while "no xrefs"/"no PLT stub"/"no code at" are ctx.ui.notify calls that
# render in the transcript UNDERNEATH the still-open panel and are therefore
# invisible until it closes. Check for the overlay first, then close and look
# for the notify. Returns 0 if a code view opened (panel still open), 1 if not.
picker_enter() {
	local label="$1"
	local panel_title="$2"
	local notify_regex="$3"
	keys Enter
	if wait_for '· disasm$' 20; then
		pass "$label (opened a code view)"
		keys Escape
		sleep 2
		return 0
	fi
	close_overlay "$panel_title"
	if wait_for "$notify_regex" 10; then
		pass "$label (reported no target)"
	else
		fail "$label"
		diagnose
	fi
	return 1
}

# Send a prompt and wait for the model's reply. On timeout, latch MODEL_OK=0 so
# every later model_step short-circuits to a skip, and return 1 so the caller
# skips its dependent assertions. A provider outage degrades phases G/H/K to
# SKIP without failing the run.
model_step() {
	local label="$1"
	local prompt="$2"
	local regex="$3"
	local want="${4:-1}"
	local timeout="${5:-180}"
	if [ "$MODEL_OK" -eq 0 ]; then
		skip "$label" "model round-trip timed out earlier"
		return 1
	fi
	say "$prompt"
	if wait_for_count "$regex" "$want" "$timeout"; then
		pass "$label"
		return 0
	fi
	MODEL_OK=0
	skip "$label" "model round-trip timed out"
	diagnose
	return 1
}

# --- launch ----------------------------------------------------------------
# Launch without --binary: Phase A needs the no-binary states, and opening from
# inside via /re open is what a human does anyway.
# --approval-mode yolo so the Phase H annotation never stalls on an approval
# prompt. --session-dir so evidence/annotation entries do not leak into a real
# session directory and each run starts clean.

tmux new-session -d -s "$SESSION" -x 80 -y 24 -c "$REPO_DIR"
tmux resize-window -t "$SESSION" -x 80 -y 24 2>/dev/null || true
tmux send-keys -t "$SESSION" \
	"omp --session-dir '$TMP/session' --approval-mode yolo" Enter

# --- readiness handshake ----------------------------------------------------
# Startup takes ~40s on a machine with MCP servers configured: they connect
# during startup and swallow keystrokes sent earlier, and the status band
# renders well before they finish. So the band alone is NOT readiness. Poll for
# the band, then retry the /re help round-trip until it answers. That round-trip
# is the real handshake: it proves the TUI accepts input, the extension is
# loaded, and its command is registered. It doubles as assertion A6.

if ! wait_for '[0-9]+ fn · [0-9]+ findings · [0-9]+ evidence' 120; then
	echo "FAIL: readiness handshake (status band never rendered)"
	diagnose
	exit 1
fi

READY=0
for attempt in 1 2 3 4 5 6 7 8; do
	# MCP startup swallows keystrokes; a partially swallowed attempt can leave
	# a fragment (e.g. "elp") in the editor, which the next iteration would
	# append to and submit as prose. Settle and explicitly clear first so
	# every attempt types into a known-empty editor.
	wait_idle
	ensure_editor
	keys C-u
	sleep 1
	slash "/re help"
	if wait_for 'disable RE tools' 15; then
		READY=1
		break
	fi
done
if [ "$READY" -eq 0 ]; then
	echo "FAIL: readiness handshake (/re help never answered after 8 attempts)"
	diagnose
	exit 1
fi

# --- plan mode ---------------------------------------------------------------
# omp may start in plan mode (a user/machine setting). Plan mode wraps every
# model reply in a blocking Plan Review overlay and defers write tools, which
# would wedge this session and invalidate phases G/H/K. Leave it if it is on;
# on a machine where it is already off, this is a no-op.

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
	# The confirm dialog is a modal overlay that REPLACES the editor's status
	# line, so "status line absent" is indistinguishable from "plan mode off"
	# unless checked explicitly. Only check here, after the wait above has
	# given the modal its window to appear and be dismissed — never inside
	# that wait, where the modal is legitimately up.
	if ! pane | grep -qE '^╭── '; then
		echo "FAIL: could not verify plan mode — editor status line is gone (stuck overlay?)"
		diagnose
		exit 1
	fi
	if plan_mode_active; then
		echo "FAIL: could not leave plan mode — model phases would be invalid"
		diagnose
		exit 1
	fi
fi

slash "/re help"
if ! wait_for 'disable RE tools' 20; then
	echo "FAIL: /re help did not render after leaving plan mode"
	diagnose
	exit 1
fi
expect 'A6 help line: open'     '/re open <path>      open a binary'
expect 'A6 help line: evidence' '/re evidence \[id\]    evidence log'
expect 'A6 help line: off'      '/re off              disable RE tools'

# Checks two physically-adjacent cheatsheet lines with one assertion via
# fixed-string matching (avoids ERE-escaping the "[", "]", "(" in several
# lines). Used to land 6 previously-unasserted cheatsheet lines in exactly 4
# calls: two paired, two singles (their neighbors are already covered above).
expect_lines() {
	local label="$1" line1="$2" line2="$3" timeout="${4:-15}"
	local i
	for ((i = 0; i < timeout; i++)); do
		if pane | grep -Fq -- "$line1" && pane | grep -Fq -- "$line2"; then
			pass "$label"
			return
		fi
		sleep 1
	done
	fail "$label"
	diagnose
}
expect_lines 'A6 help line: functions+strings' \
	'/re functions        function navigator   alt+s  strings' \
	'/re strings          string list          in code view:'
expect 'A6 help line: imports' '/re imports          import list             d  toggle decompile'
expect_lines 'A6 help line: undo+report' \
	'/re undo             revert annotation       a  ask the model' \
	'/re report [path]    write report'
expect 'A6 help line: on' '/re on               enable RE tools'

# --- Phase A — cold start, nothing open -------------------------------------

A1="$(band | sed -n '1p')"
if printf '%s' "$A1" | grep -qx 'no binary'; then
	pass 'A1 band line 1 is "no binary"'
else
	fail "A1 band line 1 is \"no binary\" (got: $A1)"
fi

A2="$(band | sed -n '2p')"
if printf '%s' "$A2" | grep -Eq '^0 fn · 0 findings · 0 evidence$'; then
	pass 'A2 band line 2 zeroed metrics'
else
	fail "A2 band line 2 zeroed metrics (got: $A2)"
fi

slash "/re bogus"
expect 'A7 unknown subcommand "bogus"' 'omp-re: unknown /re subcommand "bogus" — try /re help'

slash "/re"
expect 'A8 bare /re renders empty subcommand' 'omp-re: unknown /re subcommand "" — try /re help'

slash "/re open"
expect 'A9 /re open without a path' 'Usage: /re open <path>'

slash "/re open /tmp/omp-re-nope.bin"
expect 'A10 /re open on a missing file' 'omp-re: no such binary: /tmp/omp-re-nope\.bin'

slash "/re undo"
expect 'A11 /re undo with no annotations' 'omp-re: no annotation left to undo'

# A12-A14 assert the same literal through three separate code paths in ui.ts.
# Scrollback accumulates, so a plain match would let A13/A14 pass on A12's
# output; count occurrences instead so each panel's guard is really exercised.
NOBIN='omp-re: no binary open — use /re open <path> first'
slash "/re functions"
expect_count 'A12 functions panel guards on no binary' "$NOBIN" 1

slash "/re strings"
expect_count 'A13 strings panel guards on no binary' "$NOBIN" 2

slash "/re imports"
expect_count 'A14 imports panel guards on no binary' "$NOBIN" 3

# The evidence panel has no binary guard, so it opens empty rather than
# erroring. That asymmetry with A12-A14 is intentional; this pins it.
slash "/re evidence"
expect 'A15 evidence panel opens with no binary' 'omp-re: evidence'
close_overlay 'omp-re: evidence'

slash "/re cite"
expect 'A16 /re cite without an id' 'Usage: /re cite <id>'

slash "/re cite deadbeef"
expect 'A17 /re cite with an unknown id' 'omp-re: no evidence found with id deadbeef'

# --- Phase B — open the PE binary -------------------------------------------
# Generous timeout: R2Session.spawn runs `aaa` synchronously on a 3.6 MB PE.

# PE_NAME may contain regex metacharacters (a `.` is common, `+`/`[` possible
# for a user-supplied OMPRE_TEST_BINARY); escape it before using it in an ERE.
PE_NAME_RE="$(printf '%s' "$PE_NAME" | sed 's/[][^$.*+?(){}|\\]/\\&/g')"

slash "/re open $PE_BINARY"
expect 'B1 re.binary renderer announces the open' "\\[re: opened .*${PE_NAME_RE}\\]" 240

B_LINE1="$(band | sed -n '1p')"
# Format/arch checks are deliberately loose: the suite is documented to hold
# for any fixture given via OMPRE_TEST_BINARY, not only a PE32/x86 one.
if printf '%s' "$B_LINE1" | grep -qF "$PE_NAME" \
	&& printf '%s' "$B_LINE1" | grep -Eq '(PE32|PE32\+|ELF(32|64)|Mach-O)' \
	&& printf '%s' "$B_LINE1" | grep -Eq '[a-z0-9_]+/(8|16|32|64)'; then
	pass 'B2 band shows name, format, arch'
else
	fail "B2 band shows name, format, arch (got: $B_LINE1)"
fi

if printf '%s' "$B_LINE1" | grep -q 'entry 0x' \
	&& printf '%s' "$B_LINE1" | grep -Eq '[0-9](\.[0-9])?([KMGT]|B)'; then
	pass 'B3 band shows entry point and size'
else
	fail "B3 band shows entry point and size (got: $B_LINE1)"
fi

B_LINE2="$(band | sed -n '2p')"
if printf '%s' "$B_LINE2" | grep -Eq '[1-9][0-9]* fn'; then
	pass 'B4 band function count is nonzero (aaa completed)'
else
	fail "B4 band function count is nonzero (got: $B_LINE2)"
fi

# --- Phase C — functions panel and its filter ------------------------------
# r2 names unnamed functions "fcn.<addr>" and thunks "sub.<dll>_<sym>", never
# IDA's "sub_", so "fcn" is the filter substring that actually matches rows.

slash "/re functions"
expect 'C1 functions panel title'        'omp-re: functions'
expect 'C2 functions panel hint'         'enter open · type to filter · esc close'
expect 'C3 functions filter placeholder' '\(type to filter\)'

lit "fcn"
sleep 3
C4="$(pane)"
if printf '%s' "$C4" | grep -q '/fcn' \
	&& ! printf '%s' "$C4" | grep -q '(type to filter)' \
	&& printf '%s' "$C4" | grep -q 'fcn\.'; then
	pass 'C4 typing filters the list'
else
	fail 'C4 typing filters the list'
	diagnose
fi

keys BSpace
sleep 3
C5="$(pane)"
if printf '%s' "$C5" | grep -q '/fc' && ! printf '%s' "$C5" | grep -q '/fcn'; then
	pass 'C5 BSpace trims one filter character'
else
	fail 'C5 BSpace trims one filter character'
	diagnose
fi

keys Escape
sleep 3
C6="$(pane)"
if printf '%s' "$C6" | grep -q '(type to filter)' && printf '%s' "$C6" | grep -q 'omp-re: functions'; then
	pass 'C6 first Escape clears the filter, keeps the panel'
else
	fail 'C6 first Escape clears the filter, keeps the panel'
	diagnose
fi

keys Escape
expect_gone 'C7 second Escape closes the panel' 'omp-re: functions'

# alt+g must be sent as a literal ESC g byte pair; tmux's M-g form does not
# register and yields a false failure.
lit $'\x1bg'
expect 'C8 alt+g reopens the functions panel' 'omp-re: functions'

# --- Phase D — code view from the functions panel --------------------------

# Filter to a function that is actually CALLED before opening it: entry0 (the
# first row) has zero xrefs, which would make Phase E's `x` assertion depend on
# an empty result that is invisible behind the open code view.
lit "main"
sleep 3
D_FILTER_PANE="$(pane)"
# Guard: on a fixture with no "main"-matching function, Enter is a no-op, the
# code view never opens, and D1-D8/E1-E3 would fail on the wrong thing (a
# missing overlay) instead of skipping with a clear, fixture-specific reason.
if printf '%s' "$D_FILTER_PANE" | grep -q '/main' \
	&& ! printf '%s' "$D_FILTER_PANE" | grep -q 'No matching items'; then
	keys Enter
	expect 'D1 code view opens in disasm mode' '· disasm$' 30
	expect 'D2 code view hint'                 'd decomp · x xrefs · a ask · esc back' 10

	if pane | grep -Eq '^0x[0-9a-f]+ '; then
		pass 'D3 disassembly rows rendered'
	else
		fail 'D3 disassembly rows rendered'
		diagnose
	fi

	D_BEFORE="$(pane | grep -E '^0x[0-9a-f]+ ' | head -1)"
	keys Down
	sleep 2
	D_AFTER="$(pane | grep -E '^0x[0-9a-f]+ ' | head -1)"
	if [ -n "$D_BEFORE" ] && [ "$D_BEFORE" != "$D_AFTER" ]; then
		pass 'D4 Down advances the scroll offset'
	else
		fail "D4 Down advances the scroll offset (before='$D_BEFORE' after='$D_AFTER')"
	fi

	D_PAGE_BEFORE="$D_AFTER"
	keys PageDown
	sleep 2
	D_PAGE_AFTER="$(pane | grep -E '^0x[0-9a-f]+ ' | head -1)"
	if [ -n "$D_PAGE_BEFORE" ] && [ "$D_PAGE_BEFORE" != "$D_PAGE_AFTER" ]; then
		pass 'D5 PageDown advances by a page'
	else
		fail "D5 PageDown advances by a page (before='$D_PAGE_BEFORE' after='$D_PAGE_AFTER')"
	fi

	# D6/D7 cover the untested Up/PageUp rewind directions of the same scroll
	# offset; neither key touches decode mode.
	D_UP_BEFORE="$D_PAGE_AFTER"
	keys Up
	sleep 2
	D_UP_AFTER="$(pane | grep -E '^0x[0-9a-f]+ ' | head -1)"
	if [ -n "$D_UP_BEFORE" ] && [ "$D_UP_BEFORE" != "$D_UP_AFTER" ]; then
		pass 'D6 Up rewinds the scroll offset'
	else
		fail "D6 Up rewinds the scroll offset (before='$D_UP_BEFORE' after='$D_UP_AFTER')"
	fi

	D_PAGEUP_BEFORE="$D_UP_AFTER"
	keys PageUp
	sleep 2
	D_PAGEUP_AFTER="$(pane | grep -E '^0x[0-9a-f]+ ' | head -1)"
	if [ -n "$D_PAGEUP_BEFORE" ] && [ "$D_PAGEUP_BEFORE" != "$D_PAGEUP_AFTER" ]; then
		pass 'D7 PageUp rewinds by a page'
	else
		fail "D7 PageUp rewinds by a page (before='$D_PAGEUP_BEFORE' after='$D_PAGEUP_AFTER')"
	fi

	# D8 covers the untested decompile->disasm toggle direction. It MUST stay
	# inside Phase D, before E1: an unasserted priming `d` enters decompile
	# (or is a no-op if pdc is unavailable, in which case the second `d` is
	# also a no-op and D8 degrades to a trivially-true disasm check — the same
	# environment limit E1 already tolerates), then the second `d` asserts
	# disasm reappears, leaving disasm as E1's unchanged precondition. E1
	# performs the "real" toggle into decompile that stays unreset through E2,
	# so E7 below can only see `disasm` from a genuinely new nested view, not
	# a leaked outer state — placing D8 after E1 would make E7 vacuous instead.
	lit "d"
	sleep 2
	lit "d"
	expect 'D8 second d toggles back to disasm' '· disasm$' 10

	# --- Phase E — code view keys d, x, a ------------------------------
	# E1/E2 are environment-dependent: whether r2 has a decompiler plugin, and
	# whether the chosen function has xrefs. Both outcomes are correct behavior.

	lit "d"
	expect_any 'E1 d toggles decompile or reports pdc unavailable' \
		'· decompile$' 'omp-re: no decompiler output \(pdc unavailable\)'

	lit "x"
	expect_any 'E2 x opens xrefs or reports none' \
		'omp-re: xrefs to 0x[0-9a-f]+' 'omp-re: no xrefs to 0x[0-9a-f]+'
	if pane | grep -Eq 'omp-re: xrefs to 0x[0-9a-f]+'; then
		expect 'E6 xrefs panel hint' 'enter open · esc back' 10
		keys Enter
		expect 'E7 enter on an xref opens a nested code view' '· disasm$' 15
		keys Escape
		sleep 2
		close_overlay 'omp-re: xrefs to'
	else
		# E2 already accepted "no xrefs" as a correct outcome, so E6/E7 have
		# nothing to open. They must still account for themselves: an assertion
		# that silently does not run drifts the final total and would make the
		# count-drift guard hard-fail an otherwise healthy run.
		skip 'E6 xrefs panel hint' 'the filtered function has no xrefs in this fixture'
		skip 'E7 enter on an xref opens a nested code view' 'the filtered function has no xrefs in this fixture'
	fi

	lit "a"
	expect_gone 'E3 a closes the code view' 'd decomp · x xrefs · a ask · esc back' 10
else
	skip 'D1 code view opens in disasm mode' 'no function matching "main" in this fixture'
	skip 'D2 code view hint' 'no function matching "main" in this fixture'
	skip 'D3 disassembly rows rendered' 'no function matching "main" in this fixture'
	skip 'D4 Down advances the scroll offset' 'no function matching "main" in this fixture'
	skip 'D5 PageDown advances by a page' 'no function matching "main" in this fixture'
	skip 'D6 Up rewinds the scroll offset' 'no function matching "main" in this fixture'
	skip 'D7 PageUp rewinds by a page' 'no function matching "main" in this fixture'
	skip 'D8 second d toggles back to disasm' 'no function matching "main" in this fixture'
	skip 'E1 d toggles decompile or reports pdc unavailable' 'no function matching "main" in this fixture'
	skip 'E2 x opens xrefs or reports none' 'no function matching "main" in this fixture'
	skip 'E3 a closes the code view' 'no function matching "main" in this fixture'
	skip 'E6 xrefs panel hint' 'no function matching "main" in this fixture'
	skip 'E7 enter on an xref opens a nested code view' 'no function matching "main" in this fixture'
fi

# E5 comes before the prefill check: the code view was pushed over the
# functions panel with onChoose returning "keep", so that panel is still up and
# still covering the editor. Assert it, THEN close it to uncover the editor.
expect 'E5 functions panel is still open underneath' 'omp-re: functions' 10
close_overlay 'omp-re: functions'

if ! editor_visible; then
	fail 'E3 a prefills the editor with the model hand-off (editor box not on screen)'
	diagnose
elif editor | grep -q 'Use the RE tools to gather evidence'; then
	pass 'E3 a prefills the editor with the model hand-off'
else
	fail 'E3 a prefills the editor with the model hand-off'
	echo "--- editor ---"
	editor
	echo "--- end editor ---"
fi

# Clearing is load-bearing, not cosmetic: a leftover prefill would get the next
# slash command appended to it and submit as prose, starting an agent run.
if clear_editor; then
	pass 'E4 the prefilled editor can be cleared'
else
	fail 'E4 the prefilled editor can be cleared'
	echo "--- editor ---"
	editor
	echo "--- end editor ---"
fi

# --- Phase F — strings and imports panels -----------------------------------

slash "/re strings"
expect 'F1 strings panel title' 'omp-re: strings'
expect 'F1 strings panel hint'  'enter open · type to filter · esc close'

picker_enter 'F2 enter on a string jumps to its xref or reports none' \
	'omp-re: strings' 'omp-re: (no xrefs to that string|no code at 0x[0-9a-f]+)'

close_overlay 'omp-re: strings'
# "Closed" must mean every overlay is gone, not merely that this title is out
# of view: a code view left open on top of the strings panel (picker_enter's
# other branch) would hide this exact title while the panel is still open
# underneath. editor_visible only becomes true once nothing is covering it.
F3_CLOSED=1
for ((f3_i = 0; f3_i < 10; f3_i++)); do
	if ! pane | grep -Eq 'omp-re: strings' && editor_visible; then
		F3_CLOSED=0
		break
	fi
	sleep 1
done
if [ "$F3_CLOSED" -eq 0 ]; then
	pass 'F3 strings panel closes'
else
	fail 'F3 strings panel closes'
	diagnose
fi

lit $'\x1bs'
expect 'F4 alt+s reopens the strings panel' 'omp-re: strings'

# Filter lifecycle for the strings panel, mirroring C3/C4/C5/C6 for the
# functions panel. "dll" is a near-universal substring in a PE string table
# (library names); guard on a real match count since the filter line itself
# always echoes the typed text back as "/dll".
expect 'F7 strings filter placeholder' '\(type to filter\)'

lit "dll"
sleep 3
F8_PANE="$(pane)"
F8_COUNT="$(printf '%s' "$F8_PANE" | grep -Eic -- 'dll' || true)"
if [ "${F8_COUNT:-0}" -ge 2 ]; then
	if printf '%s' "$F8_PANE" | grep -q '/dll' && ! printf '%s' "$F8_PANE" | grep -q '(type to filter)'; then
		pass 'F8 typing filters the strings list'
	else
		fail 'F8 typing filters the strings list'
		diagnose
	fi

	keys BSpace
	sleep 3
	F9_PANE="$(pane)"
	if printf '%s' "$F9_PANE" | grep -q '/dl' && ! printf '%s' "$F9_PANE" | grep -q '/dll'; then
		pass 'F9 BSpace trims one filter character (strings)'
	else
		fail 'F9 BSpace trims one filter character (strings)'
		diagnose
	fi

	keys Escape
	sleep 3
	F10_PANE="$(pane)"
	if printf '%s' "$F10_PANE" | grep -q '(type to filter)' && printf '%s' "$F10_PANE" | grep -q 'omp-re: strings'; then
		pass 'F10 first Escape clears the filter, keeps the strings panel open'
	else
		fail 'F10 first Escape clears the filter, keeps the strings panel open'
		diagnose
	fi
else
	skip 'F8 typing filters the strings list' 'no string rows matched the filter substring dll'
	skip 'F9 BSpace trims one filter character (strings)' 'no string rows matched the filter substring dll'
	skip 'F10 first Escape clears the filter, keeps the strings panel open' 'no string rows matched the filter substring dll'
	keys Escape
	sleep 2
fi
close_overlay 'omp-re: strings'

slash "/re imports"
expect 'F5 imports panel title' 'omp-re: imports'
if pane | grep -Eq '0x[0-9a-f]+'; then
	pass 'F5 imports rows carry a PLT address'
else
	fail 'F5 imports rows carry a PLT address'
	diagnose
fi

# Filter lifecycle for the imports panel, mirroring C3/C4/C5/C6 for the
# functions panel. "Get" is a near-universal substring in a PE import table
# (GetProcAddress, GetModuleHandleA, ...); guard on a real match count since
# the filter line itself always echoes the typed text back as "/Get".
expect 'F11 imports filter placeholder' '\(type to filter\)'

lit "Get"
sleep 3
F12_PANE="$(pane)"
F12_COUNT="$(printf '%s' "$F12_PANE" | grep -Eic -- 'Get' || true)"
if [ "${F12_COUNT:-0}" -ge 2 ]; then
	if printf '%s' "$F12_PANE" | grep -q '/Get' && ! printf '%s' "$F12_PANE" | grep -q '(type to filter)'; then
		pass 'F12 typing filters the imports list'
	else
		fail 'F12 typing filters the imports list'
		diagnose
	fi

	keys BSpace
	sleep 3
	F13_PANE="$(pane)"
	if printf '%s' "$F13_PANE" | grep -q '/Ge' && ! printf '%s' "$F13_PANE" | grep -q '/Get'; then
		pass 'F13 BSpace trims one filter character (imports)'
	else
		fail 'F13 BSpace trims one filter character (imports)'
		diagnose
	fi

	keys Escape
	sleep 3
	F14_PANE="$(pane)"
	if printf '%s' "$F14_PANE" | grep -q '(type to filter)' && printf '%s' "$F14_PANE" | grep -q 'omp-re: imports'; then
		pass 'F14 first Escape clears the filter, keeps the imports panel open'
	else
		fail 'F14 first Escape clears the filter, keeps the imports panel open'
		diagnose
	fi
else
	skip 'F12 typing filters the imports list' 'no import rows matched the filter substring Get'
	skip 'F13 BSpace trims one filter character (imports)' 'no import rows matched the filter substring Get'
	skip 'F14 first Escape clears the filter, keeps the imports panel open' 'no import rows matched the filter substring Get'
	keys Escape
	sleep 2
fi

# A PE import's `plt` points at an IAT thunk, which frequently has no analyzed
# function behind it, so "no code at <addr>" is a third legitimate outcome
# alongside a code view and "no PLT stub".
picker_enter 'F6 enter on an import opens its PLT stub or reports none' \
	'omp-re: imports' 'omp-re: (no PLT stub for that import|no code at 0x[0-9a-f]+)'
close_overlay 'omp-re: imports'

# --- Phase G — evidence surface (needs one model round-trip) ----------------
# Compute the expected digest at runtime so the assertion holds for any fixture
# passed via OMPRE_TEST_BINARY, not just the WannaCry one.

EXPECTED_SHA256="$(sha256sum "$PE_BINARY" | awk '{print $1}')"
[ -n "$EXPECTED_SHA256" ] || { echo 'FAIL: could not compute the fixture digest'; exit 1; }

if model_step 'G1 model calls hash_binary and reports the real digest' \
	'Call hash_binary on the open binary and report only the SHA-256.' \
	"$EXPECTED_SHA256" 1 180; then

	# The audit HMAC warning fires on the first RE tool call, not at startup
	# (appendAuditLine in extensions/re/audit.ts), so G1 is the earliest point
	# it can be asserted.
	expect 'G1b audit HMAC warning on first tool call' \
		'omp-re: OMPRE_AUDIT_HMAC_KEY not configured' 10

	G_LINE2="$(band | sed -n '2p')"
	if printf '%s' "$G_LINE2" | grep -Eq '[1-9][0-9]* evidence'; then
		pass 'G2 tool_result refreshed the band evidence count'
	else
		fail "G2 tool_result refreshed the band evidence count (got: $G_LINE2)"
	fi

	slash "/re evidence"
	expect 'G3 evidence panel lists the hash_binary entry' '\[[0-9a-f]{8}\] hash_binary @'

	EV_ID="$(pane | grep -oE '\[[0-9a-f]{8}\] hash_binary' | head -1 | grep -oE '[0-9a-f]{8}' | head -1)"
	if [ -n "$EV_ID" ]; then
		# Filter to hash_binary first: the model's own tool calls also write
		# evidence, so row 1 is whatever ran last, not necessarily this entry.
		lit "hash_binary"
		sleep 2
		keys Enter
		expect 'G4 enter shows the evidence detail' '\[hash_binary:' 10
		close_overlay 'omp-re: evidence'

		# The picker only ever shows 8 chars of the UUID, so exact-equality
		# lookup alone would be unusable; this proves the prefix match.
		slash "/re evidence $EV_ID"
		expect 'G5 /re evidence <8-char prefix> resolves' '\[hash_binary:' 15

		slash "/re cite $EV_ID"
		if wait_for "Re: evidence $EV_ID" 15 && clear_editor; then
			pass 'G7 /re cite prefills the editor'
		else
			fail 'G7 /re cite prefills the editor'
			diagnose
		fi
	else
		fail 'G4 enter shows the evidence detail (could not capture an evidence id)'
		close_overlay 'omp-re: evidence'
		skip 'G5 /re evidence <8-char prefix> resolves' 'no evidence id captured'
		skip 'G7 /re cite prefills the editor' 'no evidence id captured'
	fi

	slash "/re evidence deadbeef"
	expect 'G6 /re evidence with an unknown id' 'no evidence found with id deadbeef'
else
	skip 'G1b audit HMAC warning on first tool call' 'model round-trip timed out'
	skip 'G2 tool_result refreshed the band evidence count' 'model round-trip timed out'
	skip 'G3 evidence panel lists the hash_binary entry' 'model round-trip timed out'
	skip 'G4 enter shows the evidence detail' 'model round-trip timed out'
	skip 'G5 /re evidence <8-char prefix> resolves' 'model round-trip timed out'
	skip 'G6 /re evidence with an unknown id' 'model round-trip timed out'
	skip 'G7 /re cite prefills the editor' 'model round-trip timed out'
fi

# --- Phase H — annotate, then undo ------------------------------------------
# H1 hands the model a completion marker (RENAMED) it cannot pick up from the
# prompt echo. wait_for_count matches occurrences on the currently VISIBLE
# pane, not scrollback, despite its docstring; counting "qa_probe_fn" itself
# would stall whenever a long reply scrolls the prompt echo off screen.

if model_step 'H1 model renames a function via rename_function' \
	'Use rename_function to rename the function at the entry point to qa_probe_fn. Report the tool result verbatim, then end your reply with the bare word RENAMED on its own line.' \
	'^ *RENAMED *$' 1 180; then

	if pane | grep -q 'qa_probe_fn'; then
		pass 'H1b tool result mentions qa_probe_fn'
	else
		fail 'H1b tool result mentions qa_probe_fn'
		diagnose
	fi

	slash "/re undo"
	expect 'H2 /re undo reverts the rename' \
		'omp-re: undid rename_function @ 0x[0-9a-f]+ \(restored ' 20

	# Proves the re.undo marker makes a repeated undo step back through history
	# rather than re-applying the same reversal.
	slash "/re undo"
	expect 'H3 /re undo again reports nothing left' \
		'omp-re: no annotation left to undo' 20
else
	skip 'H1b tool result mentions qa_probe_fn' 'model round-trip timed out'
	skip 'H2 /re undo reverts the rename' 'model round-trip timed out'
	skip 'H3 /re undo again reports nothing left' 'model round-trip timed out'
fi

# --- Phase I — report writer -------------------------------------------------
# The withheld-report path needs an ungrounded IOC-shaped annotation, which
# cannot be produced deterministically through the TUI; report.test.ts covers it.

slash "/re report $TMP/qa-report.md"
expect 'I1 /re report <path> confirms the write' "omp-re: report written to" 60

if [ -f "$TMP/qa-report.md" ] && head -1 "$TMP/qa-report.md" | grep -q '^# Analysis Report — Session '; then
	pass 'I2 report file exists with the expected heading'
else
	fail 'I2 report file exists with the expected heading'
	[ -f "$TMP/qa-report.md" ] && head -3 "$TMP/qa-report.md"
fi

slash "/re report"
expect 'I3 /re report with no path renders inline' '# Analysis Report — Session' 60

slash "/re report /nonexistent-dir-$$/x.md"
expect 'I4 /re report to an unwritable path reports an error' 'omp-re: could not write report to' 30

# --- Phase J — retarget to a second binary ----------------------------------

if [ "$ALT_OK" -eq 0 ]; then
	skip 'J1 /re open swaps to the second binary' "$ALT_BINARY not readable"
	skip 'J2 band re-renders for the new binary' "$ALT_BINARY not readable"
	skip 'J3 band function count for the new binary' "$ALT_BINARY not readable"
else
	slash "/re open $ALT_BINARY"
	expect 'J1 /re open swaps to the second binary' "\\[re: opened .*${ALT_NAME}\\]" 240

	# Proves openBinary closes the old R2Session, swaps state.binaryPath, and
	# the band re-renders rather than caching the first binary's facts.
	J_LINE1="$(band | sed -n '1p')"
	if printf '%s' "$J_LINE1" | grep -q "$ALT_NAME" && ! printf '%s' "$J_LINE1" | grep -q "$PE_NAME"; then
		pass 'J2 band re-renders for the new binary'
	else
		fail "J2 band re-renders for the new binary (got: $J_LINE1)"
	fi

	J_LINE2="$(band | sed -n '2p')"
	if printf '%s' "$J_LINE2" | grep -Eq '[0-9]+ fn'; then
		pass 'J3 band function count for the new binary'
	else
		fail "J3 band function count for the new binary (got: $J_LINE2)"
	fi
fi

# --- Phase K — tool gating and triage registration --------------------------
# Gating is asserted BEHAVIOURALLY, not by asking the model what tools it has.
# A model's self-report proved unreliable here: with the RE tools disabled it
# still claimed hash_binary=YES while correctly denying the others. What it
# cannot fake is the digest — hash_binary either runs and produces the real
# SHA-256, or it does not exist and the digest never appears.

slash "/re off"
expect 'K1 /re off disables the RE tools' 'omp-re: RE tools disabled for this session — /re on to re-enable' 20

ALT_SHA256="$EXPECTED_SHA256"
if [ "$ALT_OK" -eq 1 ]; then
	# Phase J retargeted the session, so the digest to expect is the alt binary's.
	ALT_SHA256="$(sha256sum "$ALT_BINARY" | awk '{print $1}')"
fi

if [ "$MODEL_OK" -eq 1 ]; then
	say 'Call hash_binary on the open binary and report only the SHA-256. If you have no such tool, reply exactly NOTOOL.'
	# Completion must be a real turn boundary, not the reply's wording: with the
	# RE tools gated off the model may decline in prose instead of emitting the
	# literal NOTOOL, and that is still a correct gating outcome. wait_turn
	# gates on the busy edge and accepts the marker only as a fallback.
	if wait_turn 'NOTOOL' 180; then
		# Absence is checked against the VISIBLE pane, never scrollback: when
		# the alt fixture is unavailable ALT_SHA256 falls back to the PE's
		# digest, which phase G1 already printed into scrollback on purpose.
		if ! pane | grep -q "$ALT_SHA256"; then
			pass 'K2 hash_binary cannot run while the RE tools are off'
		else
			fail 'K2 hash_binary cannot run while the RE tools are off (digest appeared anyway)'
			diagnose
		fi
	else
		skip 'K2 hash_binary cannot run while the RE tools are off' 'model turn never completed'
	fi

	slash "/re on"
	expect 'K3 /re on re-enables the RE tools' 'omp-re: RE tools enabled for this session' 20

	if model_step 'K4 hash_binary runs again once the RE tools are back on' \
		'Call hash_binary on the open binary and report only the SHA-256.' \
		"$ALT_SHA256" 1 180; then

		# K5: triage tools self-register only when their backing binary is on
		# PATH (isOnPath, extensions/re/tools-triage.ts). Proven behaviourally
		# and cheaply via a rules file that does not exist: resolveExistingFile
		# rejects it before yara is ever executed, so a registered tool answers
		# with its own validation error while an unregistered one could not be
		# called at all. A missing path is used rather than an empty string
		# because a model cannot reliably be made to send an empty argument.
		# Skipped when yara is absent: non-registration is then correct, and
		# there is nothing cheap to observe.
		if command -v yara >/dev/null 2>&1; then
			model_step 'K5 triage_yara is registered because yara is on PATH' \
				'Call the tool named triage_yara with rules_path set to /tmp/omp-re-no-such-rules.yar and report the exact error text you get back.' \
				'omp-re: invalid rules_path' 1 180 || true
		else
			skip 'K5 triage_yara is registered because yara is on PATH' 'yara not on PATH'
		fi
	else
		skip 'K5 triage_yara is registered because yara is on PATH' 'model round-trip timed out'
	fi
else
	skip 'K2 hash_binary cannot run while the RE tools are off' 'model round-trip timed out'
	skip 'K3 /re on re-enables the RE tools' 'model round-trip timed out'
	skip 'K4 hash_binary runs again once the RE tools are back on' 'model round-trip timed out'
	skip 'K5 triage_yara is registered because yara is on PATH' 'model round-trip timed out'
fi


# --- Phase L — layout invariants at three widths ----------------------------
# The machine-checkable substitute for a human's eye. Runs last so the
# scrollback holds every panel, error message, and tool result the QA touched.
# The band is checked BEFORE opening a panel: an open overlay replaces the
# editor area, so band() legitimately returns nothing while one is up.

check_layout() {
	local width="$1"
	local height="$2"
	local dims="${width}x${height}"

	tmux resize-window -t "$SESSION" -x "$width" -y "$height"
	sleep 3

	# L2: the band's two lines hold their documented shapes (renderBand,
	# extensions/re/ui.ts:143-150), not just a line count. "wc -l -eq 2" was
	# a tautology: band()'s awk unconditionally prints two (possibly empty)
	# lines whenever the editor anchor exists, making it exactly equivalent
	# to editor_visible — a band that wrapped to 3 rows at 60 columns, the
	# defect this width exists to catch, would still read as 2.
	local band_out band_line1 band_line2 expect_name
	band_out="$(band)"
	band_line1="$(printf '%s\n' "$band_out" | sed -n '1p')"
	band_line2="$(printf '%s\n' "$band_out" | sed -n '2p')"
	expect_name="$PE_NAME"
	if [ "$ALT_OK" -eq 1 ]; then
		expect_name="$ALT_NAME" # Phase J retargets the session when it can.
	fi
	if [ -n "$band_line1" ] && printf '%s' "$band_line1" | grep -qF "$expect_name" && printf '%s' "$band_line2" | grep -Eq '^[0-9]+ fn · [0-9]+ findings · [0-9]+ evidence$'; then
		pass "L2 band lines hold their documented shapes at $dims"
	else
		fail "L2 band lines hold their documented shapes at $dims (line1: $band_line1 | line2: $band_line2)"
		diagnose
	fi

	slash "/re functions"
	if ! wait_for 'omp-re: functions' 10; then
		fail "panel did not open at $dims"
		diagnose
		return
	fi

	# L1: truncateToWidth must keep every rendered line inside the pane. A
	# character-length check can never observe this: without -J, tmux emits
	# one string per grid row and a grid row holds exactly `width` cells, so
	# the character count is always <= the cell count <= real width — an
	# overflowing line does not arrive long, it wraps into an extra row or
	# gets clipped instead. Assert the panel's total ROW COUNT rather than
	# any line's length: makePickerPanel renders [title, filterLine,
	# ...selectList.render(), hint] (ui.ts:223-227), and SelectList appends
	# one "Type to search" status row whenever the pre-filtered item count
	# exceeds MAX_VISIBLE_ROWS=12 (pi-tui select-list.ts
	# #shouldRenderSearchStatus). A wrapped or clipped line changes this count.
	local fn_count=0
	if printf '%s' "$band_line2" | grep -Eq '^[0-9]+ fn '; then
		fn_count="$(printf '%s' "$band_line2" | sed -E 's/^([0-9]+) fn.*/\1/')"
	fi
	local sl_rows
	if [ "$fn_count" -eq 0 ]; then
		sl_rows=1 # "No matching items"
	elif [ "$fn_count" -gt 12 ]; then
		sl_rows=13 # 12 visible rows + the search-status row
	else
		sl_rows="$fn_count"
	fi
	local expected_rows=$((3 + sl_rows)) # title + filterLine + selectList rows + hint
	local panel_block panel_rows
	panel_block="$(pane | sed -n '/omp-re: functions/,/esc close/p')"
	panel_rows="$(printf '%s\n' "$panel_block" | wc -l)"
	if [ "$panel_rows" -eq "$expected_rows" ]; then
		pass "L1 functions overlay renders exactly $expected_rows rows at $dims ($fn_count fn)"
	else
		fail "L1 functions overlay renders exactly $expected_rows rows at $dims (got $panel_rows, $fn_count fn)"
		diagnose
	fi

	# L3: classic render-path artifacts.
	if ! pane | grep -Eq 'undefined|NaN|\[object Object\]'; then
		pass "L3 no render artifacts at $dims"
	else
		fail "L3 no render artifacts at $dims"
		diagnose
	fi

	close_overlay 'omp-re: functions'
}

check_layout 80 24
check_layout 100 30
check_layout 60 20

tmux resize-window -t "$SESSION" -x 80 -y 24
sleep 2

# L4: the branding regression guard, extended from one panel title to the
# entire session's output. Filtered by LINE, never by mutating the text: an
# unanchored, unescaped sed delete of the fixture's dir token self-defeats in
# three ways — an "rzx"-named parent dir (e.g. /opt/rzx/sample.exe) erases
# every occurrence anywhere before the grep runs; a relative fixture path
# makes the token "." and "s|.||g" deletes every character; and a token
# containing "|" makes sed error out, leaving the text empty (no set -e).
L4_HITS="$(pane_all | grep -iF 'rzx' | grep -vF "$PE_BINARY" | grep -vF "$ALT_BINARY")"
if [ -z "$L4_HITS" ]; then
	pass 'L4 no rzx branding anywhere in the session output'
else
	fail 'L4 no rzx branding anywhere in the session output'
	printf '%s\n' "$L4_HITS" | head -20
fi

# The audit HMAC warning is once-per-session (state.auditHmacWarned), and by
# now many RE tool calls have run.
AUDIT_HITS="$(pane_all | grep -c 'OMPRE_AUDIT_HMAC_KEY not configured' || true)"
if [ "${AUDIT_HITS:-0}" -le 1 ]; then
	pass 'L5 audit HMAC warning fired at most once per session'
else
	fail "L5 audit HMAC warning fired at most once per session (saw $AUDIT_HITS)"
fi

# --- final summary ----------------------------------------------------------

# The busy sentinel (⟦esc⟧ / nerd-font ⟨esc⟩ / ASCII [esc]) is wait_idle's
# only signal that a turn is running; under a fourth glyph set it would
# return 0 on its first sample and fail OPEN — exactly the hazard its own
# docstring warns about (slash/say would then type into a running turn, and
# ensure_editor's Escape would cancel it). If a model turn actually ran this
# session, the many wait_idle call sites chained after one (band/slash/say)
# should have caught the hint at least once. Fail loudly here instead of
# letting the gate silently stay disabled for a future theme change.
if [ "$MODEL_OK" -eq 1 ] && [ "$SENTINEL_SEEN" -eq 0 ]; then
	echo "FAIL: busy sentinel was never observed during any model turn — wait_idle is effectively disabled for this theme"
	exit 1
fi

# Skips never touch FAIL_COUNT and nothing else checks the expected total,
# so a model-outage skip cascade could print PASS 62 / FAIL 0 / SKIP 15 and
# still exit 0. Pin the total so any drift fails loudly.
[ $((PASS_COUNT + FAIL_COUNT + SKIP_COUNT)) -eq 99 ] || { echo "FAIL: assertion count drift (expected 99, got $((PASS_COUNT + FAIL_COUNT + SKIP_COUNT)))"; exit 1; }

echo ""
echo "=============================================="
echo "omp-re TUI QA: PASS $PASS_COUNT / FAIL $FAIL_COUNT / SKIP $SKIP_COUNT"
echo "=============================================="
if [ "$FAIL_COUNT" -gt 0 ]; then
	exit 1
fi
exit 0