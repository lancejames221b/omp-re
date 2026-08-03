# omp-re TUI QA findings

Defects found by `test/tui-qa.sh` whose fix would change a surface's contract
or span modules, so they were recorded rather than patched mid-QA. Everything
else the pass turned up was either a harness bug (fixed in `test/tui-qa.sh`) or
a localized product bug (fixed in `extensions/re/`).

Fixed during this pass, for reference:

- `/re off` and `/re on` emitted `re: ...` while every other user-facing string
  in the suite uses `omp-re: ...`. Both are now `omp-re:`
  (`extensions/re/index.ts`, the `sub === "off"` and `sub === "on"` branches).


### 2026-08-03 release-polish pass (real WannaCry fixture, first time)

`test/tui-qa.sh` had only ever been run with `OMPRE_TEST_BINARY=/bin/ls`
before this pass; running it against the real default fixture
(`/tmp/rzx-dogfood/wannacry.bin`) surfaced one genuine product bug and two
harness robustness gaps that a tiny ELF never exercised:

- **`resolveEA` (`extensions/re/tools-mutate.ts`) read the wrong JSON field.**
  It pulled a hex EA out of a read-back's `offset` field, but r2 6.x renamed
  that field to `addr` on `afij` (the read-back command `rename_function`
  and `set_prototype` both use). Confirmed directly: `r2 -q -c 'afij @
  entry0'` on the WannaCry fixture returns `{"addr":4233750,...}` — no
  `offset` key at all. `resolveEA` therefore *always* fell back to the
  caller's raw address string, so `/re undo`'s message showed the literal
  argument the model passed (e.g. `omp-re: undid rename_function @ entry0
  (restored ...)`) instead of a normalized hex address — this is the `H2`
  defect from the invalidated `/bin/ls` QA run. `addrOf`/`eaFromOffset`
  (`extensions/re/r2.ts`) already exist and handle exactly this `addr`/
  `offset` split for every read-tool callsite; `resolveEA` just never used
  them. Fixed by routing it through the same two helpers. Verified: the
  `test/tools-mutate-registry.test.ts` `set_prototype` undo test previously
  asserted the buggy literal (`@ entry0`) and now asserts the real hex form;
  `H2` passes live against the real fixture post-fix
  (`omp-re: undid rename_function @ 0x...`).
- **`clear_editor`'s backspace budget (`test/tui-qa.sh`) was sized for a
  short single-line prefill, not a real evidence summary.** A real
  `hash_binary` evidence entry against WannaCry is ~250 bytes; the prior
  20s/40-keys-per-batch budget cleared only ~85% of it before its deadline,
  leaving a `Re: evidence <id> (hash_binary @ 0` fragment that the next
  `slash` call appended text to, submitting the glued string as a chat
  message instead of a command (`G6`'s failure mode in the first full run).
  Widened to 45s/80 keys per batch — comfortable margin up to
  `EVIDENCE_SUMMARY_MAX_BYTES` (512).
- **Typed filter text could race a panel's render and land in the chat
  editor instead.** Reproduced live: after the E-phase code view/xrefs
  nesting closes back out, pressing `a` sometimes landed while the
  functions panel underneath had not yet fully redrawn, so the keypress
  (and later, `dll`/`Get` in the F-phase strings/imports filters) fell
  through to the still-focused chat editor and got submitted as prose,
  sending the model off on an unrelated tool-call tangent for the rest of
  that run. Careful, deliberately slow manual replays of the exact same key
  sequence (2-3s between every keystroke) never reproduced this — it is a
  render-timing race, not a logic defect in `ui.ts`'s overlay stack. Added
  `ensure_panel`, a bare `wait_for` with no pass/fail bookkeeping, before
  every `lit <filter text>` call that assumes a panel or code view is
  already on screen (functions, strings, imports, evidence panels; the code
  view's `d`/`x`/`a` keys). The readiness handshake's own `/re help` retry
  loop (8 attempts x 15s) was also too tight for a machine with a large MCP
  tool catalog — a startup dump was observed still swallowing keystrokes 75s
  after launch — widened to 16 x 20s.
- **Separately, and not a `test/tui-qa.sh` or `extensions/re/` defect:** on
  this session's specific shared host, repeated full-tier runs kept failing
  at different, non-reproducible points (a startup handshake timeout, a
  cascading stray-keystroke derailment even with the guards above, and
  literal `Error: omp-re: radare2 process exited` mid-run) that correlate
  with measured, severe, third-party resource contention on that host:
  `uptime` load average 6-9 sustained across multiple checks, `free -h`
  showing ~80GiB of swap in active use with as little as 2GiB RAM free, 21-23
  concurrent logged-in users, and an unrelated process (`./complicated 4
  init`, running since Aug 1) pinned at 99.8% CPU throughout. `r2`/r2ghidra's
  Ghidra decompile bridge is memory- and CPU-heavy; a host thrashing this
  hard can plausibly starve or kill it independent of any omp-re code path.
  One full run did complete end to end on this same host earlier in the
  session (before the harness fixes above, before the host's swap usage
  climbed further): **PASS 94 / FAIL 5 / SKIP 0** — of the 5 failures, `G6`
  and the `E3`/`E4`/`E5`/`L4` cascade are the exact classes the fixes above
  target, and `D5`/`D7` already passed clean in that same run (the `/bin/ls`
  "no matching function" artifact this pass exists to resolve). No
  subsequent attempt on this host reached a clean run to independently
  confirm 99/0/0; re-run this tier on an otherwise-idle host to get a
  trustworthy number rather than retrying again here.
- **`test/tui.sh` (smoke tier) on this same host:** two assertions
  consistently failed with `OMPRE_TEST_BINARY=/bin/ls` (needed to avoid the
  `--binary`-races-MCP-startup crash above) — "status band line 1 missing
  ... PE32 ..." is expected and fixture-specific (the assertion hardcodes
  `PE32`/`x86/32`; `/bin/ls` is ELF64/x86-64), not a defect. "/re off did
  not notify RE tools disabled" reproduced 3/3 times with `/bin/ls` even
  after adding an explicit wait for the editor's status border before
  sending the command (a real, if unrelated, robustness fix now in
  `test/tui.sh`); the immediately-following `/re on` on the identical
  session always succeeded. Not isolated further — plausibly the same
  local-skill/autocomplete collision on `/re` documented for `G6` above,
  or another instance of the render-timing class this pass fixed
  elsewhere, but neither was confirmed. The default WannaCry fixture could
  not be used to cross-check because of the `--binary` crash. Treat as
  unverified on this host rather than a confirmed regression: nothing in
  this pass's diff touches `/re off`'s handler (`extensions/re/index.ts`)
  or its test.

---

## 1. A notify raised from an open panel is invisible to the user

**Phases:** F2, F6 (also reachable via E1, E2)
**Origin:** `extensions/re/ui.ts` — `showStringsPanel` / `showImportsPanel`
`onChoose`, `showCodeView`'s no-code and xref-chain-depth guards,
`followXrefs`, and `makeCodeView`'s `onToggle`.

### What happens

Every one of these paths reports a dead end with `ctx.ui.notify(...)` and then
keeps the panel open (`onChoose` returns `"keep"`, or the code view simply
stays up):

| Surface | Message |
| --- | --- |
| strings panel, Enter on a string with no xrefs | `omp-re: no xrefs to that string` |
| imports panel, Enter on an import with no PLT | `omp-re: no PLT stub for that import` |
| any panel opening a code view at an address with no code | `omp-re: no code at 0x…` |
| code view, `x` with no xrefs | `omp-re: no xrefs to 0x…` |
| code view, `d` with no decompiler | `omp-re: no decompiler output (pdc unavailable)` |
| code view, `x` recursing past 8 hops | `omp-re: xref chain too deep — stopping to avoid an unbounded loop` |

`ctx.ui.notify` writes to the transcript, which renders *underneath* the
overlay. A picker draws up to `MAX_VISIBLE_ROWS` (12) rows plus a title, filter
line and hint, so a full list plus the surrounding chrome pushes the transcript
off an 80x24 pane entirely. The message is emitted, but the user never sees it.

From the user's side, pressing Enter on such a row does *nothing at all*: no
code view, no error, no state change. The affordance says the row is openable
and the failure is silent.

### Evidence

Observed directly by the harness. In the run before `picker_enter` existed, F2
asserted on both possible outcomes and failed on both: the pane showed the
strings panel with a full 12 rows and no message anywhere:

```
omp-re: strings
(type to filter)
> Sleep                           0x40a40a
  GetTickCount                    0x40a412
  ... 10 more rows ...
enter open · type to filter · esc close
```

`test/tui-qa.sh` now works around it in `picker_enter`, which is itself the
proof: it checks for a code view first, and only after **closing the panel**
does the notify become greppable. F2 and F6 both report
`(reported no target)`, meaning the message existed but was unobservable until
the overlay went away.

Note the severity is list-length dependent, which is why it is easy to miss:
the evidence panel (G4) had only 7 rows, left enough transcript on screen, and
its detail notify *was* visible. The bug bites exactly when a list is full,
which is the normal case for strings, imports and functions.

### Why it was not fixed here

The fix changes the panel contract rather than a string. The message has to
render *inside* the overlay — a status/message line in `makePickerPanel` and
`makeCodeView` that `onChoose`/`onToggle`/`onXrefs` can write to. That touches
two distinct interfaces, not one:

- `PickerOptions` (`ui.ts:190-200`) — 5 call sites: `ui.ts:288, 455, 532, 565,
  612`.
- `makeCodeView`'s (unexported) opts type (`ui.ts:319-329`) — 1 call site:
  `ui.ts:468`.

Plus three hub functions that need actual new rendering logic, not just a
threaded setter: `makePickerPanel` (`ui.ts:205`), `showPanel` (`ui.ts:262`),
and `makeCodeView` (`ui.ts:319`).

Total: 6 call sites across 2 distinct interfaces — not 5 call sites of one.

`showCodeView` itself has exactly 4 callers today (`ui.ts:292, 459, 582,
620`), every one a panel `onChoose`; no command handler in `index.ts` calls
it directly. Whether a future fix should have `showCodeView` report failures
through its caller, or keep using `notify` when it is one day invoked from a
command rather than a panel, is a design question for that fix — not a
description of anything the current code already does.

Worth pairing with a second decision: for a PE, `iij`'s `plt` points at an
IAT thunk that may have no analyzed function behind it. That was observed
once, on the WannaCry fixture in phase F6, whose assertion accepts either
outcome (`no PLT stub for that import` or `no code at 0x…`) as legitimate —
it is not a measured frequency claim. There is no PE/ELF-aware branching
anywhere in `ui.ts`, and the only in-repo characterisation of `plt` semantics
is generic/ELF-flavoured (`tools-read.ts:81`, `:138`). The imports panel may
still want to resolve to the calling stub, or mark unopenable rows, rather
than offering Enter on every row and failing — but that should follow from
measuring the actual rate on a representative sample of binaries, not from
one fixture's single outcome.

---

## 2. Mutate-tier command-template defects — fixed in v0.1.0

**Discovered by:** `test/tools-mutate-registry.test.ts`, the deterministic unit
tier for the 5 MUTATE-tier tools plus the `/re undo` switch.
**Origin:** `extensions/re/tools-mutate.ts`.

Four defects made 3 of the 5 mutate tools always fail against real radare2
and the fifth (`set_comment`) fail on its second call at any given address.
All four are fixed as of v0.1.0, verified directly against real radare2
6.1.8 (not inferred from source alone):

1. **`rename_variable`** sent `afvn ${new} ${old} ${addr}` — a trailing
   address token `afvn`'s grammar does not accept. Fixed to seek with r2's
   `@ addr` temporary-seek syntax: `afvn ${new} ${old} @ ${addr}`.
2. **`set_variable_type`** had the identical defect in `afvt`; fixed the
   same way.
3. **`set_prototype`** sent `af ${sig} ${addr}` — `af` renames a function,
   it does not set a signature. Fixed to use `afs ${sig} @ ${addr}`. r2's
   `afij` read-back always re-punctuates a signature (adds a space before
   `(`, appends a trailing `;`); the tool now normalizes both sides
   (whitespace and trailing `;` stripped) before comparing, so it tolerates
   r2's own cosmetic reformatting without weakening the check — a different
   signature still fails loudly.
4. **`set_comment`** issued `CC ${text} @ ${addr}`, and r2's `CC` **appends**
   to an existing comment rather than replacing it, so a second call at the
   same address always failed its own read-back. Fixed to clear first
   (`CC- @ ${addr}`) before writing, making the forward path idempotent.

The `/re undo` switch shared some of these defects and one more found while
verifying the fixes: `rename_variable`'s and `set_variable_type`'s undo
branches also sent `afvn`/`afvt` without an `@ addr` seek, so undo reported
success while silently doing nothing — confirmed by probing an actual
rename/retype-then-undo round trip. Both branches now use the same `@ addr`
form as the forward tools. `set_comment`'s and `set_prototype`'s undo
branches got the same clear-first and `afs`/normalization fixes as their
forward paths. `set_prototype`'s forward path also now strips r2's trailing
`;` from the captured old signature before storing it, so a later undo does
not trip `validateTypeLike`'s forbidden-character check on a semicolon r2
itself appended.

`rename_function` was unaffected by any of the above (it already used
`afn ${name} ${addr}` — no seek needed since `afn` takes an address
directly) and remains proven working end to end by `test/tui-qa.sh`
phase H.

## 3. Phase L's `L1` is a row-count assertion, not an overflow detector

`test/tui-qa.sh`'s L1 was rewritten (remediation step 2d) on the stated premise
that "an overflowing line adds a wrapped row", replacing a character-length
check that provably could never fire. The replacement is a genuine assertion,
but **it does not detect line overflow**, and the premise it was built on is
wrong. Both halves were established by failure injection, not by reading:

| Injection | Result |
| --- | --- |
| Append 108 chars to the panel's first rendered line (bypassing `truncateToWidth`) | 96 PASS / 0 FAIL — no extra row |
| Append an extra row *after* the `esc close` hint | 96 PASS / 0 FAIL — outside the measured range |
| `MAX_VISIBLE_ROWS` 12 → 11 (`extensions/re/ui.ts:177`) | L1 FAILs at all three widths (`got 15`, expected 16) |

The first injection is the load-bearing one: an over-wide line produced **no**
extra grid row, because this TUI (and tmux's `capture-pane` without `-J`)
**clips** an over-wide line at the last column rather than wrapping it. So no
row-count check can observe overflow, exactly as no character-count check
could.

What L1 does guard, and guards correctly, is the overlay's row arithmetic:
`[title, filterLine, ...selectList.render(), hint]` with SelectList's extra
search-status row past `MAX_VISIBLE_ROWS` — 16 rows for the fixture's 22
functions. A regression in `MAX_VISIBLE_ROWS`, in the 3-line chrome, or in the
search-status threshold fails it at every width. That is worth having; it is
simply not what the assertion's name and its predecessor's intent imply.

Consequence for a future implementer: **line-width overflow is currently
unasserted anywhere in either tier.** Detecting it needs a different oracle —
comparing `capture-pane -p` against `capture-pane -p -J` (which rejoins wrapped
lines) would reveal wrapping, and asserting no rendered line ends exactly at
the last column would catch clipping. Do not "fix" L1 by loosening its expected
count to accommodate a wrap; a wrap there is a real defect.

---

## 4. `decompileAt` falls back to `pdc` inside the real omp extension even
## though r2ghidra is installed and its identical protocol sequence works
## standalone

**Discovered during:** the 2026-08-03 release-polish pass, capturing the
`decompile` scene for `tools/shotgen`.
**Origin:** `extensions/re/decompile.ts` (`resolveKind`/`decompileAt`), or
possibly an environment difference outside this repo — not conclusively
isolated to one side.

### What happens

Opening `main` in `/bin/ls` and pressing `d` for decompile mode renders r2's
native `pdc` pseudo-C (`int main (int argc, char **argv) { loc_0x0000475f:
... }`), not r2ghidra's real output, even though:

- `r2 -q -c 'pdg @ main' /bin/ls` from a plain shell produces genuine Ghidra
  decompilation (`uint main(int argc,char **argv) { char **ppcVar1; ... }`).
- A standalone script replicating `R2Session`'s exact protocol byte-for-byte
  (spawn `r2 -q0 <bin>`, consume the startup banner frame, run `aaa`, probe
  `pdg?` for the "not available" signature, run `pdg @ main`) also succeeds:
  the probe correctly reports r2ghidra present, and `pdg @ main` returns
  35KB of real decompiled output in ~8s.
- The fallback reproduces in a **fresh** interactive session with **zero**
  prior model tool calls (opened the binary, jumped straight to `main`,
  pressed `d` — no `hero`-style triage prompt in between), ruling out
  interference from a concurrent/earlier r2 command on the same session.

### What was ruled out

- **Frame-count desync in `cmd()`'s 8-frame loop**: measured directly —
  `pdg?`'s ~958-byte help text arrives as exactly one r2pipe frame, not one
  frame per line, so it can never approach the ceiling.
- **Session already closed** (an earlier timeout having called
  `R2Session.close()`, killing the process): ruled out because `pdfj`
  (disassembly) succeeds on the same session immediately before and after
  the failed decompile — a closed session's `cmd()` throws
  `"radare2 process exited"` unconditionally, which would break disasm too.
- **Model tool-call interference**: ruled out by the zero-prior-turn
  reproduction above.

### Why it was not fixed here

The standalone replica proves `resolveKind`'s probe *logic* is sound against
the exact same r2 binary and command sequence; the real extension still
degrades. That gap points at something in the omp/bun execution context
(PATH resolution for the spawned `r2`, an environment variable r2ghidra
reads, a working-directory-dependent plugin lookup) rather than the
TypeScript itself, but this pass did not isolate which — confirming it needs
comparing `process.env.PATH` and `r2 -v`/loaded-plugin output *from inside*
a running omp session against a plain shell's, which is instrumentation this
pass didn't have time to add. Recorded here rather than guessed at further.

**Consequence for the shipped screenshots:** `docs/img/decompile.png` shows
the honest `pdc` fallback rather than r2ghidra output. That is still a real,
accurate capture of the extension's actual behavior (including the
degradation labeling working as designed) — not a defect in the screenshot
pipeline — but it is the less impressive of the two possible outcomes.