# omp-re TUI QA findings

Defects found by `test/tui-qa.sh` whose fix would change a surface's contract
or span modules, so they were recorded rather than patched mid-QA. Everything
else the pass turned up was either a harness bug (fixed in `test/tui-qa.sh`) or
a localized product bug (fixed in `extensions/re/`).

Fixed during this pass, for reference:

- `/re off` and `/re on` emitted `re: ...` while every other user-facing string
  in the suite uses `omp-re: ...`. Both are now `omp-re:`
  (`extensions/re/index.ts`, the `sub === "off"` and `sub === "on"` branches).

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