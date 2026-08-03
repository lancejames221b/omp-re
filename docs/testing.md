# Testing

Three tiers: `bun test` (unit), `bash test/tui.sh` (fast smoke), `bash
test/tui-qa.sh` (full tmux QA). Run from the repo root after
`bun install --ignore-scripts`.

## Unit tests — `bun test`

```bash
bun install --ignore-scripts
bun test
```

Eight test files. Five run unconditionally; three require both a real
`radare2` on PATH and a test binary, and **skip entirely** (not fail) when
either is missing:

| File | Needs r2 + fixture? |
| --- | --- |
| `r2-pure.test.ts` | No |
| `format.test.ts` | No |
| `evidence.test.ts` | No |
| `audit.test.ts` | No |
| `report.test.ts` | No |
| `r2-integration.test.ts` | Yes |
| `tools-registry.test.ts` | Yes |
| `tools-mutate-registry.test.ts` | Yes |

**The default fixture is a real WannaCry sample** at
`/tmp/rzx-dogfood/wannacry.bin`. It is **deliberately not distributed** with
this repo — do not add it, and do not ask CI to fetch it. Set
`OMPRE_TEST_BINARY=/path/to/your/binary` to point the fixture-dependent
suites at a different sample; some assertions (e.g. specific variable names
like `var_14h` in `main`) assume the WannaCry fixture's actual disassembly
and may not hold against an arbitrary substitute, so treat overriding it as
"at your own risk" for exact-match assertions, not a general-purpose swap.

Expected shape with the real fixture + r2 present: 73 pass, 0 fail. Without
either: the three fixture-gated files report 0 tests each (skipped, not
failed) and the rest still pass in full — this is CI's actual, permanent
shape (see below), not a degraded state to "fix".

## Fast smoke tier — `bash test/tui.sh`

```bash
bash test/tui.sh
```

A short tmux-driven smoke test against the real TUI. ~30s, 7 PASS, exit 0.
Requires a real terminal/tmux and the fixture; not run in CI (see below).

## Full QA tier — `bash test/tui-qa.sh` (`bun run qa:tui`)

```bash
bun run qa:tui
```

A long, comprehensive tmux-driven QA pass against the live TUI — 99
assertions covering every `/re` subcommand, both shortcuts, the evidence
panel, undo, and the audit log. Requires tmux, a real radare2, and the
fixture; also not run in CI.

The suite pins its own assertion count as a drift guard (a literal `-eq 99`
near the end of the script): if you add or remove an assertion, update that
literal in the same commit, and give any conditional assertion an explicit
`skip` mirror on every other branch it could take — the guard fails a
healthy run if a branch silently produces a different total than every
other branch.

## What CI actually runs

Two jobs, both fixture-free by design:

- **`check`** — `bun install --ignore-scripts && bun run check` (`tsc
  --noEmit`). Needs nothing beyond Bun.
- **`test`** — `bun install --ignore-scripts && bun test`. Deliberately does
  **not** install radare2 or supply a fixture. Expected result: the 5
  fixture-free files pass in full, the 3 fixture-gated files skip (0 tests,
  not a failure), overall exit code 0. This is the permanent, correct CI
  shape — a future PR "fixing" the skips by installing radare2 or fetching a
  malware sample into CI would be the actual regression.

Both tmux tiers (`test/tui.sh`, `test/tui-qa.sh`) are **local/self-hosted
only**: both hard-exit 0 when the fixture is unreadable, which would make
them pure theatre on a hosted runner that has neither tmux nor the fixture.

## Local dev loop

`extensions/re/` changes are picked up by a **fresh `omp` start** if you're
dev-loading via the `extensions:` config entry in
[the README](../README.md#install) — no build step, but also no hot reload;
restart `omp` after an edit. If you installed as a plugin instead, the
cached copy under `~/.omp/plugins/cache/plugins/...` is a **copy, not a
symlink**, so an edit to your checkout does nothing until you reinstall:

```bash
omp plugin upgrade omp-re@unit221b
```
