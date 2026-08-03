# Contributing

## Setup

```bash
bun install --ignore-scripts
```

`--ignore-scripts` matters: don't run lifecycle scripts from dependencies
without reviewing them first.

## Before opening a PR

```bash
bun run check      # tsc --noEmit — must exit 0
bun test           # unit tests; 5 files run unconditionally, 3 skip without
                    # a real radare2 + the (undistributed) WannaCry fixture —
                    # see docs/testing.md
bash test/tui.sh   # fast tmux smoke test, ~30s
bun run qa:tui     # full tmux QA pass, 99 assertions
```

The last two need tmux, a real `radare2`, and the test fixture; set
`OMPRE_TEST_BINARY` to point at your own sample if you don't have the
WannaCry one. See [`docs/testing.md`](docs/testing.md) for what each tier
actually needs and the exact PASS/SKIP matrix.

## Two hard rules `test/tui-qa.sh` depends on

1. **The assertion-count drift guard.** `test/tui-qa.sh` pins its own total
   assertion count in a literal near the end of the script (currently `-eq
   99`). Any PR that adds or removes an assertion **must** update that
   literal in the same commit — the guard exists specifically to catch a
   silent count drift (e.g. a model-outage skip cascade) that would
   otherwise still exit 0.
2. **Every conditional assertion needs a `skip` mirror on every other branch
   it could take.** If an assertion only runs inside an `if [ -n "$SOME_ID"
   ]` block, the corresponding `else` branch (and any outer failure branch)
   must call `skip '<same assertion name>' '<reason>'` — otherwise the total
   assertion count differs between branches, and the drift guard fails a
   run that is actually healthy.

## Style

- No emojis in commits, code, or PR descriptions.
- Keep PR descriptions technical and direct — what changed and why, not
  marketing language.
- Match the file's existing patterns before introducing a new one; this
  project has a strict "one canonical way to do X" convention throughout
  (see e.g. the single `findEvidence` prefix-match lookup shared by `/re
  evidence` and `/re cite`).
