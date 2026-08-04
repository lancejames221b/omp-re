---
name: re-triage
description: First-pass reverse engineering of a binary using omp-re's RE tools. Use whenever asked to analyse, reverse, triage, decompile, characterise, or unpack an executable, and when a binary has just been opened and no findings exist yet.
---

# RE with omp-re

These tools are the only source of recorded evidence in this session. Anything
learned another way — `bash`, `cat`, a pasted dump, prior knowledge — has no
evidence id behind it, and `/re report` withholds the **entire** report if any
claim in it is unbacked. Get findings through the tools.

## Start here

`/re open <path>` spawns radare2, runs full analysis, and populates the status
band. Nothing works until a binary is open — every tool returns
`omp-re: no binary open` first.

There is no `/re triage`. The subcommands are: `open <path>`, `functions`,
`strings`, `imports`, `evidence [id]`, `cite <id>`, `undo`, `report [path]`,
`on`, `off`, `help`.

## Order of work

Do not skip ahead — later steps depend on evidence the earlier ones record.

1. `hash_binary` — establish identity before anything else.
2. `list_segments`, `list_imports`, `list_exports` — shape and external surface.
3. `list_strings` with a `filter` when the set is large — never page blindly
   through thousands.
4. `list_functions`; then `get_function` on the handful that matter.
5. `decompile_function` only on functions you have a reason to read.
6. `triage_capa` when it is registered — it is the only source that grounds
   ATT&CK and verdict claims.

A triage tool exists only when its binary was on PATH at load: `triage_capa`
needs `capa`, `triage_floss` needs `floss`, `triage_die` needs `diec`,
`triage_yara` needs `yara`. A missing tool means the binary is absent, not that
the call failed.

## Navigating

`alt+g` opens the function navigator, `alt+s` the strings panel; type to filter.
In the code view: `d` toggles decompiled pseudo-C, `x` follows the selected
cross-reference, `a` hands the function to the model with a grounding prompt,
`Escape` goes back.

`/re evidence` lists what has actually been recorded; `/re cite <id>` pulls one
entry into your next message so a follow-up carries its context.

## Annotating

`rename_function`, `rename_variable`, `set_comment`, `set_prototype`, and
`set_variable_type` write back into the r2 session and record annotations.
`/re undo` reverts the last one.

## Grounding rules

- Every address you name must have come from tool output in this session. Never
  infer an address arithmetically and never carry one over from another binary.
- Quote the `ea` field a tool returned. Do not convert decimal offsets yourself.
- When `decompile_function` output begins `(disassembly only — no decompiler
  plugin available)`, say so before drawing behavioural conclusions from it.
- Hedge genuine hypotheses ("this resembles…", "possibly…"). Hedged reasoning is
  legitimate; an unhedged claim with no evidence is not.
- Absence of evidence is a finding. "No network imports observed" beats silence.
