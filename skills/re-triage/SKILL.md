---
name: re-triage
description: Structured first-pass triage of an unknown binary using omp-re's RE tools. Use when a binary has just been opened and no findings exist yet, or when asked to triage, analyse, or characterise an executable.
---

# RE triage

Work in this order. Do not skip ahead — later steps depend on evidence the earlier ones record.

1. `hash_binary` — establish identity before anything else.
2. `list_segments`, `list_imports`, `list_exports` — establish shape and external surface.
3. `list_strings` with a `filter` when the set is large — never page blindly through thousands.
4. `list_functions`; then `get_function` on the handful that matter.
5. `decompile_function` only on functions you have a reason to read.
6. `triage_capa` when available — it is the only source that grounds ATT&CK and verdict claims.

## Grounding rules

- Every address you name must have come from tool output in this session. Never infer an address arithmetically and never carry one over from another binary.
- Quote the `ea` field a tool returned. Do not convert decimal offsets yourself.
- When `decompile_function` output begins `(disassembly only — no decompiler plugin available)`, say so before drawing behavioural conclusions from it.
- Hedge genuine hypotheses ("this resembles…", "possibly…"). Hedged reasoning is legitimate; an unhedged claim with no evidence is not.
- Absence of evidence is a finding. "No network imports observed" beats silence.
