# Security

## Reporting a vulnerability

Open a private security advisory on this repository's GitHub Security tab,
or email the maintainer listed in `package.json`. Do not open a public issue
for an unpatched vulnerability. Include a minimal reproduction and the
`omp`/`radare2`/`omp-re` versions involved; expect an initial response
within a few business days.

## Analysis hygiene — this is not a sandbox

`omp-re` is a dual-use tool: it runs radare2 against binaries you feed it,
which may include real, live malware. Neither `omp-re` nor radare2 itself
provides any isolation:

- **`aaa` (full analysis) on a hostile binary is not a sandbox.** radare2 is
  a static analysis tool — it disassembles and analyzes the file, it does
  not execute it — but radare2 itself, its plugins (r2ghidra, capa, etc.),
  and any file-format parsing anywhere in that chain are attack surface. A
  malformed binary crafted to exploit a parser bug is a real, if narrow,
  risk. **Run this suite against untrusted samples inside a VM or other
  disposable environment you're prepared to lose, not on your primary
  machine.**
- `omp-re` never executes the binary you open. `debug`-tool-driven dynamic
  analysis (attach, breakpoints) is a separate, explicit action via omp's
  own built-in `debug` tool — see [`docs/workflow.md`](docs/workflow.md).
  If you use it, the sandboxing responsibility is entirely yours.
- Triage tools (`triage_capa`, `triage_yara`, etc.) shell out to real
  external binaries you installed yourself. Their own security posture is
  out of scope for this document — keep them updated.

## Mutations never touch the file on disk

`set_comment`, `rename_function`, `rename_variable`, `set_prototype`, and
`set_variable_type` only mutate radare2's **in-process analysis database**
for the running session. `R2Session.spawn` launches radare2 as
`r2 -q0 <path>` — no `-w` (write) flag — so radare2 opens the file
read-only and none of these tools ever writes back to the sample on disk.
Closing the session (or the omp process) discards every annotation unless
you've written a `/re report`.

## Scope

In scope: `extensions/re/*.ts`, the `/re` command surface, and the tool
implementations. Out of scope: radare2 itself, r2ghidra, capa/floss/diec/
yara, and omp — report vulnerabilities in those projects upstream.
