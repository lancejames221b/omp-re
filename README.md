# omp-re

`omp-re` is a reverse-engineering plugin for [omp](https://omp.sh) (oh-my-pi):
it wraps [radare2](https://rada.re) behind 22 agent tools, a `/re` slash
command, five overlay panels, a content-addressed evidence store, an
HMAC-signable audit log, and a report writer that refuses to write a claim
with no supporting evidence. The agent gathers facts through the tools; the
evidence store remembers exactly what it observed; the report writer will not
let it claim more than that.

Opening a binary (`/re open /bin/ls`) mounts an always-visible status band
above the editor and runs a full radare2 analysis. What you see immediately
after:

```
ls  ELF64 x86/64 linux  entry 0x6d30  139K
207 fn · 0 findings · 0 evidence
```

`alt+g` opens the function navigator — a filterable, scrollable panel:

```
omp-re: functions
(type to filter)
> sym.imp.__ctype_toupper_loc      0x46f0
  sym.imp.getenv                   0x4700
  sym.imp.sigprocmask              0x4710
  sym.imp.__snprintf_chk           0x4720
  sym.imp.raise                    0x4730
  sym.imp.__mempcpy_chk            0x4740
  ... 201 more rows ...
enter open · type to filter · esc close
```

## Prerequisites

| Requirement | Notes |
| --- | --- |
| `omp` ≥ 17.2.4 | Marketplace-installed extension modules load correctly starting at 17.2.4. |
| `bun` | The runtime `omp` invokes plugin code with; omp ships it as a dependency, but you need it to run this repo's own `bun install`/`bun test` for local development. |
| **radare2 — required** | Absent, `/re open` throws exactly: `omp-re: radare2 not found on PATH — install r2 (https://rada.re) or set OMPRE_R2_PATH`. Both r2 5.x (`offset`) and 6.x (`addr`) JSON field names are handled, so 5.5.0 works. **r2 6.1+ is recommended** — a real decompiler plugin (r2ghidra) can't be built against the older apt-packaged 5.5.0 (see [`docs/install.md`](docs/install.md)). |
| **r2ghidra — optional, strongly recommended** | Without it, `decompile_function` and the code viewer's `d` key fall back to r2's native `pdc` — register-level pseudo-C, not a real decompile. Every such output is prefixed with `(disassembly only — no decompiler plugin available) `. Install with `r2pm -ci r2ghidra`. |
| Optional triage binaries | Each is independently probed on PATH at load time and simply not registered when absent: `capa` → `triage_capa`, `floss` → `triage_floss`, `diec` → `triage_die`, `yara` → `triage_yara`. |

## Install

```bash
omp plugin marketplace add lancejames221b/omp-re
omp plugin install omp-re@unit221b
```

`unit221b` is the *marketplace catalog name* declared inside
`.omp-plugin/marketplace.json` — it is independent of the `lancejames221b`
GitHub owner, so the two identifiers being different is expected, not a typo.

To develop against a local checkout instead of installing as a plugin, point
omp at the extension directory directly:

```yaml
# ~/.omp/agent/config.yml
extensions:
  - /path/to/omp-re/extensions/re
```

TypeScript loads natively through Bun; an edit is picked up on the next omp
start with no build step. Never use a real home directory in this config
(`/path/to/omp-re`, not a machine-specific path).

## First run walkthrough

1. Open a binary: `/re open /bin/ls`. The status band above the editor
   updates immediately (see the transcript above).
2. `alt+g` opens the function navigator; type to filter, `Enter` to open a
   function in the code view.
3. In the code view: `d` toggles decompiled pseudo-C (falls back to plain
   disassembly if no decompiler is available), `x` follows the selected
   xref, `a` hands the current function off to the model with a grounding
   prompt.
4. `alt+s` opens the strings panel the same way.
5. `/re evidence` lists every fact the agent has gathered this session so
   far, keyed by an 8-character id; `/re cite <id>` pulls a specific entry
   into your next chat message.
6. `/re report` writes a Markdown report — see
   [`docs/workflow.md`](docs/workflow.md) for how the evidence chain that
   backs it actually works.

## Command reference

```
/re open <path>      open a binary        alt+g  function navigator
/re functions        function navigator   alt+s  strings
/re strings          string list          in code view:
/re imports          import list             d  toggle decompile
/re evidence [id]    evidence log            x  follow xrefs
/re cite <id>        cite evidence in chat
/re undo             revert annotation       a  ask the model
/re report [path]    write report
/re on               enable RE tools
/re off              disable RE tools (quick toggle, no restart)
```

## Tool reference

All 22 tools — see [`docs/tools.md`](docs/tools.md) for full parameter
tables. Triage tools appear only when their backing binary is on PATH, so
your own tool list may legitimately show fewer than 22.

| Tool | Tier | What it does |
| --- | --- | --- |
| `open_binary` | session-setup | Spawns radare2 on a binary and runs full analysis (`aaa`). |
| `list_functions` | read | List all analyzed functions. |
| `search_functions` | read | Search functions by name substring. |
| `get_function` | read | Get metadata for one function. |
| `decompile_function` | read | Decompile a function (r2ghidra `pdg`, or `pdc` fallback). |
| `disassemble_function` | read | Disassemble a function to raw instructions. |
| `get_xrefs_to` | read | Cross-references pointing at an address. |
| `get_xrefs_from` | read | Cross-references originating from an address. |
| `list_imports` | read | List imported symbols. |
| `list_exports` | read | List exported symbols. |
| `list_strings` | read | List strings, optionally filtered. |
| `list_segments` | read | List memory segments/sections. |
| `hash_binary` | read | SHA-256/SHA-1/MD5 of the binary. |
| `rename_function` | mutate | Rename a function, with read-back verification. |
| `rename_variable` | mutate | Rename a local variable, with read-back verification. |
| `set_comment` | mutate | Set (or clear) a comment at an address. |
| `set_prototype` | mutate | Set a function's C-style signature/prototype. |
| `set_variable_type` | mutate | Set a local variable's C-style type. |
| `triage_capa` | triage | Run capa rules (capabilities, ATT&CK techniques). |
| `triage_floss` | triage | Extract obfuscated strings (FLOSS). |
| `triage_die` | triage | Detect packers/compilers/file types (Detect It Easy). |
| `triage_yara` | triage | Scan with user-supplied YARA rules. |

Every mutate tool follows read → write → read-back → verify, and throws
rather than reporting success when the mutation did not actually land. `/re
undo` reverses the most recently applied annotation.

## Configuration

Three environment variables, all optional:

| Variable | Default | Effect |
| --- | --- | --- |
| `OMPRE_R2_PATH` | `r2` | Path to the radare2 executable. |
| `OMPRE_R2_ANALYSIS_TIMEOUT_MS` | `300000` | Budget for the one-time `aaa` analysis run on open. |
| `OMPRE_AUDIT_HMAC_KEY` | unset | HMAC-SHA256 key for signing audit log lines. Unset → lines are written unsigned plus a one-time warning notification. |

## Known limitations

- **A notify raised from an open panel can render underneath the overlay and
  be invisible.** If pressing `Enter` on a panel row appears to do nothing,
  the row had no target — press `Esc` to close the panel and see the
  message. Full writeup: [`test/QA-FINDINGS.md`](test/QA-FINDINGS.md) §1.
- **No delegatable `re` analyst agent ships** (`agents/` is an empty
  directory). omp does not currently surface extension-registered tools to
  `task`-dispatched subagents, so a packaged agent could not call any RE
  tool.
- **`/re report` withholds the entire report, not just the ungrounded part,**
  when any claim has zero backing evidence ids — see
  [`docs/workflow.md`](docs/workflow.md) for why that's the point, not a bug.
- Historical mutate-tier command-template defects (all fixed as of v0.1.0):
  [`test/QA-FINDINGS.md`](test/QA-FINDINGS.md) §2.
