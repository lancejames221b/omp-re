# Tool reference

All 22 `omp-re` tools, grouped by tier. Triage tools register only when their
backing binary is on PATH at load time, so your own tool list may legitimately
show fewer than 22.

Every tool follows omp's standard `ToolDefinition` shape: `approval` gates
whether omp prompts before running it (`tools.approvalMode` /
`tools.approval.<name>` in your omp config), and every read-tier tool call
also becomes a `re.evidence` entry — see [`workflow.md`](workflow.md).

## Session-setup (1 tool)

| Tool | Approval | Parameters | What it does |
| --- | --- | --- | --- |
| `open_binary` | `read` | `path: string` | Spawns radare2 on a binary and runs full analysis (`aaa`). Every other RE tool acts on whichever binary was most recently opened — call this first in a delegated/subagent session that has no `--binary` flag or `/re open` command available. |

## Read tier (12 tools)

Every read-tier call that succeeds is recorded as a `re.evidence` entry.

| Tool | Approval | Parameters | What it does |
| --- | --- | --- | --- |
| `list_functions` | `read` | `offset?, limit?` | List all functions detected in the open binary. |
| `search_functions` | `read` | `query, offset?, limit?` | Search functions by substring match on name. |
| `get_function` | `read` | `target` (name or address) | Get detailed info for a single function. |
| `decompile_function` | `read` | `addr` (address or name) | Decompile to pseudo-C, preferring a real decompiler plugin (r2ghidra `pdg` / r2dec `pdd`); falls back to r2's native `pdc` and flags the fallback in the output. |
| `disassemble_function` | `read` | `addr` | Disassemble to annotated instructions (comments, flags/labels, xrefs folded in where r2 reports them). |
| `get_xrefs_to` | `read` | `addr, offset?, limit?` | Cross-references pointing at an address. |
| `get_xrefs_from` | `read` | `addr, offset?, limit?` | Cross-references originating from an address. |
| `list_imports` | `read` | `offset?, limit?` | List imported symbols. |
| `list_exports` | `read` | `offset?, limit?` | List exported symbols. |
| `list_strings` | `read` | `offset?, limit?, filter?` | List strings, optionally filtered by substring. |
| `list_segments` | `read` | `offset?, limit?` | List memory segments/sections. |
| `hash_binary` | `read` | (none) | SHA-256, SHA-1, and MD5 digests of the session's bound binary. |

`offset`/`limit` default to 0/200 and cap at 1000; every paginated result
reports its total so the model knows a view is partial.

## Mutate tier (5 tools)

Every mutate tool follows read-old → write → read-back → verify: it throws
rather than reporting success when the requested mutation did not actually
land against real radare2. `/re undo` reverses the most recently applied
annotation, tool by tool, in the same way.

| Tool | Approval | Parameters | What it does |
| --- | --- | --- | --- |
| `rename_function` | `write` | `addr, new` | Rename a function. |
| `rename_variable` | `write` | `addr, old, new` | Rename a local variable within a function. |
| `set_comment` | `write` | `addr, text` (empty clears) | Set or clear a comment at an address. Calling it twice at the same address replaces the comment rather than appending. |
| `set_prototype` | `write` | `addr, sig` | Set a function's C-style signature/prototype. |
| `set_variable_type` | `write` | `addr, var, type` | Set a local variable's C-style type. |

## Triage tier (up to 4 tools, conditional on PATH)

Each takes no session-specific parameters beyond what's listed; all run
against the currently open binary.

| Tool | Approval | Requires on PATH | Parameters | What it does |
| --- | --- | --- | --- | --- |
| `triage_capa` | `exec` | `capa` | (none) | Run capa rules to detect capabilities and ATT&CK techniques. |
| `triage_floss` | `exec` | `floss` | (none) | Extract obfuscated strings (stack, decoded, static) via FLOSS. |
| `triage_die` | `exec` | `diec` | (none) | Detect packers, compilers, and file types via Detect It Easy. |
| `triage_yara` | `exec` | `yara` | `rules_path` (required — no default ruleset ships) | Scan the binary with user-supplied YARA rules. |

For `triage_capa`/`triage_floss`/`triage_die`, a non-zero exit code with
non-empty stdout is treated as "the tool ran and reported zero findings",
matching how capa signals "no matches". A non-zero exit with *empty* stdout
is treated as a real failure and throws, so a tool that never ran doesn't
read as a false all-clear.
