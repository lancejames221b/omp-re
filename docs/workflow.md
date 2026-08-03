# Workflow

## Triage walkthrough, end to end

Use a binary you're allowed to run commands against without a sandbox — a
system binary like `/bin/ls` is enough to learn the flow.

1. `/re open /bin/ls` — spawns radare2, runs full analysis (`aaa`), and
   populates the status band.
2. `alt+g` (function navigator) or `/re functions` — browse everything r2's
   analysis found. Type to filter.
3. Select a function to open the code view. `d` toggles decompiled pseudo-C;
   `x` follows the selected cross-reference one hop; `a` hands the function
   off to the model with a grounding prompt ("use the RE tools to gather
   evidence first; report only what the evidence supports").
4. `alt+s` / `/re strings` — the string list, same filter-and-open pattern.
5. `/re imports` — imported symbols, useful for a quick capability guess
   before diving into decompilation.
6. If `capa`/`floss`/`diec`/`yara` are on PATH, ask the model to run the
   matching `triage_*` tool for a fast capability/packer read before manual
   analysis.
7. `/re evidence` lists everything gathered so far; `/re cite <id>` pulls a
   specific entry's tool/address/summary into your next chat message so you
   can ask a follow-up about it without retyping context.
8. `/re report [path]` writes a Markdown report. With no path, it prints the
   report directly instead of writing a file.

## How the evidence chain actually works

Every successful call to one of the **12 read-tier tools** —
`list_functions`, `search_functions`, `get_function`, `decompile_function`,
`disassemble_function`, `get_xrefs_to`, `get_xrefs_from`, `list_imports`,
`list_exports`, `list_strings`, `list_segments`, `hash_binary` — is
automatically recorded as a `re.evidence` session entry via a `tool_result`
hook (`extensions/re/evidence.ts`), content-addressed and hashed. Mutations
(`rename_function`, `set_comment`, etc.) similarly record `re.annotation`
entries.

**This is the single most useful thing to know about this suite: work done
outside these tools produces no evidence.** If the model reads a file with
`bash`/`cat`, greps a disassembly dump you pasted in, or reasons from
something it already knew, none of that is backed by an evidence id — and
`/re report`'s write gate is hard: if *any* claim in the built report has
zero evidence ids, the **entire report is withheld**, not just the
ungrounded parts. Headless failure is loud (`console.error` plus a non-zero
exit code), never a silently dropped report. The gate exists so an
ungrounded report never reaches a ticket — a partial, quietly-trimmed report
would be worse than an obvious failure, because it would look complete.

In practice: if you want something in the final report, get it through a
tool call, not a shell command or a paraphrase. `/re evidence` and `/re cite
<id>` exist specifically so the model (and you) can look back at exactly
what was actually observed, in its own words, before writing a claim that
depends on it.

Evidence and annotation entries persist in the session JSONL and survive a
`--continue`/reload, but they are **not** injected into LLM context and are
**not** rendered inline in the transcript — omp's `pi.appendEntry()`
explicitly does not forward custom entries to the model, and there is no
ported adviser rail to render them into. The status band's evidence counter
and the `/re evidence`/`/re cite` panel and command are the only visible
surfaces.

## Related capabilities

**Dynamic analysis.** This suite does not build its own disassembler or
debugger. omp's built-in `debug` tool already provides a real DAP debugger
(`attach` by pid or `host:port`, source/function/instruction/data
breakpoints, `read_memory`/`write_memory`, `disassemble`) — use it directly
for anything dynamic; `omp-re` covers static analysis only.

**Enabling the grounding advisor.** omp's own advisor
(`/advisor configure`, or hand-editing `WATCHDOG.yml`) can run a second
model that reviews whether the analyst's claims are backed by evidence. Add
to your project's or user-level `WATCHDOG.yml`:

```yaml
advisors:
  - name: RE-Grounding
    model: anthropic/claude-opus-5
    tools: [read, grep, glob]
    instructions: |
      Review only whether the analyst's claims are supported by observations made this session.
```

Two constraints:

- **The advisor's model must differ from the RE session's model.** omp has
  no self-review guard — setting both to the same model is silently allowed
  and defeats the point of a second reviewer.
- **The `tools:` grant is restricted to omp's built-in tool names.** This
  suite's own tools (`list_strings`, `decompile_function`, etc.) are
  extension-registered, not built-in, so listing them here does nothing —
  the advisor gets `read`/`grep`/`glob` regardless, which is enough to read
  evidence blobs and session entries directly. Never grant a mutating tool
  to an advisor even experimentally: advisor tool grants bypass the primary
  agent's approval wrapper, so a granted mutating tool would run unprompted.

`WATCHDOG.md` (this repo's root file, if you're dev-loading from a checkout)
carries RE-specific review priorities, but omp only discovers `WATCHDOG.md`
by walking up from your current working directory plus the user agent
dir — never inside an installed plugin's package directory. After
installing as a plugin, copy `WATCHDOG.md` into the project you're actually
reverse-engineering in, or into `<agentDir>/WATCHDOG.md` for a user-wide
default.

**No delegatable `re` analyst agent ships** (`agents/` is an empty
directory) — omp does not currently surface extension-registered tools to
`task`-dispatched subagents, so a packaged agent could not call any RE tool.
