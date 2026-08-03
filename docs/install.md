# Install

## radare2

**radare2 6.1+ is recommended.** `omp-re` accepts both r2 5.x (`offset`) and
r2 6.x (`addr`) JSON field names via `addrOf()`, so 5.5.0 technically works
for the read/mutate tools — but a real decompiler plugin (r2ghidra) cannot
be built against it, which matters for `decompile_function` and the code
viewer's `d` key (see the next section).

### Ubuntu / Debian

Ubuntu 24.04's `apt` package is radare2 5.5.0 — usable, but see the r2ghidra
warning below before relying on it for decompilation:

```bash
sudo apt install radare2
```

For 6.1+, install from the upstream `.deb` on the
[radare2 GitHub releases page](https://github.com/radareorg/radare2/releases)
instead of `apt`.

### macOS

```bash
brew install radare2
```

Homebrew tracks upstream releases, so this gets you a current 6.x build
directly.

### Verify

```bash
r2 -v
```

## r2ghidra (optional, strongly recommended)

Without it, `decompile_function` and the code viewer's `d` key fall back to
r2's native `pdc` — register-level pseudo-C (`rsp -= 0x28`-style output), not
a real decompile. Every such fallback output is prefixed with
`(disassembly only — no decompiler plugin available) ` so it's never
mistaken for the real thing.

```bash
r2pm -ci r2ghidra
```

**The trap this project hit for real:** Ubuntu 24.04's apt-packaged radare2
(5.5.0) cannot build r2ghidra — the build fails with errors like
`RAnal has no member named 'config'`, `RFlagItem has no member named 'addr'`,
and `R_VEC_FOREACH was not declared`, because r2ghidra's build targets r2's
current internal API and 5.5.0 predates it. `r2pm -ci r2dec` (the other
common decompiler plugin) fails differently, on a missing `sdb.h`. Neither
failure is a network/environment fluke — they're a real API mismatch against
an old radare2. **The working path is radare2 6.1.8+** (the upstream `.deb`
or Homebrew build above), then `r2pm -ci r2ghidra` against that.

### Verify

```bash
r2 -qc 'aaa; s main; pdg' /bin/ls
```

Expected shape: a typed C function signature with named locals — something
like `int main(int argc, char **argv) { ... }` with real variable names and
types, not `rsp -= 0x28` / raw register arithmetic. If you see the latter,
r2ghidra isn't actually loaded; `pdg` silently falls back to disassembly
comments in some r2 builds instead of erroring, so check the output shape,
not just the exit code.

## Optional triage binaries

Each is independently probed on PATH when the plugin loads, and its tool is
simply not registered if the binary is absent — no configuration needed
either way.

| Binary | Tool | Install |
| --- | --- | --- |
| `capa` | `triage_capa` | See [capa's releases](https://github.com/mandiant/capa/releases). |
| `floss` | `triage_floss` | See [FLOSS's releases](https://github.com/mandiant/flare-floss/releases). |
| `diec` | `triage_die` | See [Detect It Easy's releases](https://github.com/horsicq/Detect-It-Easy/releases) — the CLI binary is named `diec`, not `die`. |
| `yara` | `triage_yara` | `apt install yara` / `brew install yara`. No default ruleset ships; `triage_yara` requires an explicit `rules_path`. |

## Installing omp-re itself

```bash
omp plugin marketplace add lancejames221b/omp-re
omp plugin install omp-re@unit221b
```

See the [README](../README.md#install) for the dev-load alternative and the
marketplace-name-vs-GitHub-owner distinction.

## Verify the full stack

```bash
r2 -v                                   # radare2 present, ideally 6.1+
r2 -qc 'aaa; s main; pdg' /bin/ls       # r2ghidra actually producing typed pseudo-C
omp plugin list                         # omp-re installed
```

Then inside omp: `/re open /bin/ls`, `alt+g`, open a function, press `d`. If
the decompiled output does not start with the disassembly-only prefix, the
full stack is working.
