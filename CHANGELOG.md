# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [0.1.0] - 2026-08-03

Initial public release.

### Added

- `/re cite <id>` — pulls a specific `/re evidence` entry into the editor as
  a prefilled chat message (`Re: evidence <id> (<tool> @ <addr>)` plus its
  summary), so a picked row's detail can actually be handed to the model
  instead of only rendering underneath the still-open evidence panel.
- Public docs: `docs/install.md`, `docs/workflow.md`, `docs/tools.md`,
  `docs/testing.md`, `CONTRIBUTING.md`, `SECURITY.md`.
- `.github/workflows/ci.yml` — `check` (typecheck) and `test` (unit tests)
  jobs on every push/PR.
- `LICENSE` (MIT).

### Fixed

- `rename_variable` and `set_variable_type` sent a bare `${addr}` as a
  trailing positional token to r2's `afvn`/`afvt`, which don't take an
  address argument at all; both tools threw `mutation did not land` on
  every input. Fixed to use r2's `@ addr` temporary-seek syntax. The
  identical defect in `/re undo`'s `rename_variable`/`set_variable_type`
  branches — found while verifying this fix — is fixed the same way; those
  branches previously reported success while silently reverting nothing.
- `set_prototype` sent `af ${sig} ${addr}` — `af` renames a function, it
  does not set a signature. Fixed to use `afs ${sig} @ ${addr}` (both the
  forward tool and `/re undo`'s branch). r2's `afij` read-back always
  re-punctuates a stored signature (adds a space before `(`, appends a
  trailing `;`); the tool now normalizes both sides of the comparison
  before checking they match, so it tolerates r2's own cosmetic
  reformatting without weakening the check — a genuinely different
  signature still fails loudly. The forward tool also now strips that
  trailing `;` from the captured old signature before storing it, so a
  later `/re undo` doesn't trip the `sig` validator's forbidden-character
  check on a semicolon r2 itself appended.
- `set_comment` used plain `CC ${text} @ ${addr}`, and r2's `CC` **appends**
  to an existing comment rather than replacing it, so a second call at the
  same address always failed its own read-back. Fixed to clear first
  (`CC- @ ${addr}`) before writing, in both the forward tool and `/re
  undo`'s branch, making both idempotent.

All four defects (and their `/re undo` counterparts) are verified fixed
against real radare2 6.1.8. All 5 mutate-tier tools and all 5 `/re undo`
branches now work end to end; the advertised tool count stays at 22. See
[`test/QA-FINDINGS.md`](test/QA-FINDINGS.md) §2 for the historical record
and [`test/tools-mutate-registry.test.ts`](test/tools-mutate-registry.test.ts)
for the regression coverage.

### Changed

- `test/tui-qa.sh` gained 3 assertions for `/re cite` (bare usage, unknown
  id, and prefill-into-editor); the suite's assertion-count drift guard
  moved from 96 to 99.
