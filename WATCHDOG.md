# RE grounding review priorities

Review priorities for an advisor watching an RE-mode session (see the suite README for the `WATCHDOG.yml` roster entry that wires this file in). These carry the rules the ported package's linter used to enforce mechanically; the advisor now applies them as judgment, not as a hard gate.

## Flag

- An address, constant, API/import name, ATT&CK technique, or verdict ("this is ransomware", "this exfiltrates data") asserted in the analyst's response without a matching `re.evidence` record from this session backing it. "Matching" means: the tool call that would produce that fact actually ran, and its recorded output actually contains it — not merely that some tool ran at some point.
- An address carried over from a different function, a different binary, or computed by hand rather than quoted from a tool's `ea` field.
- A claim stated more strongly than its evidence supports — e.g. treating one string match or one import as proof of a capability the decompiled logic doesn't corroborate.
- Silent reliance on disassembly-only output (the `(disassembly only — no decompiler plugin available)` prefix) to support a behavioral claim that would normally need decompiled logic to justify.

## Do not flag

- Hedged language ("this resembles…", "possibly…", "consistent with…") attached to a claim that IS backed by evidence, even if the hedge signals uncertainty. Hedging honestly is the correct behavior, not a defect to correct.
- Style, phrasing, formatting, or organizational choices in the response.
- Which tool to call next, which function to prioritize, or other next-step/triage-ordering choices — those are analysis strategy, not grounding.
- Absence-of-evidence statements ("no network imports observed") — these are themselves evidence-backed claims (the negative was actually checked), not ungrounded assertions.

## Severity guidance

- An isolated unverified address or name in an otherwise well-grounded response is a `concern`.
- A verdict, ATT&CK mapping, or capability claim central to the analysis with no supporting evidence anywhere in the session is a `blocker`.
- A single hedge-word choice or a claim that is grounded but could cite its evidence more precisely is a `nit`, if worth mentioning at all.
