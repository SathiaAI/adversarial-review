# Security policy

## Supported versions

The `main` branch. There are no maintained release branches; fixes land on `main` and
are tagged.

## Reporting a vulnerability

Please report privately first:

1. **Preferred:** GitHub private vulnerability reporting — *Security → Report a
   vulnerability* on this repository, if enabled.
2. **Fallback:** email the maintainer at `pjpoulose@gmail.com` with `[adversarial-review
   security]` in the subject.

Best-effort acknowledgment within 7 days. There is no bug bounty; credit in the fix and
release notes is offered gladly.

## What is in scope — and especially welcome

This project's security surface is unusual: it is a *review pipeline for untrusted
code*, so the most valuable reports are the ones that subvert the review itself.

- **Prompt-injection bypasses.** Repository content shown to reviewers is wrapped in
  per-run randomized untrusted-data boundaries (`references/roles.md`). If you can craft
  diff content that makes a reviewer follow embedded instructions, suppress findings, or
  misreport — that is a vulnerability here, not a curiosity.
- **Aggregator bypasses.** Any artifact arrangement that makes `scripts/aggregate.py`
  emit PASS when the recorded facts should yield FAIL or BLOCKED (forged validation
  records the checks accept, independence-check evasion, suppression-expiry tricks).
- **Independence-computation evasion.** Model-slug or family-alias patterns that let a
  development-family model onto the panel undetected.
- **Secret handling.** Any path by which keys or `.env` content could enter run
  artifacts, reviewer prompts, or reports.

Out of scope: vulnerabilities in the model providers or routers themselves, findings
requiring a compromised local machine, and the inherent limitation that no client-side
tool can force a remote transport to deliver a prompt intact (that failure mode is
detected downstream by local validation, by design).

## Disclosure

Please allow a fix to land before public disclosure. Since successful attacks on this
tool would show up as *quietly green verdicts* for other users, coordinated disclosure
matters more than usual.
