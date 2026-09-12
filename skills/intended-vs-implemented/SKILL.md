---
name: intended-vs-implemented
description: Verify what the code actually does against what the docs, roadmap, or handoff claim it does — the code is the source of truth. Use before relying on any documented behavior or status.
---

# Intended vs. implemented

Documentation describes intent. Code describes reality. When they disagree, **the code wins**,
and the disagreement is itself a finding worth surfacing.

## Why this matters here
A roadmap, a handoff, a changelog, or a prior review report can confidently assert that a
behavior shipped when it did not — a merge dropped it, a fix was described but implemented
differently, or a status was aspirational. Building on the *claim* instead of the *code*
propagates the error into your own work.

> Worked example (real, this repo): the roadmap stated E3-S2b landed a `do_POST` slow-loris
> **read-timeout**. Checking the code on `main` — no `settimeout` on the POST read, no `408`,
> no handler `timeout` — and `git log -S '408' -- scripts/mcp_server.py` (empty) proved it
> **never landed**. Not a regression (nothing was lost); an overstated status. The fix was
> then correctly scoped into the story that actually owns it, and the discrepancy recorded.

## The check
1. **Read the claim** (roadmap status, changelog line, handoff, a "DONE" checkbox).
2. **Read the code that would implement it** — the actual function, the actual test, the
   actual workflow. Not a summary of it; the lines.
3. **Prove presence or absence within a defined scope.** Search the relevant source *and* generated
   artifacts (`grep`/pickaxe `git log -S`, run the test, inspect the output). An empty result is evidence
   only for the scope you searched — generated files, dynamic registration, aliases, and excluded paths
   can still hold the implementation — so record it as **inconclusive** when those remain possible, not
   as proof of global absence.
4. **When they disagree, the code is authoritative.** Update your plan to reality, and record
   the discrepancy (in the PR, the changelog, or a decision note) — do not silently "fix" the
   doc to match a reality you assumed, and do not silently build on the false claim.

## Applies to your own output too
"[stated]" means someone said it, not that it is true. Your own tool output — a file's
contents, a command's exit code — is what *is*, and it can contradict what you were told.
Trust the primary source over the narrative every time, including when the narrative is yours.
