---
name: shipping-artifacts
description: Every claim ships with the artifact that proves it — test output, a run dir, an attestation, a review verdict. Use when finishing a change or asserting that something works.
---

# Shipping artifacts

A claim without an artifact a skeptic would accept is an opinion. This project's whole
premise is "is this change correct?" answered with *evidence*, not model self-assurance — so
hold yourself to the same bar.

## The rule
When you assert something is done, correct, safe, or passing, attach the artifact that lets
someone else confirm it **without rerunning your reasoning**:

| Claim | Artifact that ships with it |
|---|---|
| "Tests pass" | The suite's `N passed, M failed` line, and — for a change that could regress others — the byte-identical fail-set vs the base branch (prove the deltas are yours or nobody's). |
| "No regressions" | A baseline run of the *unchanged* base plus your run; a diff of the two fail-sets. |
| "The verdict is X" | The run dir under `.adversarial-review/` — the immutable audit record — and the `aggregate.py`-computed `verdict.json`, never a hand-authored verdict. |
| "It's tamper-evident" | The `compute_attestation()` digest (and a detached signature when `--sign` is used). |
| "It was reviewed" | The adversarial-review run's verdict, attached to the PR, at the stated tier. |
| "A behavior holds" | An offline test that asserts the *observable outcome and the failure path*, not a mocked success. |

## Discipline
- **Determinism.** An artifact you cite must be reproducible: same inputs → same artifact.
  No `Date.now`, unsorted iteration, or unrecorded RNG in anything recorded.
- **No secrets in artifacts.** Keys never land in run dirs, tests, logs, or docs.
- **Honest status.** If a check could not run (a missing permission, an unavailable binary),
  the artifact records **BLOCKED / unknown** — never a faked pass. A BLOCKED verdict from an
  honest gap is a correct artifact; a green one you can't back is a lie that outlives you.
- **The sandbox is not storage.** A build environment can vanish, so don't let keepable work live only
  in a scratch dir. But **push only when you have explicit authorization to push** — this repo makes that
  non-negotiable (see `AGENTS.md`). Where you may push, do it the same turn you commit; where you may not,
  keep the work safe another way (a durable clone, a patch) and hand the commit to whoever merges. The
  durable artifact is the recorded commit, not the scratch copy.

## Anti-pattern
"I ran it and it looked fine." Ship the output, the run id, the diff, or the verdict — the
thing the next person opens instead of trusting you.
