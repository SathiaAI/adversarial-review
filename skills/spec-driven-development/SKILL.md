---
name: spec-driven-development
description: Write the spec before the code, make the spec the contract, and loop until the implementation is verified against it. Use before starting any non-trivial change in this repo.
---

# Spec-driven development

The spec comes first. Code is what you write *to satisfy* a spec, not the thing you
reverse-engineer a spec from afterward.

## The loop
1. **Locate the source of truth.** In this repo that is `roadmap/engineering-roadmap.md`
   (a project planning doc) plus the global **Definition of Done** in its §3. The story's
   acceptance criteria + the DoD are the contract. If they conflict with a handoff, the
   roadmap/DoD win; if a paste declares itself scope authority, it wins over both.
2. **Write the spec down before touching code.** Restate the acceptance criteria in your
   own words, list the concrete decisions you will make, name the files you will touch, and
   enumerate the tests that will prove each criterion. Surface every decision as a question
   a skeptic could attack — do not bury a choice as an assumption.
3. **Get the spec reviewed before building** when the change is sensitive (auth, transport,
   the verdict/attestation path). A frontier decision panel or a second reviewer on the
   *spec* is cheaper than one on the *diff*. Record the decisions and dissent durably
   (a `reviews/*.md` doc), not just in chat.
4. **Build the minimum that satisfies the spec.** Nothing speculative. Touch only what the
   spec requires. If the change grows, split it and note the split — do not silently expand.
5. **Verify against the spec, and loop.** Define the success criteria as pass/fail
   (matrix green on 3.9 + 3.12, every criterion has a test, invariants intact) and loop
   until they all hold. "It runs" is not "it is verified."

## Invariants this repo's specs must never trade away
- Zero runtime dependencies (stdlib only in `scripts/*.py`).
- Python 3.9+ (no 3.10+ syntax — a repeat regression).
- The verdict is computed by `aggregate.py` alone; no path lets a model or human override it.
- Audit-record determinism (same run dir in → same attestation out).

## Done means
Every acceptance criterion is met, its tests are green on the full matrix, the DoD holds,
the docs shipped in the same change, and the change passed adversarial-review at its tier.
A checkbox is checked only when its criteria are met *and* its tests pass — never on intent.
