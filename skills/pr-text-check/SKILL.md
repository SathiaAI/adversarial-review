---
name: pr-text-check
description: Make the PR description, commit messages, and CHANGELOG match what actually changed — no drift, honest status, docs in the same change. Use before opening or updating a PR.
---

# PR text check

The prose around a change (its PR body, commit messages, and changelog entry) is part of the
deliverable. It is read far more often than the diff, so it must be *true to the diff*.

## Before opening or updating a PR, verify:
1. **The description matches the diff.** Every claim in the PR body corresponds to an actual
   change; every non-trivial change is described. Read the final diff and reconcile it line
   by claim — do not describe what you intended, describe what shipped.
2. **The CHANGELOG is updated in the same PR.** Add an entry under `## [Unreleased]` for any
   user-visible change (this repo's DoD requires it). Do not hardcode counts that will drift
   (reviewer counts, "N scenarios") — those are a repeat bug; assert them from code instead.
   The `pyproject` version and the newest *released* heading must agree (a test enforces it).
3. **Docs shipped with the code.** Enumerate every affected `SKILL.md`, `README*`, `references/*.md`,
   and `docs/` file, and check claim-by-claim that each reflects the behavior change *in this PR*, not a
   follow-up. A sensitive surface ships its committed threat model and its review verdict in the same PR.
4. **Status is honest.** Say what is done, what is deferred, and what is BLOCKED/unknown —
   never round a partial up to done, never a BLOCKED (e.g. a permission gap) up to a pass.
   Name residual risks explicitly; a documented residual is honest, a hidden one is a defect.
5. **No scope drift in the text.** If the change grew beyond its story, the PR says so and the
   growth is split out or justified — the text never quietly redefines the scope.
6. **No secrets in the text.** No tokens, keys, or credential values in the body, commits,
   or the changelog. Attribution/footers follow the repo's convention.
7. **Commit messages are self-contained.** Subject in the imperative; body says *why*, not just *what*.
   Push a keepable commit the same turn — but only where you have explicit authorization to push (a
   non-negotiable in this repo; see `AGENTS.md`); otherwise hand the commit to whoever merges.

## The test
Hand the PR text to someone who has not seen the diff. If they would be surprised by anything
in the diff, or misled about what is done, the text fails — fix the text, not the reader.
