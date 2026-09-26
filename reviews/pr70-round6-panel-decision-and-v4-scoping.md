# PR #70 round 6: panel decision and v4 scoping note

**Date:** 2026-09-26
**Trigger:** 2 new Codex P1 findings surfaced after round 5.5's push, both empirically
reproduced against the branch. Ran through `/pr-review-loop` + the 4-model frontier
panel (Fable 5.1, GPT-6 Astra, Grok 4.6, Gemini 3.1 Pro) per Paul's explicit request.

## Live thread count correction

Paul's framing this round was "there are still 5 comments." A live GraphQL re-fetch
(hard rule 11) found this was not accurate as a live count: all 5 round-5.5 threads are
resolved. There were exactly **2 new, different, unresolved threads**, both created
after round 5.5's push/re-review request — dbId 4110155767 (Finding A) and 4110155771
(Finding B).

## Finding A — fixed this round

`scripts/_common.py`'s `_pr_author_controlled_trigger()` (used by
`authenticate_risk_tier()` to decide the PR-exemption path) trusted
`GITHUB_EVENT_NAME=='pull_request'` with no check that `GITHUB_ACTIONS=='true'` first —
the exact gap round 5.5 (commit `567f558`) already closed in the sibling function
`ci_signing_context()`, just never backported to this second, independent call site.
Empirically reproduced: with `GITHUB_ACTIONS` unset, `GITHUB_EVENT_NAME=pull_request`,
and `AR_SIGNING_REQUIRED=1` set, the function returned `True` and
`authenticate_risk_tier()` took the unsigned-exempt path — an explicit operator demand
for strict signing, silently bypassed by anyone who can set one env var, without ever
touching real GitHub Actions.

Jev's per-comment triage escalated this (raw `jev_action: fix`, conf 0.56, but the
script's fail-closed sensitive-area rule overrode to `escalate` on `severity: critical`)
so it went to the panel rather than being fixed unilaterally, per hard rule 3.

**Fixed.** Gated the GitHub branch on `GITHUB_ACTIONS=='true'`, mirroring the
pre-existing `GITLAB_CI=='true'` gate on the GitLab branch — identical shape to round
5.5's shipped fix. 2 new regression tests added (a direct unit test on the function, and
an end-to-end test proving `AR_SIGNING_REQUIRED=1` + a faked `pull_request` event
without real `GITHUB_ACTIONS` now correctly forces `RISK TIER UNAUTHENTICATED` instead
of `UNSIGNED EXEMPT`). Full suite: 619/619 passing (617 baseline + 2 new).

## Finding B — scoped as a v4 follow-up, not fixed this round

`scripts/aggregate.py`'s `check_rebuttal()` reads `meta['rebuttal_policy']` straight
from `run.json` — an unauthenticated, attacker-writable file in the run directory.
`run.json`'s *other* field `risk` **is** one of the values bound into the cryptographic
signature via `policy_attest_bytes()`, but `rebuttal_policy` is not. Empirically
reproduced: for an identical SENSITIVE run with a high-severity finding, editing only
`run.json`'s `rebuttal_policy` from `contention` to `critical` flips
`check_rebuttal()`'s `required` from `True` (blocked) to `False` (passes) — no other
file touched, signature unaffected.

This is the **3rd independently-discovered instance of the same gap class**. The
round-5.2/5.3 decision packet (`reviews/pr70-round5.2-close-and-signed-payload-decision-
packet.md`) already flagged two siblings — `dev_providers` not bound (dbId 4077803877,
P1) and the absence attestation's `captured_at`/`dev_providers` not bound (dbId
4082681160, P2) — recommending "ship #70 now, treat items 1–3 as a bundled v5(sic)
follow-up" at ~85% confidence. **That recommendation was never explicitly confirmed by
Paul — no closing doc exists**, and "roadmap" has in practice meant "never revisited"
for over a week. (The doc's own "v5" label was a simple off-by-one: `POLICY_ATTEST_
VERSION` is currently the string `"3"`, so the correct next bump is **v4**.)

### Panel result

Ran the full triage → 4-model panel → adjudicate flow (brief enriched twice after the
first triage scored `context_sufficient` low; settled at effort `medium`, stakes
`high`, `needs_panel≈0.85` consistently across all triage passes).

**Adjudicated winner:** `fix_a_now_bundle_b_as_v4_followup` (winner_conf 0.81, nominal
consensus 0.82).

**The nominal consensus overstates how settled this is.** Reading each reviewer's own
text, the real split is closer to even:

| Reviewer | Position | Notes |
|---|---|---|
| Grok (8/10) | Ship #70 now, Finding A fixed; v4 is its own next dedicated round | `production_ready: true` for shipping now |
| Gemini (9/10) | Ship #70 now, Finding A fixed; v4 is its own next dedicated round | `production_ready: true`; only con noted was "slightly conflicts with finish fast" |
| Astra (5/10) | Proposed a *stricter* variant: fix A now, but **hold #70's merge** until v4 is fully implemented and separately reviewed | Rated the "ship now" bucket itself `production_ready: false`; Jev's bucketing folded this into the same named option, inflating the apparent consensus |
| Fable | Do the **full v4 bump in this same round**, before merging anything | Argues shipping v3 with a known, reproduced, publicly-relevant hole and "fixing later" repeats the round-5.2/5.3 pattern where later meant never |

So: 2 of 4 (Grok, Gemini) genuinely support merging #70 now with v4 deferred. Astra
wants v4 done *before* #70 merges. Fable wants v4 done *in* this round. Only Finding
A's fix has true 4/4 agreement.

### What all 4 reviewers agree on regardless of the merge-timing question

1. Fix Finding A now (unanimous, done — see above).
2. Do not leave Finding B undocumented — `docs/THREAT-MODEL.md`'s open-gaps table must
   name it this round regardless of sequencing (**done** — see the table's new rows).
3. Don't put v4 on a vague "roadmap" — write a concrete scoping note now, with a
   specific inventory and a real trigger condition (this document).
4. The eventual v4 design should not bind fields one at a time again (that's *why* this
   is the 3rd instance) — 2 reviewers (Fable, and Jev's `merged_variants` mapping)
   explicitly floated binding a **canonical digest of the whole policy-relevant
   `run.json`** instead of naming each field, closing the entire class at once.

## v4 scope (for whenever Paul schedules the round)

- **Complete field inventory first** — every `run.json` / `policy.absence.json` /
  policy field that can change verdict, rebuttal, waiver, or signer-identity outcome,
  not just the 3 named IDs (dev_providers, rebuttal_policy, absence captured_at/
  dev_providers). Bind all of them, or explicitly document each one left unbound and
  why (fail-closed: an unlisted field found later should read as a bug, not a surprise).
- **Design choice to bring to that round's own panel:** bind named fields one at a time
  (matches the existing `risk`-binding pattern, smaller diff) vs. bind a canonical
  digest of the whole policy-relevant `run.json` (closes the whole class permanently,
  larger design surface). 2 of 4 reviewers this round leaned toward the digest approach.
- **Cost precedent** (the only real data point, not an estimate): the v2→v3 bump
  (commit `3e31f4a`) — which added an entirely new binding source, `ci_signing_context()`
  — touched 3 files for 241 insertions / 32 deletions total, including 5 new regression
  tests, and shipped as its own dedicated round under its own dedicated frontier-gate
  panel run (consensus 0.97). Binding fields that already exist in `run.json` (no new
  data-gathering function needed) is very likely smaller than that.
- **Required alongside the code change:** `POLICY_ATTEST_VERSION` bump to `"4"`,
  tamper-each-field regression tests (mirroring `t_policy_sig_risk_tamper_blocks`),
  `references/schemas.md` + `CHANGELOG.md` updates, and an explicit compatibility note
  for `viaid` (or any other `AR_SIGNING_REQUIRED` adopter) covering any in-flight v3 runs.
- **Also needed regardless of design choice:** a guard test that fails CI if `run.json`
  ever gains a key that is neither in the bound-fields allow-list nor an explicit
  "unbound by design" list — this is what stops a 4th instance from appearing silently.

## Recommendation

My read, after the panel: **fix Finding A now (done), ship #70, and put a real date on
v4** — not Paul's implicit sign-off on another open-ended "roadmap" item. Grok's and
Gemini's position (2 of 4) matches what I originally proposed and remains defensible:
Finding A was the more severe, more easily-triggered bug (a full signing-requirement
bypass) and it's closed; Finding B is real but narrower in blast radius (it only
affects the rebuttal-policy knob on SENSITIVE-tier runs with high/critical findings,
not a wholesale authentication bypass). But Astra's and Fable's objection is not weak:
this is the 3rd time this exact class of gap has been found, and the *previous* time
Paul was told "bundle it as a follow-up," nothing happened for over a week with no
closing decision. Confidence on the sequencing question specifically: ~75%, not above
90% — this is a genuine, defensible split among the panel, not a case where I disagree
with a fringe minority.
