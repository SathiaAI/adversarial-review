# Threat model — policy-snapshot signing (waiver / NOT_APPLICABLE authorization)

**Status:** batches 1-4 of 4 shipped (frontier-gate run `pr70-architecture-review`, 2026-09-20,
Paul's decision "A — `redesign_signing_boundary`"). Two design questions remain explicitly open
(the cross-job signature hand-off, and approval-gated waivers) — see the status table below, not silently dropped.
**Scope:** the policy-snapshot signature (`policy.snapshot.sig`, `_common.py`'s
`policy_attest_bytes()` / `verify_policy_snapshot_signature()` / `trusted_signer_guard_error()`,
and `panel.py`'s `_sign_policy_snapshot_if_possible()`) — the mechanism that lets `gate.py plan
--waive` and `gate.py record --status NOT_APPLICABLE` proceed. It does **not** cover the separate
`aggregate.py --sign`/`--verify-signature` verdict-attestation feature (E6-S1), which signs the
*result* for audit purposes and carries no self-authorization risk — a PR author gains nothing by
forging their own verdict's audit signature, since the verdict itself is still computed
independently by `aggregate.py` from recorded gate evidence.

## What this mechanism is (and is not)

A policy file (`.adversarial-review.yml`/`.json`) can raise the waiver ceiling above the strict
built-in defaults — e.g. allow a CRITICAL-tier waiver, or extend `max_waiver_days`. Whenever a
policy file is configured, `panel.py init` opportunistically signs the exact policy text it
resolved (`policy.snapshot.json`) — bound, as of batch 3, to: the run's id, a random per-run
nonce, the run directory's own immutable name, the run's resolved risk tier, and the live
CI-orchestrator identity (repository/commit/CI-run-id/CI-run-attempt). Any run that later records
a WAIVED or NOT_APPLICABLE gate must present a signature that verifies against this exact payload,
or `gate.py`/`aggregate.py` BLOCK. A run that never waives anything never touches any of this — the
common path stays completely infrastructure-free.

This is **not** a general code-signing or supply-chain-integrity mechanism. It answers exactly one
question: *did the policy this waiver is judged against actually come from wherever the signer was
configured to trust, unmodified, for this specific run?* It says nothing about whether that trust
was well-placed — that is the adopter's workflow-configuration responsibility, below.

## The attacker

A **same-repository pull request author** (including, for a public repo, a fork PR author) with:
write access to their own branch and its commits; the ability to make the PR's job run whatever
commands the triggered CI job runs (build/test/lint steps, and — before this fix — the
review/signing steps too, if the adopter's workflow ran everything in one `pull_request`-triggered
job); **no** write access to the base branch, repo secrets, or branch protection / required-status
configuration. This is deliberately a weaker attacker than "arbitrary code execution on the CI
runner" — the goal is to stop a PR from **authorizing its own exception**, not to defend against a
fully compromised runner or a maintainer acting in bad faith.

## What batches 1–3 close

| # | Gap (round-1 finding) | Closed by |
|---|---|---|
| 1 | Cosign keyless silently auto-activated whenever `cosign` + identity/issuer were present, contradicting Paul's explicit "not keyless" decision | Batch 1: `AR_ALLOW_KEYLESS` explicit opt-in (commit `6ac59c0`) |
| 2 | A validly-signed run's `policy.snapshot.json`/`.sig` could be copied onto a **different run** — different repository, commit, or CI execution — and still verify, as long as the run directory's own name (and therefore `run_id`/`run_nonce`/risk) was forced to match | Batch 2: `ci_signing_context()` bound into `policy_attest_bytes` v3 — repository/commit/CI-run-id/CI-run-attempt, read fresh from the verifying process's **own** environment, never from a copyable file (commit `3e31f4a`) |
| 3 | Signing was **opportunistic**: any job that happened to have a working signer configured would sign, with no check on *which* job that was — including a `pull_request`-triggered job running alongside the PR author's own code | Batch 3: `AR_TRUSTED_SIGNER` explicit opt-in **and** a refusal when `GITHUB_EVENT_NAME=pull_request` (`trusted_signer_guard_error()`) |

## What remains open after batch 3 — adopter (workflow-configuration) responsibilities

These are guarantees **no library-level code change can make on its own**, because a composite
GitHub Action (`action.yml`) runs entirely as steps inside one calling job — it cannot itself span
two jobs with different permission scopes, secrets, or checkout refs. Closing them requires the
**adopter's own workflow YAML** (or this repo's own example workflows) to define the topology
correctly. `trusted_signer_guard_error()` is a best-effort, defense-in-depth backstop for when this
is misconfigured — it is not a substitute for doing it right:

- **Job separation (checklist item 6).** The trusted signer must run in a job triggered by
  something the PR author cannot cause to execute alongside their own code — `workflow_run`
  (after the untrusted review job completes), a protected `push`, `schedule`, or manual
  `workflow_dispatch` — never `pull_request`. `examples/policy-signer-workflow.yml` sketches what
  such a job's trigger/checkout/secret-scoping looks like, but is explicitly **not** a complete,
  deployment-ready topology — see "the cross-job signature hand-off problem" below.
- **The cross-job signature hand-off problem (unresolved design question, not yet built).**
  `policy_attest_bytes` binds a fresh `run_id`/`run_nonce`/directory-name that each `panel.py init`
  call generates independently. A trusted job's own, separate `panel.py init` call therefore signs
  a policy snapshot for *its own* run directory — not the untrusted review job's run directory,
  which is the one `gate.py plan --waive` actually reads. Getting a trusted signature into the
  correct run directory needs an explicit hand-off mechanism that does not exist yet: candidates
  include cross-workflow artifact passing (`actions/upload-artifact` / `download-artifact` keyed
  off `github.event.workflow_run.id`) or a new CLI entry point that signs a *given*
  `(run_id, run_nonce, risk)` tuple against independently-resolved policy without also creating its
  own run. This is a real architectural decision with tradeoffs of its own — it is being flagged
  here rather than decided unilaterally while writing batch 3, and is recommended for its own
  frontier-gate panel run before implementation, not folded into this checklist item's closure.
- **Pinned execution (checklist items 3, 11).** The trusted job must run `gate.py`/`aggregate.py`
  from a **pinned action ref or tag** (`uses: SathiaAI/adversarial-review@<sha-or-tag>`), never
  from the PR's own checked-out copy of this repo's scripts — a tampered local copy could patch out
  `trusted_signer_guard_error()` itself. This is unenforceable from inside the script being
  executed; it is a property of what the workflow YAML tells the runner to execute.
- **Protected policy resolution (checklist item 15).** The trusted job must resolve
  `.adversarial-review.yml`/`.json` from the **base ref** (or a CODEOWNERS-protected path), not
  from the PR's own branch — otherwise a PR could raise its own waiver ceiling in the same PR that
  uses it. `panel.py init` has no way to tell which ref a given checkout came from; this is enforced
  entirely by which ref the trusted job's `actions/checkout` step names.
- **Secret isolation (checklist item 4).** `AR_SIGNER_CMD`, `AR_MINISIGN_KEY`, and any cosign
  OIDC permission (`id-token: write`) must be set **only** on the trusted job — never on the
  untrusted review job, and never as a repo-wide default available to `pull_request` workflows.
  GitHub Actions **environments** (with required reviewers/protection rules) are the recommended
  mechanism; this is a repo-settings configuration, not something `_common.py` can enforce.
- **Approval-gated waivers (checklist item 10).** Requiring a human approval (a GitHub environment
  reviewer, or a CODEOWNERS-protected waiver file) before a waiver's signature is even attempted is
  a genuinely new feature, not a topology fix — out of scope for batch 3, flagged as a candidate
  follow-up beyond the current four-batch plan rather than silently dropped.

## What `trusted_signer_guard_error()` cannot detect

Documented explicitly so it is never mistaken for more than it is: it inspects only
`AR_TRUSTED_SIGNER` and `GITHUB_EVENT_NAME` in the **current process's own environment**. It cannot
detect: a trusted `workflow_run` job that itself executes a tampered, PR-ref copy of this repo's
scripts instead of a pinned ref (item 3, above); a non-GitHub-Actions CI system with an equivalent
"this job runs alongside untrusted code" trigger it has no concept of (it only recognizes GitHub
Actions' `pull_request`); or an adopter who sets `AR_TRUSTED_SIGNER=1` on a `push` trigger that,
for their specific branch-protection configuration, is *also* reachable by an untrusted contributor
(e.g. a misconfigured "build on push from fork" workflow). It is one deliberately narrow,
easily-testable backstop for the single most common misconfiguration (copy-pasting one job's env
into another), not a general trust-topology verifier.

## Threats → mitigation → status

| Threat | Mitigation | Status |
|---|---|---|
| PR widens its own waiver policy in the same PR, then signs the widened policy | Trusted job resolves policy from the base ref (adopter responsibility) + risk/policy binding in `policy_attest_bytes` (batch 2) | Batch 2 code-level binding shipped; base-ref resolution is adopter-configured |
| A validly-signed run's artifacts replayed onto a different run/commit/repo, directory name forced to match | `ci_signing_context()` in `policy_attest_bytes` v3, read fresh at verify time | **Shipped batch 2** |
| Signing runs opportunistically in whatever job happens to have a signer configured, including an untrusted `pull_request` job | `AR_TRUSTED_SIGNER` opt-in + `GITHUB_EVENT_NAME` refusal | **Shipped batch 3** |
| Cosign keyless auto-activates without an explicit decision to use it | `AR_ALLOW_KEYLESS` opt-in | **Shipped batch 1** |
| Trusted job executes a PR-ref (tampered) copy of the scripts instead of a pinned ref | Pin `uses: …@<sha>` in the trusted workflow | Adopter-configured; unenforceable from inside the script |
| Secrets available to the untrusted review job | GitHub Actions environments / job-scoped secrets | Adopter-configured |
| Waiver signed without any human approval evidence | Not yet built — candidate follow-up beyond the current 4-batch plan | Open |
| A trusted job's signature cannot reach the untrusted review job's own run directory (cross-job hand-off) | Not yet designed — candidate approaches sketched above; needs its own frontier-gate panel run before implementation | Open |

## Batch 4 — adoption/consumer coverage and remaining documentation

Regression tests proving each adoption/consumer attack shape is rejected, mapped to what actually
runs them:

| Scenario (checklist item 19) | Covered by |
|---|---|
| Old-run artifact substitution (matching directory name forced) | `t_policy_sig_directory_identity_forgery_blocks`, `t_policy_sig_replay_from_another_run_blocks`, `t_policy_sig_ci_context_directory_copy_with_matching_name_still_blocked` |
| Cross-run/commit/repository/CI-run/CI-run-attempt replay | `t_policy_sig_ci_context_repository_mismatch_blocks`, `_commit_mismatch_blocks`, `_run_id_mismatch_blocks`, `_run_attempt_mismatch_blocks` (batch 4) |
| Artifact replacement after signing (policy text + risk tier) | `t_policy_sig_coordinated_two_file_tamper_still_blocks`, `t_policy_sig_risk_tamper_blocks` |
| Signature deletion after a waiver was planned | `t_policy_sig_missing_blocks_waiver_run` |
| Relabeling a WAIVED/BLOCKED outcome as PASS in `verdict.json` | `t_sign_verify_detects_relabeled_verdict` (pre-existing, E6-S1) |
| Run-id collision between two independently-created runs | `t_policy_sig_replay_survives_run_id_collision_thanks_to_nonce` |
| Signing attempted from a PR-author-controlled job (same-repo **or** fork — `GITHUB_EVENT_NAME=pull_request` does not distinguish them, and the guard treats them identically on purpose) | `t_trusted_signer_refuses_under_pull_request_event_even_when_opted_in` |
| Signing skipped entirely without the trusted-job opt-in | `t_trusted_signer_unset_skips_signing_even_with_working_signer` |
| Missing signing infrastructure / no policy file at all — ordinary review still passes | `t_policy_sig_no_signer_is_a_note_not_a_failure`, `t_policy_sig_no_policy_at_all_is_exempt`, `t_trusted_signer_guard_never_touched_when_no_policy_file_configured`, and every plain `_complete_sensitive_repo()`-based test in this file (no signer configured at all) |
| Signing succeeds from a legitimately trusted trigger + opt-in | `t_trusted_signer_opted_in_from_trusted_trigger_signs_normally`, `t_policy_sig_ci_context_consistent_real_ci_env_still_passes` |

Three items from checklist item 19 are **not** Python-testable — they depend on GitHub's own
platform behavior (check-run publishing, branch-protection matching, merge-queue semantics), not
on anything this repo's scripts compute. Documented here instead of faked as a unit test:

### Forged same-name status check (checklist item 11)

A PR job could attempt to post its own check run or commit status using the **same name** as the
real "adversarial-review" required check, to trick branch protection into treating a forged PASS
as the real one. This repo's scripts never publish a GitHub check themselves — that is the
workflow's `permissions:`/`checks: write` scope and GitHub's own required-status-check matching
(by exact job name **and** the workflow file that produced it). Adopter responsibility:

- The trusted job that runs `aggregate.py` should be the **only** job with `checks: write` (or
  `statuses: write`) permission targeting the required check's name; the untrusted review job
  should have `checks: read`/none.
- Configure the branch protection rule's required check against the **trusted job's** check name,
  not a name any `pull_request`-triggered job could also produce.
- A `pull_request`-triggered job's default `GITHUB_TOKEN` is read-only for a fork PR (GitHub
  enforces this platform-side) — but for a **same-repo** (non-fork) PR it is read-write by default
  unless the repository's Actions settings restrict it. Explicitly set
  `permissions: { contents: read }` (no `checks:`/`statuses:` write) on the untrusted review job
  regardless of fork status, rather than relying on GitHub's fork-vs-same-repo default.

### Merge queues and `pull_request_target` (not definitively characterized here)

Two GitHub Actions triggers have trust semantics this document does not assert a definitive answer
for, because they are configuration-dependent in ways `trusted_signer_guard_error()` cannot inspect:

- **`merge_group`** (merge-queue entries): runs against a synthetic merge commit of the PR into the
  target branch. Whether this should be treated as "trusted" depends on the queue's own
  configuration (which required checks gate queue entry) — this repo's guard does **not**
  currently refuse `merge_group`, which means a repo relying on a merge queue as its *only*
  protection before the trusted signer job runs should verify independently that queue entry
  itself requires the untrusted review job to have already passed. Flagged as unverified rather
  than silently assumed safe.
- **`pull_request_target`**: runs with the **base** repository's context and secrets by default,
  and by default checks out the **base** ref, not the PR head — safe in that default form. It
  becomes exactly as dangerous as `pull_request` the moment a workflow overrides
  `actions/checkout`'s `ref:` to the PR's head SHA, which is a common (and commonly
  security-relevant) pattern for workflows that need to test PR code with secrets available. This
  repo's guard does **not** refuse `pull_request_target` — doing so would break the safe, default
  usage. **Never use `pull_request_target` with a PR-head checkout for the trusted signer job.**

### Secret storage, required-check configuration, key rotation/revocation

- **Secret storage.** Store `AR_SIGNER_CMD`'s underlying key material (a minisign secret key file,
  or nothing at all for cosign keyless/OIDC) as a GitHub Actions **environment** secret scoped to
  the trusted job's environment (`environment: policy-signer` with required reviewers, or at
  minimum a repository secret never referenced by the untrusted review job's workflow file). Never
  a repository-wide secret referenced from both jobs' workflow files — that reintroduces the
  opportunistic-signing gap batch 3 closes at the code level, but at the credential-scoping level
  instead.
- **Required-check configuration.** Branch protection must require the check produced by the
  **trusted** job (or a job downstream of it), not the untrusted review job's own check — otherwise
  a repo could pass its required check without ever running the trusted signer at all on a run that
  needs one.
- **Key rotation/revocation.** Rotating `AR_SIGNER_CMD`'s key (or a minisign key pair) does not
  need to invalidate already-completed runs' signatures — `policy.snapshot.sig` is checked only at
  `gate.py plan --waive`/`record --status NOT_APPLICABLE` and `aggregate.py` time for that specific
  run, not re-verified later. A rotated key simply means: (1) update the verifier-side
  configuration (`AR_VERIFIER_CMD`/`AR_MINISIGN_PUBKEY`) everywhere it is read, atomically with the
  signer-side update, so an in-flight run signed under the old key still verifies against the old
  public key during its own lifetime, never a mixed state where the same run is checked against
  two different keys at different times; (2) revoking a compromised key means rotating it — there
  is no separate revocation list or expiry mechanism today, so a key believed compromised must be
  rotated immediately and any run signed after the suspected compromise treated as untrusted by the
  operator, manually, since nothing here can retroactively invalidate a signature that still
  verifies under the (compromised) key it was made with.
