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
built-in defaults — e.g. allow a CRITICAL-tier waiver, or extend `max_waiver_days`. As of batch 3,
signing is never opportunistic merely because a policy file is configured and a working signer
happens to be available: a designated trusted job must explicitly set `AR_TRUSTED_SIGNER=1`
(`trusted_signer_guard_error()`) before `panel.py init` will attempt to sign anything. Only once
that opt-in is set does `panel.py init` sign the exact policy text it resolved
(`policy.snapshot.json`) — bound, as of batch 3, to: the run's id, a random per-run
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

### Cryptographic CI-identity pinning for cosign keyless (post-batch-3 hardening)

`AR_ALLOW_KEYLESS=1` alone does not make keyless verification safe: Sigstore Fulcio issues
short-lived certificates to *any* OIDC-authenticated signer, so `cosign verify-blob` also needs a
`--certificate-identity`/`--certificate-oidc-issuer` (or `-regexp`) pin — without one, verification
would accept a signature from any keyless signer on the internet, not just this repository's own
CI, which would silently defeat the point of signing at all. Explicit operator configuration
(`AR_COSIGN_IDENTITY` + `AR_COSIGN_ISSUER`) always wins when both are set — this is unchanged.
When running under GitHub Actions (`GITHUB_REPOSITORY` set) with **neither** configured,
`_auto_github_cosign_identity()` now derives an **anchored** identity regexp scoped to that exact
repository (`^https://github\.com/<owner>/<repo>/`) paired with the GitHub Actions OIDC issuer
(`https://token.actions.githubusercontent.com`), so the common case is pinned to this repo's own
CI by default rather than left unpinned. Anchoring (`^...` with the repository name regex-escaped)
is deliberate: an unanchored substring match would let `SathiaAI/adversarial-review-evil-fork`, or
any repo whose name merely *contains* the trusted one, also pass. **Partial** explicit
configuration (exactly one of `AR_COSIGN_IDENTITY`/`AR_COSIGN_ISSUER` set) never falls back to
auto-derivation and never mixes an operator-set value with an auto-derived one — that would
silently narrow or drop half of an operator's intended pin. It is instead treated as "no usable
cosign-keyless config," and resolution falls through to minisign or `no verifier available`, same
as before this change. GitLab CI has an equivalent OIDC identity
(`CI_SERVER_URL`/`CI_PROJECT_PATH` via its own token issuer) that is deliberately **not**
auto-derived here — kept out to keep this a PR-sized, single-platform hardening. GitLab keyless
users still need to set `AR_COSIGN_IDENTITY`/`AR_COSIGN_ISSUER` explicitly; flagged here as an open
item, not silently dropped.

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

## What CI-identity signals do and do not prove (checklist items 9-13, frontier-gate run
pr70-round8-riskauth, 2026-09-26, panel consensus 0.97 — documentation only, no code
behavior change)

`ci_signing_context()`, `_ci_identity_established()`, and `_pr_author_controlled_trigger()`
all read the same handful of environment variables: `GITHUB_ACTIONS`, `GITHUB_REPOSITORY`,
`GITHUB_SHA`, `GITHUB_RUN_ID`, `GITHUB_RUN_ATTEMPT`, `GITHUB_EVENT_NAME`, `GITLAB_CI`,
`CI_PROJECT_PATH`, `CI_COMMIT_SHA`, `CI_PIPELINE_ID`, `CI_PIPELINE_SOURCE`. Every one of
these is **self-reported by the process's own environment** — nothing in this codebase
calls out to GitHub's or GitLab's own API, or verifies an OIDC identity token issued by
their platform, to independently confirm the job is actually executing on their
infrastructure. A local shell, a self-hosted runner, a container someone builds by hand, or
any other process can set `GITHUB_ACTIONS=true` plus plausible-looking values for the rest,
and every one of the checks above would accept them at face value. Naming this predicate
`_ci_identity_established` (and the escape-hatch flag `AR_ALLOW_LOCAL_CI_IDENTITY`) risks
reading as "this proves you are really inside GitHub/GitLab's infrastructure" — it does not,
and never has.

What these signals **do** provide: replay-binding entropy, conditioned on the *verifying*
process's own environment being trustworthy. `policy_attest_bytes` v3 binds
repository/commit/CI-run-id/CI-run-attempt fresh from that process's own environment (never
from a copyable file), so a validly-signed run's artifacts cannot be replayed onto a
different run/commit/repository as long as the values the verifier reads for that
comparison are themselves genuine — the same self-reported-variable limitation just
described above applies just as much at verify time as at sign time. An attacker who
controls the *verifying* process's own environment (not merely the signing one) could feed
it the original run's values and defeat this replay check the same way; this mechanism
protects against replay onto a run whose OWN verifying environment is honest, not against a
verifier that has itself been compromised or run outside the topology described in
"adopter (workflow-configuration) responsibilities" above. `_ci_identity_established()` exists purely so that two
independently unidentified environments (two laptops, or a laptop and an unrecognized
third-party CI system) — which would otherwise compute byte-for-byte identical "local"
placeholders and provide *no* actual distinction — are told apart from a genuine
recognized-provider run, where the four fields carry real (if self-reported) per-run
entropy. That is a **cross-run distinguishability** guarantee, never a **platform
authentication** guarantee. Read every occurrence of "CI-provided identity" / "CI identity
is established" in this codebase's docstrings and error strings with that scope in mind:
"a value distinct enough to bind a signature to one specific run" — never "verified proof
this is really CI infrastructure."

Where the actual, load-bearing trust boundary lives instead (see "adopter
(workflow-configuration) responsibilities" above, restated here because it is the direct
answer to "then what stops someone from just setting these env vars themselves?"): (a) the
trusted signer's own secret (`AR_SIGNER_CMD`'s key material, `AR_MINISIGN_KEY`, or a cosign
OIDC token) never being available to a job an untrusted contributor's code can reach —
that's a property of the adopter's own workflow YAML and platform-level job/environment
secret scoping, not of anything this codebase reads from the run directory; and (b) which
job, with which permissions, a workflow file tells the runner to execute for the *signing*
step — `trusted_signer_guard_error()` is a narrow, best-effort backstop for one common
misconfiguration of this (see above), not a substitute for it. An attacker who can forge
`GITHUB_ACTIONS=true` on their own laptop still cannot produce a valid signature without the
signer's actual secret, which this whole CI-identity mechanism was never the thing
protecting in the first place.

A real fix for "prove this process is genuinely executing inside GitHub Actions/GitLab CI
infrastructure" exists and is well-understood — verifying the platform's own OIDC identity
token (the same class of mechanism cosign keyless already leans on for signer identity,
"Cryptographic CI-identity pinning" above) against that platform's OIDC issuer, rather than
trusting self-reported environment variables at all. This is a genuinely new feature, not a
wording fix, and building it now would force every adopter without an OIDC-capable CI
provider (in particular every minisign-only or plain-`AR_SIGNER_CMD` setup) into
`AR_ALLOW_LOCAL_CI_IDENTITY=1` permanently just to keep working — a worse regression than
the gap it would close. The round-8 frontier panel's explicit decision was: document this
scope honestly now (this section), build the OIDC-based attestation later as its own,
separately-evaluated feature. **Open, tracked** — not silently dropped.

## Threats → mitigation → status

| Threat | Mitigation | Status |
|---|---|---|
| PR widens its own waiver policy in the same PR, then signs the widened policy | Trusted job resolves policy from the base ref (adopter responsibility) + risk/policy binding in `policy_attest_bytes` (batch 2) | Batch 2 code-level binding shipped; base-ref resolution is adopter-configured |
| A validly-signed run's artifacts replayed onto a different run/commit/repo, directory name forced to match | `ci_signing_context()` in `policy_attest_bytes` v3, read fresh at verify time | **Shipped batch 2** |
| Signing runs opportunistically in whatever job happens to have a signer configured, including an untrusted `pull_request` job | `AR_TRUSTED_SIGNER` opt-in + `GITHUB_EVENT_NAME` refusal | **Shipped batch 3** |
| Cosign keyless auto-activates without an explicit decision to use it | `AR_ALLOW_KEYLESS` opt-in | **Shipped batch 1** |
| Keyless verification accepts a signature from any Sigstore-issued identity, not just this repo's own CI | Explicit `AR_COSIGN_IDENTITY`/`AR_COSIGN_ISSUER`, or (GitHub Actions only) an auto-derived identity anchored to `GITHUB_REPOSITORY` | **Shipped** — explicit pin: batch 1; auto-derivation: post-batch-3 hardening |
| Trusted job executes a PR-ref (tampered) copy of the scripts instead of a pinned ref | Pin `uses: …@<sha>` in the trusted workflow | Adopter-configured; unenforceable from inside the script |
| Secrets available to the untrusted review job | GitHub Actions environments / job-scoped secrets | Adopter-configured |
| Waiver signed without any human approval evidence | Not yet built — candidate follow-up beyond the current 4-batch plan | Open |
| A trusted job's signature cannot reach the untrusted review job's own run directory (cross-job hand-off) | Not yet designed — candidate approaches sketched above; needs its own frontier-gate panel run before implementation | Open |
| A signed repo's policy.snapshot.json/signature is deleted or its verification starts failing (rotated key, tampered artifact), and the run self-reports a low risk tier so it slips through with reduced gates | `authenticate_risk_tier()` forces risk to CRITICAL and BLOCKS whenever signing was expected (a verifier resolves, or `AR_SIGNING_REQUIRED` says so) but cannot be verified — CRITICAL's `mutation` gate can never be waived | **Shipped round 5** (`AR_SIGNING_REQUIRED` anchor + `RISK TIER UNAUTHENTICATED`) |
| Downgrade-to-exempt: an attacker deletes BOTH `policy.snapshot.json` and any signed absence attestation, AND strips the verifier from the job env, making a previously-signed repo look exactly like one that was never signed | `AR_SIGNING_REQUIRED`, but only when its source is one a same-repo PR genuinely cannot edit | **Partially shipped round 5** — the mechanism (a forced anchor) shipped; closing the gap for real requires an anchor source outside the calling repo's own workflow file, which most adopters have not yet configured. See the corrected section below |
| A repository with no signing infrastructure at all gets forced to CRITICAL on every run once `mutation` is checked | Deliberately NOT built this round — see "What round 5 deliberately did not build" below | **Open, tracked** (roadmap `pr70-round5-signing-hardening-and-keyless-onboarding.md`, M4-dependent) |
| A process that merely sets `GITHUB_EVENT_NAME=pull_request` (never running inside real GitHub Actions) is trusted by `_pr_author_controlled_trigger()` as a PR-author-controlled job, letting `authenticate_risk_tier()`'s unsigned-exempt path be forced even when `AR_SIGNING_REQUIRED=1` demands strict authentication | `_pr_author_controlled_trigger()` now only reads `GITHUB_EVENT_NAME` when `GITHUB_ACTIONS=="true"` — the same fail-closed platform-selection gate `ci_signing_context()` already had | **Shipped round 6** |
| `run.json` fields other than `risk` that affect the computed verdict are not bound into the policy-attestation signature, so editing them post-signing (with the signature staying valid) can silently change verdict-relevant behavior: `rebuttal_policy` (contention→critical drops a required SENSITIVE-tier rebuttal round), `dev_providers` (makes a development-only review look independent), and the absence-attestation's `captured_at`/`dev_providers` | `POLICY_ATTEST_VERSION` **v4**: `canonical_policy_fields_bytes()` binds a canonical-JSON digest of `BOUND_RUN_JSON_KEYS` (`dev_providers`, `rebuttal_policy`) into both `policy_attest_bytes` and `policy_absence_attest_bytes`, closing the whole class at once rather than one field at a time; a new `t_v4_run_json_key_inventory_is_exhaustive` guard test fails CI if a future `run.json` key is added without being classified into `BOUND_RUN_JSON_KEYS` or `UNBOUND_RUN_JSON_KEYS_BY_DESIGN`. Deliberately no v3-signature migration path — see `references/schemas.md`'s policy-attestation-signing section | **Shipped round 7** (commit pending) |
| `policy.absence.json`'s OWN file content (`{policy_absent, captured_at}`) was never bound by its own signature at all — `verify_policy_absence_signature` accepted an `absence_bytes` keyword that `policy_absence_attest_bytes` never actually referenced, so editing the claim file post-signing (without touching `policy.absence.sig`) went completely undetected | `POLICY_ATTEST_VERSION` **v4**: `panel.py`'s `_sign_policy_absence_if_possible` now computes `policy.absence.json`'s exact bytes in memory, signs over them (threaded through as `absence_bytes`), and only writes them to disk afterward; `verify_policy_absence_signature` verifies against those same bytes | **Shipped round 7** (commit pending) |
| `GITHUB_ACTIONS`/`GITHUB_REPOSITORY`/etc. (and their GitLab equivalents) are entirely self-reported environment variables, never verified against the platform's own OIDC identity or API — a process outside real CI infrastructure that sets them is indistinguishable, to `ci_signing_context()`/`_ci_identity_established()`/`_pr_author_controlled_trigger()`, from a genuine CI job | Documented, not code-fixed this round — see "What CI-identity signals do and do not prove" above for the actual trust boundary (signer-secret isolation + job separation, both adopter-configured) and the tracked OIDC-attestation follow-up | **Open, tracked** (documentation-only round 8; round-8 panel decision `fix_b_and_c_now_document_a`, consensus 0.97) |
| `aggregate.py`'s `main()` reads `run.json` multiple independent times within one invocation — once at the top for `meta` (`rebuttal_policy`/`dev_providers`, used by `check_rebuttal()`/`check_panel()`), and again inside `authenticate_risk_tier()`'s own `read_run_risk()`/`load_attested_policy_bundle()` calls (used to authenticate and rebind `meta["risk"]`). Only `risk` gets rebound to the authenticated value; a write to `run.json` landing in the (narrow, intra-process) window between these reads could leave `rebuttal_policy`/`dev_providers` reflecting a stale snapshot while `risk` reflects a fresher, authenticated one — e.g. a stale `"rebuttal_policy": "critical"` suppressing a rebuttal round the current, signed policy would require (CodeRabbit r4112007466, round 8) | Not fixed this round — flagged as a "Heavy lift" by CodeRabbit's own review and confirmed on inspection: closing it properly means threading pinned `run.json` bytes through `authenticate_risk_tier()`/`read_run_risk()`/`load_attested_policy_bundle()` (mirroring the `snap_bytes`/`policy_fields_bytes` pinning pattern already used elsewhere in this module), which changes a shared function `gate.py` also calls with no pinned bytes available in its own context — a real design decision, not a mechanical fix, and a genuinely narrower/harder-to-exploit window than the round-8 flip-and-restore attack (which spans separate CLI invocations with a large time gap) rather than one intra-process race | **Open, tracked** — flagged for its own frontier-gate panel run before implementation, not decided unilaterally while closing out round 8's other findings |

## Round 5 — unauthenticated risk-tier fallback (checklist item 6, refined)

(frontier-gate run pr70-item6-scope, 2026-09-23, panel consensus 0.97, Paul's decision:
refined Option A / `scope_down_never_break_unsigned`.) The original trust-model panel's
item 6 said: "unauthenticated risk tier defaults to CRITICAL, mutation waivers
disabled." Built literally, this would CRITICAL-default every repository with no
signing infrastructure at all — as of 2026-09-22, 0 of 40 repositories across Paul's
two GitHub accounts, including the confirmed production consumer `viaid` — which would
permanently block them all on CRITICAL's unwaivable `mutation` gate (real CRITICAL-tier
mutation testing, milestone M4, is not yet built). `authenticate_risk_tier()` in
`_common.py` is the narrowed, shipped version:

- **AUTHENTICATED** — a verifiably-signed policy snapshot or absence attestation
  governs this run. Risk tier is the cryptographically-backed value. No stamp needed.
- **UNSIGNED EXEMPT** (`RISK TIER UNSIGNED EXEMPT`) — no verifier resolves in this
  environment AND `AR_SIGNING_REQUIRED` is not set for this repository. Risk tier is
  self-reported, non-blocking — the pre-existing infrastructure-free exemption for the
  common no-waiver path (see "What this mechanism is (and is not)" above), unchanged.
- **UNAUTHENTICATED** (`RISK TIER UNAUTHENTICATED`) — signing WAS expected (a verifier
  resolves here, or the repository's own `AR_SIGNING_REQUIRED` anchor says so) but
  could not be cryptographically verified. Risk is forced to CRITICAL and the run is
  BLOCKED. `mutation` can never be waived at CRITICAL, which is what actually makes
  this un-bypassable rather than merely a printed warning.

### `AR_SIGNING_REQUIRED` — closing the downgrade-to-exempt gap (partially — see caveat)

The frontier panel's own reviewers (all four, most explicitly Astra) flagged a real gap
in the first version of this option: inferring "signing was configured" only from
whether a verifier happens to resolve in the CURRENT environment is not enough — an
attacker who can also influence the workflow file that launches that environment (a
same-repo PR editing `.github/workflows/*`, or simply removing `AR_VERIFIER_CMD`/
`AR_ALLOW_KEYLESS` from the job env) could make the verifier silently fail to resolve,
at which point a previously-signed repository looks exactly like one that was never
signed and falls through to the exemption instead of BLOCKING.

`AR_SIGNING_REQUIRED=1` is the mechanism that closes this — **but only when its value
reaches the job from a source a same-repo PR genuinely cannot edit.** CodeRabbit
r4082557491 (Major, valid) correctly caught that the original wording here overstated
this: a "repository secret or Action `with:` input on the calling reusable workflow" is
not, by itself, safe when that calling workflow lives in the SAME repository as the
one being protected. GitHub Actions runs a `pull_request`-triggered job using the
workflow file from the PR's own head ref, so a same-repo PR can simply delete the line
that maps the secret into `AR_SIGNING_REQUIRED` (`env: AR_SIGNING_REQUIRED:
${{ secrets.AR_SIGNING_REQUIRED }}`) from its own copy of that file — the secret's
*value* is safe from the PR, but the *wiring* that exposes it to the job is not, if
that wiring lives in a file the PR controls.

What actually closes the gap is an anchor whose **wiring**, not just its value, sits
outside the protected repo's own PR-editable surface. Two setups qualify:

1. **A SHA-pinned reusable workflow hosted in a separate repository**, whose own file
   (not a `with:` input passed in from the calling repo) sets `AR_SIGNING_REQUIRED`
   directly — combined with branch protection on the calling repo that prevents a PR
   from changing which reusable workflow (or which pinned SHA) that calling file
   invokes. If the calling file's `uses: org/other-repo/...@<sha>` line is itself
   unprotected, a PR can simply repoint it at a workflow that doesn't set the anchor,
   so the SHA pin alone is not sufficient without that protection.
2. **An organization-level "required workflow" ruleset** (GitHub's own feature for
   exactly this problem) — configured by an org owner, defined and pinned outside the
   target repository, and enforced regardless of what the target repo's own workflow
   files say.

A plain repository secret referenced from this repo's own `.github/workflows/*.yml`
does **not** close the gap on its own — it only raises the bar from "delete two files"
to "also delete one line," which is not a meaningfully higher bar for a same-repo PR.
Adopters who have configured neither of the two setups above are, honestly, still
exposed to the downgrade-to-exempt attack this section describes; they are no worse off
than before this change (the pre-existing "verifier resolves here" check still applies
on its own, unchanged), but `AR_SIGNING_REQUIRED` has not yet closed anything for them
in practice. This gap in adopter guidance — not the mechanism itself — is why the table
row above reads "partially shipped": the code faithfully honors whatever
`AR_SIGNING_REQUIRED` says, but most adopters do not yet have a way to set it that the
threat model actually defends.

**`pull_request`-triggered runs are exempt from this escalation entirely, regardless of
`AR_SIGNING_REQUIRED` or a resolvable verifier.** `panel.py init` already refuses to
sign under `GITHUB_EVENT_NAME=pull_request` / GitLab's `CI_PIPELINE_SOURCE=
merge_request_event` (`trusted_signer_guard_error()`, above) — no production hand-off
mechanism exists yet for a trusted job to sign on behalf of a PR-triggered run's own
directory. Forcing CRITICAL on every such run regardless would not close any gap (there
is no way for that job to ever produce the signature being demanded) — it would just
permanently block PR-gating CI for any repository that has a verifier binary on its
runner's `PATH` or sets `AR_SIGNING_REQUIRED`, which is precisely the kind of silent,
undisclosed breaking change Option A was chosen specifically to avoid. `authenticate_
risk_tier()` detects this the same way `trusted_signer_guard_error()` does and takes
the ordinary self-reported/exempt path for these runs; a WAIVED or NOT_APPLICABLE gate
on a `pull_request` run is still independently required to carry a valid signature by
the separate, pre-existing GAP-A check further down `aggregate.py`, unaffected by this.

### What round 5 deliberately did not build

A repository with **no** signing infrastructure at all (no verifier resolvable, no
`AR_SIGNING_REQUIRED` anchor set) stays exempt — the literal panel wording's full
intent (treat ANY unauthenticated risk claim as untrustworthy) is only half-closed by
design. This is a deliberate, disclosed deferral, not an oversight — tracked here
rather than silently dropped:

- **What's deferred:** extending CRITICAL-default treatment to cover "no signing
  configured at all," not just "signing was configured, then broke or was stripped"
  (the half this file's round 5 section above already closes).
- **Why:** at the time this was scoped (2026-09-22), 0 of 40 repositories across both
  connected GitHub accounts — including `viaid`, the one confirmed production
  consumer — had signing configured. Forcing CRITICAL (whose `mutation` gate can never
  be waived) on every one of those runs would be an undisclosed breaking change /
  outage, not a hardening, and real CRITICAL-tier mutation testing (milestone **M4**
  in `gate.py`'s own roadmap) isn't built yet to give such a repo any way to pass.
- **Trigger to revisit:** when M4 actually ships.
- **What revisiting should mean:** re-run the item-6 question through a fresh
  frontier-gate brief rather than just flipping a flag — M4's actual design may change
  what "CRITICAL-default" should even mean; re-check the then-current signed/unsigned
  repo count (it will likely have moved, especially once the keyless-default
  onboarding work below has shipped and `AR_SIGNING_REQUIRED` has seen real adoption);
  then decide, with real data, whether to extend CRITICAL-default to the
  no-signing-at-all case or keep the infrastructure-free exemption permanently as the
  final, intentional design.
- **Owner:** whoever picks up `gate.py`'s M4 work should read this section first,
  before touching risk-tier defaulting.

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
