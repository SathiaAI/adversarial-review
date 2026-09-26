# Artifact schemas

All artifacts live under `.adversarial-review/<run-id>/`. The aggregator consumes these
files and nothing else — an unrecorded fact does not exist for verdict purposes.

## Reviewer report — `panel/<role>.json`

Enforced via `response_format: json_schema` (strict) where the endpoint supports it, and
always validated locally by `panel.py` (one retry on malformed output; raw responses
preserved under `panel/raw/`).

```json
{
  "role": "correctness|security|data_privacy|test_quality|reliability|output_fidelity",
  "model_id": "provider/model-slug",
  "summary": "string",
  "findings": [
    {
      "id": "role-1",
      "title": "string",
      "severity": "critical|high|medium|low",
      "confidence": 0.0,
      "file": "path",
      "line": 0,
      "evidence": "what in the code makes this true",
      "scenario": "concrete inputs/state -> wrong outcome",
      "reproduction": ["step", "step"],
      "fix": "string",
      "regression_test": "what test would catch this forever",
      "release_blocking": true
    }
  ],
  "assumptions": ["string"],
  "additional_tests": ["string"],
  "areas_reviewed": ["string"],
  "areas_not_reviewed": ["string"],
  "top_residual_risks": ["string (min 1)"],
  "injection_suspected": false,
  "output_statements_checked": [
    { "rendered": "a human-facing string the reviewer rendered from the diff",
      "states_truth": true, "note": "why it holds — or how it misstates the real state",
      "finding_id": "" },
    { "rendered": "a FAIL branch that asserts the success condition",
      "states_truth": false, "note": "inverted claim", "finding_id": "output_fidelity-2" }
  ]
}
```

**Finding ids are unique across the panel.** Each `id` uses the reviewer's own `role-N` prefix.
The aggregator builds one cross-report map keyed by `id`; a duplicate id from a later report is
rejected (BLOCKED), never allowed to overwrite an earlier finding — otherwise a low finding
reusing a high finding's id would hide it from the high/critical coverage check (4th-panel
`security-2`). Malformed artifacts fail safe the same way: a non-list `findings`, a finding with a
non-string `id` or invalid `severity`, a validation record that is not an object, a non-string
`finding_ids` member, or a malformed `suppressions.json` (non-list, or a non-object entry) each
BLOCKs with a specific reason and still writes a verdict — never a crash, never a silent PASS
(4th-panel `security-1/3`, `correctness-1/2/3`).

`output_statements_checked` is a **required, forced** attestation (every role emits it). It
exists to catch output-semantics defects — a generated sentence whose claim inverts or
overstates the state it describes (e.g. a FAIL branch that asserts the success condition) —
which have no crash or exploit and so slip past a purely threat/logic review. Such a finding is
valid with an empty `reproduction`; cite the wrong output versus the correct output in
`evidence` and `scenario`.

**Enumeration scope.** The dedicated **output_fidelity** reviewer records EVERY human-facing
string (true ones included) — for that role an empty list is a positive claim ("the diff emits
no human-facing text"). The other roles report **by exception**: only statements they judge
false, misleading, or uncertain, so a large text/localization diff cannot exhaust the
completion cap across 4–6 reviewers and false-BLOCK a clean change.

**Linkage that makes it a gate.** Every item carries `finding_id`: the id of the finding that
reports a false statement, or an empty string `""` for a true one. It is a required key on every
item — strict structured-output providers (e.g. OpenAI) reject a schema whose `required` omits
any property, so an optional field would break those reviewers outright. `aggregate.py` BLOCKS
the run on any false statement whose `finding_id` is empty, is **not a finding in the attesting
reviewer's own report** (membership in that report's `findings`, not merely a role-prefix match
against the cross-report id map — a finding another report planted under this reviewer's prefix
does not count), or names one that is **not resolved** (a `confirmed`/`false_positive`/
`accepted_risk` triage decision — a bare `unresolved` record does not clear it) — regardless of
that finding's severity — so a recorded falsehood can never silently reach PASS, and a garbled or
foreign link fails safe to BLOCKED. A malformed `output_statements_checked` that is present but
not a list also BLOCKs (and never crashes the aggregator). The reviewer-supplied link and rendered
text are HTML-escaped before they appear in any reason, so a crafted value cannot forge markup in
the rendered verdict. Membership + resolution still do not prove the linked finding is *about* the
statement, so a resolving record must additionally **confirm the specific statement**: its
`output_statements_confirmed` must echo the rendered text (whitespace-normalized). Because that
confirmation lives on the **trusted operator's** record — not the semi-trusted reviewer's link — a
reviewer cannot clear a false statement by pointing `finding_id` at an unrelated but resolved own
finding (2nd-panel `security-2`).

## Panel plan — `panel/plan.json`

Written by `panel.py assign`. Records resolved model slugs (exact, from the live
catalog), family per role, exclusions applied, substitutions made, and any degraded-mode
authorization. The aggregator checks family uniqueness and dev-family exclusion against
this file.

## Gate record — `gates/<name>.json`

```json
{"gate": "unit", "command": "npm test", "exit_code": 0,
 "status": "PASS|FAIL|BLOCKED|NOT_APPLICABLE|WAIVED",
 "summary": "312 passed", "output_tail": "...", "recorded_at": "ISO-8601",
 "source": "run|record|plan", "authorized_by": "name (NOT_APPLICABLE/WAIVED only)"}
```

`status` BLOCKED marks required coverage that could not be run or verified (`exit_code`
may be null there). `status` NOT_APPLICABLE marks a required gate that genuinely does not
apply to this stack (e.g. a config-only repo with no build or unit gate); unlike BLOCKED
it does **not** restrict the verdict, but it is an accountable determination — the
aggregator requires a named `authorized_by` and a non-empty `summary` (stripped), and an
N/A record missing either is itself BLOCKED. The stricter waiver-reason rule (>=16 chars,
no placeholder) applies to WAIVED `reason`s only, **not** to N/A `summary`s. Every N/A gate
is listed distinctly (with its
authorizer) in `verdict.json` coverage (`gates.not_applicable`) and in `verdict.md`, so a
skipped gate is never silent. Absent `status` falls back to the exit code.

`status` WAIVED (written by `gate.py plan --waive`, `source: "plan"`) is the third
accountable, non-restricting exception: `{"gate": "mutation", "status": "WAIVED",
"authorized_by": "name", "reason": "why (>=16 chars, not a placeholder)",
"expires": "YYYY-MM-DD", "tier": "SENSITIVE", "planned_at": "ISO-8601",
"source": "plan"}`. Unlike the pre-M1 waiver, the waived gate is **never removed from
`required`** — this record is what the aggregator checks for it, and it is
**independently re-validated at every aggregate run** (never trusted just because
`gate.py plan` wrote it — and `gate.py plan` now runs the **same** validator, so an invalid
waiver is rejected at plan time and never produces an artifact): a named `authorized_by`, a
`reason` (>=16 chars, not a placeholder); `expires` must be a strict `YYYY-MM-DD` strictly
after the run's clock date — the **later** of today UTC and the date part of
`GITHUB_RUN_STARTED_AT` when that's set (a stale/backdated run-start timestamp can never
un-expire a waiver; a forward-dated one is still honored — a set-but-unparseable value
BLOCKS the run rather than guessing); and `expires` must be no more than `max_waiver_days`
after the run's planning time, anchored to the **earlier** of the record's own `planned_at`
and the run plan's `planned_at` in `gates/_required.json` (so editing either one forward
alone cannot slide the window — an honest run always has both equal, since `gate.py plan`
writes them together). A `planned_at` in the future relative to the run's clock — on either
the record or the manifest — is rejected as tampered; there is no lower bound requiring the
record's `planned_at` to be no earlier than the manifest's. `max_waiver_days` (default 14) is bounded to 1–365 at policy
load, and the limits (`max_waiver_days`, `allow_critical_waivers`) are read from the policy
**attested at init** (`policy.snapshot.json`), never a post-init working-tree edit. On
CRITICAL tier, waiving (or marking NOT_APPLICABLE)
any gate is refused unless policy sets `allow_critical_waivers: true`; `mutation` on
CRITICAL is refused regardless of that setting — it stays BLOCKED until real CRITICAL
mutation coverage ships (M4). Every waived gate is listed distinctly (with its
authorizer, reason, and expiry) in `verdict.json` coverage (`gates.waived`) and in
`verdict.md`.

`authorized_by` (WAIVED and NOT_APPLICABLE) and `reason`/`summary` must additionally be
**UTF-8 encodable** — a JSON string may legally contain a lone UTF-16 surrogate (e.g.
`"\ud800"`), which `isinstance`/`len()` accept but which crashes `.encode("utf-8")`. Since
all three are copied verbatim into `verdict.json`'s `gates.waived`/`gates.not_applicable`
entries and `write_json()` always writes with `ensure_ascii=False`, an unencodable value
there is rejected at validation time (BLOCKED, `"...contains characters that cannot be
represented in UTF-8"`) rather than crashing the whole aggregation run with no
`verdict.json` written at all.

The tier-floor gates aggregate.py's `check_gates()` reconstructs independently from
`gate.py`'s `MINIMUM_GATES` are not the only ones it re-derives: it also reconstructs
whatever the **attested policy** additionally requires for this tier via
`required_gates.<tier>` in `.adversarial-review.yml`/`.json` (see `gate.py cmd_plan`'s
`base_required = requested | MINIMUM_GATES[tier]`, where `requested` can come from the
policy). A `gates/_required.json` manifest that omits a policy-required gate entirely —
never waived, never marked NOT_APPLICABLE, simply absent — is BLOCKED exactly like one
missing a tier-floor gate, not silently accepted just because the omitted gate was never
part of `MINIMUM_GATES` to begin with.

## Validation record — `validation/<slug>.json` (one per deduped issue)

```json
{
  "finding_ids": ["security-1", "correctness-3"],
  "classification": "confirmed|false_positive|unresolved|accepted_risk",
  "severity": "critical|high|medium|low",
  "evidence": "what you did and observed — commands, outputs, code inspection",
  "reproduced": true,
  "regression_test": "path::test_name or why impractical",
  "resolution": {"fixed": true, "gates_rerun": ["unit", "sast"]},
  "concurrence": {"model_id": "provider/slug", "agrees_false_positive": true, "reasoning": "..."},
  "output_statements_confirmed": ["the exact rendered false statement this record triages"]
}
```

`output_statements_confirmed` (optional) is the operator's confirmation that this record triages a
specific reviewer-attested false human-facing statement: list the `rendered` text of each such
statement. The output-fidelity gate clears a `states_truth:false` attestation only when a resolving
record covering its `finding_id` echoes the statement here (whitespace-normalized) — resolution of
the linked finding alone is not enough (2nd-panel `security-2`). Omit it for records that triage
ordinary findings with no false-output attestation.

Field rules the aggregator enforces: `false_positive` on high/critical requires
`evidence` AND `concurrence.agrees_false_positive == true` from a family different from
every finding author's family. `confirmed` requires `resolution.fixed == true` with
`gates_rerun` non-empty, else FAIL. `accepted_risk` requires a matching, unexpired
`suppressions.json` entry covering every finding ID.

## Suppressions — `suppressions.json`

```json
[{"finding_id": "sast:rule:file:line", "evidence": "string", "owner": "string", "expires": "YYYY-MM-DD"}]
```

Field rules addendum: findings a reviewer marked `release_blocking: true` require a
validation record at any severity — untriaged flagged findings are BLOCKED. The run's
`rebuttal_policy` (in `run.json`: `critical`, `contention` (default), or `any`) sets
which tiers require the rebuttal round when high/critical findings exist. A
human-readable `verdict.md` is written alongside `verdict.json`.

## Jev triage artifacts — `triage/`, `rebuttal/plan.json`, `rebuttal/digest.json`, `patch_check/round-N.json`

Written by the optional `scripts/jev_triage.py` layer (`references/jev.md`). Advisory only
— `aggregate.py` never computes PASS/FAIL/BLOCKED from these; `verdict.md` displays
`triage/` records purely for the operator, and `rebuttal/plan.json` narrows *which* findings
`check_rebuttal()` treats as needing contest but never whether the rebuttal round itself is
skipped for a policy/tier that requires it.

```json
// triage/<finding-id>.json — one per finding, from `jev_triage.py triage`
{
  "finding_id": "security-1", "role": "security", "component": "api/invoices.py",
  "reviewer_severity": "high", "title": "string", "release_blocking": true,
  "jev": {"model": "typesafe/jev-1.13", "called_at": "ISO-8601", "error": "string|null",
          "cost": 0.00003, "is_real": 0.0,
          "severity": {"score": 0.0, "label": "low|medium|high|critical", "legend": {}},
          "duplicate_of": {"choice": "none|<earlier-finding-id>", "confidence": 0.0,
                            "probabilities": {}},
          "needs_human": 0.0, "fix_is_obvious": 0.0}
}
```

`jev.error` non-null means every `jev.*` value above it is a fail-closed default
(`is_real`/`needs_human=1.0`, `fix_is_obvious=0.0`), not a real Jev answer — see
*Fail-closed* in `references/jev.md`.

```json
// rebuttal/plan.json — from `jev_triage.py rebuttal-gate`; read by aggregate.py's
// _rebuttal_jev_gate(). required_finding_digests/skipped_finding_digests (round 4) are
// REQUIRED alongside required_finding_ids/skipped_finding_ids, one digest per id in the
// same order — each is _common.canonical_finding_digest() of the corresponding finding's
// title/file/line/severity/evidence/scenario/author_role, not the id itself, so a stale
// plan whose ids happen to match a `panel.py run --force` re-run's NEW findings (which
// can reuse a conventional id like "security-1" for a completely different defect) is
// detected and rejected rather than silently trusted. A plan is treated identically to a
// run that never ran rebuttal-gate (falls back to the stricter blanket rebuttal rule) if
// it is absent; malformed (not an object); required_finding_ids/skipped_finding_ids or
// required_finding_digests/skipped_finding_digests not same-length lists of strings; or
// the digest sets recomputed fresh from this run's own panel/<role>.json reports are not
// a subset of (required_finding_digests ∪ skipped_finding_digests) — content coverage,
// not just id-set coverage.
{
  "generated_at": "ISO-8601", "model": "typesafe/jev-1.13|null",
  "decisions": {"<finding-id>": {"contested": 0.0, "would_change": 0.0, "error": "string|null",
                                  "decision": "run|skip", "digest": "sha256 hex string"}},
  "required_finding_ids": ["security-1"], "skipped_finding_ids": [],
  "required_finding_digests": ["sha256 hex string"], "skipped_finding_digests": [],
  "jev_cost_usd": 0.0
}
```

```json
// rebuttal/digest.json — same item shape as panel.high_critical_digest(), filtered to
// required_finding_ids. Pass to `panel.py rebuttal --digest-file <path>`.
[{"id": "security-1", "title": "string", "severity": "high|critical", "file": "path",
  "line": 0, "evidence": "string", "scenario": "string", "author_role": "security"}]
```

```json
// patch_check/round-N.json — one per `jev_triage.py patch-check` invocation, N auto-
// incrementing per run directory
{
  "generated_at": "ISO-8601", "round": 1, "patch": "path", "patch_sha256": "hex",
  "model": "typesafe/jev-1.13|null", "jev_cost_usd": 0.0,
  "items": [{"slug": "security-1", "finding_ids": ["security-1"],
             "resolved_by_patch": 0.0, "patch_introduces_new_risk": 0.0,
             "status": "resolved (operator must confirm)|still open|still open (ambiguous -- verify by hand)",
             "error": "string|null", "validation_sha256": "hex"}]
}
```

`patch_sha256` is the sha256 of the patch file as read; each item's `validation_sha256` is
the sha256 of that `validation/<slug>.json` record as it stood at check time — nothing
reads these back automatically, they let a later comparison detect drift instead of
trusting the round file on faith.

A `resolved_by_patch ≥ 0.8` item is a **proposal**, not a closed finding — the operator
still inspects the patch and still updates `validation/<slug>.json` by hand; nothing in
`patch_check/` closes a finding on its own.

## Policy-attestation signing — `policy.snapshot.sig` / `policy.absence.sig` (v4)

The signed payload behind `policy.snapshot.sig` (the detached signature over
`policy.snapshot.json`) and `policy.absence.sig` (the detached signature over
`policy.absence.json`, GAP A's "checked, found no policy file" claim) is built by
`policy_attest_bytes()` / `policy_absence_attest_bytes()` in `_common.py`.
`POLICY_ATTEST_VERSION` is currently `"4"`. **Bound** into the signed message, at both
sign time (`panel.py init`) and verify time (`aggregate.py`, `gate.py plan`/`record`),
in order:

1. The version tag (`ar-policy-attest-v4` / `ar-policy-absence-attest-v4` — different
   domain-separation prefixes, so a signature minted for one can never verify as the
   other).
2. `run_id`, `run_nonce`, the run directory's own name, and the resolved `risk` tier —
   unchanged since v2; `run_name` and `risk` are checked separately from `run.json`'s own
   content, not via the digest below (see item 5).
3. The live CI-orchestrator identity (`repository`, `commit`, CI run id, CI run
   attempt) from `ci_signing_context()`, read fresh from the signing/verifying
   process's own environment — unchanged since v3.
4. **New in v4:** a length-prefixed copy of the canonical-JSON bytes themselves (not hashed —
   `canonical_policy_fields_bytes()`, built by `canonical_json_bytes()`) of `run.json`'s
   `BOUND_RUN_JSON_KEYS` — currently `dev_providers` and `rebuttal_policy`. A key present in `run.json` at sign
   time but deleted (not merely edited) by verify time is bound as JSON `null`, never
   simply omitted, so deletion doesn't silently match "key absent" either.
5. For a snapshot: `policy.snapshot.json`'s full raw bytes (unchanged since v1). For an
   absence claim: **new in v4**, a length-prefixed copy of `policy.absence.json`'s exact
   raw bytes — pre-v4 this file's own content was never bound by its signature at all
   (see the CHANGELOG "Round 7" entry).

`canonical_json_bytes()` accepts only `str`/`bool`/`None`/`list`/`dict` (of those),
`sort_keys=True` with fixed separators — dict key order never affects the output, list
order always does. `int` and `float` are deliberately unsupported (raise `TypeError`):
float repr is not guaranteed byte-identical across Python versions/platforms, and
NaN/Infinity have no valid JSON representation at all.

**What's deliberately left unbound, and why** (`UNBOUND_RUN_JSON_KEYS_BY_DESIGN` in
`_common.py`, confirmed by reading every call site in `panel.py`/`aggregate.py`/`gate.py`
— none of these are ever branched on by a decision path):

| key | why it's safe to leave unbound |
|---|---|
| `product`, `diff_ref` | interpolated into the human-readable reviewer-prompt text only |
| `sources` | audit trail of where `risk`/`dev_providers`/`rebuttal_policy` were resolved from (CLI flag / env var / policy file) — written once, never read back |
| `created_at` | a timestamp for a human reading `run.json`; nothing checks it for staleness/expiry |
| `policy` | the `{file, sha256}` pointer to the policy-file snapshot — redundant with `snap_bytes` itself, which already changes the moment `policy.snapshot.json`'s content does; this pointer only cross-checks a wholesale-swapped snapshot *file* |
| `attest_version` | not written as of v4 (no dual-version dispatch yet); reserved so adding it later needs no reclassification |

A future run.json key that lands in neither `BOUND_RUN_JSON_KEYS` nor
`UNBOUND_RUN_JSON_KEYS_BY_DESIGN` is caught by `tests/run_tests.py`'s
`t_v4_run_json_key_inventory_is_exhaustive` before it can ship silently unbound.

**For `AR_SIGNING_REQUIRED` adopters: v4 is not backward compatible with v3
signatures, by design.** There is no migration path — this mirrors how v1→v2 and
v2→v3 were each handled. A run signed under a pre-v4 script version must be
re-initialized (`panel.py init`) under the v4 script before it will verify; there is no
silent fallback from a v4 verification failure to v3 leniency, because that would be a
downgrade vulnerability, not a compatibility feature. If a real population of
already-signed v3 runs is ever found to need continued verification, the fix is an
explicit `run.json['attest_version']`-keyed dispatch — never an unconditional
try-v4-then-silently-try-v3 fallback.

## Verdict — `verdict.json` (written by aggregate.py only)

```json
{"verdict": "PASS|FAIL|BLOCKED", "reasons": ["string"],
 "next_steps": ["plain-language guidance derived from the verdict; never alters it"],
 "counts": {"gates": 0,
 "reviewers": 0, "findings_high_critical": 0, "confirmed": 0, "unresolved": 0},
 "coverage": {"risk": "TIER",
   "gates": {"plan_recorded": true, "required": [], "recorded": [], "passed": [],
             "failed": [], "blocked": [{"name": "", "reason": ""}], "missing": [],
             "waived": [{"name": "", "authorized_by": "", "reason": "",
                         "expires": "YYYY-MM-DD", "tier": ""}]},
   "panel": {"roles_required": [], "roles_filled": [], "substitutions": 0,
             "degraded": null, "dev_families_excluded": []},
   "rebuttal": {"policy": "contention", "required": false, "ran": false},
   "findings": {"raised": 0, "triaged": 0, "untriaged_release_blocking": 0},
   "cost_usd": 0.0, "cost_aborted": false, "cost_cap_usd": 20.0, "cost_cap_source": "default",
   "policy_snapshot_sha256": "hex or null (sha256 of the policy attested at init whose waiver limits governed this verdict; null when the run had no policy file or the snapshot was rejected)",
   "areas_not_reviewed": ["union of reviewer attestations"]},
 "attestation": {"algorithm": "sha256-canonical-json-v4", "inputs": 0,
   "digest": "hex", "files": {"run.json": "hex", "gates/unit.json": "hex"}},
 "computed_at": "ISO-8601"}
```

The main aggregation **exits 0 for PASS, 1 for FAIL, 2 for BLOCKED**, writing `verdict.json`
first and then the human-readable `verdict.md`. Any **unexpected error exits 3** — a code
deliberately outside the verdict set `{0,1,2}` — so a crash *after* `verdict.json` is already
written (e.g. an untrusted run has `verdict.md` as a directory, so the markdown write raises)
can never be mistaken for a completed `FAIL` by a consumer that matches the exit code to the
written verdict (`mcp_server`'s `ar_aggregate`). Intentional exits pass through unchanged, so a
subcommand's own codes (e.g. `--sign`'s exit 3 for "no signer configured") are unaffected.

**Concurrent aggregation — the per-run write lock.** Writing `verdict.json` for a run is serialized by an
`O_EXCL` lock file, `verdict.json.lock`, in the run directory (it is not `*.json`, so it never enters the
attestation). Both entry points honor it: the standalone `aggregate.py` CLI acquires it **before reading any
run artifacts** and holds it through the `verdict.json`/`verdict.md` writes — so the whole read→compute→write
is one critical section (a stale computation can't overwrite a fresher verdict) — and **exits 3** if it is
already held (another aggregate is in progress); `mcp_server`'s `ar_aggregate` holds it across its wider
*move-aside → aggregate → settle* section so a concurrent aggregate cannot roll back a freshly written
verdict. Because `ar_aggregate` spawns `aggregate.py`
as its child *while already holding* the lock, the child must skip re-acquiring it — authorized by an
**unforgeable parent→child token**, not a CLI flag (which any caller could pass): the wrapper mints a random
token, writes its **SHA-256 hash** into the `0o600` lock file it owns, and hands the child the **preimage**
via the `AR_AGGREGATE_LOCK_TOKEN` environment variable; the child skips the lock only when its env token
hashes to the stored hash. A standalone invocation has no such token and, seeing only the hash, cannot
invert it — so it can never bypass a held lock. The lock is released (closed, then unlinked) on every exit
path by whichever process created it; a process never unlinks a lock it did not create.

The `attestation` block makes the audit record tamper-evident. Every `*.json` file in
the run directory except `verdict.json` (the output) is canonicalized — sorted keys,
compact separators, so cosmetic re-serialization is not tampering — and hashed, **plus
two explicit non-JSON exceptions, each hashed as a raw-bytes input whenever it
exists: `policy.snapshot.json`'s detached signature sidecar, `policy.snapshot.sig`
(v3 — a required, pre-verdict input for any policy-backed exception, so deleting or
corrupting it now changes the digest; v2 and earlier missed this, since
`compute_attestation` only globbed `*.json`), and `policy.absence.json`'s detached
signature sidecar, `policy.absence.sig` (v4 — GAP A's signed no-policy attestation,
folded into the attestation coverage the same way v3 already covered
`policy.snapshot.sig`, closing the same gap for a policyless exception run)**. Both
sidecars — and every tracked `*.json` artifact — are read the hardened way (`read_regular_file_once`:
no-follow at the leaf, size-capped), so a symlink planted in place of any of them is refused rather
than read through or silently skipped. That refusal raises `NotRegularFileError` (an `OSError`), which
every caller of `compute_attestation` (`--check-digest`, `--sign`, `--verify-signature`, and ordinary
aggregation) treats as **cannot verify**, never as a hashed value and never as detected drift: it is
not a `raw:`-prefixed digest entry, `--check-digest` exits 2 (not 1), `--sign`/`--verify-signature`
refuse with exit 2, and ordinary aggregation folds it into a `BLOCKED` verdict rather than crashing
before `verdict.json` is written. A verdict computed under v3 (no `policy.absence.sig`
in scope yet) is a recognized legacy algorithm for `--check-digest`, not a current one;
see the legacy-transition handling below. The unrelated, post-verdict `attestation.sig` (the standalone
`--sign` feature's detached signature *over* `verdict.json` itself) stays excluded —
including it would be circular. A `.json` file that fails UTF-8 decoding or JSON
parsing, **or whose bytes exceed a fixed,
version-independent cap on nesting depth OR integer-literal width**, is hashed over its raw
bytes (`raw:` prefix) rather than crashing the aggregator — these cases are treated
identically and deliberately. Deciding raw-vs-canonical **from the bytes, *before* parsing**
(rather than from whether `json.loads` happens to raise) is what keeps the digest identical
across Python versions *and* interpreter configurations: both the recursion-depth limit and the
integer-string-conversion limit (`PYTHONINTMAXSTRDIGITS`) are per-runtime, so a byte-measured
policy is the only portable one. The per-file hashes are folded into one manifest digest.
Re-aggregating an untouched run reproduces the digest bit-for-bit, on any supported runtime.
Within the ONE call site that computes this digest for the first time in the same
process invocation that also verified a policy-snapshot/absence signature (ordinary
aggregation, not `--check-digest`/`--sign`/`--verify-signature` — those are standalone,
re-checking an *existing* `verdict.json` against whatever is on disk now, with no
signature-verification call in scope, so they always read fresh, unchanged), the four
signature-adjacent inputs — `policy.snapshot.json`, `policy.snapshot.sig`,
`policy.absence.json`, `policy.absence.sig` — are hashed from the *exact bytes the
signature check already read and verified* (`load_attested_policy_bundle()`'s `.raw`/
`.absence_raw`, and `verify_policy_*_signature`'s `capture_sig_bytes`), never from a
second, independent re-read of the live path moments later (Codex 4099660083, P2,
valid). Without this, an actor with concurrent write access to the run directory could
swap any of the four between the signature check and this later read, so the digest
baked into `verdict.json` — and anything signed over it afterward via `--sign` — would
silently attest to different bytes than the ones actually verified. This changes
*which read* feeds the hash for those four inputs in that one flow; it does not change
what gets hashed, the algorithm, or any field shape above.

`aggregate.py --check-digest` recomputes it against the stored value: exit 0 intact;
exit 1 with each drifted artifact named `DRIFT modified|added|removed`; exit 2 when the
digest cannot be checked at all — no verdict, an unreadable/malformed or non-object
verdict.json, or an attestation that is not a usable object: not a dict, or a dict that
lacks a string `digest` or a dict `files` (e.g. a legacy record computed before #5 — its
absent/non-string digest would otherwise fall through to the exit-1 mismatch path, and a
non-dict `files` would crash the drift report and leak as exit 1); and when the stored `algorithm`
id is one this version does **not** recognize — a newer, unknown, or malformed id — because its
representation cannot be interpreted here. Exit 2 also covers a **legacy representation
transition**: a verdict recorded by a recognized predecessor (`sha256-canonical-json-v1`, before
the byte-based raw policy) canonicalized a deep or wide-integer artifact and stored a plain
canonical hash, which this version now hashes `raw:`. `--check-digest` gates purely on the id being
that recognized predecessor **and** every differing file being a canonical->`raw:` transition —
never by re-parsing the artifact, which would reintroduce the very runtime dependence the byte
policy removes (canonicalizing a deep artifact raises `RecursionError` on a lower-limit runtime; a
wide integer trips the integer limit). Such a transition is **unverifiable, not proven-unchanged**:
from the recorded hashes alone the tool cannot tell a benign representation change from a real
modification that kept the artifact beyond the cap (a deep artifact changed to *different* deep
content is still canonical->`raw:`). It reports cannot-verify with re-aggregation guidance
(`LEGACY <file>`) — exit 2 is a tool error, **never an intact pass**, so nothing tampered is let
through, and re-aggregation yields a fresh, fully-verifiable current-algorithm verdict. (Reporting
`DRIFT` instead would false-alarm on an *unchanged* legacy artifact — the case this path exists to
avoid — and no runtime-independent re-canonicalization of a deep artifact exists.) A
**current**-algorithm verdict is never routed here — a canonical->`raw:` mismatch on it is real
`DRIFT`. Exit 1 is reserved for a real recomputed mismatch, never a read/parse/shape,
unrecognized-id, or legacy-transition case, so a host that treats exit 1 as "tampered" is never
misled by an uncheckable run. Third parties can verify a shipped run
directory the same way.

Optionally, `aggregate.py --sign` produces a **detached cryptographic signature over the
run's `verdict.json`** (binding the verdict decision, not only this digest), written as the
sidecar `attestation.sig` (cosign keyless primary, minisign fallback, invoked out-of-process
— no signing library is imported). The signature is a sidecar, **not** an attested input: it
is not a `*.json` file, so it is never folded back into the digest. `--sign` and
`--verify-signature` are standalone post-verdict modes that refuse a drifted run;
`--verify-signature` recomputes this digest **and** checks the signature over `verdict.json`.
The full outside-verifier path (identity/issuer, cosign/minisign commands) is in
`references/config.md`, *Signing the verdict*.

The `coverage` block is the machine-readable manifest of what the run did and did not
verify. It is assembled exclusively from recorded artifacts — the same inputs as the
verdict — so an unrecorded fact is absent from coverage too, never inferred. It is
present on every aggregation, including FAIL and BLOCKED. `roles_required` is
reconstructed from the panel plan plus any roles a recorded degraded authorization
dropped; `areas_not_reviewed` is the deduplicated union of the reviewers' own
attestations (a hand-recorded report carrying null or a non-list there is skipped —
ingest-validated reports always carry a list, and the aggregator must not crash on
artifacts that bypassed ingest). Consumers gating in CI should treat `gates.missing`, `gates.blocked`,
and a `rebuttal` of `{"required": true, "ran": false}` as the specific unknowns behind
a BLOCKED verdict.

The cost fields (E4-S2) meter reviewer spend from the recorded `panel/meta/*.json`. `cost_usd`
is the finite USD total across the panel, rebuttal, and concurrence phases — a missing, non-finite,
or negative per-reviewer `cost` is metered as `$0`, and the MCP-ingest path's nested `usage.cost`
is read when no top-level `cost` was recorded. `cost_cap_usd` and `cost_cap_source` echo the
ceiling `panel.py run` actually enforced and where it was resolved from (`env`, `policy`, or
`default`). `cost_cap_usd` is `null` when the cap is disabled (e.g. `AR_MAX_COST_USD=none`) —
`cost_cap_source` still records where that setting came from; both are `null` only when the run
predates cost accounting (no `cost_policy.json`).
`cost_aborted` is `true` when `panel.py` stopped a phase on the cap and wrote `cost_abort.json`,
which drives a **BLOCKED** verdict with an explicit cost reason. Because the cap is a pre-call
gate, `cost_usd` may exceed `cost_cap_usd` by up to the in-flight reviewer's cost.

Definitions: **PASS** — all tier-required gates recorded and passing, panel complete and
independent, every high/critical finding validated with a compliant record. **FAIL** — a
recorded gate failed, or a confirmed-unfixed / unresolved / non-suppressed-accepted
high/critical finding exists. **BLOCKED** — required verification is missing or
incomplete (absent gates, incomplete panel, unvalidated findings, missing concurrence,
expired suppressions, missing rebuttal at CRITICAL, or a panel aborted on the cost cap).
BLOCKED is not "probably fine" — it means you do not know.
