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
 "status": "PASS|FAIL|BLOCKED|NOT_APPLICABLE",
 "summary": "312 passed", "output_tail": "...", "recorded_at": "ISO-8601",
 "source": "run|record", "authorized_by": "name (NOT_APPLICABLE only)"}
```

`status` BLOCKED marks required coverage that could not be run or verified (`exit_code`
may be null there). `status` NOT_APPLICABLE marks a required gate that genuinely does not
apply to this stack (e.g. a config-only repo with no build or unit gate); unlike BLOCKED
it does **not** restrict the verdict, but it is an accountable determination — the
aggregator requires a named `authorized_by` and a non-empty `summary`, and an N/A record
missing either is itself BLOCKED. Every N/A gate is listed distinctly (with its
authorizer) in `verdict.json` coverage (`gates.not_applicable`) and in `verdict.md`, so a
skipped gate is never silent. Absent `status` falls back to the exit code.

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

## Verdict — `verdict.json` (written by aggregate.py only)

```json
{"verdict": "PASS|FAIL|BLOCKED", "reasons": ["string"],
 "next_steps": ["plain-language guidance derived from the verdict; never alters it"],
 "counts": {"gates": 0,
 "reviewers": 0, "findings_high_critical": 0, "confirmed": 0, "unresolved": 0},
 "coverage": {"risk": "TIER",
   "gates": {"plan_recorded": true, "required": [], "recorded": [], "passed": [],
             "failed": [], "blocked": [{"name": "", "reason": ""}], "missing": [],
             "waived": [{"name": "", "authorized_by": ""}]},
   "panel": {"roles_required": [], "roles_filled": [], "substitutions": 0,
             "degraded": null, "dev_families_excluded": []},
   "rebuttal": {"policy": "contention", "required": false, "ran": false},
   "findings": {"raised": 0, "triaged": 0, "untriaged_release_blocking": 0},
   "cost_usd": 0.0, "cost_aborted": false, "cost_cap_usd": 20.0, "cost_cap_source": "default",
   "areas_not_reviewed": ["union of reviewer attestations"]},
 "attestation": {"algorithm": "sha256-canonical-json-v1", "inputs": 0,
   "digest": "hex", "files": {"run.json": "hex", "gates/unit.json": "hex"}},
 "computed_at": "ISO-8601"}
```

The `attestation` block makes the audit record tamper-evident. Every `*.json` file in
the run directory except `verdict.json` (the output) is canonicalized — sorted keys,
compact separators, so cosmetic re-serialization is not tampering — and hashed; a
`.json` file that fails UTF-8 decoding or JSON parsing is hashed over its raw bytes
(`raw:` prefix) rather than crashing the aggregator — both failure modes are treated
identically and deliberately. The per-file hashes are folded into one manifest digest.
Re-aggregating an untouched run reproduces the digest bit-for-bit.
`aggregate.py --check-digest` recomputes it against the stored value: exit 0 intact;
exit 1 with each drifted artifact named `DRIFT modified|added|removed`; exit 2 when no
verdict or no attestation exists. Third parties can verify a shipped run directory the
same way.

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
`default`); both are `null` when the cap is disabled or the run predates cost accounting.
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
