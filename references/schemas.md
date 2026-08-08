# Artifact schemas

All artifacts live under `.adversarial-review/<run-id>/`. The aggregator consumes these
files and nothing else — an unrecorded fact does not exist for verdict purposes.

## Reviewer report — `panel/<role>.json`

Enforced via `response_format: json_schema` (strict) where the endpoint supports it, and
always validated locally by `panel.py` (one retry on malformed output; raw responses
preserved under `panel/raw/`).

```json
{
  "role": "correctness|security|data_privacy|test_quality|reliability",
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
  "injection_suspected": false
}
```

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
  "concurrence": {"model_id": "provider/slug", "agrees_false_positive": true, "reasoning": "..."}
}
```

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
{"verdict": "PASS|FAIL|BLOCKED", "reasons": ["string"], "counts": {"gates": 0,
 "reviewers": 0, "findings_high_critical": 0, "confirmed": 0, "unresolved": 0},
 "coverage": {"risk": "TIER",
   "gates": {"plan_recorded": true, "required": [], "recorded": [], "passed": [],
             "failed": [], "blocked": [{"name": "", "reason": ""}], "missing": [],
             "waived": [{"name": "", "authorized_by": ""}]},
   "panel": {"roles_required": [], "roles_filled": [], "substitutions": 0,
             "degraded": null, "dev_families_excluded": []},
   "rebuttal": {"policy": "contention", "required": false, "ran": false},
   "findings": {"raised": 0, "triaged": 0, "untriaged_release_blocking": 0},
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

Definitions: **PASS** — all tier-required gates recorded and passing, panel complete and
independent, every high/critical finding validated with a compliant record. **FAIL** — a
recorded gate failed, or a confirmed-unfixed / unresolved / non-suppressed-accepted
high/critical finding exists. **BLOCKED** — required verification is missing or
incomplete (absent gates, incomplete panel, unvalidated findings, missing concurrence,
expired suppressions, missing rebuttal at CRITICAL). BLOCKED is not "probably fine" —
it means you do not know.
