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
{"gate": "unit", "command": "npm test", "exit_code": 0, "status": "PASS|FAIL|BLOCKED",
 "summary": "312 passed", "output_tail": "...", "recorded_at": "ISO-8601",
 "source": "run|record"}
```

`status` BLOCKED marks required coverage that could not be run or verified (`exit_code`
may be null there). Absent `status` falls back to the exit code.

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
 "computed_at": "ISO-8601"}
```

Definitions: **PASS** — all tier-required gates recorded and passing, panel complete and
independent, every high/critical finding validated with a compliant record. **FAIL** — a
recorded gate failed, or a confirmed-unfixed / unresolved / non-suppressed-accepted
high/critical finding exists. **BLOCKED** — required verification is missing or
incomplete (absent gates, incomplete panel, unvalidated findings, missing concurrence,
expired suppressions, missing rebuttal at CRITICAL). BLOCKED is not "probably fine" —
it means you do not know.
