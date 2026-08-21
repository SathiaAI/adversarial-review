# Reviewer meta-evaluation corpus

This directory holds the labeled cases the reviewer panel is measured against: does the
panel actually catch the defects a skeptic cares about, and how often does it cry wolf on
clean code? Each case is **data** — you add one by dropping in a directory, no harness change.

The **case format** and its validator are E1-S1 (`evals/corpus_schema.py`); the **scoring** that
consumes these labels — true-positive / false-negative / false-positive — is E1-S2
(`evals/score.py`, documented below). The offline harness that drives the corpus through the panel
and rolls the scores up per role/model/tier is E1-S3 (`evals/run.py`, not yet built).

## Layout

```text
evals/corpus/<case-id>/
  meta.json      # identity + classification
  context.md     # the diff + surrounding code, exactly as a reviewer receives it
  expected.json  # ground-truth labels the scorer grades reviewer output against
```

`<case-id>` is the directory name and must equal `meta.json`'s `id`.

## `meta.json`

```json
{
  "id": "sec-idor-invoice",
  "title": "Invoice endpoint returns any invoice by id (missing ownership check)",
  "tier": "NORMAL | SENSITIVE | CRITICAL",
  "category": "security | correctness | test_quality | output_fidelity | clean",
  "language": "python",
  "source": "seeded | historical | cve",
  "cwe": "CWE-639"
}
```

`cwe` is optional. `source` is where the case came from: `seeded` (synthetic), `historical`
(mined from our own merged PRs / run artifacts), or `cve` (a canonical public pattern
re-expressed as a synthetic case — we do **not** import external CVE repos wholesale; see the
roadmap §7.3).

## `context.md`

Exactly what a reviewer receives: the change's requirements/acceptance criteria/invariants,
the full diff, and the surrounding code the change depends on (a diff-only view misses broken
invariants in unchanged callers). Keep it self-contained and free of real secrets — the corpus
is synthetic on purpose.

## `expected.json`

```json
{
  "defects": [
    {
      "defect_id": "idor-1",
      "must_detect": true,
      "locators": [{ "file": "api/invoices.py", "line_range": [41, 44] }],
      "root_cause_tags": ["idor", "authz", "missing-ownership-check"],
      "severity_floor": "high"
    }
  ],
  "fp_budget": 1
}
```

- **`defects`** — one entry per known defect. `must_detect: true` means the panel is expected
  to find it (a miss is a false negative). `locators` point at the defect in the files as they
  appear in `context.md`'s diff (`line_range` is `[start, end]`, 1-indexed, inclusive).
  `root_cause_tags` are free-form tags the match function (E1-S2) intersects against a
  reviewer's finding. `severity_floor` is the least severity that still counts as a real catch.
- **`fp_budget`** — how many findings are tolerated before an extra one scores as a false
  positive. A `clean` case (`defects: []`) bounds total findings; a defect case bounds findings
  beyond the known set. These are **initial** values; E1-S5 recalibrates them from the first
  real run rather than inventing an aspirational number.

A `clean` case carries `defects: []` (and a small `fp_budget`); every other category needs at
least one `must_detect` defect, or it could never score a true positive. The validator enforces
this.

## Scoring (`score.py`)

`evals/score.py` grades a list of reviewer findings (a report's `findings` array) against a case's
`expected.json`. Every function is pure and stdlib-only, with 100% branch coverage in the offline
suite (`t_eval_score_*`).

**Match rule.** A finding matches a defect when it is in the same file **and** either its cited line
is within a locator's range (±`line_tol`, default 3) **or** the finding's text names one of the
defect's `root_cause_tags` (all of a tag's words appear in the finding's title/evidence/scenario/fix).
Both halves of the OR are needed: an exact-line match is too strict (reviewers cite *near* a defect),
and a bare tag match is too loose (a root-cause word can appear while discussing an unrelated part of
the file — so the tag path still requires the right file). This mirrors Step-4 dedup's "same
component + same root cause", not "same line".

**Outcomes.** For each `must_detect` defect: **TP** if a matching finding meets the `severity_floor`,
**PARTIAL** if matched only below the floor (noticed but under-rated — recorded, not a detection),
**FN** if unmatched. A `must_detect: false` defect is informational (a bonus if matched, never an FN).
Each finding credits **at most one** defect: findings are assigned to defects by maximum bipartite
matching, so one finding that lands near two defects cannot score two detections, while several
findings that genuinely cover several nearby defects still each count.
A **FP** is a finding matching no defect: on a clean case, any finding beyond `fp_budget`; on a defect
case, only an unmatched **high/critical** finding beyond budget (an extra low/medium is noise). `aggregate()`
rolls per-case results up overall and per category/tier; `detection_rate` counts only true positives.

## Add a case in under 10 minutes

1. `mkdir evals/corpus/<case-id>` and add the three files above.
2. Write a minimal, realistic `context.md` with one seeded defect (or none, for a `clean` case).
3. Label it in `expected.json`.
4. Validate: `python3 evals/corpus_schema.py` (exits non-zero and lists every problem if a
   case is malformed). The test suite runs the same validator over the whole corpus, so a bad
   case fails CI.

## Validating

```bash
python3 evals/corpus_schema.py            # validate evals/corpus/
python3 evals/corpus_schema.py <dir>      # validate a different corpus directory
```

The validator reuses `scripts/panel.py:validate_obj` — the same stdlib JSON-schema subset the
panel applies to reviewer reports — so the corpus is held to the pipeline's strictness with no
new dependencies (Python 3.9+, stdlib only).
