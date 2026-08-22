# Reviewer meta-evaluation corpus

This directory holds the labeled cases the reviewer panel is measured against: does the
panel actually catch the defects a skeptic cares about, and how often does it cry wolf on
clean code? Each case is **data** — you add one by dropping in a directory, no harness change.

The **case format** and its validator are E1-S1 (`evals/corpus_schema.py`); the **scoring** that
consumes these labels — true-positive / false-negative / false-positive — is E1-S2
(`evals/score.py`, documented below). The offline harness that drives the corpus through the panel
and rolls the scores up per case, category, tier, and reviewer role is E1-S3 (`evals/run.py`,
documented below). That same runner's **live** mode (E1-S4) runs the corpus against real models
for a calibration report (opt-in, spends money) — also documented below.

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

## `scripts.offline` — scripted reviewers for the offline harness

`expected.json` may carry an **optional** `scripts` block. Its `offline` map holds the findings
each reviewer *role* returns when the case is run through the offline meta-eval harness (E1-S3,
`evals/run.py`). Each entry is the scoring-relevant subset of a real reviewer finding; the harness
fills the structural rest before the mock router serves it, so the run still exercises the real
ingest/validation path — offline mode measures **harness correctness**, not model quality.

```json
{
  "defects": [ /* ... */ ],
  "fp_budget": 1,
  "scripts": {
    "offline": {
      "security": [
        { "title": "IDOR: invoice fetched without an ownership check",
          "severity": "high", "file": "api/invoices.py", "line": 11,
          "evidence": "no authz check; missing ownership check enables IDOR" }
      ]
    }
  }
}
```

- Keyed by reviewer role (`security`, `correctness`, `data_privacy`, `test_quality`,
  `reliability`, `output_fidelity`). A role **absent** from the map reviews and finds nothing —
  that is how a case scripts a **deliberate miss** (false negative).
- An extra finding that matches no defect scripts a **false positive**; a finding **below** a
  defect's `severity_floor` scores a **partial**. The six seed cases together exercise every
  outcome (TP / partial / FN / FP / noise) end-to-end.
- `title`, `severity`, `file`, `line` are required per scripted finding; `evidence`/`scenario`
  carry the text the root-cause-tag match scans. `scripts` is optional: a case without it is still
  valid, just not runnable in `--mode offline` (the harness skips it and says so).

## Running the offline harness

```bash
python evals/run.py --mode offline                 # whole corpus -> evals/report/<ts>.json + summary.md
python evals/run.py --mode offline --only sec-idor-invoice
python evals/run.py --mode offline --no-write --print-result   # canonical result JSON to stdout
```

Offline mode drives the **real** panel pipeline (`panel.py assign` → `run` → ingest) against the
in-process mock router with the scripted reviewers, then scores with `score.py` (E1-S2). No network,
no API keys, and deterministic: the same corpus + scripts produce a byte-identical scored `result`
(the timestamp is stamped only outside it). CI runs a fast 2–3 case subset on every push and the
full corpus as a separate `evals` job. Live-model calibration is `--mode live` (next section).

## Running the live calibration (`--mode live`)

Live mode runs the corpus against **real models** to measure the panel's actual efficacy — the
evidence offline mode can't give, since offline serves scripted findings. It is **opt-in and never
in CI**: it needs a provider and it spends money.

```bash
export OPENROUTER_API_KEY=sk-...                    # or AR_API_KEY, or an AR_KEY_FILE path
python evals/run.py --mode live                     # whole corpus, 1 rep/case
python evals/run.py --mode live --reps 3            # 3 panels/case to expose reviewer variance
python evals/run.py --mode live --budget-usd 5 --only sec-idor-invoice
```

- **Provider key required.** Live mode resolves credentials exactly as the panel does
  (`panel.api_config`): an `OPENROUTER_API_KEY`, an `AR_API_KEY`, or an `AR_KEY_FILE` that exists — a
  key is required even behind an `AR_BASE_URL` proxy. With none it exits up front rather than spend a
  run on no-op panels.
- **Budget.** `--budget-usd` (default **$20**) is a cumulative ceiling for the whole run, checked
  before each panel; when it is reached the remaining `(case, rep)` units are recorded in `not_run`
  and the run stops — never a silent partial, and overspend is bounded by the one in-flight panel.
  (This is the harness-level cap; each individual panel still honours its own `AR_MAX_COST_USD`
  ceiling from E4-S2.) Cadence is monthly; the report records the actual spend.
- **Report.** Writes a dated `evals/report/live-<ts>.json` + `live-<ts>.summary.md` with the
  detection rate per **category** and **tier** (where a defect denominator is well-defined), a
  per-**reviewer-role** and per-**model** contribution breakdown (findings emitted, and how many were
  true positives / partials / unmatched — plus cost per model), the clean-case false-positive rate
  (`clean_fp_rate`), cost per case, and per-rep detail so single-run noise stays visible. Per-role and
  per-model FN / detection-rate are intentionally **not** attributed — which role or model *should*
  catch a given defect is not encoded. Each case runs at **its own tier** (a SENSITIVE case gets the
  six-role panel), so per-tier numbers reflect real panels.
- **Not deterministic.** Real models vary run to run, so — unlike offline mode — the live scored
  payload is not byte-identical across runs (that is what `--reps` quantifies). The per-rep raw
  detail is kept so the aggregate stays auditable. The corpus is synthetic and carries no secrets,
  so reports are committable under `evals/report/` as the project's standing evidence base.

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
4. Optional: add a `scripts.offline` block so the case runs in the offline harness (see above).
5. Validate: `python3 evals/corpus_schema.py` (exits non-zero and lists every problem if a
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
