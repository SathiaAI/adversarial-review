# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

The version in `pyproject.toml` and the newest released heading below must always agree —
this is enforced by a regression test (`t_version_matches_changelog` in `tests/run_tests.py`).

## [Unreleased]

### Fixed
- **`ar-mcp` follow-up on the #7c review (PR #24, merged before its review landed; refined again after the CodeRabbit + Codex review of the follow-up PR #55).** Hardened the MCP tool handlers in `scripts/mcp_server.py`:
  - **`ar_init` returns the run it created**, parsed from the **basename of the run-dir path** in `panel.py init`'s stdout (`initialized <path>`), instead of the lexicographically-newest `run-*` directory or the first `run-…` substring in stdout — a directory scan races a concurrent init and mis-sorts `run-…-9` vs `run-…-10`, and an unanchored substring search would match a `run-YYYYMMDD-HHMMSS` segment inside `AR_RUN_DIR` or any ancestor directory. The "newest run" fallback sorts the `-N` disambiguator numerically too.
  - **Every `ar_*` tool that targets a run resolves the newest run once and passes it as an explicit `--run` to every subprocess.** `mcp_server`'s numeric run ordering (`run-…-10` > `run-…-9`) otherwise diverges from `panel.py`/`aggregate.py`'s lexicographic newest-sort, so `ar_panel_run` could write `context.md` into one run while reviewer artifacts and the verdict landed in another. Resolving once and pinning `--run` keeps every pipeline phase on a single audit record and closes the concurrent-init TOCTOU uniformly.
  - **`ar_aggregate` never surfaces a stale verdict**: it moves any pre-existing `verdict.json` **aside** before invoking `aggregate.py` and requires a recognized exit code (0/1/2) plus a **newly written** `verdict.json` — proving freshness by the new file's existence rather than an mtime bump (which a coarse-granularity filesystem can leave unchanged on a same-quantum rewrite). An aggregation that crashes without recomputing is an error (and the prior verdict is restored), not an apparently-successful pre-existing `PASS`.
  - **`ar_check_digest`** distinguishes intact (`0`) / drifted (`1`) / cannot-verify (`2` = no verdict or no attestation → tool error), instead of collapsing a missing verdict into a false `{"intact": false}`.
  - **`ar_panel_rebuttal` added** — the rebuttal round is now reachable over MCP (keyless `prepare=true` writing per-reviewer request bodies for `ar_panel_ingest phase="rebuttal"`, or a direct HTTP call), so an MCP-only host can carry a SENSITIVE/CRITICAL run with high/critical findings to a verdict instead of staying BLOCKED.
  - **`authorized_by` must be a non-empty string** across `ar_gate_plan` / `ar_gate_record` / `ar_panel_assign`: a schema-invalid value (bool/number/list) is rejected rather than stringified (e.g. `true` → `"True"`) into a named authorizer that waives a gate.
  - **`catalog_file` confinement** now also rejects Windows-absolute paths (drive letter, backslash, UNC), and — beyond the lexical checks — **resolves the path (following symlinks) and rejects any target outside the working tree**, so a relative path that is itself a symlink to an out-of-tree file cannot make the CLI read it. **`ar_panel_run` forwards `catalog_file`** so a reviewer substitution can resolve when the live catalog is unavailable.
  - **A falsy non-`dict` `arguments`** (`[]`, `""`, `0`, `false`) on `tools/call` is now a `-32602` error instead of being silently defaulted to `{}`.
  - The **panel-run wrapper timeout scales with `AR_TIMEOUT_S`** budgeted for `panel.py`'s true worst case — up to **8 request budgets per role** (2 outer attempts × a corrective-JSON retry × a provider substitution) across up to 6 roles — so a legitimately slow-but-valid run is not killed before its retry/substitution protocol finishes.
  - Removed the **hardcoded model slug** from the `ar_panel_assign` tool schema (a concrete `provider/model` goes stale and steers hosts to pin it); uses a `<provider>/<model-slug>` placeholder.
  - **Durability + integrity hardening from the latest review round (CodeRabbit + Codex on PR #55, plus a dev-side Fable pass):**
    - `ar_aggregate`'s prior-verdict restore is now **crash-durable**: when `verdict.json` cannot be moved aside to `.prev`, the prior is snapshotted to a durable `verdict.json.bak` **before** aggregation (an in-memory copy alone was lost if the process died mid-run or the write-back itself failed), and a restore failure that occurs **while another error is unwinding** (e.g. a subprocess timeout) is now folded into that error instead of silently dropped — so a client is never told only "aggregate timed out" while its accepted verdict sits stranded and `ar_get_verdict` can no longer return it.
    - `ar_check_digest` treats a **missing or typo'd run** as a tool error, not a false `{"intact": false}` (a nonexistent run makes `aggregate.py` exit 1 — the same code as real drift); and a **pathologically deep `verdict.json`**, whose parse raises `RecursionError` (a `RuntimeError` subclass, not `ValueError`), is cannot-verify (exit 2), never a crash the wrapper reads as drift. `aggregate.py`'s attestation over recorded artifacts likewise raw-hashes a `RecursionError`-deep artifact instead of crashing aggregation.
    - `mcp_server` puts its own directory on `sys.path` (as `panel.py` / `aggregate.py` do) so the in-process `catalog_file` validation and policy `high_samples` timeout budgeting work under the `ar-mcp` console-script entry point too — not only when the module is launched by file path.
    - Run-directory selection anchors `RUN_RE` with `\Z` instead of `$` (which also matches just before a trailing newline): a crafted `run-…\n` directory in the untrusted repository tree can no longer pass `RUN_RE.match`, sort "newest", and redirect every run-pinned tool to that non-minted directory. And `ar_panel_run` rejects a `catalog_file` that is not a regular file before loading it, so a FIFO in the working tree can no longer block the in-process catalog load — which no `_run_cli` timeout guards — and hang the server.
    - Lower-severity follow-ups from the dev-side pass: a run killed between a move-aside and its settle leaves the prior at `verdict.json.prev`, which the next `ar_aggregate` adopts and restores; a rejected aggregate now names *why* (stale / malformed / unrecognized / wrong-run); and `authorized_by` is trimmed of surrounding whitespace before it enters the audit record.
    - Corrections from the CodeRabbit + Codex review of that round (commit `9b93b4c`): `ar_aggregate` **refuses to aggregate unpinned** — with no run passed and none yet minted it errors (`call ar_init first`) rather than resolving the newest run itself, since an unpinned resolve lets a run a concurrent caller inits in the meantime be aggregated (and its `verdict.json` mutated) by a call that never selected it; every aggregate now carries an explicit `--run`, which subsumes fix-15's accept-time run-dir pin (that fixed only *which* verdict got surfaced, not the concurrent mutation — CodeRabbit's merge-risk). A successful `ar_init` whose stdout can't be parsed for the run id now **returns a tool error** (the new run is on disk under the run root) instead of falling back to a newest-run directory scan that re-opened the concurrent-scan race and could hand back a valid-looking *wrong* id.
    - Corrections from the CodeRabbit + Codex review of that round (commit `274b460`): a recovery sidecar (`verdict.json.prev`/`.bak`) already present next to `verdict.json` is now **refused**, not silently reconciled. Such a sidecar is ambiguous — it is *either* a crash mid-settle (the sidecar is the last accepted verdict and `verdict.json` the crashed output) *or* a **successful** aggregate whose best-effort sidecar cleanup failed (`verdict.json` is the newer accepted verdict and the sidecar is obsolete) — and disk state cannot tell the two apart. fix-16's preserve-and-track guessed "crash" and, in the second case, rolled a newer accepted verdict **back** to an older one on a later rejection (a newer FAIL reverted to an older PASS); the rename fallback likewise overwrote an existing good `.bak`, destroying the last accepted verdict (both Codex). `ar_aggregate` now refuses at entry when a sidecar **file** is present — leaving both files for the operator to reconcile so nothing is rolled back or lost — while the unambiguous crash-recovery path (`verdict.json` absent, a stranded `.prev`) still auto-recovers, and a stray `.prev` *directory* still falls through to the move-aside fallback. Two recovery error messages were also sharpened (CodeRabbit): `ar_init`'s unparseable-stdout hint now names the actual run root (`AR_RUN_DIR` when set, not a hardcoded `.adversarial-review/`) so it never points at an empty directory, and the snapshot-failure error now includes the underlying `OSError` cause (the `tools/call` path sends only the message text to clients).
    - Correction from the Codex review of that round (commit `8c999b9`): `aggregate.py`'s attestation is now **byte-identical across Python versions**. It hashes each recorded artifact by canonicalizing it (`json.loads` → sorted, compact JSON) and falls back to a raw-byte hash when that fails — but whether a deeply nested artifact *failed* was decided by `json.loads` raising `RecursionError`, a threshold that differs by Python version, so the same 20,000-level artifact hashed canonically on one interpreter and raw on another and a verdict made under one version reported false `DRIFT modified` when checked under another (Codex reproduced this across 3.13 and 3.14). The canonical-vs-raw choice is now made from a **fixed, version-independent nesting-depth cap** measured from the bytes *before* parsing, so an artifact takes the same path — and yields the same digest — on every interpreter; real artifacts (a handful of levels deep) are canonicalized exactly as before.

## [0.2.0]

### Added
- **Experimental local Streamable-HTTP transport for `ar-mcp` (E3-S2a).** `AR_MCP_TRANSPORT=http` (or `--http`) starts a stdlib `http.server` MCP endpoint that reuses the same `serve_message()`/`handle()` dispatch as stdio: a **POST** carrying JSON-RPC returns `application/json` for a response or **202** for a notification; requests are `Origin`-validated (DNS-rebinding defense) and the listener binds `127.0.0.1` by default — a **non-loopback bind is refused** (there is no auth yet), so the endpoint cannot be exposed to the network from here. Non-POST methods → `405`, an oversized body → `413`, an unsupported `MCP-Protocol-Version` → `400`, and a rejected request closes its connection (no keep-alive desync). **No authentication or session yet** — it is localhost-only (enforced) and MUST NOT be exposed remotely until the auth sub-story (E3-S2c) lands; `stdio` stays the default. New env: `AR_MCP_HTTP_HOST` / `AR_MCP_HTTP_PORT` / `AR_MCP_HTTP_ORIGINS` / `AR_MCP_HTTP_MAX_BYTES`. Still **not** a command-execution surface.
- Multi-sample corroboration of high/critical findings (E4-S3): the opt-in `AR_HIGH_SAMPLES=N`
  (integer, default `1`; also the policy key `high_samples`) makes `panel.py run` re-run any role
  that raised a `high`/`critical` finding to `N` low-temperature samples and record a
  `corroboration: {samples, agreed, rate}` object on that finding — the share of samples whose own
  high/critical findings match it (same file + similar title via a `difflib` ratio). Only flagged
  roles are resampled, each sample is recorded under `panel/samples/` (with cost metered under
  `panel/meta/`, honoring the per-run cost cap — a resample that would cross the cap records a
  `corroboration`-phase `cost_abort.json` and BLOCKS rather than overspend), and `N=1` is a strict
  no-op (byte-identical reviewer artifacts). The agreement rate is **informational only**:
  `aggregate.py` alone still decides the verdict, so disagreement never overrides the gate. See
  `references/config.md`. Review hardening (CodeRabbit + Codex on #48): `high_samples` is validated
  at policy-load exactly as `panel.py run` resolves it (`int(str(value))`), so an integral-looking
  float (`3.0`, `1e1`) that `init` would accept can no longer be rejected later at `run`; a plain
  `run` resume no longer re-buys corroboration samples (only roles produced in that invocation are
  resampled, so recorded cost can't undercount real spend); the `corroboration` object is declared in
  the finding schema so an enriched report stays schema-valid; the resolved count + source are
  persisted to `sample_policy.json` (even at the default `1`) for the audit; a cost-cap abort during
  corroboration names every later flagged role it skipped; and the keyless prepare/ingest (MCP) path
  now surfaces that corroboration is not applied there instead of silently ignoring `high_samples`.
- Release hygiene: this changelog and a "cutting a release" ritual in `CONTRIBUTING.md`.
- Documentation drift guards: `tests/run_tests.py` now asserts the gate matrix in
  `references/gates.md` stays consistent with `MINIMUM_GATES` in `scripts/gate.py`, and that
  no hardcoded test-scenario counts are reintroduced into the README.
- Test-harness seam: `tests/mock_router.py` supports a swappable `response_provider` and a
  `reset()` helper, so future suites can inject per-scenario reviewer responses without
  forking the request handler.
- Model-capability profile: `scripts/_common.py` can resolve a per-model capability profile
  (catalog defaults merged with an optional `.adversarial-review.capabilities.yml` and an
  `AR_CAP_OVERRIDES` env override), laying the groundwork for capability-driven request
  building.
- Reviewer meta-evaluation corpus (E1-S1): a versioned, self-describing case format under
  `evals/corpus/<case-id>/` (`meta.json` / `context.md` / `expected.json`) with a stdlib
  validator (`evals/corpus_schema.py`) that reuses the panel's schema checker, seed cases
  across every defect category plus clean cases, an `evals/README.md`, and CI coverage. This
  is the groundwork for measuring the panel's true-positive / false-negative / false-positive
  rates (scoring lands in E1-S2).
- Reviewer meta-evaluation scoring (E1-S2): `evals/score.py` grades reviewer findings against the
  corpus ground truth. A finding matches a defect when it is in the same file **and** either its
  cited line is within a locator's range (±`line_tol`, default 3) **or** the finding's text names one
  of the defect's `root_cause_tags` — file-overlap is required even on the tag path, so a root-cause
  word in the wrong file is not a match (neither line-only nor tag-only is sufficient on its own).
  Scoring is severity-aware: a `must_detect` defect matched at/above its `severity_floor` is a true
  positive, a match below the floor is a **partial** (noticed but under-rated, not a detection), an
  unmatched one is a false negative; a `must_detect: false` defect is informational. A false positive
  is a finding matching no defect — any finding beyond `fp_budget` on a clean case, or an unmatched
  high/critical one beyond budget on a defect case (an extra low/medium is noise). `aggregate()` rolls
  per-case results up overall and per category/tier. Pure, stdlib-only, 3.9-safe, 100% branch-covered
  offline (`t_eval_score_*`); the offline harness that drives it is E1-S3 (below).
- Reviewer meta-evaluation offline harness (E1-S3): `evals/run.py --mode offline` drives the **real**
  panel pipeline (`panel.py assign` → `run` → ingest) over the corpus against the in-process mock
  router, serving each case's scripted reviewer findings — a new optional `scripts.offline` block in
  `expected.json` — through the E0-S1 `response_provider`, then scores the ingested findings with
  `evals/score.py`. It emits a dated `evals/report/<ts>.json` plus a human-readable `summary.md` with
  true-positive / partial / false-negative / false-positive metrics overall and per category and tier,
  plus a per-reviewer-role breakdown (findings emitted, and how many were true positives, partials, or
  unmatched — per-role FN/FP are not attributed, since which role should catch a given defect is not
  encoded). Because reviewer outputs are scripted, it measures harness correctness, not
  model quality (live calibration is E1-S4); a role omitted from a case's script is a deliberate miss
  and an extra finding is a false positive, so the seed corpus exercises every scoring outcome
  end-to-end. Deterministic (same corpus + scripts → byte-identical scored `result`; wall-clock
  stamped only outside it), stdlib-only, 3.9-safe, no network and no keys. A fast 2–3 case subset runs
  in the suite on every push; the full corpus runs as a separate CI `evals` job. This change also
  **restores the `t_eval_score_*` scorer tests** (100% branch coverage) that the E1-S2 (#44) merge
  dropped from `tests/run_tests.py` — `evals/score.py` had shipped to `main` untested — so the scorer
  the harness relies on is verified again.
- Reviewer meta-evaluation live calibration (E1-S4): `evals/run.py --mode live` runs the corpus
  through **real** model panels (`--reps N` per case) over the configured transport, scoring each
  panel's ingested findings with `evals/score.py`. Unlike offline mode it serves no scripts and starts
  no mock router — reviewers answer for real — so it measures model + panel quality, not just harness
  assembly. It emits a dated `evals/report/live-<ts>.json` + `live-<ts>.summary.md` with the detection
  rate per category and tier, a per-reviewer-role and per-model contribution breakdown (findings
  emitted / true positives / partials / unmatched, plus cost per model), the clean-case false-positive
  rate (`clean_fp_rate`), cost per case, and per-rep detail so single-run noise stays visible (per-role
  and per-model FN / detection-rate are not attributed — which role/model should catch a defect is not
  encoded); each case runs at its own tier (a SENSITIVE
  case gets the six-role panel). A cumulative USD budget (`--budget-usd`, default **$20**) caps the
  whole run: checked before each panel, and when reached the remaining `(case, rep)` units are recorded
  in `not_run` and the run stops — never a silent partial, overshoot bounded by the one in-flight
  panel; each individual panel still honours its own `AR_MAX_COST_USD` cap (E4-S2). Opt-in and never in
  CI: it needs a provider key resolved the same way the panel resolves it (`OPENROUTER_API_KEY` /
  `AR_API_KEY` / an existing `AR_KEY_FILE`; required even behind an `AR_BASE_URL` proxy) and exits
  rather than spend a run on no-op panels without one. Live results are non-deterministic by nature (the per-rep raw detail
  keeps the aggregate auditable); the harness code itself is exercised offline against the mock router
  with no network and no keys. Regression thresholds seeded from the first live report are E1-S5.
- Reviewer meta-evaluation regression thresholds (E1-S5): `evals/thresholds.json` records **descriptive**
  floors and `evals/thresholds.py` enforces them. `thresholds.py check` runs the offline harness and fails
  (exit 1) when the overall or per-category detection rate drops below, or the false-positive count rises
  above, the committed floor, so a change to `score.py`, the corpus scripts, or the panel wiring that
  quietly weakens detection is caught in CI (the `evals` job now runs it on 3.9 and 3.12). Because offline
  serves scripted findings this guards harness/scorer/dispatch correctness, not model quality; the floors
  are seeded from the current deterministic offline run (overall detection >= 0.5 and <= 1 FP; security and
  correctness >= 1.0) and are updated deliberately, never invented (mirrors the mutation-threshold rule in
  `references/gates.md`). `thresholds.py compare` is the **model-degraded alarm**: it diffs two live
  calibration reports and flags any overall/per-category detection drop past `live.max_detection_drop`
  (default 20%) plus any model whose true-positive contribution fell — a candidate for pin removal /
  substitution — with a runbook in `evals/README.md`. The baseline live report is committed after the first
  live calibration (the E1-S4 $20 run). Stdlib-only, 3.9-safe.
- Distribution: a `release` workflow publishes to PyPI on a `v*` tag via **Trusted Publishing**
  (OIDC, no stored token); an `action-selftest` workflow exercises the composite action keyless
  and asserts the honest BLOCKED verdict; a GitLab CI template (`examples/.gitlab-ci.yml`); and a
  `Changelog` project URL.
- CI-integration guide + Marketplace steps (E2-S3): a new `docs/ci-integration.md` presents **both**
  the GitHub Action and the GitLab template together — the Action's real inputs (`risk`,
  `dev-providers`, `gates`, `fail-on`, `diff-ref`, `product`, `openrouter-api-key`) and outputs
  (`verdict`, `exit-code`), the keyless→BLOCKED path, the verdict→exit-code (`0`/`1`/`2`) contract,
  and an Action-input↔GitLab-variable mapping. It also documents the remaining **manual** GitHub
  Marketplace publishing steps a maintainer performs by hand (publish from the repo's Releases page,
  choose categories, and adopt a moving `v1` major tag; branding already lives in `action.yml`),
  since Marketplace listing cannot be automated from this repo. Referenced from `README.md`,
  `docs/using-on-your-platform.md`, and the docs-site footer. A `t_ci_docs_and_gitlab_mirror_action`
  guard test asserts the guide names every real `action.yml` input and output (no invented inputs),
  proves `aggregate.py` is ar-panel's terminal command (so the job exit code is the verdict), and
  locks in the secrets-transmission guard and the full-floor starter workflow below.
  Review hardening (CodeRabbit + Codex on #49): the composite **`action.yml` now gates diff
  transmission to the reviewer panel on a passing `secrets` gate** — mirroring the GitLab job, so a
  correctly-configured secrets scan is required before the diff is transmitted, and every
  gate/panel/aggregate step is
  pinned with `--run` to the exact run directory `panel.py init` created, so a repository-committed
  `.adversarial-review/run-*` in the checkout cannot forge the secrets gate or hijack the pipeline;
  the documented starter workflow
  configures the whole NORMAL floor (build/unit/secrets/deps/sast) with explicit `risk`/`dev-providers`
  so it is a complete, safe copy; and the guide now distinguishes the computed **verdict / `exit-code`**
  from the **job pass/fail status** that `fail-on` (GitHub) / `allow_failure` (GitLab) derive from it,
  noting that a failed deterministic gate takes precedence over BLOCKED.
- Reviewer robustness & cost control (E4): `build_request` is now capability-driven — a model whose
  profile forbids `temperature` is sent none, `max_tokens` is floored at the profile's
  `max_tokens_floor`, and a mandatory-reasoning model receives a `reasoning` budget
  (`AR_REASONING_EFFORT`, default `high`); a profile's `structured_outputs` flag overrides the
  catalog's in either direction (so a wrong catalog can't force an unsupported `response_format`);
  and a model with an all-default profile gets the byte-identical request it did before — the
  pre-E4 key order (`temperature` before `max_tokens`) is preserved, not just the values. A per-run
  cost ceiling (`AR_MAX_COST_USD`, or policy `max_cost_usd`, default `$20`) is enforced as a
  pre-call gate across **every** paid phase — panel, rebuttal, and concurrence — aborting the
  remaining calls once reached (each phase records its own skipped work), recording a BLOCKED cost
  reason, and surfacing the run's total. The cap the run records in `cost_policy.json` is
  authoritative for the whole run: rebuttal and concurrence reuse it rather than re-resolving live
  settings, so changing `AR_MAX_COST_USD` mid-run can neither disable nor raise it. Also surfaced:
  `cost_usd` plus the enforced `cost_cap_usd`/`cost_cap_source` on the verdict; a verbose model can
  raise the bill but never buy a silent partial PASS. Cost accounting is hardened end to end: a
  malformed-JSON retry (a second billed call) is fully counted, the MCP-ingest path's nested
  `usage.cost` is read, non-finite/negative per-reviewer costs are metered as `$0`, and a
  non-finite or negative cap is rejected at policy load and at resolution rather than silently
  disabling the guard. The new `coverage.cost_usd` / `cost_aborted` / `cost_cap_usd` /
  `cost_cap_source` fields and the cost-triggered BLOCKED reason are documented in
  `references/schemas.md`; being a pre-call gate (not a reservation), the recorded total can
  overshoot the cap by up to the in-flight reviewer's cost, as `references/config.md` now states.

### Changed
- MCP server transport seam (E3-S1): the stdio framing in `scripts/mcp_server.py` is extracted
  into a `StdioTransport` class around a transport-agnostic `serve_message()` core, leaving the
  `handle()` dispatch untouched. Framing is byte-identical for well-formed and ordinarily-malformed
  messages (`-32700` parse errors, `-32603` handler-crash containment, notification suppression);
  the extracted parse guard catches every malformed-input failure `json.loads` can raise — a
  `JSONDecodeError`, a `RecursionError` from pathologically nested input, and a `UnicodeDecodeError`
  from bad bytes — and frames each as `-32700` instead of letting it escape and kill the loop
  (closing a pre-existing gap), so the seam's "a single malformed message never kills the transport"
  guarantee holds for the stdio loop and for the byte-oriented Streamable-HTTP transport (E3-S2) that
  will reuse the exact dispatch and error semantics. Stdlib-only, 3.9-safe.

## [0.1.0]

### Added
- Initial public release: deterministic gate recorder (`gate.py`), independent multi-model
  reviewer panel (`panel.py`), machine-computed verdict + attestation (`aggregate.py`), and a
  dual-era stdio MCP server (`mcp_server.py`). Zero runtime dependencies, Python 3.9+.

[Unreleased]: https://github.com/SathiaAI/adversarial-review/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/SathiaAI/adversarial-review/releases/tag/v0.2.0
[0.1.0]: https://github.com/SathiaAI/adversarial-review/releases/tag/v0.1.0
