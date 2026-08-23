# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

The version in `pyproject.toml` and the newest released heading below must always agree —
this is enforced by a regression test (`t_version_matches_changelog` in `tests/run_tests.py`).

## [Unreleased]

### Added
- Detached signature over the verdict (E6-S1): `aggregate.py --sign` writes a detached cryptographic
  signature (`attestation.sig`) over the run's canonical `verdict.json`, and
  `aggregate.py --verify-signature` checks it (exit 0 valid / 1 not verified / 2 missing / 3 no
  verifier). `--sign` and `--verify-signature` are **standalone** post-verdict modes (like
  `--check-digest`): they operate on the existing `verdict.json` and never re-aggregate. Signing the
  canonical `verdict.json` — not merely its input digest — **binds the computed verdict decision**
  (verdict / reasons / coverage) to the signature, so a relabeled verdict no longer verifies; both
  `--sign` and `--verify-signature` first **recompute the attestation** from the artifacts and refuse
  a drifted run, so a tampered input is caught even when the sidecar is untouched and signing never
  silently re-attests changed state. The signature is a sidecar, not a `*.json` file, so it is never
  folded back into the attestation and the digest algorithm is unchanged. The signer/verifier is
  invoked **out-of-process** under a bounded timeout (`AR_SIGN_TIMEOUT`, default 120s; sigstore/cosign
  keyless primary, minisign fallback, `AR_SIGNER_CMD`/`AR_VERIFIER_CMD` override with `{msg}`/`{sig}`
  tokens), preserving the stdlib-only runtime contract; no signer, a malformed command template, a
  signer that cannot start, or a subprocess timeout all fail loudly (exit 3) rather than silently
  skipping. cosign keyless verification requires `AR_COSIGN_IDENTITY` + `AR_COSIGN_ISSUER` (else it is
  not auto-selected); a minisign public key is supplied inline via `AR_MINISIGN_PUBKEY` (`-P`) or as a key file via `AR_MINISIGN_PUBKEY_FILE` (`-p`) — the key is never chosen by probing the filesystem.
  Documented in `references/config.md` (with the outside-verifier path) and `references/schemas.md`.
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

[Unreleased]: https://github.com/SathiaAI/adversarial-review/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/SathiaAI/adversarial-review/releases/tag/v0.1.0
