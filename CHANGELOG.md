# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

The version in `pyproject.toml` and the newest released heading below must always agree —
this is enforced by a regression test (`t_version_matches_changelog` in `tests/run_tests.py`).

## [Unreleased]

### Added
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
  remaining calls once reached, recording a BLOCKED cost reason, and surfacing the run's total
  `cost_usd` plus the enforced `cost_cap_usd`/`cost_cap_source` on the verdict; a verbose model can
  raise the bill but never buy a silent partial PASS. Cost accounting is hardened end to end: a
  malformed-JSON retry (a second billed call) is fully counted, the MCP-ingest path's nested
  `usage.cost` is read, non-finite/negative per-reviewer costs are metered as `$0`, and a
  non-finite or negative cap is rejected at policy load and at resolution rather than silently
  disabling the guard. The new `coverage.cost_usd` / `cost_aborted` / `cost_cap_usd` /
  `cost_cap_source` fields and the cost-triggered BLOCKED reason are documented in
  `references/schemas.md`; being a pre-call gate (not a reservation), the recorded total can
  overshoot the cap by up to the in-flight reviewer's cost, as `references/config.md` now states.

## [0.1.0]

### Added
- Initial public release: deterministic gate recorder (`gate.py`), independent multi-model
  reviewer panel (`panel.py`), machine-computed verdict + attestation (`aggregate.py`), and a
  dual-era stdio MCP server (`mcp_server.py`). Zero runtime dependencies, Python 3.9+.

[Unreleased]: https://github.com/SathiaAI/adversarial-review/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/SathiaAI/adversarial-review/releases/tag/v0.1.0
