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

## [0.1.0]

### Added
- Initial public release: deterministic gate recorder (`gate.py`), independent multi-model
  reviewer panel (`panel.py`), machine-computed verdict + attestation (`aggregate.py`), and a
  dual-era stdio MCP server (`mcp_server.py`). Zero runtime dependencies, Python 3.9+.

[Unreleased]: https://github.com/SathiaAI/adversarial-review/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/SathiaAI/adversarial-review/releases/tag/v0.1.0
