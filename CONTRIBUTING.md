# Contributing

Thanks for looking under the hood. This project is small on purpose — three Python
scripts, a protocol document, and a test suite — so contributions are easy to make and
easy to review.

## Five-minute setup

There is nothing to install. The scripts are Python 3.9+ standard library only, and the
test suite runs against an in-process mock router — no network, no API keys:

```bash
git clone https://github.com/SathiaAI/adversarial-review
cd adversarial-review
python tests/run_tests.py     # must print: N passed, 0 failed
```

If that passes, you have a working development environment.

## Ground rules

These keep the skill portable and the verdict trustworthy. PRs that break them will be
asked to change, however good the idea:

1. **Stdlib-only, Python 3.9-compatible.** Portability is the point — the scripts must
   run anywhere an agent can run Python. No third-party imports, no 3.10+ syntax.
2. **`scripts/aggregate.py` is the enforcement core.** Any change to verdict semantics
   needs a matching regression scenario in `tests/run_tests.py` and a doc update in
   `references/schemas.md`. The suite must stay 100% green on 3.9 and 3.12.
3. **No hardcoded model IDs.** Reviewer models are resolved from the router's live
   catalog at run time by design. Catalogs churn; hardcoded slugs rot.
4. **Never weaken a gate to make something pass.** If a check can't run, the honest
   answer is `--status BLOCKED`, and the code should make honesty the easy path.
5. **Keep `SKILL.md` under ~500 lines.** Detail belongs in `references/`.

`AGENTS.md` carries the condensed version of these rules for coding agents working on
the repo — if you're pointing an agent at this codebase, start it there.

## How pull requests are reviewed

CI (the mocked suite on Python 3.9 and 3.12) is required on every PR — the branch
ruleset will not let anything merge without it.

Substantive changes get the full treatment: they are run through this repository's own
adversarial-review pipeline before merge — deterministic gates, then an independent
panel of reviewer models from provider families that did not author the change, with
the verdict computed by `aggregate.py`. You can see what that looks like in practice in
[PR #3](https://github.com/SathiaAI/adversarial-review/pull/3), where the panel raised
seven findings against the fix and six forced changes. Expect your PR to be reviewed by
models that have no stake in being nice to it. Docs-only changes go through CI alone.

## Cutting a release

Releases are tags; PyPI publishes from them via Trusted Publishing (no stored token).

1. Ensure `main` is green and the change is merged.
2. Bump `version` in `pyproject.toml` (SemVer).
3. In `CHANGELOG.md`, rename the `## [Unreleased]` section to `## [X.Y.Z]`, add a fresh
   empty `## [Unreleased]`, and update the compare/link footer.
4. Confirm `t_version_matches_changelog` passes (the `pyproject` version must equal the newest
   `## [X.Y.Z]` heading in the changelog).
5. Commit the version bump and changelog and merge them to `main` (a release PR), so the tag
   points at a commit that actually contains the bump.
6. Tag `vX.Y.Z` on that merged commit and push the tag. On tag push the release workflow
   (`.github/workflows/release.yml`) builds and publishes to PyPI via Trusted Publishing —
   confirm that workflow is present on `main` first; until it is, a pushed tag publishes
   nothing.

## Commit and PR style

- Small, focused PRs merge fastest. One concern per PR.
- Explain *why* in the commit body; the diff already says *what*.
- If your change was developed with an AI model's help, say which provider family in
  the PR description — it determines who is excluded from the review panel. That is not
  a mark against the PR; hiding it is.

## Ideas that are welcome

Gate adapters for more stacks and CI systems, additional router transports, reviewer
prompt improvements with before/after evidence, red-team scenarios for the test suite
(especially attempts to trick the aggregator), and real-world run reports — what broke,
what the panel caught, what it missed.
