# Deterministic gates: tier matrix, commands, thresholds, suppressions

Detect the project's languages, frameworks, and tooling first. Run every applicable gate
for the tier — "applicable" means the technology exists in the repo, not that the tool is
convenient. If a required tool doesn't support the stack, use the best maintained
equivalent and record the substitution in the gate summary. Do not skip a gate because
the stack is unfamiliar.

Every gate goes through `gate.py` so the aggregator can see it:

```bash
python <skill>/scripts/gate.py run --name <gate> [--tier-required NORMAL] -- <command...>
python <skill>/scripts/gate.py record --name <gate> --exit-code <N> --summary "ran in CI: <link>"
```

## Gate matrix

| Gate name | Tier | What / typical command |
|---|---|---|
| `build` | ALL | Clean build (`npm run build`, `cargo build`, `mvn -q package`, …) |
| `format` | ALL | Formatter check mode (`prettier --check`, `black --check`, `gofmt -l`) |
| `lint` | ALL | Project linter (`eslint .`, `ruff check`, `golangci-lint run`) |
| `typecheck` | ALL | `tsc --noEmit`, `mypy`, compiler warnings-as-errors where native |
| `unit` | ALL | Unit tests |
| `integration` | ALL (if present) | Integration tests |
| `secrets` | ALL | `gitleaks detect --no-banner` (files AND git history: `gitleaks git`) |
| `deps` | ALL | `osv-scanner scan .` (vulnerable dependencies) |
| `sast` | ALL | `opengrep scan --config auto .` (or `semgrep scan --config auto`) |
| `iac` | ALL (if IaC present) | `checkov -d .` on Terraform/K8s/Docker/CI configs |
| `e2e` | SENSITIVE+ | End-to-end / browser tests if the project has them |
| `migration` | SENSITIVE+ (if migrations changed) | Apply AND rollback against a scratch DB |
| `mutation` | SENSITIVE+ | Changed-scope only — see below |
| `dast` | CRITICAL (if staging target exists) | `zap-baseline.py -t <staging-url>` — **authorized targets only** |
| `enforcement` | SENSITIVE+ (if repo host in scope) | Branch protection verified via `gh api` |

Mutation testing must be scoped to changed code or it will not survive real repos:
Stryker `--incremental` (JS/TS), PIT incremental analysis / `scmMutationCoverage` (JVM),
`mutmut` scoped by paths to changed modules (Python). Compare against the repository's
threshold; if none exists, propose one to the user rather than inventing a passing one.

## Blocking semantics

Gate status is tri-state. Exit code 0 = PASS. Anything else on a tier-required gate =
FAIL (aggregator enforces). A tier-required gate with no record at all = BLOCKED, and a
gate recorded with `--status BLOCKED` (required coverage that could not be run or
verified: unsupported stack, missing access, unreachable staging) = BLOCKED — unknown
is never recorded as pass or fail. Specifically blocking, per tool:

- Confirmed secret exposure (gitleaks) — also rotate the secret; a removed line does not
  un-leak a key that was committed.
- High/critical SAST findings; critical vulnerable dependencies; high-risk IaC
  misconfiguration; high-confidence DAST findings.
- Failed authn/authz/tenant-isolation tests; unsafe or irreversible migration behavior;
  mutation score below the repository threshold.

Scanner findings below high/critical: triage in the report; not blocking.

## Suppressions

A finding may be suppressed only via an entry in `.adversarial-review/<run>/suppressions.json`:

```json
[{"finding_id": "sast:rule-id:file:line", "evidence": "why this is not exploitable, technically",
  "owner": "name", "expires": "2026-11-01"}]
```

Narrow (one finding ID, not a rule or a directory), technically evidenced, owned, and
expiring — the aggregator rejects expired or incomplete suppressions. Broad ignores
(disabling a rule, raising a threshold, `// nolint` sweeps) are prohibited; if you find
yourself wanting one, the correct move is fixing the findings or getting the user to
accept the risk explicitly, on the record.

## Supply-chain hygiene for the gate tools themselves

Pin external scanners to immutable versions or digests where practical and verify
release signatures/checksums when supported. In CI: minimum workflow permissions, never
expose production secrets to PR-triggered workflows, and never use `pull_request_target`
to execute untrusted changes.
