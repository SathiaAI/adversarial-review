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
| `ai-defects` | ALL | Phantom references / invented APIs — see [The ai-defects gate](#the-ai-defects-gate) |
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

## The ai-defects gate

AI-generated code has a defect class deterministic tools can catch before the panel
spends tokens on it: phantom references (calls to helpers that do not exist), invented
package APIs, impossible dependency versions, unfinished stubs. `ai-defects` is a
**category, not a vendor** — the protocol hardcodes no model IDs and hardcodes no tool
IDs.

What it verifies: that symbols, APIs, and dependency versions referenced in changed
code actually exist — to the depth the chosen tool can see. A strict type-checker
catches most phantom references in typed code; dynamically-typed call patterns and
invented package APIs are exactly what the deeper verifiers below exist for. Baseline:
the stack's type-checker/compiler in strict mode, scoped to the diff. Example tools
per ecosystem (any maintained equivalent qualifies; record substitutions in the gate
summary as usual):

- **Python** — `pyright --strict` or `mypy --strict` on changed modules. Dependency
  existence: `pip check` validates the installed environment;
  `pip install --dry-run -r requirements.txt` runs the full resolver, so an
  unsatisfiable or nonexistent version set fails loudly at resolution
- **TypeScript/JS** — `tsc --noEmit` under `strict`, or ESLint with `no-undef` +
  `import/no-unresolved`. Dependency existence: `npm install --dry-run` (full tree
  resolution) or `npm ls` for consistency of the installed tree
- **Go** — `go vet ./...` plus `staticcheck ./...` (`go build` itself already refuses
  unknown symbols)
- **Rust** — `cargo check` (the compiler is this gate) plus `cargo clippy -- -D warnings`
- **JVM** — the build's compile step with `-Werror` plus Error Prone (or a comparable
  compile-time checker)

Deeper options: any AI-code-verification tool that emits an exit code (skylos-class
verifiers) — adopted by command, never by name in the protocol. Recorded like every
gate, so the aggregator can see it:

```bash
python <skill>/scripts/gate.py run --name ai-defects -- \
  bash -c 'files=$(git diff --name-only main...HEAD -- "*.py"); \
           if [ -z "$files" ]; then echo "no python files changed"; \
           else pyright --strict $files; fi'
```

(The guard matters: with an empty file list, bare `pyright --strict $(...)` would fall
back to scanning the whole project — wrong scope, and a false FAIL on an unrelated
tree. Filenames with spaces need `-z`/`xargs -0` variants.)

Recommended at NORMAL and above, like `sast`. Standard tri-state semantics apply:
nonzero exit on a required `ai-defects` gate = FAIL; tooling unavailable on the stack ⇒
`gate.py record --name ai-defects --status BLOCKED --summary "<what could not run>"` or
an on-record waiver (`gate.py plan --waive ai-defects --authorized-by "<user>"`) —
never silence. `MINIMUM_GATES` floors are unchanged (promoting `ai-defects` into the
floors would be a separate, breaking decision), and no aggregator change is involved —
gates are already tool-agnostic commands with exit codes.

## The enforcement gate: 404 is not "absent"

Branch-protection verification (the `enforcement` gate, SENSITIVE+) has one recurring
trap worth calling out because it produces a confident-but-wrong record: a **404 from
the classic protection endpoint is ambiguous**. It means any of "no classic protection
configured," "a ruleset applies instead of classic protection," or "the token cannot see
the repository." (Insufficient permission on a *visible* repo returns 403, not 404 — so
neither status proves absence.) Never record a 404 as protection confirmed-absent. The
skill does not — and cannot — introspect a token's grants; the operator confirms scope
out of band. Query `repos/{owner}/{repo}/rules/branches/{branch}` as well, and treat
protection as verified-absent **only** when, under a token confirmed to carry
`admin:repo`, the classic endpoint 404s AND `rules/branches` returns an empty list; a
non-empty `rules/branches` means ruleset protection is active (present, not absent). If
scope is unconfirmed, or the secondary query itself fails or is ambiguous, the honest
record is `--status BLOCKED` — unknown is not pass, and a permission gap must never read
as a clean bill of health. See `SKILL.md`, Step 5.

## Blocking semantics

Gate status is four-state. Exit code 0 = PASS. Anything else on a tier-required gate =
FAIL (aggregator enforces). A tier-required gate with no record at all = BLOCKED, and a
gate recorded with `--status BLOCKED` (required coverage that could not be run or
verified: unsupported stack, missing access, unreachable staging) = BLOCKED — unknown
is never recorded as pass or fail.

The fourth state is **`NOT_APPLICABLE`** — a required gate that genuinely does not exist
for this stack (a config-only repo has no build to run, no unit suite to execute). It is
distinct from BLOCKED on purpose: BLOCKED means "should exist but I couldn't verify it"
and restricts the verdict; NOT_APPLICABLE means "there is nothing here to verify" and does
**not** restrict it, so a genuinely config-only repo can reach a clean PASS. That is not a
self-service skip: `gate.py record --name build --status NOT_APPLICABLE --authorized-by
"<user>" --summary "<why this stack has no build gate>"` requires a named authorizer and a
reason, the aggregator BLOCKS an N/A record missing either, and every N/A gate is listed
with its authorizer in the verdict — accountable and never silent. (Contrast with
`plan --waive`, which drops a gate from the required set entirely; NOT_APPLICABLE keeps it
on the record as an explicit, attributed determination — prefer it when the gate is simply
inapplicable to the stack.) Floors are unchanged: an N/A floor gate is still *required to
be addressed*, just addressed as inapplicable-with-accountability rather than skipped.

Specifically blocking, per tool:

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
