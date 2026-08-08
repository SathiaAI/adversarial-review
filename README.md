# Adversarial Review

**Multi-model adversarial code review with a deterministic, machine-computed release verdict.**

[![tests](https://github.com/SathiaAI/adversarial-review/actions/workflows/ci.yml/badge.svg)](https://github.com/SathiaAI/adversarial-review/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue)
![stdlib only](https://img.shields.io/badge/dependencies-stdlib%20only-brightgreen)
[![GitHub stars](https://img.shields.io/github/stars/SathiaAI/adversarial-review?style=social)](https://github.com/SathiaAI/adversarial-review/stargazers)

> **Dogfooded from day one:** every substantive change to this repo has to pass its own
> multi-model panel before it merges — real models, real findings, real verdicts.
> [See the receipts ↓](#proven-on-itself-the-first-real-runs)

A portable agent skill that answers one question honestly: **is this change actually safe to ship?**
It combines deterministic verification (build, tests, SAST, secrets, dependencies, mutation, DAST)
with an independent panel of reviewer models from providers that did **not** write the code —
and the final PASS / FAIL / BLOCKED verdict is computed by a script from recorded artifacts,
never narrated by a model.

Works in **Claude Code**, **Claude (Cowork)**, **OpenAI Codex CLI**, and any agent platform
that reads `SKILL.md` — the scripts are plain Python 3.9+, standard library only.

---

## Why this exists

When an AI model writes code and then reviews its own work, you get the fox auditing the
henhouse. Asking the same model "are you sure?" produces confidence, not verification.
This skill enforces three structural rules instead:

1. **Separation of duties.** Reviewer models are resolved at run time from the router's
   live catalog, and every provider family involved in planning, coding, debugging, or
   advising the change is excluded from the panel. Provider independence is *computed from
   model IDs*, not self-declared.
2. **A deterministic floor.** AI approval can never override a failing build, test, or
   scanner. Every check is recorded as an artifact with an exit code and tri-state status.
3. **A computed verdict.** `aggregate.py` alone emits PASS / FAIL / BLOCKED (exit 0 / 1 / 2)
   from the recorded artifacts. The orchestrating model relays it verbatim. "Never
   reinterpret FAIL as probably-fine" is enforced by architecture, not by asking nicely.

## How it works

```mermaid
flowchart LR
    A[init\nrisk tier, dev providers] --> B[Deterministic gates\ngate.py: build, tests,\nSAST, secrets, deps, mutation]
    A --> C[Panel assign\nlive catalog, exclude dev\nfamilies, collision-free roles]
    C --> D[Independent reviews\n3-5 models, strict JSON,\ninjection-hardened prompts]
    D --> E[Rebuttal round\nrefute / corroborate / extend\nwith evidence]
    E --> F[Validate findings\nreproduce, fix, concurrence\nfor dismissals]
    B --> G[aggregate.py\ncomputed verdict]
    F --> G
    G --> H{{PASS / FAIL / BLOCKED\nexit 0 / 1 / 2}}
```

Every step writes JSON artifacts to `.adversarial-review/<run-id>/` (gates, reviewer
reports, rebuttals, validation records, suppressions). The aggregator consumes those files
and nothing else — an unrecorded fact does not exist for verdict purposes. Completed runs
are immutable audit records — and provably so: every verdict embeds a **coverage**
manifest of what the run did and did not verify, plus a tamper-evident **attestation**
digest over the entire recorded run
([details ↓](#whats-inside-verdictjson-coverage-and-attestation)).

### The reviewer panel

Roles: **security**, **correctness**, **data/privacy**, **test quality**, **reliability**
(3 roles at NORMAL risk, all 5 at SENSITIVE/CRITICAL). Each role goes to a distinct
provider family, assigned greedily with collision-free re-solving after any failure or
substitution. Fewer independent families than required → **BLOCKED**, unless a degraded
panel is explicitly authorized on the record.

Reviewers get low temperature, strict JSON schemas (enforced via `response_format:
json_schema` where the endpoint supports it, validated locally always), one retry on
malformed output, and provider substitution on transport failure. Prompts wrap all
repository content in randomized untrusted-data boundaries; content that tries to
instruct the reviewers is itself reported as a high-severity finding. Every reviewer must
attest what it reviewed, what it could not review, and its top residual risks — a lazy
"LGTM" is malformed output.

When high/critical findings exist, a **rebuttal round** makes the panel adversarial
rather than merely parallel: reviewers see each other's findings and must refute,
corroborate, or extend them with evidence. Disputes are settled by reproduction, never by
vote.

### What the aggregator refuses to accept

These are tested behaviors, not aspirations (see `tests/run_tests.py`, 30 scenarios):

| Attempt | Outcome |
|---|---|
| Skip a required gate, or record one without an exit code | BLOCKED |
| Record a gate that couldn't run as "passed" | BLOCKED (`--status BLOCKED` is required honesty) |
| Failing gate anywhere in the required set | FAIL |
| Panel smaller than the tier requires, or a dev-family model on it | BLOCKED |
| Two roles served by the same provider family | BLOCKED |
| High/critical finding with no validation record | BLOCKED |
| Dismiss a high/critical finding without independent concurrence | BLOCKED |
| Concurrence from the finding author's own family or a dev family | BLOCKED |
| "Fixed" without rerunning the affected gates | FAIL |
| Reviewer-flagged release-blocking finding left untriaged (any severity) | BLOCKED |
| Accepted risk without a narrow, owned, unexpired suppression | FAIL |
| Skipping the rebuttal round when policy requires it | BLOCKED |
| Edit, add, or remove any recorded artifact after the verdict is computed | `--check-digest` exits 1 and names each drifted file |

## Proven on itself: the first real runs

This repository is gated by the skill it ships. The first two production runs are public,
linkable, and unedited — the run history *is* the case study.

**Run 1 — the panel found a real bug in its own plumbing.** Reviewing
[PR #1](https://github.com/SathiaAI/adversarial-review/pull/1) (a docs patch) with a live
3-family panel over the Composio MCP transport, both keyless-path reviewers failed strict
JSON validation on their first attempt. Root cause: the MCP tool schema silently strips
`response_format`, so the "provided schema" the prompt referenced never reached the
models. That observation became
[issue #2](https://github.com/SathiaAI/adversarial-review/issues/2) — filed with the
failure evidence and a control group from the same run.

**Run 2 — the skill reviewed its own fix, and pushed back.** The fix for issue #2 went
through the full pipeline in
[PR #3](https://github.com/SathiaAI/adversarial-review/pull/3): five deterministic gates,
then an independent panel of `google/gemini-3.6-flash` (security),
`mistralai/mistral-small-2603` (correctness), and `qwen/qwen3.6-flash` (test quality) —
deliberately the same three models as Run 1, making it a controlled A/B on the fix
itself.

| What happened | Numbers |
|---|---|
| First-attempt schema-valid reviews, before → after the fix | **0/2 → 2/2** |
| Findings raised by the panel against its author's own fix | **7** (3 high, 3 medium, 1 low) |
| Findings that survived triage and forced code/doc/test changes | **6 confirmed** across 3 records — an input guard, a documented prompt-budget policy, and closed test-coverage gaps |
| Findings dismissed | **1**, as an evidence-backed false positive (per-request random boundaries make the claimed collision impossible) |
| The aggregator blocking its own author | **Once** — `BLOCKED: gate plan missing` when the operator skipped `gate.py plan`; the step was completed and re-aggregation earned the PASS |
| Total panel cost | **$0.038** |
| Final verdict, computed by `aggregate.py` | **PASS** (exit 0) — then, and only then, merged |

Three details worth noticing: the panel's high findings were real enough to change the
code; a wrong finding could not be waved away — dismissal required written evidence
against the concrete claim; and the pipeline blocked *its own author* for a process skip
with zero pushback, because the verdict is computed, not negotiated.

## How it compares

| | "Are you sure?" self-review | CI scanners alone | Single-model AI PR bots | **adversarial-review** |
|---|---|---|---|---|
| Reviewer independent of the code's author | ✗ same model | n/a | ✗/partial — one vendor, often the authoring family | ✓ computed from model IDs; authoring families excluded |
| Multiple model perspectives | ✗ | ✗ | ✗ | ✓ 3–5 distinct provider families, per-role rubrics |
| Deterministic floor AI cannot override | ✗ | ✓ | ✗ advisory comments | ✓ gates recorded as artifacts; FAIL is FAIL |
| Final verdict | vibes | per-tool exit codes | prose | ✓ one machine-computed PASS / FAIL / BLOCKED |
| "Couldn't verify" distinct from "passed" | ✗ | ✗ | ✗ | ✓ tri-state; unknown = BLOCKED = unshippable |
| Audit trail | ✗ | partial | vendor-hosted | ✓ immutable JSON artifacts per run |
| Runs in Claude Code / Codex / any SKILL.md agent | — | — | ✗ SaaS | ✓ one folder, stdlib-only Python |

These categories complement each other — keep your scanners; this skill is the layer
that makes their results *and* the AI review converge into one honest verdict.

## Quickstart

```bash
export OPENROUTER_API_KEY=sk-or-...

# from your repository root
python <skill>/scripts/panel.py init --risk SENSITIVE --dev-providers anthropic \
    --diff-ref "main...HEAD" --product "my-service"
python <skill>/scripts/gate.py plan --require build,lint,typecheck,unit,secrets,deps,sast
python <skill>/scripts/gate.py run --name unit -- npm test        # one per gate
python <skill>/scripts/panel.py assign
python <skill>/scripts/panel.py run --context-file context.md      # your diff + context
python <skill>/scripts/panel.py rebuttal                           # when findings exist
python <skill>/scripts/aggregate.py                                # the only verdict
```

`context.md` is the review bundle: requirements, invariants, the full diff, relevant
surrounding code, tests, and migrations. The protocol for assembling it — and for
validating findings afterward — is in [SKILL.md](SKILL.md).

Expected on a first dry run with no gates recorded: **BLOCKED**. That is the system
working — it does not guess.

## Installation

The whole skill is one folder. `SKILL.md` is the entry point on every platform.

**Claude Code / Claude (Cowork)**

```bash
git clone https://github.com/SathiaAI/adversarial-review ~/.claude/skills/adversarial-review
```

**OpenAI Codex CLI** (global, or per-project)

```bash
git clone https://github.com/SathiaAI/adversarial-review ~/.codex/skills/adversarial-review
# or inside a project:
git clone https://github.com/SathiaAI/adversarial-review .agents/skills/adversarial-review
```

Invoke with `$adversarial-review`, browse via `/skills`, or let implicit matching trigger
it. `agents/openai.yaml` provides the Codex display metadata.

**Cursor, Copilot, Antigravity, and other SKILL.md-compatible agents** — clone into the
platform's skills directory; the format is identical. **Any other agent**: point it at
`SKILL.md` as instructions ([AGENTS.md](AGENTS.md) has the short version); the scripts
run anywhere Python 3.9+ runs.

## Keys and transports

Four ways to reach reviewer models, resolved in order (details in
[references/config.md](references/config.md)):

| Option | How | Notes |
|---|---|---|
| OpenRouter key | `OPENROUTER_API_KEY` | Default; full provider routing + privacy controls |
| Key file | `AR_KEY_FILE=~/.config/adversarial-review/key` | Keeps keys out of shell history |
| LiteLLM / any OpenAI-compatible proxy | `AR_BASE_URL` + `AR_API_KEY` | Your own provider keys behind your gateway |
| MCP transport (e.g. Composio), no local key | `panel.py prepare` → execute via MCP → `panel.py ingest` | Same validation and verdict path; see privacy note |

Privacy routing is automatic by risk tier: SENSITIVE requests carry
`data_collection: "deny"`; CRITICAL adds `zdr: true` (zero-data-retention endpoints
only), per OpenRouter's provider routing and ZDR enforcement. MCP transport routes
content through the MCP provider's infrastructure — confirm that is acceptable before
using it for SENSITIVE/CRITICAL changes.

## Risk tiers and gates

| Tier | Panel | Gates |
|---|---|---|
| NORMAL | 3 reviewers | build, format, lint, typecheck, unit, integration, secrets (gitleaks), deps (osv-scanner), SAST (opengrep/semgrep), IaC (checkov) |
| SENSITIVE | 5 reviewers | + e2e, migration/rollback tests, changed-scope mutation testing |
| CRITICAL | 5 + rebuttal always in scope | + authorized OWASP ZAP against staging, branch-protection enforcement check |

Mutation testing is scoped to changed code (Stryker `--incremental`, PIT incremental
analysis, path-scoped mutmut) so the gate survives real repositories. A minimum gate
floor per tier cannot be silently dropped — only waived on the record with a named
authorizer, which the verdict surfaces.

**Rebuttal policy** (`--rebuttal-policy` at init, or `AR_REBUTTAL`): `critical` |
`contention` (default: SENSITIVE + CRITICAL) | `any`. In every mode the round only runs
when there are high/critical findings to contest — cost scales with contention.

## Verdict semantics

- **PASS** (exit 0) — every tier-required gate recorded and passing; panel complete and
  provably independent; every high/critical or release-blocking finding validated with a
  compliant record.
- **FAIL** (exit 1) — a recorded gate failed, or a confirmed-unfixed / unresolved /
  improperly-accepted finding exists.
- **BLOCKED** (exit 2) — required verification is missing or incomplete. BLOCKED is not
  "probably fine"; it means *you do not know*. The gate treats unknown as unshippable.

Wire it into CI: run the aggregator as the last step and let the exit code gate the
deploy. `verdict.json` (machine) and `verdict.md` (human) land in the run directory.

### What's inside verdict.json: coverage and attestation

Beyond the verdict itself, every aggregation embeds two blocks that make the audit
record self-describing and self-verifying:

```jsonc
"coverage": {                       // what this run did and did not verify
  "risk": "NORMAL",
  "gates": {"plan_recorded": true, "required": [...], "passed": [...],
            "failed": [], "blocked": [], "missing": [], "waived": [...]},
  "panel": {"roles_required": [...], "roles_filled": [...],
            "degraded": null, "dev_families_excluded": ["anthropic"]},
  "rebuttal": {"policy": "contention", "required": false, "ran": false},
  "findings": {"raised": 8, "triaged": 8, "untriaged_release_blocking": 0},
  "areas_not_reviewed": ["union of the reviewers' own attestations"]
},
"attestation": {                    // tamper-evident digest over the recorded run
  "algorithm": "sha256-canonical-json-v1",
  "inputs": 27,
  "digest": "1f58da91…",
  "files": {"run.json": "…", "gates/unit.json": "…"}
}
```

**Coverage** is assembled exclusively from recorded artifacts — the same inputs as the
verdict — so an unrecorded fact is absent here too, never inferred. It is present on
every aggregation, including FAIL and BLOCKED; CI consumers can read `gates.missing`,
`gates.blocked`, and `rebuttal {"required": true, "ran": false}` as the specific
unknowns behind a BLOCKED verdict.

**Attestation** is a reproducible SHA-256 over every recorded `*.json` artifact except
`verdict.json` itself. Artifacts are canonicalized (sorted keys, compact separators),
so cosmetic re-serialization is not tampering, while a file that fails UTF-8 decoding
or JSON parsing hashes over its raw bytes instead of crashing the aggregator.
Re-aggregating an untouched run reproduces the digest bit-for-bit, and anyone holding
the run directory can verify it:

```bash
python scripts/aggregate.py --check-digest
# attestation OK: sha256 1f58da91… over 27 artifacts        → exit 0
#   DRIFT modified gates/deps.json                          → exit 1, each file named
```

## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `OPENROUTER_API_KEY` | — | Direct OpenRouter credential |
| `AR_KEY_FILE` | — | Path to a file containing the key |
| `AR_BASE_URL` | `https://openrouter.ai/api/v1` | Any OpenAI-compatible router |
| `AR_API_KEY` | — | Key for `AR_BASE_URL` |
| `AR_TRANSPORT` | auto | `http` or `mcp` |
| `AR_PRIVACY` | by tier | `default`, `deny`, `zdr` |
| `AR_TEMPERATURE` | `0.1` | Reviewer sampling temperature |
| `AR_MAX_TOKENS` | `8000` | Reviewer response cap |
| `AR_TIMEOUT_S` | `240` | Per-request timeout |
| `AR_RUN_DIR` | `.adversarial-review` | Artifact root |
| `AR_PINS` | — | `role=provider/model-slug` overrides |
| `AR_REBUTTAL` | `contention` | Rebuttal policy |

No model IDs are hardcoded anywhere: reviewers resolve from the router's live `/models`
catalog at run time (floating aliases, `:free` routes, and previews are filtered out),
and the exact resolved IDs are pinned into the run's `plan.json` for the audit record.

## Testing

```bash
python tests/run_tests.py
```

30 end-to-end scenarios against an in-process mock router — no network, no API keys:
role assignment and collision-resolution under multi-provider exclusions, degraded-mode
authorization, malformed-JSON retry, dead-provider substitution, the full verdict matrix,
rebuttal policies, suppression expiry, and the keyless MCP prepare/ingest path. CI runs
the suite on Python 3.9 and 3.12.

## Repository layout

```
SKILL.md              # canonical protocol (all platforms)
AGENTS.md             # condensed instructions for AGENTS.md-reading agents
CONTRIBUTING.md       # dev setup, ground rules, how PRs get (adversarially) reviewed
SECURITY.md           # how to report vulnerabilities, incl. prompt-injection bypasses
agents/openai.yaml    # Codex display metadata
scripts/
  panel.py            # catalog resolution, role assignment, reviewer calls, rebuttal, concurrence
  gate.py             # deterministic gate runner/recorder (tri-state: PASS/FAIL/BLOCKED)
  aggregate.py        # the only thing that can emit a verdict
references/
  config.md           # keys, transports, privacy, env vars
  gates.md            # gate matrix, thresholds, suppression rules, supply-chain hygiene
  roles.md            # role rubrics, prompt contract, injection defense
  schemas.md          # artifact schemas and blocking rules
  report.md           # final report template
tests/                # mock router + 24-scenario suite
```

## Security notes

Repository content shown to reviewers is delimited as untrusted data with per-run
randomized boundaries; prompt-injection attempts are reported as findings (see OWASP's
LLM Top 10, LLM01). Secrets, `.env` files, and production data must never enter review
context or artifacts. The skill never merges, pushes, publishes, or deploys — verdicts
gate those actions, humans authorize them.

## Contributing

Contributions welcome — [CONTRIBUTING.md](CONTRIBUTING.md) has the five-minute setup
(no dependencies to install) and the ground rules. The short version: run the test
suite, keep the scripts stdlib-only, and pair any verdict-semantics change with a
regression test. Substantive PRs are reviewed the only way this repo knows how: by an
independent multi-model panel, with the verdict computed. Security reports:
[SECURITY.md](SECURITY.md) — prompt-injection bypasses of the review boundaries are
explicitly in scope and especially welcome.

## Star history

If independent, computed verdicts are how you think AI code review should work, a ⭐
helps other engineers find this.

[![Star History Chart](https://api.star-history.com/svg?repos=SathiaAI/adversarial-review&type=Date)](https://star-history.com/#SathiaAI/adversarial-review&Date)

## License

[MIT](LICENSE) © 2026 SathiaAI.
