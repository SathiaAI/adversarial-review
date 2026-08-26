# Configuration: credentials, transports, privacy

## Credential and transport options (in resolution order)

The panel scripts need a way to reach reviewer models. Four options, checked in this
order by `panel.py`; the first one that resolves wins unless overridden with
`AR_TRANSPORT`:

1. **Direct OpenRouter key (default)** — set `OPENROUTER_API_KEY`. Simplest; full
   support for provider routing, privacy controls, and live catalog resolution.
2. **Key file** — set `AR_KEY_FILE` to a path (e.g.
   `~/.config/adversarial-review/openrouter_key`) containing only the key. Keeps the key
   out of shell history and session env dumps. File should be `chmod 600`.
3. **Any OpenAI-compatible proxy (LiteLLM, etc.)** — set `AR_BASE_URL` (e.g.
   `http://localhost:4000/v1`) and `AR_API_KEY`. The scripts use the standard
   `/models` and `/chat/completions` endpoints. Note: OpenRouter-specific `provider`
   routing preferences (privacy pinning, fallback control) are still sent but a non-
   OpenRouter proxy may ignore them — you own privacy routing at the proxy config level.
4. **MCP transport, no local key (e.g. Composio)** — set `AR_TRANSPORT=mcp` or simply
   have no key configured. `panel.py prepare` writes complete request bodies to
   `panel/requests/<role>.json`; the agent executes each through an available MCP that
   can reach OpenRouter or the target providers (for Composio: search its tool catalog
   for an OpenRouter / chat-completions execute tool, pass the prepared payload
   verbatim, save the raw JSON response to a file), then `panel.py ingest` validates it.
   Catalog resolution needs a model list: if the MCP can fetch
   `https://openrouter.ai/api/v1/models`, save it to a file and pass
   `panel.py assign --catalog-file <path>`.

   Some MCP tool schemas silently drop `response_format` (and `provider` preferences)
   from the payload — observed with Composio's OpenRouter chat-completions tool — so
   server-side strict JSON enforcement never reaches the model on this path. Two
   mitigations are built in: every request `build_request` produces carries the full
   JSON schema inlined in the system message (so the model sees it even when
   `response_format` is stripped), and `panel.py ingest` validates locally against the
   same schema, which remains the guarantee regardless of transport. If ingest reports
   errors, send them back to the model for one corrective round, then re-ingest.

   Prompt budget: the inlined schema adds roughly 600-900 tokens per request, and
   `AR_MAX_TOKENS` caps the completion, not the prompt. Context assembly (Step 1)
   owns the prompt budget — if context plus schema exceeds the model's window,
   OpenRouter rejects the request with an explicit context-length error (a loud
   transport failure that surfaces through retry/substitution, not a silent pass).
   Keep `context.md` comfortably below the smallest panel model's window. Reasoning
   models spend completion tokens on hidden reasoning before emitting JSON; if a
   reviewer returns `finish_reason: length` with empty content, raise `AR_MAX_TOKENS`
   and re-run that role rather than treating it as a malformed report.

Never paste API keys into chat transcripts or commit them. Never put keys in the run
artifacts — the scripts don't, and you shouldn't either.

## Privacy tiers

- NORMAL: default routing.
- SENSITIVE: requests carry `provider: {"data_collection": "deny"}` automatically.
- CRITICAL: requests carry `provider: {"data_collection": "deny", "zdr": true}` —
  OpenRouter then routes only to zero-data-retention endpoints and refuses otherwise.
  Set `AR_PRIVACY=zdr|deny|default` to override in either direction (overriding *down*
  for SENSITIVE/CRITICAL requires user authorization; record it in the report).

MCP transport caveat: request content transits the MCP provider's infrastructure
(e.g. Composio) in addition to the model provider. For SENSITIVE/CRITICAL changes,
confirm with the user that this is acceptable before using MCP transport, or use a
direct key. ZDR guarantees only hold on the direct OpenRouter path.

## Policy file: repo-versioned defaults

Review standards can live with the code they govern: `.adversarial-review.yml` (or
`.adversarial-review.json` — keep exactly one) at the reviewed repo's root supplies
defaults to `panel.py init`, `gate.py plan`, and `panel.py assign` pins.

```yaml
risk: SENSITIVE            # default tier for this repo
dev_providers: [anthropic] # always-excluded families
rebuttal_policy: contention
required_gates:
  NORMAL: [build, unit, secrets, deps, sast]
  SENSITIVE: [build, unit, secrets, deps, sast, mutation]
pins: {}                   # role: provider/model-slug
mutation:                  # scoped/bounded mutation budget (all fields optional)
  scope: changed           # changed | all
  threshold: 60            # min kill-rate %
  max_mutants: 500         # cap total mutants (budget)
  sample_pct: 100          # % of eligible mutants to test
  concurrency: 4           # parallel test runners (memory lever)
  timeout_s: 60            # per-mutant timeout
  exclude_files: []        # globs never mutated
  exclude_tests: []        # tests dropped from the mutant run
```

The `mutation:` block is a repo-tunable cost cap so mutation testing survives large or
resource-constrained repos (see `references/gates.md`, *Scoped & bounded mutation*). Every
field is optional and validated strictly; the configured budget is snapshotted into
`policy.snapshot.json`, so a bounded run's coverage reduction is on the record, never
silent. `scope` is `changed`/`all`; `max_mutants`/`concurrency`/`timeout_s` are positive
integers; `sample_pct`/`threshold` are numbers in `[0, 100]`; `exclude_files`/
`exclude_tests` are lists of path/glob strings.

Precedence, everywhere: **CLI flag > env var > policy file > built-in default** —
explicit beats ambient. The resolution is recorded in the run's artifacts so the
audit trail shows where every setting came from: `run.json` gets a `sources` block
(`cli|env|policy|default` per setting) and a `policy` block (file name + sha256), the
exact policy text is snapshotted into `policy.snapshot.json` (covered by the
attestation digest), `gates/_required.json` records `requested_source`, and pinned
roles in `panel/plan.json` record `pin_source`.

Guarantees, enforced by regression tests:

- **Missing file** — behavior identical to a repo without one: `init` still demands
  risk and dev providers from a flag or env var, `plan` still demands `--require` or
  `AR_REQUIRE`. Nothing becomes silently optional.
- **Malformed file** — a loud error, never a silent fallback, even when CLI flags
  would have sufficed. Unknown keys, invalid values, bad indentation, and both file
  variants present at once all refuse to run.
- **No coercion** — every scalar parses as a string; there is no yes/no-boolean or
  version-number-becomes-float YAML footgun.

The YAML parser is a deliberately strict stdlib-only subset: `key: value` scalars,
inline `[a, b]` lists, `- item` block lists, ONE nested mapping level, `{}` for an
empty map, `#` comments. Anchors, aliases, tags, multiline blocks, deeper nesting,
and tab indentation are errors that name the unsupported construct. If you need
richer structure, use `.adversarial-review.json` (parsed with `json.loads`).

`required_gates` is a per-tier map; the entry matching the run's tier is used. A
missing tier entry simply means "not provided" and resolution falls through to the
next source. Tier floors from `references/gates.md` are always unioned in regardless
of source — a policy file can add gates, never remove floors.

## Model capability profiles

Some model quirks the live catalog can't express — a model that *rejects* `temperature`, one
with *mandatory* reasoning that needs a larger completion budget, or a slow tier — can be
declared per model. A profile has: `temperature` (`supported`/`forbidden`/`default`),
`structured_outputs` (bool), `reasoning` (`none`/`optional`/`mandatory`), `max_tokens_floor`
(positive int or null), `latency_class` (`fast`/`slow`/null), and `notes`.

Defaults are derived from the catalog's `supported_parameters`. Override them in an optional
`.adversarial-review.capabilities.yml` (or `.json`) at the repo root, keyed by model slug,
and/or via `AR_CAP_OVERRIDES=<path>`. Precedence is **catalog < file < env** (env wins per
key). The file uses the same strict YAML subset as the policy file; unknown keys or bad
values fail loudly.

```yaml
# .adversarial-review.capabilities.yml
openai/gpt-5.6-luna-pro:
  temperature: forbidden        # this model rejects the temperature parameter
qwen/qwen3.8-2.4t-a95b:
  reasoning: mandatory
  max_tokens_floor: 32000       # reasoning models need headroom before they emit JSON
```

Profiles are resolved at `assign` and recorded on `panel/plan.json`; `build_request` consumes
them: a `temperature: forbidden` model is sent no `temperature`, `max_tokens` is floored at the
profile's `max_tokens_floor`, and a `reasoning: mandatory` model receives a `reasoning` budget
(`AR_REASONING_EFFORT`, default `high`). A model with an all-default profile is sent exactly the
request it was before.

## Per-run cost cap

`panel.py run` enforces a per-run USD ceiling as a **pre-call gate** — not a reservation. Before
each paid reviewer call — across the panel, rebuttal, and concurrence phases — the cost recorded so
far (summed from `panel/meta/*.json`) is compared against the cap; once it is reached the remaining
calls are **not run**, a `cost_abort.json` is recorded, and the run exits BLOCKED. Because the check
runs *before* each call and a call's cost is only known *after* it returns, a reviewer already in
flight can overshoot: the recorded total can exceed the cap by up to one reviewer's cost (e.g. a
`$0.60` cap may record ~`$1.00` before aborting). The cap bounds how many further calls are made,
not the exact dollar total. The incomplete panel makes `aggregate.py` report BLOCKED with an
explicit cost reason, and the run's total `cost_usd` — together with the enforced `cost_cap_usd`
and `cost_cap_source` — is surfaced on the verdict coverage: a verbose model can raise the bill but
can never buy a silent partial PASS. Precedence is `AR_MAX_COST_USD` > policy `max_cost_usd` >
default **`$20`**; set any of them to `0`, `none`, `off`, or `unlimited` to disable. A non-finite or
negative value is rejected loudly (it would otherwise silently remove the guard). A provider that
omits `cost` is metered as `$0`.

## Multi-sample corroboration of high/critical findings

`AR_HIGH_SAMPLES=N` (integer, default **`1`**) makes `panel.py run` **corroborate** high/critical
findings across `N` low-temperature samples: after the primary review, each such finding is
re-sampled and its cross-sample agreement rate is recorded on the finding. It is **informational
only** — it enriches findings after they are raised and never changes the gate; a single primary
high/critical finding still gates, whatever its agreement rate.

- **`N=1` (default) changes no reviewer output**: no resampling happens and no `corroboration`
  field is written, so every reviewer report is byte-identical to pre-E4-S3. (`run` still records
  the resolved `sample_policy.json` — value `1`, source `default` — as it does at any `N`; see below.)
- With `N>1`, after every primary reviewer completes, each role that raised a `high`/`critical`
  finding (only those roles — a thin loop, not the whole panel) is re-run to `N` total samples.
  Each extra sample is recorded under `panel/samples/<role>.<i>.json` (its raw response and cost
  metadata alongside the primary, under `panel/raw/` and `panel/meta/`), so the agreement rate
  reproduces from the recorded artifacts.
- Each flagged finding gains a `corroboration` object: `{ "samples": N, "agreed": k, "rate": k/N }`.
  `agreed` counts the samples whose own high/critical findings **match** this one; sample 1 is the
  primary report itself, so it always counts. Two findings match when they cite the **same file**
  (case-insensitive) **and** their titles are similar — a `difflib` ratio ≥ `0.6` over
  whitespace/case-normalized titles. A sample that fails to produce a valid report simply does not
  match, which honestly lowers the rate.
- **The verdict is unchanged.** `aggregate.py` alone decides PASS/FAIL/BLOCKED from the recorded
  artifacts; a low agreement rate is **not** a majority-vote override and never flips the gate. The
  agreement rate is recorded for downstream variance measurement, not for gating.
- **Cost-aware.** Resamples are billed calls that count against and honor the per-run cost cap
  (see *Per-run cost cap*): each sample is gated *before* the call, and if the cap is already
  reached the resampling stops, records a `cost_abort.json` with phase `corroboration`, and the run
  exits BLOCKED — a resample never silently exceeds the ceiling. Because it runs only after every
  primary report is complete, corroboration never starves primary coverage of the budget.

Precedence is `AR_HIGH_SAMPLES` > policy `high_samples` > default **`1`**. The value is validated
identically at policy load (`init`) and at `run` — an integer in `[1, 25]`; an integral-looking
float such as `3.0` or `1e1` is rejected in **both** places, so a value that passes `init` can never
be rejected later at `run`. The resolved count and its source are recorded to `sample_policy.json`
in the run directory (even at the default `1`), so the audit shows exactly which value applied.

**Transport scope.** Corroboration resampling runs only on the direct-HTTP `panel.py run` path. The
keyless `panel.py prepare` + `ingest` (MCP) transport does **not** take corroboration samples; when
`AR_HIGH_SAMPLES > 1` is set, `ingest` prints a note saying so rather than silently ignoring it.

## Environment variables

| Variable | Default | Purpose |
|---|---|---|
| `OPENROUTER_API_KEY` | — | Direct OpenRouter credential |
| `AR_KEY_FILE` | — | Path to file containing the key |
| `AR_BASE_URL` | `https://openrouter.ai/api/v1` | OpenAI-compatible router base URL |
| `AR_API_KEY` | — | Key for `AR_BASE_URL` (falls back to OpenRouter key) |
| `AR_TRANSPORT` | auto | `http` or `mcp` |
| `AR_MCP_TRANSPORT` | `stdio` | `ar-mcp` transport: `stdio` (default) or `http` (experimental **local** Streamable-HTTP endpoint, E3-S2a/b — sessions but no auth yet, localhost-only, never expose remotely). Also selectable with `--http`. |
| `AR_MCP_HTTP_HOST` | `127.0.0.1` | Bind host for the `http` transport. Keep it loopback until auth lands. |
| `AR_MCP_HTTP_PORT` | `8730` | Bind port for the `http` transport (`0` = OS-assigned). |
| `AR_MCP_HTTP_ORIGINS` | — | Comma list of allowed `Origin` values (DNS-rebinding defense). An absent Origin (non-browser client) is allowed; any *present* Origin must be listed, else `403`. |
| `AR_MCP_HTTP_MAX_BYTES` | `1048576` | Max POST body bytes for the `http` transport; a larger declared length is refused with `413`. |
| `AR_MCP_HTTP_MAX_SESSIONS` | `128` | Max concurrent Streamable-HTTP sessions (E3-S2b). The store evicts the least-recently-used id past this bound, so an `initialize` flood cannot exhaust memory. |
| `AR_MCP_HTTP_REQUIRE_SESSION` | off | When on (`1`/`true`/`yes`/`on`), every `http` request except the `initialize` handshake and the `server/discover` probe must carry a valid `Mcp-Session-Id`, else `400` (E3-S2b). Off by default (the stateless path keeps working); intended to default on with the bearer token in E3-S2c. |
| `AR_PRIVACY` | by tier | `default`, `deny`, or `zdr` |
| `AR_TEMPERATURE` | `0.1` | Reviewer sampling temperature |
| `AR_MAX_TOKENS` | `8000` | Reviewer response cap (floored per model by `max_tokens_floor`) |
| `AR_REASONING_EFFORT` | `high` | Reasoning budget for models whose profile marks `reasoning: mandatory` |
| `AR_MAX_COST_USD` | `20` | Per-run USD ceiling (pre-call gate across panel/rebuttal/concurrence/corroboration; BLOCKS the remaining calls once reached and may overshoot by the in-flight call). `0`/`none`/`off`/`unlimited` disables; non-finite/negative is rejected. Also settable via the policy key `max_cost_usd`. |
| `AR_HIGH_SAMPLES` | `1` | Number of low-temperature samples to corroborate each high/critical finding (see *Multi-sample corroboration*). `1` = today's behavior (no resampling). Informational-only: records an agreement rate, never changes the verdict. Resamples honor `AR_MAX_COST_USD`. Also settable via the policy key `high_samples`. |
| `AR_TIMEOUT_S` | `240` | Per-request timeout |
| `AR_RUN_DIR` | `.adversarial-review` | Artifact root |
| `AR_RISK` | — | Default risk tier for `init` (below `--risk`, above policy) |
| `AR_DEV_PROVIDERS` | — | Comma list of dev families for `init` (below flag, above policy) |
| `AR_REQUIRE` | — | Comma list of gates for `plan` (below `--require`, above policy) |
| `AR_PINS` | — | Comma list `role=model-slug` to pin specific models |
| `AR_REBUTTAL` | `contention` | Rebuttal policy at init: `critical`, `contention`, `any` |
| `AR_CAP_OVERRIDES` | — | Path to a capability-overrides file (see *Model capability profiles*) |
| `AR_SIGNER_CMD` | auto | `aggregate.py --sign` signer command template (`{msg}`/`{sig}` tokens); overrides cosign/minisign auto-detect (see *Signing the verdict*) |
| `AR_VERIFIER_CMD` | auto | `aggregate.py --verify-signature` verifier command template (`{msg}`/`{sig}` tokens); overrides auto-detect |
| `AR_MINISIGN_KEY` | — | Path to a minisign secret key; enables the minisign signing fallback |
| `AR_MINISIGN_PUBKEY` | — | minisign **inline** public-key value for `--verify-signature` (`-P`) |
| `AR_MINISIGN_PUBKEY_FILE` | — | Path to a minisign public-key **file** for `--verify-signature` (`-p`); wins over `AR_MINISIGN_PUBKEY` when both are set |
| `AR_SIGN_TIMEOUT` | `120` | Bounded timeout (seconds) for each signer/verifier subprocess; expiry converts to the tooling-error exit (3) |
| `AR_COSIGN_IDENTITY` | — | Expected signer identity (SAN) for cosign keyless `--verify-signature` |
| `AR_COSIGN_ISSUER` | — | Expected OIDC issuer for cosign keyless `--verify-signature` |

An empty env var counts as unset. Note one precedence fix shipped with the policy
feature: `--pin` now beats `AR_PINS` for the same role (previously the env var
silently won), matching the CLI-over-env rule above.

## Live test (first-time setup check)

From a repo with a trivial change and `OPENROUTER_API_KEY` set:

```bash
python <skill>/scripts/panel.py init --risk NORMAL --dev-providers anthropic --diff-ref "HEAD~1...HEAD"
python <skill>/scripts/panel.py assign          # should print 3 role→model assignments, all distinct families
python <skill>/scripts/panel.py run --context-file context.md
python <skill>/scripts/aggregate.py             # BLOCKED at this point is correct — no gates recorded yet
```

Success criteria: assign produces collision-free families excluding yours; run writes
validated JSON per role under `panel/`; aggregate refuses to PASS without gate records.
