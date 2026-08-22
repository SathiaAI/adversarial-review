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

## Signing the verdict (detached signature)

Every aggregation records a tamper-evident **attestation digest** — a reproducible SHA-256 over
the run's recorded `*.json` artifacts (see `references/schemas.md`). `--check-digest` proves those
bytes have not drifted *since the verdict was computed*, but it proves nothing about **who** stands
behind them. `aggregate.py --sign` closes that gap: it produces a **detached cryptographic
signature over the run's `verdict.json`**, so a third party who never ran the pipeline can verify
both that the run is intact **and** that a specific identity signed this exact verdict.

```bash
python <skill>/scripts/aggregate.py                      # aggregate first: writes verdict.json
python <skill>/scripts/aggregate.py --sign               # then sign: writes attestation.sig
python <skill>/scripts/aggregate.py --verify-signature   # 0 valid, 1 not verified, 2 missing, 3 no verifier
```

Design guarantees (each enforced by a regression test):

- **Standalone, not a re-aggregation.** `--sign` and `--verify-signature` are post-verdict modes
  (like `--check-digest`): they operate on the **existing** `verdict.json` and never re-run the
  aggregation. Adding a signature changes no verdict or attestation state, and the verdict never
  depends on whether a signature exists.
- **Signs the verdict decision, not only its input digest.** The signed message is the canonical
  `verdict.json` (sorted keys; the non-reproducible `computed_at` excluded so re-aggregating an
  untouched run reproduces the signable bytes). This binds the computed **verdict / reasons /
  coverage** and the attestation digest together — a relabeled verdict (`BLOCKED`→`PASS`) no longer
  verifies, even though the input artifacts are untouched.
- **Refuses to sign — and to accept — a drifted run.** Before signing, `--sign` recomputes the
  attestation from the on-disk artifacts and **refuses** (exit 1) unless it still matches the digest
  recorded in `verdict.json`; it never silently re-attests changed state. `--verify-signature`
  performs the same recompute, so a tampered **input** artifact fails verification even when the
  sidecar and `verdict.json` are untouched.
- **The signature is a sidecar, not an attested input.** It is written as `attestation.sig`
  alongside `verdict.json`. Because it is not a `*.json` file, the attestation (which hashes only
  `*.json`) never folds it back in — `--check-digest` stays intact with the sidecar present, and
  re-aggregating an untouched run reproduces the same digest. The signature is **not** self-attesting.
- **Zero runtime dependency preserved.** The signer is invoked **out-of-process** via `subprocess`
  under a bounded timeout (`AR_SIGN_TIMEOUT`, default 120s — a hung signer converts to the
  tooling-error exit rather than wedging the gate); `scripts/*.py` import no third-party signing
  library. cosign / minisign are executed, never imported.
- **Fails loudly, never silently.** No signer/verifier available, a malformed `AR_SIGNER_CMD` /
  `AR_VERIFIER_CMD` template (unbalanced quotes), a signer that cannot start, or a subprocess
  timeout all exit non-zero (**3**) with a clear message and write no signature — never a silent
  skip, never a false success.

**Signer resolution** (first match wins):

1. **`AR_SIGNER_CMD`** — an explicit command template, the override and the test seam. `{msg}` is
   substituted with a temp file holding the canonical `verdict.json` to sign; `{sig}` with the path
   the detached signature must be written to. A template with no `{sig}` token has its signature
   read from stdout instead; a template with unbalanced quotes exits 3.
   Example: `AR_SIGNER_CMD='cosign sign-blob --yes --bundle {sig} {msg}'`.
2. **cosign, keyless (primary)** — auto-detected when `cosign` is on `PATH`. Uses
   `cosign sign-blob --yes --bundle {sig} {msg}`: an ephemeral Fulcio certificate tied to an
   ambient OIDC identity plus a Rekor transparency-log entry, packaged into one self-contained
   `--bundle` sidecar. No long-lived private key to manage — ideal for CI with an OIDC identity.
3. **minisign, Ed25519 (fallback)** — auto-detected when `minisign` is on `PATH` **and**
   `AR_MINISIGN_KEY` points to a secret key. Uses `minisign -S -s $AR_MINISIGN_KEY -m {msg} -x {sig}`.
   Use a password-less key for non-interactive runs.

**Outside-verifier path** (someone who did *not* run the pipeline, holding only the shipped run
directory) — `aggregate.py --verify-signature` performs the complete check:

1. It recomputes the attestation from the artifacts, requires it to match `verdict.json`'s recorded
   digest, and verifies `attestation.sig` against the canonical `verdict.json` with the **expected
   signer identity** — the trust decision the verifier owns, not the script.
   - **cosign keyless:** reads the expected identity/issuer from `AR_COSIGN_IDENTITY` /
     `AR_COSIGN_ISSUER` (**both required** — without them cosign `verify-blob` accepts *any* valid
     Fulcio certificate, so cosign is not auto-selected as the verifier until both are set).
   - **minisign:** set `AR_MINISIGN_PUBKEY` to either a **public-key file** or an **inline key**
     value — `-p` vs `-P` is chosen automatically by whether the value names an existing file.
2. A verifier that runs and returns non-zero yields exit **1** (a bad/absent signature, a relabeled
   verdict, or a verifier misconfiguration — the stderr is surfaced); a verifier that cannot start,
   has a malformed template, or times out yields exit **3**.

The verifier command is resolved exactly like the signer: `AR_VERIFIER_CMD` override (same
`{msg}`/`{sig}` tokens) > cosign `verify-blob` > minisign `-V`. Signing and verifying are always
out-of-process; the enforcement guarantee — that only `aggregate.py` computes the verdict from
recorded artifacts — is unchanged, because a signature attests a verdict but can never author one.

## Environment variables

| Variable | Default | Purpose |
|---|---|---|
| `OPENROUTER_API_KEY` | — | Direct OpenRouter credential |
| `AR_KEY_FILE` | — | Path to file containing the key |
| `AR_BASE_URL` | `https://openrouter.ai/api/v1` | OpenAI-compatible router base URL |
| `AR_API_KEY` | — | Key for `AR_BASE_URL` (falls back to OpenRouter key) |
| `AR_TRANSPORT` | auto | `http` or `mcp` |
| `AR_PRIVACY` | by tier | `default`, `deny`, or `zdr` |
| `AR_TEMPERATURE` | `0.1` | Reviewer sampling temperature |
| `AR_MAX_TOKENS` | `8000` | Reviewer response cap (floored per model by `max_tokens_floor`) |
| `AR_REASONING_EFFORT` | `high` | Reasoning budget for models whose profile marks `reasoning: mandatory` |
| `AR_MAX_COST_USD` | `20` | Per-run USD ceiling (pre-call gate across panel/rebuttal/concurrence; BLOCKS the remaining calls once reached and may overshoot by the in-flight call). `0`/`none`/`off`/`unlimited` disables; non-finite/negative is rejected. Also settable via the policy key `max_cost_usd`. |
| `AR_TIMEOUT_S` | `240` | Per-request timeout |
| `AR_RUN_DIR` | `.adversarial-review` | Artifact root |
| `AR_RISK` | — | Default risk tier for `init` (below `--risk`, above policy) |
| `AR_DEV_PROVIDERS` | — | Comma list of dev families for `init` (below flag, above policy) |
| `AR_REQUIRE` | — | Comma list of gates for `plan` (below `--require`, above policy) |
| `AR_PINS` | — | Comma list `role=model-slug` to pin specific models |
| `AR_REBUTTAL` | `contention` | Rebuttal policy at init: `critical`, `contention`, `any` |
| `AR_CAP_OVERRIDES` | — | Path to a capability-overrides file (see *Model capability profiles*) |
| `AR_SIGNER_CMD` | auto | `aggregate.py --sign` signer command template (`{msg}`/`{sig}` tokens); overrides cosign/minisign auto-detect (see *Signing the attestation*) |
| `AR_VERIFIER_CMD` | auto | `aggregate.py --verify-signature` verifier command template (`{msg}`/`{sig}` tokens); overrides auto-detect |
| `AR_MINISIGN_KEY` | — | Path to a minisign secret key; enables the minisign signing fallback |
| `AR_MINISIGN_PUBKEY` | — | minisign public key for `--verify-signature`: a key **file** (`-p`) or an **inline** key value (`-P`), auto-selected by whether it names an existing file |
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
