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
| `AR_MAX_TOKENS` | `8000` | Reviewer response cap |
| `AR_TIMEOUT_S` | `240` | Per-request timeout |
| `AR_RUN_DIR` | `.adversarial-review` | Artifact root |
| `AR_PINS` | — | Comma list `role=model-slug` to pin specific models |
| `AR_REBUTTAL` | `contention` | Rebuttal policy at init: `critical`, `contention`, `any` |

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
