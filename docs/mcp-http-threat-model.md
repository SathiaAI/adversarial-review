# Threat model — the `ar-mcp` Streamable-HTTP surface

**Status:** committed with E3-S2c (the SENSITIVE merge gate for the whole E3-S2 HTTP transport).
**Scope:** the stdlib `http.server` Streamable-HTTP transport in `scripts/mcp_server.py` (`HttpTransport`,
`_MCPHTTPHandler`, `_SessionStore`, `_BoundedThreadingHTTPServer`). stdio is unchanged and out of scope.

## What this surface is (and is not)
`ar-mcp` is a **framing / dispatch** surface, never a command-execution one. Every transport routes a raw
JSON-RPC message through the same `serve_message()` / `handle()` core as stdio, so HTTP inherits stdio's exact
dispatch and error semantics. It deliberately does **not** expose `gate run` (arbitrary shell), does **not**
sign, and does **not** expose the OpenRouter or signing keys. The verdict is computed solely by `aggregate.py`.
A host reachable only through MCP therefore cannot use this server to run commands or read secrets.

## Assets to protect
- The reviewer tool surface exposed over MCP (read/dispatch of `ar_*` tools + `server/discover`).
- The run artifacts those tools can read (the immutable run dir is the audit record).
- The host process and its resources (threads, file descriptors, memory).

**Explicitly NOT reachable over MCP:** the OpenRouter key, signing keys, and gate/command execution.

## Trust boundary
stdio is a same-host, same-user pipe — the caller *is* the local user, implicitly trusted. HTTP introduces a
**network boundary**: the caller is no longer necessarily the local user. Every mitigation below exists to keep
the HTTP boundary **at least as safe as stdio** before it is ever exposed beyond localhost. The switch that
opens the boundary is a bearer token: **without a token the listener binds loopback only** (a non-loopback bind
is refused), so the only unauthenticated surface is same-host/same-user — the stdio trust model. **With a token,
every request must authenticate**, on every host including loopback.

## Threats (STRIDE) → mitigation → status
| Threat | Mitigation | Status |
|---|---|---|
| **Spoofing / DNS-rebinding** — a malicious web page rebinds a localhost hostname and drives the server from the victim's browser | Validate the `Origin` header against an allowlist (`AR_MCP_HTTP_ORIGINS`) → **403**; bind **127.0.0.1** by default. The Origin check runs **before** auth on every verb. | Shipped S2a; auth-ordering added S2c |
| **Elevation of privilege / unauthenticated access** — any network caller invoking tools without being the local user | **Bearer-token auth** (`AR_MCP_HTTP_TOKEN`): no tool dispatch before auth, **401** on missing/invalid, constant-time compare (`hmac.compare_digest`); a non-localhost bind is **refused unless a token is set**. `server/discover` is gated too — no pre-auth catalog/version leak. | **Shipped S2c** |
| **Tampering / session hijack** — guessing or fixating a session id | **Cryptographically-random**, server-minted `Mcp-Session-Id` (via `secrets`), bound to the negotiated protocol version, rotatable/terminable; a client-supplied id the server never minted is refused **404**. | Shipped S2b |
| **Denial of service / resource exhaustion** — oversized bodies, slow-loris, unbounded concurrency/sessions/streams | Max body size (**413**); `Transfer-Encoding` refused (**400**, anti-smuggling); **bounded, evicting session store** (`AR_MCP_HTTP_MAX_SESSIONS`); **bounded SSE stream pool** (`AR_MCP_HTTP_MAX_STREAMS` → **503**); **bounded worker/connection pool** (`AR_MCP_HTTP_MAX_WORKERS`, refuse-by-close past the cap, enforced `> MAX_STREAMS` at bind); **per-recv socket read timeout** (`AR_MCP_HTTP_READ_TIMEOUT`) on the request read and response write; a malformed/oversized message frames as a JSON-RPC error and never crashes the listener. | Body/limits S2a; sessions/streams S2b; **worker pool + read timeout S2c** |
| **Information disclosure** — stack traces or secrets in error bodies/headers | JSON-RPC errors only (no tracebacks on the wire — `serve_message` normalizes to `-32603`); tools already scrub secrets; minimal `Server` header; the bearer token is **env-only** (never argv/URL/query) and **never logged**; a 401 body is a constant that never echoes the supplied credential. | Shipped S2a; token hygiene S2c |
| **Repudiation** | None new: the audit record is the immutable run dir, unchanged by transport; the verdict is still computed by `aggregate.py`. | n/a |

## Authentication design (E3-S2c)
- **Token presence is the switch.** `AR_MCP_HTTP_TOKEN` unset → no auth, loopback-only. Set → auth enforced on
  every request (POST/GET/DELETE), on every host. A **blank or too-short (<16 char) token fails closed at
  startup** — it never silently disables auth or authenticates a network surface with a guessable secret.
- **Check order per verb:** `Origin` (rebinding) → protocol version → **auth** → dispatch. Running the cheap
  network-boundary checks first means attacker bytes never reach the credential comparator for a request already
  doomed on Origin; a bad-Origin browser gets **403**, a no-credential programmatic client gets **401**.
- **Credential parsing:** exactly one `Authorization: Bearer <token>` header (a missing, malformed, or duplicate
  header → 401); scheme is case-insensitive; the token is compared with `hmac.compare_digest` on utf-8 bytes.
- **`server/discover` is gated** behind auth like every other method — an unauthenticated caller gets 401 and
  learns nothing about the tool catalog or supported versions. MCP does not require discover to be pre-auth.
- **Remote bind requires a token.** `bind()` refuses a non-loopback host unless a token is set. This is the only
  way to expose the surface to a network, and it cannot be done unauthenticated.

## Residual risks (on record — accepted or deferred, not hidden)
- **Plaintext transport / TLS.** stdlib `http.server` speaks **plaintext HTTP**; the bearer token travels in
  cleartext on a non-loopback bind. A remote bind therefore **MUST sit behind a TLS-terminating reverse proxy
  or a trusted network** — the server logs a WARNING when it binds non-loopback. Bearer replay after theft, and
  remote request flooding, remain residual risks even behind TLS; the bounded pools cap the flooding blast
  radius. Terminating TLS in-process is a possible future hardening, deliberately out of this PR.
- **Sub-timeout slow-loris.** The per-recv read timeout bounds an *idle* connection; a client dribbling a byte
  just under the timeout can still hold a worker. The **bounded worker pool caps the blast radius** (a flood
  can hold at most `MAX_WORKERS` connections, beyond which new connections are fast-closed). A true absolute
  wall-clock read deadline is a follow-up (S2d hardening), kept out of the SENSITIVE auth PR to avoid a fragile
  stdlib `http.server` read-path override.
- **Serialized dispatch.** `_HTTP_DISPATCH_LOCK` serializes tool dispatch (the handlers are stateful/one-at-a-
  time by design). A long-running tool (up to `AR_TIMEOUT_S`) makes concurrent authenticated POSTs queue, each
  holding a worker; the bounded pool caps this at `MAX_WORKERS`. A bounded pending-queue / busy-503 admission is
  a possible follow-up.
- **Cancellation is best-effort, not forced.** SSE client-disconnect frees the stream slot promptly and a
  DELETE wakes streams (both tested). A client that disconnects mid-POST does **not** abort the running
  subprocess — it completes and its result is discarded. Preemptive "kill-means-kill" cancellation of an
  in-flight tool is **deferred** (it is not achievable by mutual exclusion and is not required by the E3-S2c
  criteria); this is documented rather than faked.
- **Browser CORS is a separate intake.** This surface is not interactively browser-usable (no
  `Access-Control-Allow-Origin`, no `OPTIONS` preflight — an `OPTIONS` gets 405). The `AR_MCP_HTTP_ORIGINS`
  allowlist is anti-rebinding **defense**, not browser **enablement**. Note the fire-and-forget footgun
  documented at `AR_MCP_HTTP_ORIGINS` in `references/config.md` is **closed for the authenticated case**: a
  cross-origin `no-cors` POST cannot set an `Authorization` header without triggering a preflight, which this
  endpoint answers 405 — so with a token set, an allow-listed browser origin still cannot invoke a tool. Full
  browser enablement (ACAO across verbs + preflight + a browser-usable session mechanism + rejecting non-JSON
  `Content-Type`) is tracked separately (`e3-s2c-intake-browser-cors`) and is **not** in this PR.

## Invariants preserved
Zero runtime dependencies (stdlib only in `scripts/*.py`); Python 3.9+ (no 3.10+ syntax); the verdict is
computed by `aggregate.py` alone; audit-record determinism is untouched. All new behavior is covered by offline
tests (no network, no keys) on the 3.9 + 3.12 CI matrix.
