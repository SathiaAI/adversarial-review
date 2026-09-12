# MCP Streamable-HTTP conformance (E3-S2d)

**Pinned revision:** MCP **2026-07-28** ([changelog](https://modelcontextprotocol.io/specification/2026-07-28/changelog)).
**Scope:** the `ar-mcp` Streamable-HTTP transport in `scripts/mcp_server.py`. The transport **dispatches the registered `ar_*` MCP tool handlers** (the same set stdio exposes) through `serve_message()`; some of those handlers create or modify run state via `panel.py` / `aggregate.py` (e.g. `ar_init` starts a run). It is **not an arbitrary command-execution surface** — there is no shell and no `gate run -- <command>` reachable over HTTP, and the verdict is still computed solely by `aggregate.py`. Stdlib-only, Python 3.9+.

## What this suite guarantees

E3-S2a/S2b/S2c already cover the transport *mechanics* (status codes, framing, sessions, auth, DoS bounds) across 60+ `t_mcp_http_*` tests. E3-S2d adds a thin **conformance layer** that pins the *dispatch-level* protocol behaviors to the 2026-07-28 revision and proves they survive the HTTP framing. Because every transport routes through the same `serve_message()` / `handle()` core (the E3-S1 seam), most dispatch behavior is correct on HTTP by construction; these tests assert it against **explicit expected values** (an independent oracle, not a transport-vs-transport tautology) and guard it against drift.

**No runtime code change shipped with S2d** — the core was already conformant. In particular, two behaviors that look like deviations to a reviewer working from an older revision are confirmed **conformant** to 2026-07-28:

| Behavior | Conformant because | Clause |
|---|---|---|
| modern `ping` → method-not-found (`-32601`) | 2026-07-28 **removed** `ping`; a bare `{}` result would omit the now-required `resultType` | changelog #5 |
| unsupported version → `-32022` (`UnsupportedProtocolVersionError`) | version mismatches return this error; clients discover supported versions via `server/discover` | changelog #2, #12 |
| legacy `ping` → `{}` | the legacy era (≤2025-11-25) still has `ping` | dual-era |

## Error-status convention (important)

The transport returns **in-band JSON-RPC errors with HTTP 200**; non-200 HTTP statuses are reserved for **transport-layer** rejections. So:

- **HTTP 200 + JSON-RPC error body:** invalid request (`-32600`), method-not-found (`-32601`), invalid params / unsupported version (`-32602` / `-32022`), parse error (`-32700`). A **top-level JSON array** (removed JSON-RPC batching) is one of these — a single `-32600`, `id: null`, no element dispatched.
- **Non-200 (transport):** `403` disallowed Origin, `401` missing/bad bearer token, `400` bad/duplicate `MCP-Protocol-Version` header or Transfer-Encoding, `413` oversized body, `404` unknown/terminated session, `405` unsupported verb (incl. a **modern** GET/DELETE — see below), `406` unacceptable `Accept` on the SSE GET.

## Batch (removed)

JSON-RPC batching was removed in MCP 2025-06-18 and **not** reinstated in 2026-07-28. A top-level JSON array is rejected **wholesale** at the shared decoder (`handle()` rejects any non-`dict` before method routing): `-32600`, `id: null`, **no element iterated or dispatched** (a side-effect probe asserts no run directory is created), never a crash. This holds identically on stdio and HTTP.

## GET / SSE posture

The 2026-07-28 revision **removed the HTTP GET stream** and replaced it with a POST `subscriptions/listen` stream for opt-in server→client notifications (changelog #4), and **removed SSE resumability** / `Last-Event-ID` (#9). This server:

- Treats the `initialize` → `Mcp-Session-Id` → GET(SSE)/DELETE lifecycle as **legacy** (≤2025-11-25). A **modern** (`2026-07-28`) GET or DELETE is **`405`** — the modern era is POST-only here.
- Does **not** implement `subscriptions/listen` (no server-initiated change notifications). This is a **documented non-goal** for a reviewer surface that dispatches only the fixed `ar_*` tool set, not a conformance gap. If server→client notifications are ever needed, that is a separate story designed against the threat model.

## Known gaps (tracked, not closed by S2d)

- **Required routing headers (2026-07-28 changelog #4).** The revision requires `Mcp-Method` (and `Mcp-Name` for `tools/call`) on Streamable-HTTP POSTs, and defines a `HeaderMismatch` error (`-32020`). This transport routes a modern request off its `params._meta` version and already enforces the `MCP-Protocol-Version` header/`_meta` **agreement** and **rejects conflicting (distinct-valued)** `MCP-Protocol-Version` headers — identical repeats from an intermediary are tolerated (see the E3-S2b review rounds) — but it does **not** yet *require* `Mcp-Method`/`Mcp-Name`. The conformance requests (`_http_modern`) **send** `Mcp-Method` (and `Mcp-Name` for `tools/call`) so they are spec-shaped and forward-compatible; the server currently ignores them. Server-side **enforcement** (reject-when-absent → `HeaderMismatch`) and its dedicated negative tests are a **server behavior change**, out of scope for this test/doc story; tracked as a follow-up.

## Drift guard

`tests/run_tests.py` holds a **curated** conformance manifest, `_S2D_CONFORMANCE`: one row per dispatch behavior mapping `behavior_id → stdio_test → http_test → spec clause`. The meta-test `t_mcp_s2d_conformance_manifest_covers_http` **fails CI if a listed conformance test is renamed or removed** — a regression guard for the curated set. It **does not** auto-detect a brand-new dispatch behavior added without a row (there is no authoritative behavior registry to diff against), so adding a row for a new behavior is a manual, reviewed step. It is curated on purpose — a name-grep of all `t_mcp_*` would false-positive on the ~80 pipeline/aggregate tests that are not transport conformance.

## Running

The conformance tests are ordinary offline `t_mcp_*` / `t_mcp_http_*` functions in `tests/run_tests.py`; they run in the standard suite (`python tests/run_tests.py`) on the CI 3.9 + 3.12 matrix. No network, no API keys.
