# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

The version in `pyproject.toml` and the newest released heading below must always agree —
this is enforced by a regression test (`t_version_matches_changelog` in `tests/run_tests.py`).

## [Unreleased]

### Added
- **Streamable-HTTP sessions for `ar-mcp` (E3-S2b).** The local HTTP transport implements the **legacy** Streamable-HTTP session lifecycle (MCP revisions through 2025-11-25; the stateless 2026-07-28 revision removed protocol-level sessions and `Mcp-Session-Id` — see the era-enforcement entries above). A successful `initialize` mints a cryptographically-random `Mcp-Session-Id` (via `secrets`, returned in the response header; a fresh id per handshake, so sessions rotate). A request that *presents* a session id must present a **valid, server-minted** one — a forged or already-terminated id is refused with **404**, never silently honored (anti-hijack). **GET** opens the server→client `text/event-stream` channel for a valid session (missing id → `400`, forged → `404`); **DELETE** terminates a session (**204**; reuse → `404`). The session store is **bounded with LRU eviction** (`AR_MCP_HTTP_MAX_SESSIONS`, default 128), so an `initialize` flood cannot exhaust memory; the GET/SSE stream carries a **bounded socket write timeout** so a stalled client cannot pin a server thread indefinitely. Sessions are **optional** on the legacy path — a version-less client keeps working unchanged — with `AR_MCP_HTTP_REQUIRE_SESSION` (default off) making a session mandatory on every request except the `initialize` handshake and the `server/discover` probe; it composes with, and defaults on alongside, the bearer token in E3-S2c. Still localhost-only and **not** a command-execution surface; **no authentication yet** (E3-S2c). Review hardening (Codex on #54): the `MCP-Protocol-Version` check now runs on **every** verb (GET and DELETE are validated too, not just POST — a bogus pinned version → closed **400**); concurrent GET/SSE streams are **bounded** (`AR_MCP_HTTP_MAX_STREAMS`, default 64) so a valid session cannot open unlimited thread-pinning streams (past the cap → **503**, `Retry-After: 1`); a session terminated mid-stream stops SSE output immediately (the keepalive loop re-checks validity after its wait, so a `DELETE` yields **no** further keepalive); `AR_MCP_HTTP_REQUIRE_SESSION` now **rejects** a non-blank unrecognized value (e.g. `tru`) — the transport refuses to start rather than silently failing open to off; and the docs no longer imply a stateless `2026-07-28` client can open the SSE channel — the session lifecycle (GET/SSE included) is the optional `initialize`-based path, while the modern stateless path is POST-only until server-initiated messages and auth land (E3-S2c). New env: `AR_MCP_HTTP_MAX_SESSIONS` / `AR_MCP_HTTP_MAX_STREAMS` / `AR_MCP_HTTP_REQUIRE_SESSION`.
- **Protocol-era enforcement for the `ar-mcp` HTTP transport (E3-S2b review round 2).** The transport now routes by protocol era per the MCP 2026-07-28 spec, which made the revision **stateless**: it removed protocol-level sessions and the `Mcp-Session-Id` header, removed the `initialize` handshake, and **replaced the HTTP GET stream** with a POST `subscriptions/listen` stream. So the session lifecycle (`initialize` → `Mcp-Session-Id` → GET/DELETE) is now correctly treated as **legacy** (revisions through 2025-11-25), and a **GET or DELETE pinned to a modern version (`2026-07-28`) is `405`** — the modern era has no session channel to open or terminate (CodeRabbit r3941912010). A POST that pins an `MCP-Protocol-Version` header **and** declares `params._meta.io.modelcontextprotocol/protocolVersion` must have the two **agree**, else the contradictory request is refused `400` (r3941912010). Each session is now **bound to the protocol version its `initialize` negotiated**: a GET/DELETE/POST pinned to a *different* version is not honored for it (`404`), so a legacy session cannot be driven under a modern version (Codex r3941957895). Three independent stream fixes: a GET is **revalidated after acquiring its stream slot and before the `200`** so a session terminated in that window never receives `200` + `: connected` (TOCTOU, Codex r3941957879 — **this "never" was later relaxed to best-effort in round 6 below, which moved the `200`/`: connected` commit off the dispatch lock; a DELETE landing between the `wake.is_set()` check and the `: connected` write can still emit that one comment line on this localhost-only, single-user, pre-auth transport, with strict no-output-after-terminate ordering deferred to E3-S2c; Codex r3951751944**); a GET whose `Accept` does not admit `text/event-stream` is refused **`406` before a slot is acquired** (Codex r3941957888); and terminating (or evicting/​shutting down) a session **wakes its open SSE stream immediately**, releasing the bounded stream slot at once instead of holding it until the next keepalive tick — so the `503`'s `Retry-After` is no longer a lie (Codex r3941957873).
- **Era-enforcement follow-ups (E3-S2b review round 3).** From the CodeRabbit + Codex re-review of the era-enforcement commit: a **POST that pins a modern `MCP-Protocol-Version` on a legacy `initialize` body is now `400`** (CodeRabbit r3943894656 / Codex r3943958158) — the header/`_meta` check does not fire when the body carries no `_meta`, so a modern-pinned `initialize` previously negotiated a legacy version yet echoed the modern one and minted an `Mcp-Session-Id` the client could never use (its modern GET/DELETE/POST are `405`/`405`/`404`) while still consuming an LRU slot, letting repeated modern handshakes evict live legacy sessions. The **GET stream re-validation and wake registration are now atomic** (Codex r3943958149): `register_wake` validates the session and registers under one store lock and returns a pre-set event when the session is already gone, which the handler checks before committing the `200`, closing the window in which a DELETE landing exactly at registration could still stream `: connected` for a dead session. A **client disconnect now frees the stream slot promptly** (Codex r3943958155): the keepalive wait polls on a bounded interval and detects a peer close via `select` + a `MSG_PEEK` EOF, so a client that closes right after `: connected` releases its slot within the advertised `Retry-After` instead of holding it until the next keepalive write. And the **`Accept` parser honors media-range parameters** (Codex r3943958164 / CodeRabbit r3943913914): a parameterized range such as `text/event-stream;level=1` only matches a representation carrying that parameter, so it no longer overrides a plainer acceptable alternative — `text/event-stream;level=1;q=0, text/event-stream;q=1` now correctly admits the stream instead of returning `406`.
- **Negotiated-version match (E3-S2b review round 5).** From the re-review of round 4: a legacy `initialize` whose `MCP-Protocol-Version` header disagrees with the version the handshake will **negotiate** is now `400` — the round-4 guard compared the header to the raw body `protocolVersion`, so a body that **omits** `protocolVersion` (or sends an unsupported/non-string one) slipped through: it negotiates `SUPPORTED_PROTOCOLS[0]` while the response echoes the header, leaving the client pinned to an echoed version its own `Mcp-Session-Id` then `404`s on. The check now compares the header to the negotiated version (body version when supported, else `SUPPORTED_PROTOCOLS[0]`) (CodeRabbit r3945516733).
- **Session termination stays off the dispatch lock (E3-S2b review round 6).** Rounds 4–5 progressively took `_HTTP_DISPATCH_LOCK` on `DELETE` (termination) and the `GET` SSE `200`-commit, to make termination atomic with request dispatch. But `do_POST` holds that same lock across `serve_message()`, which runs a tool for up to `AR_TIMEOUT_S` (~300 s), so a concurrent `DELETE` or `GET` could block for the whole tool call (CodeRabbit 🟠 Major r3945707197) — and the atomicity was incomplete anyway (the `: connected` write and LRU eviction fall outside the lock; Codex r3945744724 / r3945744727). Round 6 **reverts** the `DELETE`/`GET`-commit lock acquisition: `terminate()` is internally synchronized and O(1), so a `DELETE` now takes effect immediately regardless of an in-flight tool, and a `GET` opens its stream without waiting on dispatch. `do_POST` still re-checks the session under the lock immediately before dispatch (unchanged). What is now **best-effort** on this **localhost-only, single-user, pre-auth** transport is the strict "no dispatch or stream output after terminate" ordering — a multi-client / revocation property (whose full form requires cancelling an in-flight tool, not mutual exclusion) **deferred to E3-S2c** (auth + remote bind), where it is designed against the committed threat model. Two best-effort behaviors are accepted in the meantime: a `DELETE` does **not** cancel an already-admitted tool — `do_POST` re-checks the session under the lock immediately before dispatch, but a `DELETE` landing after that re-check and before `serve_message()` lets the admitted request run to completion (its `204` can return before the tool even starts) — and a `GET` racing a `DELETE` may emit one stray `: connected` for a session just terminated. Both are self-races for the single local user; strict ordering and in-flight cancellation arrive with the multi-client surface in S2c.
- **Reject a modern-declared `initialize` (E3-S2b review round 7).** An `initialize` body that declares the modern era in `params._meta` (`io.modelcontextprotocol/protocolVersion: 2026-07-28`) is now rejected as method-not-found (`-32601`) instead of being served as a legacy handshake: the stateless 2026-07-28 revision has no `initialize`, so serving one negotiated a legacy version and (over HTTP, where no `MCP-Protocol-Version` header is present to trip the era check) minted a legacy `Mcp-Session-Id` for a client that declared modern — a contradictory state on which its own modern requests then fail: a modern **GET or DELETE is `405`** (the stateless era is POST-only, with no session channel to open or terminate) and a modern **POST `404`s** on the session's negotiated-version mismatch. The era is now validated from the request **body** in the shared `handle()` core, independent of transport or header presence, so the legacy handshake requires a legacy (`_meta`-less) body (Codex r3949809506).
- **Browser CORS deferred to E3-S2c (E3-S2b review round 8).** The S2b HTTP transport's `Origin` allow-list (`AR_MCP_HTTP_ORIGINS`) is anti-rebinding **defense** (reject a disallowed origin, per the committed threat model), not browser **enablement**: it does not emit `Access-Control-Allow-Origin`, answer the CORS preflight (`OPTIONS`), or give a browser `EventSource` a way to carry the session — so an allow-listed browser origin is *permitted at the gate* but cannot yet drive the transport. Making it browser-usable — ACAO (the validated origin) on POST/GET/DELETE, an `OPTIONS` preflight, and a browser-usable session mechanism — is one coherent unit **deferred to the E3-S2c auth/session story**, designed there against the threat model rather than retrofitted here; a lone SSE `Access-Control-Allow-Origin` header would be a half-measure a real browser still can't reach (`EventSource` cannot set the required `Mcp-Session-Id` header, and a browser `POST` preflight — an `OPTIONS` request — gets `405` from this POST/GET/DELETE-only endpoint, not a valid preflight response). The standing limitation is documented in `references/config.md` (the `AR_MCP_HTTP_ORIGINS` entry); the S2c work is tracked as an `e3-s2c-intake-browser-cors` intake note in the project's engineering roadmap (a planning doc, not a file in this repo) (Codex `r3950383352` / `r3951256109`, PR #54).
- **Combine repeated `Accept` field lines + correct the round-8 CORS note (E3-S2b review round 9).** From the Codex re-review of round-8: (1) `do_GET` negotiated the SSE `Accept` from only the FIRST `Accept:` field line (`get("Accept")`), so a client (or intermediary) that split the list-valued header across lines — `Accept: application/json` then `Accept: text/event-stream` (RFC 9110 §5.3) — got a wrong `406` even though the combined value admits SSE. It now combines every line via `get_all("Accept")` before negotiating; a single line behaves exactly as before, and an absent `Accept` still means accept-anything (Codex `r3951256116`). (2) The round-8 CORS note above is corrected (Codex `r3951256109`): a browser `OPTIONS` preflight returns **`405`** from this POST/GET/DELETE-only endpoint (not `501`); the standing limitation is now actually documented in `references/config.md` (the `AR_MCP_HTTP_ORIGINS` entry); and the S2c intake note is described as a project-roadmap planning doc rather than a repo path (a repo-wide search found no such file, which the earlier wording implied). Revert-proof regression `t_mcp_http_get_combines_repeated_accept_lines` (an SSE-admitting value on a *later* `Accept` line still opens the stream, in either order; two SSE-excluding lines still `406`).
- **`Accept` equal-rank tie, strict-mode discovery, a stale no-race claim, and the browser fire-and-forget POST (E3-S2b review round 10).** From the Codex re-review of round-9:
  - **`Accept` negotiation is order-independent among equal-specificity alternatives** (Codex P3 `r3951751953`): `_accepts_event_stream` used a strict `r > best_rank`, so with equal-specificity ranges of differing quality the FIRST occurrence permanently won — `text/event-stream;q=0, text/event-stream;q=1` returned `406` while the reverse opened the stream (also reachable after combining repeated `Accept` field lines). Ties are now OR-merged (an acceptable equal-rank alternative wins), so the outcome no longer depends on field order; a MORE specific range still overrides a less specific one, so `*/*;q=1, text/event-stream;q=0` still correctly refuses. Revert-proof `t_accepts_event_stream_equal_rank_tie_is_order_independent`.
  - **`server/discover` no longer advertises the stateless modern revision in strict mode** (Codex P2 `r3951751963`): with `AR_MCP_HTTP_REQUIRE_SESSION` on, a stateless `2026-07-28` request has no session and is `400`'d, and a legacy-minted id `404`s (sessions are version-bound) — so the modern revision cannot be served, yet `server/discover` still listed it, letting a client select a version the endpoint then rejects. In strict mode the HTTP layer now filters `MODERN_PROTOCOLS` out of the discover `supportedVersions` (the transport-agnostic `_discover_result` stays era-complete for stdio and non-strict HTTP), so a client negotiates a legacy, session-bearing version instead. Exempting modern from the session requirement was declined — it would let modern requests **bypass** strict mode, defeating its purpose. Revert-proof `t_mcp_http_discover_omits_modern_in_strict_mode`.
  - **A stale round-2 no-race claim is corrected** (Codex P2 `r3951751944`): the round-2 entry above said a session terminated in the validation-to-commit window "never" receives `200` + `: connected`, but round 6 moved that commit off the dispatch lock and explicitly accepts a residual best-effort window (a DELETE between the `wake.is_set()` check and the `: connected` write can still emit that one comment line). The round-2 wording is qualified as historical and pointed at round 6's final best-effort behavior; strict no-output-after-terminate ordering stays deferred to E3-S2c.
  - **The browser fire-and-forget POST is now accurately disclosed** (Codex P2 `r3951751957`): round-8/9 said the `Origin` allow-list does not make the transport browser-usable, but an allow-listed origin can still send a `no-cors` POST with a CORS-safelisted `Content-Type: text/plain` (which `do_POST` does not reject) carrying a JSON-RPC body, and the tool **executes** (write-only — the response is opaque to the page). `references/config.md` (the `AR_MCP_HTTP_ORIGINS` entry) now discloses this exposure and warns against allow-listing an untrusted origin. Fully closing it — rejecting non-JSON `Content-Type`s so a cross-origin browser must send a **pre-flighted** `application/json` (which `OPTIONS` → `405` blocks) — is folded into the E3-S2c browser-CORS intake note rather than bolted on ahead of that coherent CORS/auth design; it also carries a shared-test-helper blast radius (every HTTP POST test would need an explicit `Content-Type`). No behavior change this round for this item — documentation + S2c intake only.
- **Reject conflicting `MCP-Protocol-Version` headers (E3-S2b review round 11).** From the Codex re-review of round-10 (Codex P2 `r3952163012`): `MCP-Protocol-Version` is a singleton control header, but a client/intermediary may split or repeat it across field lines (RFC 9110 §5.3), and `self.headers.get()` read only the FIRST — so a contradictory later value (`2025-06-18` then `1999-01-01`, or a legacy value then the modern revision) bypassed `_protocol_ok`'s version check **and** the downstream session-version binding, which also reads the first value (Codex reproduced an `initialize` carrying a smuggled second version receiving `200` + a session id). `_protocol_ok` — shared by every verb (POST/GET/DELETE) — now reads `get_all("MCP-Protocol-Version")` and **rejects `400` when the header carries more than one DISTINCT value**; identical repeats stay harmless (the first value equals the rest), so a benign duplicating intermediary is tolerated and the single-header path is unchanged. Revert-proof regression `t_mcp_http_rejects_conflicting_protocol_version_headers` (two distinct version lines, and legacy-then-modern, both `400`; identical repeats still `200`), which returns `200` on the base.

## [0.2.0]

### Added
- **Experimental local Streamable-HTTP transport for `ar-mcp` (E3-S2a).** `AR_MCP_TRANSPORT=http` (or `--http`) starts a stdlib `http.server` MCP endpoint that reuses the same `serve_message()`/`handle()` dispatch as stdio: a **POST** carrying JSON-RPC returns `application/json` for a response or **202** for a notification; requests are `Origin`-validated (DNS-rebinding defense) and the listener binds `127.0.0.1` by default — a **non-loopback bind is refused** (there is no auth yet), so the endpoint cannot be exposed to the network from here. Non-POST methods → `405`, an oversized body → `413`, an unsupported `MCP-Protocol-Version` → `400`, and a rejected request closes its connection (no keep-alive desync). **No authentication or session yet** — it is localhost-only (enforced) and MUST NOT be exposed remotely until the auth sub-story (E3-S2c) lands; `stdio` stays the default. New env: `AR_MCP_HTTP_HOST` / `AR_MCP_HTTP_PORT` / `AR_MCP_HTTP_ORIGINS` / `AR_MCP_HTTP_MAX_BYTES`. Still **not** a command-execution surface.
- Multi-sample corroboration of high/critical findings (E4-S3): the opt-in `AR_HIGH_SAMPLES=N`
  (integer, default `1`; also the policy key `high_samples`) makes `panel.py run` re-run any role
  that raised a `high`/`critical` finding to `N` low-temperature samples and record a
  `corroboration: {samples, agreed, rate}` object on that finding — the share of samples whose own
  high/critical findings match it (same file + similar title via a `difflib` ratio). Only flagged
  roles are resampled, each sample is recorded under `panel/samples/` (with cost metered under
  `panel/meta/`, honoring the per-run cost cap — a resample that would cross the cap records a
  `corroboration`-phase `cost_abort.json` and BLOCKS rather than overspend), and `N=1` is a strict
  no-op (byte-identical reviewer artifacts). The agreement rate is **informational only**:
  `aggregate.py` alone still decides the verdict, so disagreement never overrides the gate. See
  `references/config.md`. Review hardening (CodeRabbit + Codex on #48): `high_samples` is validated
  at policy-load exactly as `panel.py run` resolves it (`int(str(value))`), so an integral-looking
  float (`3.0`, `1e1`) that `init` would accept can no longer be rejected later at `run`; a plain
  `run` resume no longer re-buys corroboration samples (only roles produced in that invocation are
  resampled, so recorded cost can't undercount real spend); the `corroboration` object is declared in
  the finding schema so an enriched report stays schema-valid; the resolved count + source are
  persisted to `sample_policy.json` (even at the default `1`) for the audit; a cost-cap abort during
  corroboration names every later flagged role it skipped; and the keyless prepare/ingest (MCP) path
  now surfaces that corroboration is not applied there instead of silently ignoring `high_samples`.
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
- Reviewer meta-evaluation scoring (E1-S2): `evals/score.py` grades reviewer findings against the
  corpus ground truth. A finding matches a defect when it is in the same file **and** either its
  cited line is within a locator's range (±`line_tol`, default 3) **or** the finding's text names one
  of the defect's `root_cause_tags` — file-overlap is required even on the tag path, so a root-cause
  word in the wrong file is not a match (neither line-only nor tag-only is sufficient on its own).
  Scoring is severity-aware: a `must_detect` defect matched at/above its `severity_floor` is a true
  positive, a match below the floor is a **partial** (noticed but under-rated, not a detection), an
  unmatched one is a false negative; a `must_detect: false` defect is informational. A false positive
  is a finding matching no defect — any finding beyond `fp_budget` on a clean case, or an unmatched
  high/critical one beyond budget on a defect case (an extra low/medium is noise). `aggregate()` rolls
  per-case results up overall and per category/tier. Pure, stdlib-only, 3.9-safe, 100% branch-covered
  offline (`t_eval_score_*`); the offline harness that drives it is E1-S3 (below).
- Reviewer meta-evaluation offline harness (E1-S3): `evals/run.py --mode offline` drives the **real**
  panel pipeline (`panel.py assign` → `run` → ingest) over the corpus against the in-process mock
  router, serving each case's scripted reviewer findings — a new optional `scripts.offline` block in
  `expected.json` — through the E0-S1 `response_provider`, then scores the ingested findings with
  `evals/score.py`. It emits a dated `evals/report/<ts>.json` plus a human-readable `summary.md` with
  true-positive / partial / false-negative / false-positive metrics overall and per category and tier,
  plus a per-reviewer-role breakdown (findings emitted, and how many were true positives, partials, or
  unmatched — per-role FN/FP are not attributed, since which role should catch a given defect is not
  encoded). Because reviewer outputs are scripted, it measures harness correctness, not
  model quality (live calibration is E1-S4); a role omitted from a case's script is a deliberate miss
  and an extra finding is a false positive, so the seed corpus exercises every scoring outcome
  end-to-end. Deterministic (same corpus + scripts → byte-identical scored `result`; wall-clock
  stamped only outside it), stdlib-only, 3.9-safe, no network and no keys. A fast 2–3 case subset runs
  in the suite on every push; the full corpus runs as a separate CI `evals` job. This change also
  **restores the `t_eval_score_*` scorer tests** (100% branch coverage) that the E1-S2 (#44) merge
  dropped from `tests/run_tests.py` — `evals/score.py` had shipped to `main` untested — so the scorer
  the harness relies on is verified again.
- Reviewer meta-evaluation live calibration (E1-S4): `evals/run.py --mode live` runs the corpus
  through **real** model panels (`--reps N` per case) over the configured transport, scoring each
  panel's ingested findings with `evals/score.py`. Unlike offline mode it serves no scripts and starts
  no mock router — reviewers answer for real — so it measures model + panel quality, not just harness
  assembly. It emits a dated `evals/report/live-<ts>.json` + `live-<ts>.summary.md` with the detection
  rate per category and tier, a per-reviewer-role and per-model contribution breakdown (findings
  emitted / true positives / partials / unmatched, plus cost per model), the clean-case false-positive
  rate (`clean_fp_rate`), cost per case, and per-rep detail so single-run noise stays visible (per-role
  and per-model FN / detection-rate are not attributed — which role/model should catch a defect is not
  encoded); each case runs at its own tier (a SENSITIVE
  case gets the six-role panel). A cumulative USD budget (`--budget-usd`, default **$20**) caps the
  whole run: checked before each panel, and when reached the remaining `(case, rep)` units are recorded
  in `not_run` and the run stops — never a silent partial, overshoot bounded by the one in-flight
  panel; each individual panel still honours its own `AR_MAX_COST_USD` cap (E4-S2). Opt-in and never in
  CI: it needs a provider key resolved the same way the panel resolves it (`OPENROUTER_API_KEY` /
  `AR_API_KEY` / an existing `AR_KEY_FILE`; required even behind an `AR_BASE_URL` proxy) and exits
  rather than spend a run on no-op panels without one. Live results are non-deterministic by nature (the per-rep raw detail
  keeps the aggregate auditable); the harness code itself is exercised offline against the mock router
  with no network and no keys. Regression thresholds seeded from the first live report are E1-S5.
- Reviewer meta-evaluation regression thresholds (E1-S5): `evals/thresholds.json` records **descriptive**
  floors and `evals/thresholds.py` enforces them. `thresholds.py check` runs the offline harness and fails
  (exit 1) when the overall or per-category detection rate drops below, or the false-positive count rises
  above, the committed floor, so a change to `score.py`, the corpus scripts, or the panel wiring that
  quietly weakens detection is caught in CI (the `evals` job now runs it on 3.9 and 3.12). Because offline
  serves scripted findings this guards harness/scorer/dispatch correctness, not model quality; the floors
  are seeded from the current deterministic offline run (overall detection >= 0.5 and <= 1 FP; security and
  correctness >= 1.0) and are updated deliberately, never invented (mirrors the mutation-threshold rule in
  `references/gates.md`). `thresholds.py compare` is the **model-degraded alarm**: it diffs two live
  calibration reports and flags any overall/per-category detection drop past `live.max_detection_drop`
  (default 20%) plus any model whose true-positive contribution fell — a candidate for pin removal /
  substitution — with a runbook in `evals/README.md`. The baseline live report is committed after the first
  live calibration (the E1-S4 $20 run). Stdlib-only, 3.9-safe.
- Distribution: a `release` workflow publishes to PyPI on a `v*` tag via **Trusted Publishing**
  (OIDC, no stored token); an `action-selftest` workflow exercises the composite action keyless
  and asserts the honest BLOCKED verdict; a GitLab CI template (`examples/.gitlab-ci.yml`); and a
  `Changelog` project URL.
- CI-integration guide + Marketplace steps (E2-S3): a new `docs/ci-integration.md` presents **both**
  the GitHub Action and the GitLab template together — the Action's real inputs (`risk`,
  `dev-providers`, `gates`, `fail-on`, `diff-ref`, `product`, `openrouter-api-key`) and outputs
  (`verdict`, `exit-code`), the keyless→BLOCKED path, the verdict→exit-code (`0`/`1`/`2`) contract,
  and an Action-input↔GitLab-variable mapping. It also documents the remaining **manual** GitHub
  Marketplace publishing steps a maintainer performs by hand (publish from the repo's Releases page,
  choose categories, and adopt a moving `v1` major tag; branding already lives in `action.yml`),
  since Marketplace listing cannot be automated from this repo. Referenced from `README.md`,
  `docs/using-on-your-platform.md`, and the docs-site footer. A `t_ci_docs_and_gitlab_mirror_action`
  guard test asserts the guide names every real `action.yml` input and output (no invented inputs),
  proves `aggregate.py` is ar-panel's terminal command (so the job exit code is the verdict), and
  locks in the secrets-transmission guard and the full-floor starter workflow below.
  Review hardening (CodeRabbit + Codex on #49): the composite **`action.yml` now gates diff
  transmission to the reviewer panel on a passing `secrets` gate** — mirroring the GitLab job, so a
  correctly-configured secrets scan is required before the diff is transmitted, and every
  gate/panel/aggregate step is
  pinned with `--run` to the exact run directory `panel.py init` created, so a repository-committed
  `.adversarial-review/run-*` in the checkout cannot forge the secrets gate or hijack the pipeline;
  the documented starter workflow
  configures the whole NORMAL floor (build/unit/secrets/deps/sast) with explicit `risk`/`dev-providers`
  so it is a complete, safe copy; and the guide now distinguishes the computed **verdict / `exit-code`**
  from the **job pass/fail status** that `fail-on` (GitHub) / `allow_failure` (GitLab) derive from it,
  noting that a failed deterministic gate takes precedence over BLOCKED.
- Reviewer robustness & cost control (E4): `build_request` is now capability-driven — a model whose
  profile forbids `temperature` is sent none, `max_tokens` is floored at the profile's
  `max_tokens_floor`, and a mandatory-reasoning model receives a `reasoning` budget
  (`AR_REASONING_EFFORT`, default `high`); a profile's `structured_outputs` flag overrides the
  catalog's in either direction (so a wrong catalog can't force an unsupported `response_format`);
  and a model with an all-default profile gets the byte-identical request it did before — the
  pre-E4 key order (`temperature` before `max_tokens`) is preserved, not just the values. A per-run
  cost ceiling (`AR_MAX_COST_USD`, or policy `max_cost_usd`, default `$20`) is enforced as a
  pre-call gate across **every** paid phase — panel, rebuttal, and concurrence — aborting the
  remaining calls once reached (each phase records its own skipped work), recording a BLOCKED cost
  reason, and surfacing the run's total. The cap the run records in `cost_policy.json` is
  authoritative for the whole run: rebuttal and concurrence reuse it rather than re-resolving live
  settings, so changing `AR_MAX_COST_USD` mid-run can neither disable nor raise it. Also surfaced:
  `cost_usd` plus the enforced `cost_cap_usd`/`cost_cap_source` on the verdict; a verbose model can
  raise the bill but never buy a silent partial PASS. Cost accounting is hardened end to end: a
  malformed-JSON retry (a second billed call) is fully counted, the MCP-ingest path's nested
  `usage.cost` is read, non-finite/negative per-reviewer costs are metered as `$0`, and a
  non-finite or negative cap is rejected at policy load and at resolution rather than silently
  disabling the guard. The new `coverage.cost_usd` / `cost_aborted` / `cost_cap_usd` /
  `cost_cap_source` fields and the cost-triggered BLOCKED reason are documented in
  `references/schemas.md`; being a pre-call gate (not a reservation), the recorded total can
  overshoot the cap by up to the in-flight reviewer's cost, as `references/config.md` now states.

### Changed
- MCP server transport seam (E3-S1): the stdio framing in `scripts/mcp_server.py` is extracted
  into a `StdioTransport` class around a transport-agnostic `serve_message()` core, leaving the
  `handle()` dispatch untouched. Framing is byte-identical for well-formed and ordinarily-malformed
  messages (`-32700` parse errors, `-32603` handler-crash containment, notification suppression);
  the extracted parse guard catches every malformed-input failure `json.loads` can raise — a
  `JSONDecodeError`, a `RecursionError` from pathologically nested input, and a `UnicodeDecodeError`
  from bad bytes — and frames each as `-32700` instead of letting it escape and kill the loop
  (closing a pre-existing gap), so the seam's "a single malformed message never kills the transport"
  guarantee holds for the stdio loop and for the byte-oriented Streamable-HTTP transport (E3-S2) that
  will reuse the exact dispatch and error semantics. Stdlib-only, 3.9-safe.

## [0.1.0]

### Added
- Initial public release: deterministic gate recorder (`gate.py`), independent multi-model
  reviewer panel (`panel.py`), machine-computed verdict + attestation (`aggregate.py`), and a
  dual-era stdio MCP server (`mcp_server.py`). Zero runtime dependencies, Python 3.9+.

[Unreleased]: https://github.com/SathiaAI/adversarial-review/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/SathiaAI/adversarial-review/releases/tag/v0.2.0
[0.1.0]: https://github.com/SathiaAI/adversarial-review/releases/tag/v0.1.0
