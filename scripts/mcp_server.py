#!/usr/bin/env python3
"""adversarial-review MCP server (stdio, JSON-RPC 2.0).

Exposes the adversarial-review pipeline as MCP tools so an MCP host can drive a
review — init, plan gates, record gate results, assign the independent panel,
prepare/run reviewers, ingest responses, and compute the deterministic verdict —
without shelling out by hand.

Design (deliberate, matching this repo's identity):
  * Zero dependencies. The MCP wire protocol is newline-delimited JSON-RPC 2.0
    over stdio; that is small enough to implement on the standard library, and
    this package's whole premise (and its own `deps` gate) is zero-dependency,
    supply-chain-minimal software. So there is no `mcp` SDK here by design.
  * Thin subprocess bridge. Each tool invokes the existing CLI module
    (`python <dir>/panel.py ...`, gate.py, aggregate.py) and returns its output.
    The server owns no verdict logic — aggregate.py alone computes PASS/FAIL/
    BLOCKED, exactly as it does for the CLI. The bridge stays correct across
    refactors of the underlying scripts.
  * Not a command-execution surface. The server deliberately does NOT expose
    `gate run` (which executes an arbitrary shell command). Gates are executed by
    you, in your own environment, and their results recorded via ar_gate_record —
    the same honest-ingest path the CLI already supports for CI-run checks. A host
    reachable only through MCP therefore cannot use this server to run arbitrary
    commands.
  * Dual-era protocol. It answers both the legacy `initialize` handshake (revisions
    through 2025-06-18) and the stateless MCP 2026-07-28 revision, in which each request
    carries its own protocol version in `_meta` and is negotiated independently — no
    session. Responses to ID-bearing legacy requests for the pre-existing methods
    (`initialize`, `tools/list`, `tools/call`, `ping`) stay byte-for-byte identical; modern
    requests additionally get per-request version negotiation and the spec-required
    `resultType` and cache metadata. The one intentional wire change is that a legacy
    *notification* (no `id`) is now correctly left unanswered per JSON-RPC — including an
    `initialize` notification, which older builds answered with a null-`id` result.
    `server/discover` is new in this revision and is answered in both eras — it is
    version-agnostic (the bootstrap probe by which a client learns the supported set), so
    it is deliberately not gated by per-request version validation.

Operates on the .adversarial-review/ directory in the server's working directory,
so launch it with the repository under review as the current directory.
"""

import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

SCRIPTS_DIR = Path(__file__).resolve().parent
SERVER_NAME = "adversarial_review_mcp"
# Legacy handshake versions (initialize / notifications/initialized). Newest first; the
# initialize handler echoes the client's if we support it, else our latest — per the
# pre-2026 MCP lifecycle spec.
SUPPORTED_PROTOCOLS = ("2025-06-18", "2025-03-26", "2024-11-05")
# Modern, stateless version (MCP 2026-07-28): no handshake — every request carries its
# protocol version and capabilities in params._meta and is negotiated independently.
# 2026-07-28 is the only revision that uses this path (2025-11-25 and earlier are "legacy"
# and negotiate through initialize).
MODERN_PROTOCOLS = ("2026-07-28",)
# Every version this dual-era server can speak — advertised by server/discover and named
# in an UnsupportedProtocolVersionError. Modern first.
ALL_PROTOCOLS = MODERN_PROTOCOLS + SUPPORTED_PROTOCOLS
# CacheableResult freshness hint (SEP-2549) for the static tool list and discovery result.
# The tool set never changes within a process (listChanged: false), so a 1-hour hint is safe.
CACHE_TTL_MS = 3_600_000

# Reserved per-request / per-result _meta keys (MCP 2026-07-28).
META_PROTOCOL_VERSION = "io.modelcontextprotocol/protocolVersion"
META_CLIENT_CAPABILITIES = "io.modelcontextprotocol/clientCapabilities"
META_SERVER_INFO = "io.modelcontextprotocol/serverInfo"

# A run id is exactly what `panel.py init` mints: run-YYYYMMDD-HHMMSS with an
# optional -N disambiguator. Constraining --run to this shape keeps an untrusted
# value from reaching resolve_run() as a path (a value containing a separator, or
# "..", would otherwise escape .adversarial-review/ and read/write an arbitrary
# existing directory). Empty/None is allowed: the CLI then targets the newest run.
RUN_RE = re.compile(r"^run-\d{8}-\d{6}(?:-\d+)?$")
ROLE_RE = re.compile(r"^[a-z][a-z_]*$")
PIN_RE = re.compile(r"^[A-Za-z0-9_]+=[A-Za-z0-9][A-Za-z0-9._/-]*$")
PROVIDER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]*$")
GATE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


class ToolError(Exception):
    """A tool-level error: reported inside the result (isError), not as a
    protocol-level JSON-RPC error."""


def _version():
    try:
        for line in (SCRIPTS_DIR / "__init__.py").read_text(encoding="utf-8").splitlines():
            if line.startswith("__version__"):
                return line.split("=", 1)[1].strip().strip("\"'")
    except Exception:
        pass
    return "0.0.0"


VERSION = _version()


def log(msg):
    # stdio servers must never write logs to stdout — that channel is JSON-RPC only.
    print(f"[{SERVER_NAME}] {msg}", file=sys.stderr, flush=True)


# --- argument validation helpers -------------------------------------------------

def _safe_run(args):
    run = args.get("run")
    if run is None:  # key omitted (or null) — target the newest run
        return []
    # A provided run must be exactly a minted id. An empty/whitespace string is a
    # caller error, not a silent "newest": reject it so an ambiguous value can never
    # slip past RUN_RE into resolve_run().
    if not isinstance(run, str) or not RUN_RE.match(run):
        raise ToolError(
            f"invalid run id {run!r}: expected the form 'run-YYYYMMDD-HHMMSS' "
            "(as returned by ar_init). Omit 'run' entirely to target the newest run.")
    return ["--run", run]


def _req_str(args, key):
    v = args.get(key)
    if not isinstance(v, str) or not v.strip():
        raise ToolError(f"missing required string argument '{key}'")
    return v


def _run_cli(module, argv, timeout=120):
    """Invoke a pipeline CLI module as a subprocess (shell=False — no injection).
    Returns (returncode, stdout, stderr)."""
    script = SCRIPTS_DIR / f"{module}.py"
    cmd = [sys.executable, str(script), *argv]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        raise ToolError(f"{module} timed out after {timeout}s")
    except Exception as e:  # pragma: no cover - defensive
        raise ToolError(f"failed to invoke {module}: {e}")
    return p.returncode, p.stdout, p.stderr


def _result(text, structured=None, is_error=False):
    out = {"content": [{"type": "text", "text": text}], "isError": is_error}
    if structured is not None:
        out["structuredContent"] = structured
    return out


def _cli_result(module, argv, timeout=120, structured=None):
    """Common shape: run the module, surface stdout+stderr, mark isError on
    non-zero exit so the host sees the failure rather than a silent empty PASS."""
    rc, out, err = _run_cli(module, argv, timeout=timeout)
    body = (out or "").strip()
    if err and err.strip():
        body = (body + "\n" + err.strip()).strip()
    if rc != 0:
        return _result(f"{module} exited {rc}:\n{body}", is_error=True)
    return _result(body or f"{module} ok", structured=structured)


def _read_json(run_args):
    """Read verdict.json for the resolved run (explicit id, else newest)."""
    root = Path(os.environ.get("AR_RUN_DIR", ".adversarial-review"))
    if run_args:  # ["--run", "<id>"]
        run_dir = root / run_args[1]
    else:
        if not root.is_dir():
            raise ToolError(f"no {root}/ directory — call ar_init first")
        runs = sorted(d for d in root.iterdir() if d.is_dir() and d.name.startswith("run-"))
        if not runs:
            raise ToolError(f"no runs under {root}/ — call ar_init first")
        run_dir = runs[-1]
    vf = run_dir / "verdict.json"
    if not vf.is_file():
        raise ToolError(f"no verdict yet for {run_dir.name} — call ar_aggregate first")
    return json.loads(vf.read_text(encoding="utf-8"))


# --- tool handlers ---------------------------------------------------------------

def h_init(args):
    risk = args.get("risk")
    if risk not in ("NORMAL", "SENSITIVE", "CRITICAL"):
        raise ToolError("risk must be one of NORMAL, SENSITIVE, CRITICAL")
    dev = args.get("dev_providers")
    if not isinstance(dev, list) or not dev or not all(
            isinstance(d, str) and PROVIDER_RE.match(d) for d in dev):
        raise ToolError("dev_providers must be a non-empty list of provider/family "
                        "names (e.g. ['anthropic']); every family that helped build "
                        "the change, so it is excluded from the panel")
    argv = ["init", "--risk", risk, "--dev-providers", ",".join(dev)]
    if args.get("diff_ref"):
        argv += ["--diff-ref", str(args["diff_ref"])]
    if args.get("product"):
        argv += ["--product", str(args["product"])]
    rp = args.get("rebuttal_policy")
    if rp:
        if rp not in ("critical", "contention", "any"):
            raise ToolError("rebuttal_policy must be critical, contention, or any")
        argv += ["--rebuttal-policy", rp]
    rc, out, err = _run_cli("panel", argv)
    if rc != 0:
        return _result(f"init failed:\n{(out + err).strip()}", is_error=True)
    # Report the run id that was just created (newest run-* dir).
    root = Path(os.environ.get("AR_RUN_DIR", ".adversarial-review"))
    run_id = None
    if root.is_dir():
        runs = sorted(d.name for d in root.iterdir() if d.is_dir() and d.name.startswith("run-"))
        run_id = runs[-1] if runs else None
    return _result((out or "").strip() or f"initialized {run_id}",
                   structured={"run_id": run_id})


def h_gate_plan(args):
    argv = ["plan"] + _safe_run(args)
    req = args.get("require")
    if req:
        if not isinstance(req, list) or not all(isinstance(g, str) and GATE_NAME_RE.match(g) for g in req):
            raise ToolError("require must be a list of gate names")
        argv += ["--require", ",".join(req)]
    waive = args.get("waive") or []
    if not isinstance(waive, list):  # a bare string would iterate per-character
        raise ToolError("waive must be a list of gate names")
    for w in waive:
        if not isinstance(w, str) or not GATE_NAME_RE.match(w):
            raise ToolError(f"invalid waive gate name {w!r}")
        argv += ["--waive", w]
    if args.get("authorized_by"):
        argv += ["--authorized-by", str(args["authorized_by"])]
    return _cli_result("gate", argv)


def h_gate_record(args):
    name = _req_str(args, "name")
    if not GATE_NAME_RE.match(name):
        raise ToolError(f"invalid gate name {name!r}")
    summary = _req_str(args, "summary")
    argv = ["record"] + _safe_run(args) + ["--name", name, "--summary", summary]
    status = args.get("status")
    if status is not None:
        if status not in ("PASS", "FAIL", "BLOCKED", "NOT_APPLICABLE"):
            raise ToolError("status must be PASS, FAIL, BLOCKED, or NOT_APPLICABLE")
        argv += ["--status", status]
    ec = args.get("exit_code")
    if ec is not None:
        if not isinstance(ec, int) or isinstance(ec, bool):
            raise ToolError("exit_code must be an integer")
        argv += ["--exit-code", str(ec)]
    if args.get("command"):
        argv += ["--command", str(args["command"])]
    if args.get("authorized_by"):
        argv += ["--authorized-by", str(args["authorized_by"])]
    return _cli_result("gate", argv)


def h_panel_assign(args):
    argv = ["assign"] + _safe_run(args)
    pins = args.get("pin") or []
    if not isinstance(pins, list):  # a bare string would iterate per-character
        raise ToolError("pin must be a list of 'role=provider/model-slug' strings")
    for pin in pins:
        if not isinstance(pin, str) or not PIN_RE.match(pin):
            raise ToolError(f"invalid pin {pin!r}: expected 'role=provider/model-slug'")
        argv += ["--pin", pin]
    if args.get("allow_degraded"):
        argv.append("--allow-degraded")
    if args.get("authorized_by"):
        argv += ["--authorized-by", str(args["authorized_by"])]
    cf = args.get("catalog_file")
    if cf is not None:
        # Untrusted path: confine it to a relative path inside the working tree so a
        # crafted value ('../../etc/shadow', '/etc/passwd') cannot make the CLI read an
        # arbitrary file. No traversal, no absolute paths, no NULs.
        if not isinstance(cf, str) or not cf or ".." in cf or cf.startswith("/") or "\x00" in cf:
            raise ToolError("catalog_file must be a relative path within the repository "
                            "(no '..', no absolute path)")
        argv += ["--catalog-file", cf]
    return _cli_result("panel", argv, timeout=300)


def _write_context(run_args, context):
    """Persist the caller-provided context to <run>/context.md and return its path.
    The path is server-controlled (fixed filename in the run dir), so the context
    string can never redirect the write elsewhere."""
    root = Path(os.environ.get("AR_RUN_DIR", ".adversarial-review"))
    if run_args:
        run_dir = root / run_args[1]
        if not run_dir.is_dir():
            raise ToolError(f"run directory not found: {run_dir.name}")
    else:
        runs = sorted((d for d in root.iterdir() if d.is_dir() and d.name.startswith("run-")),
                      key=lambda d: d.name) if root.is_dir() else []
        if not runs:
            raise ToolError("no runs yet — call ar_init first")
        run_dir = runs[-1]
    cf = run_dir / "context.md"
    cf.write_text(context, encoding="utf-8")
    return str(cf)


def h_panel_prepare(args):
    run_args = _safe_run(args)
    context = _req_str(args, "context")
    cf = _write_context(run_args, context)
    return _cli_result("panel", ["prepare"] + run_args + ["--context-file", cf])


def h_panel_run(args):
    run_args = _safe_run(args)
    context = _req_str(args, "context")
    cf = _write_context(run_args, context)
    argv = ["run"] + run_args + ["--context-file", cf]
    if args.get("force"):
        argv.append("--force")
    return _cli_result("panel", argv, timeout=300)


def h_panel_ingest(args):
    role = _req_str(args, "role")
    if not ROLE_RE.match(role):
        raise ToolError(f"invalid role {role!r}")
    response = _req_str(args, "response")
    run_args = _safe_run(args)
    phase = args.get("phase", "panel")
    if phase not in ("panel", "rebuttal"):
        raise ToolError("phase must be 'panel' or 'rebuttal'")
    tf = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8")
    try:
        tf.write(response)
        tf.close()
        argv = ["ingest"] + run_args + ["--role", role, "--response-file", tf.name, "--phase", phase]
        return _cli_result("panel", argv)
    finally:
        try:
            os.unlink(tf.name)
        except OSError:
            pass


def h_aggregate(args):
    run_args = _safe_run(args)
    rc, out, err = _run_cli("aggregate", run_args)
    body = (out or "").strip()
    if err and err.strip():
        body = (body + "\n" + err.strip()).strip()
    structured = None
    try:
        structured = _read_json(run_args)
    except ToolError:
        pass
    # aggregate exits 0 PASS, 1 FAIL, 2 BLOCKED — all are successful computations,
    # not tool errors. Surface the verdict; only a missing verdict.json is an error.
    if structured is None:
        return _result(f"aggregate exited {rc} but wrote no verdict:\n{body}", is_error=True)
    return _result(body or structured.get("verdict", ""), structured=structured)


def h_check_digest(args):
    run_args = _safe_run(args)
    rc, out, err = _run_cli("aggregate", run_args + ["--check-digest"])
    body = ((out or "") + (err or "")).strip()
    intact = rc == 0
    return _result(body or ("attestation intact" if intact else "attestation drifted"),
                   structured={"intact": intact})


def h_get_verdict(args):
    v = _read_json(_safe_run(args))
    return _result(f"{v.get('verdict')} — run {v.get('run_id')}", structured=v)


# --- tool registry ---------------------------------------------------------------

def _t(name, description, properties, required, annotations, handler):
    return {
        "name": name,
        "description": description,
        "inputSchema": {"type": "object", "properties": properties, "required": required},
        "annotations": annotations,
        "handler": handler,
    }


_RO = {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False}
_WRITE_LOCAL = {"readOnlyHint": False, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False}
_NET = {"readOnlyHint": False, "destructiveHint": False, "idempotentHint": False, "openWorldHint": True}

_RUN_PROP = {"type": "string", "description": "Run id from ar_init (run-YYYYMMDD-HHMMSS). Omit to target the newest run."}

TOOLS = [
    _t("ar_init",
       "Initialize a new adversarial-review run under .adversarial-review/. Sets the "
       "risk tier and the development provider families to exclude from the reviewer "
       "panel (so a model never reviews its own change). Returns the new run id used "
       "by every other ar_* tool.",
       {"risk": {"type": "string", "enum": ["NORMAL", "SENSITIVE", "CRITICAL"],
                 "description": "NORMAL: no auth/payments/PII/tenancy/migrations/infra. "
                                "SENSITIVE: touches one of those. CRITICAL: SENSITIVE plus "
                                "irreversibility or broad blast radius."},
        "dev_providers": {"type": "array", "items": {"type": "string"},
                          "description": "Provider/family names that planned, coded, or advised the "
                                         "change (e.g. ['anthropic']); excluded from the panel."},
        "diff_ref": {"type": "string", "description": "Git ref range for the change under review, e.g. 'main...HEAD'."},
        "product": {"type": "string", "description": "Short product/component name for the report."},
        "rebuttal_policy": {"type": "string", "enum": ["critical", "contention", "any"],
                            "description": "When the adversarial rebuttal round is required. Default contention."}},
       ["risk", "dev_providers"], _WRITE_LOCAL, h_init),

    _t("ar_gate_plan",
       "Plan the deterministic gates required for this run's risk tier and write the "
       "required-gate manifest the verdict is computed against.",
       {"run": _RUN_PROP,
        "require": {"type": "array", "items": {"type": "string"},
                    "description": "Explicit gate names to require, overriding the tier default."},
        "waive": {"type": "array", "items": {"type": "string"},
                  "description": "Gate names to drop from the required set (each needs authorized_by)."},
        "authorized_by": {"type": "string", "description": "Named authorizer, required when waiving a gate."}},
       [], _WRITE_LOCAL, h_gate_plan),

    _t("ar_gate_record",
       "Record the result of a deterministic gate you ran in your own environment "
       "(honest ingest of an externally-run check). Supports PASS/FAIL/BLOCKED/"
       "NOT_APPLICABLE. This server never executes gate commands itself: run the gate, "
       "then record its exit code (PASS/FAIL) or an explicit status here. NOT_APPLICABLE "
       "requires authorized_by and a reason; BLOCKED requires a reason.",
       {"run": _RUN_PROP,
        "name": {"type": "string", "description": "Gate name, e.g. build, unit, sast, secrets, deps."},
        "summary": {"type": "string", "description": "One-line result summary (required)."},
        "exit_code": {"type": "integer", "description": "Process exit code; 0 is PASS. Omit for BLOCKED/NOT_APPLICABLE."},
        "status": {"type": "string", "enum": ["PASS", "FAIL", "BLOCKED", "NOT_APPLICABLE"],
                   "description": "Explicit status; overrides exit-code inference."},
        "command": {"type": "string", "description": "The command that was run, for the record."},
        "authorized_by": {"type": "string", "description": "Named authorizer, required for NOT_APPLICABLE."}},
       ["name", "summary"], _WRITE_LOCAL, h_gate_record),

    _t("ar_panel_assign",
       "Assign the independent reviewer panel from the router's live model catalog, "
       "excluding every development provider family and giving each role a distinct "
       "family. Pin models with entries like 'security=google/gemini-3.6-flash'.",
       {"run": _RUN_PROP,
        "pin": {"type": "array", "items": {"type": "string"},
                "description": "Role pins, each 'role=provider/model-slug'."},
        "allow_degraded": {"type": "boolean", "description": "Permit a smaller panel when too few independent families exist (needs authorized_by)."},
        "authorized_by": {"type": "string", "description": "Named authorizer for a degraded panel."},
        "catalog_file": {"type": "string", "description": "Path to a cached catalog JSON instead of a live fetch."}},
       [], _NET, h_panel_assign),

    _t("ar_panel_prepare",
       "Assemble the run context you provide (requirements + full diff + relevant "
       "surrounding code) and write the per-reviewer request bodies for your host to "
       "execute via its own transport. Pair with ar_panel_ingest.",
       {"run": _RUN_PROP,
        "context": {"type": "string", "description": "The full review context (do not include secrets or .env content)."}},
       ["context"], _WRITE_LOCAL, h_panel_prepare),

    _t("ar_panel_run",
       "Assemble the provided context and call the assigned reviewers directly over "
       "HTTP. Requires the router API key in the server's environment. Use this when "
       "the server should execute the panel itself instead of prepare/ingest.",
       {"run": _RUN_PROP,
        "context": {"type": "string", "description": "The full review context (no secrets or .env content)."},
        "force": {"type": "boolean", "description": "Re-run reviewers even if reports already exist."}},
       ["context"], _NET, h_panel_run),

    _t("ar_panel_ingest",
       "Ingest one reviewer's raw JSON response for a role, validated against the "
       "report schema. Use with ar_panel_prepare when your host executes the reviewer "
       "calls.",
       {"run": _RUN_PROP,
        "role": {"type": "string", "description": "Reviewer role, e.g. correctness, security, test_quality."},
        "response": {"type": "string", "description": "The reviewer's raw JSON response text."},
        "phase": {"type": "string", "enum": ["panel", "rebuttal"], "description": "Which round this response belongs to. Default panel."}},
       ["role", "response"], _WRITE_LOCAL, h_panel_ingest),

    _t("ar_aggregate",
       "Compute the deterministic release verdict (PASS/FAIL/BLOCKED) from all recorded "
       "artifacts and write verdict.json. The verdict is computed only here; no model — "
       "including the one driving this server — can override it. Returns verdict, "
       "reasons, coverage, and attestation.",
       {"run": _RUN_PROP}, [], _WRITE_LOCAL, h_aggregate),

    _t("ar_check_digest",
       "Verify the run's tamper-evident attestation digest against the current "
       "artifacts. Returns intact or drifted; modifies nothing.",
       {"run": _RUN_PROP}, [], _RO, h_check_digest),

    _t("ar_get_verdict",
       "Read the computed verdict.json for a run (verdict, reasons, coverage, "
       "attestation). Read-only.",
       {"run": _RUN_PROP}, [], _RO, h_get_verdict),
]

TOOLS_BY_NAME = {t["name"]: t for t in TOOLS}


def _public_tool(t):
    return {k: t[k] for k in ("name", "description", "inputSchema", "annotations")}


# --- JSON-RPC plumbing -----------------------------------------------------------

def _error(id_, code, message, data=None):
    err = {"code": code, "message": message}
    if data is not None:
        err["data"] = data
    return {"jsonrpc": "2.0", "id": id_, "error": err}


def _ok(id_, result):
    return {"jsonrpc": "2.0", "id": id_, "result": result}


_INSTRUCTIONS = (
    "Drive an adversarial review: ar_init -> ar_gate_plan -> run your gates and "
    "ar_gate_record each -> ar_panel_assign -> ar_panel_prepare+ar_panel_ingest "
    "(or ar_panel_run) -> ar_aggregate for the verdict. Launch this server with the "
    "repository under review as the working directory."
)


def _finalize_result(result, is_modern):
    """Stamp the fields MCP 2026-07-28 requires on every modern result: resultType
    ("complete") and the server identity in _meta. Legacy (pre-2026) results are returned
    unchanged, so existing clients keep seeing byte-identical responses. isError tool
    results are still "complete" — the RPC completed; the error is tool-level, not
    protocol-level."""
    if not is_modern:
        return result
    out = dict(result)
    out.setdefault("resultType", "complete")
    meta = dict(out.get("_meta") or {})
    meta.setdefault(META_SERVER_INFO, {"name": SERVER_NAME, "version": VERSION})
    out["_meta"] = meta
    return out


def _discover_result():
    """DiscoverResult for server/discover (MCP 2026-07-28): the versions we speak, our
    capabilities, and our identity in one round-trip. Servers MUST implement this RPC; it
    also doubles as the stdio backward-compatibility probe."""
    return {
        "resultType": "complete",
        "supportedVersions": list(ALL_PROTOCOLS),
        "capabilities": {"tools": {"listChanged": False}},
        "instructions": _INSTRUCTIONS,
        "ttlMs": CACHE_TTL_MS,
        "cacheScope": "public",
        "_meta": {META_SERVER_INFO: {"name": SERVER_NAME, "version": VERSION}},
    }


def handle(msg):
    """Dispatch one parsed JSON-RPC message. Returns a response dict, or None for
    notifications (no id) which must not be answered.

    Dual-era (MCP versioning spec): an `initialize` request selects legacy handshake
    semantics; a request whose params._meta carries io.modelcontextprotocol/protocolVersion
    is served statelessly per the 2026-07-28 revision. Legacy responses are byte-identical
    to before; modern responses additionally carry resultType and server identity."""
    if not isinstance(msg, dict) or msg.get("jsonrpc") != "2.0":
        return _error(msg.get("id") if isinstance(msg, dict) else None,
                      -32600, "invalid request")
    method = msg.get("method")
    id_ = msg.get("id")
    is_notification = "id" not in msg

    # A one-way notification (no id) must never be answered — checked before any method
    # handling, so even an `initialize` or `server/discover` sent without an id stays
    # unanswered, per JSON-RPC.
    if is_notification:
        return None  # notifications/initialized, notifications/cancelled, etc.

    # params must be an object; a truthy non-dict (string/list/number) would otherwise
    # crash on params.get(...). Treat any non-dict as absent.
    params = msg.get("params")
    params = params if isinstance(params, dict) else {}
    # A modern (2026-07-28) request declares its version in params._meta. The *presence*
    # of that key — not a non-null value — is the modern/legacy signal: legacy requests
    # never carry it, and a modern request that supplies it as null/blank is a modern
    # request with an unsupported version (rejected below), not a legacy one.
    meta = params.get("_meta")
    meta = meta if isinstance(meta, dict) else {}
    requested_version = meta.get(META_PROTOCOL_VERSION)
    is_modern = META_PROTOCOL_VERSION in meta

    # Legacy initialize handshake — selects legacy semantics regardless of _meta.
    if method == "initialize":
        requested = params.get("protocolVersion")
        version = requested if requested in SUPPORTED_PROTOCOLS else SUPPORTED_PROTOCOLS[0]
        return _ok(id_, {
            "protocolVersion": version,
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": {"name": SERVER_NAME, "version": VERSION},
            "instructions": _INSTRUCTIONS,
        })

    # server/discover — servers MUST implement it. Answered in both eras: it advertises the
    # versions we speak (so a modern client can pick one) and doubles as the stdio
    # backward-compat probe. Kept ahead of version validation so a client can always learn
    # supportedVersions instead of being turned away with only an error.
    if method == "server/discover":
        return _ok(id_, _discover_result())

    # Modern per-request negotiation: reject an unsupported version with the spec's
    # UnsupportedProtocolVersionError (-32022), and reject a modern request missing a
    # required _meta field as Invalid params (-32602) — both before any work is done.
    if is_modern:
        if requested_version not in MODERN_PROTOCOLS:
            return _error(id_, -32022, "Unsupported protocol version",
                          {"supported": list(ALL_PROTOCOLS), "requested": requested_version})
        if META_CLIENT_CAPABILITIES not in meta:
            return _error(id_, -32602,
                          "malformed request: missing required _meta field "
                          f"'{META_CLIENT_CAPABILITIES}'")

    # `ping` was removed in 2026-07-28. Answer it only on the legacy path; a modern ping
    # falls through to method-not-found (-32601), since the modern revision has no ping and
    # a bare {} result would omit the required resultType.
    if method == "ping" and not is_modern:
        return _ok(id_, {})

    if method == "tools/list":
        result = {"tools": [_public_tool(t) for t in TOOLS]}
        if is_modern:  # CacheableResult (SEP-2549): required on modern list results
            result["ttlMs"] = CACHE_TTL_MS
            result["cacheScope"] = "public"
        return _ok(id_, _finalize_result(result, is_modern))

    if method == "tools/call":
        name = params.get("name")
        tool = TOOLS_BY_NAME.get(name)
        if not tool:
            return _error(id_, -32602, f"unknown tool: {name}")
        arguments = params.get("arguments") or {}
        if not isinstance(arguments, dict):
            return _error(id_, -32602, "arguments must be an object")
        try:
            return _ok(id_, _finalize_result(tool["handler"](arguments), is_modern))
        except ToolError as e:
            return _ok(id_, _finalize_result(_result(f"Error: {e}", is_error=True), is_modern))
        except Exception as e:  # pragma: no cover - defensive
            log(f"tool {name} crashed: {e}")
            return _ok(id_, _finalize_result(
                _result(f"Error: internal failure in {name}", is_error=True), is_modern))

    return _error(id_, -32601, f"method not found: {method}")


def main():
    log(f"v{VERSION} ready on stdio (cwd={os.getcwd()})")
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            sys.stdout.write(json.dumps(_error(None, -32700, "parse error")) + "\n")
            sys.stdout.flush()
            continue
        try:
            response = handle(msg)
        except Exception as e:  # a malformed message must never kill the stdio loop
            log(f"handler crashed on a message: {e}")
            response = _error(msg.get("id") if isinstance(msg, dict) else None,
                              -32603, "internal error")
        if response is not None:
            sys.stdout.write(json.dumps(response) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    main()
