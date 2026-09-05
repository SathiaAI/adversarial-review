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

import http.server
import ipaddress
import json
import os
import re
import socket
import subprocess
import sys
import tempfile
import threading
from pathlib import Path

SCRIPTS_DIR = Path(__file__).resolve().parent
# Put this dir first on sys.path so the in-process helpers below (`from panel import load_catalog`,
# `from _common import load_policy`) resolve even under the `ar-mcp` console-script entry point
# (adversarial_review.mcp_server:main), where those bare module names are not otherwise importable —
# the same one-liner panel.py and aggregate.py use. Without it a pip-installed server silently fails
# every catalog_file validation and never applies the policy `high_samples` timeout budget. Inserting
# the packaged dir FIRST also stops a module in the repo under review (the server's cwd) from ever
# shadowing these. (Fable, 60cb2c3.)
sys.path.insert(0, str(SCRIPTS_DIR))
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
# RUN_RE anchors with \Z (end-of-string), NOT $: `$` also matches just before a trailing newline, so
# RUN_RE.match("run-…\n") would admit a directory name ending in a newline. iterdir() yields untrusted
# repository content, and such a name sorts as a normal run — a crafted `run-99999999-999999\n` dir
# would then be selected as "newest" and pin every tool to that non-minted directory. \Z rejects it.
# (Codex, fc4a701.)
RUN_RE = re.compile(r"^run-\d{8}-\d{6}(?:-\d+)?\Z")
ROLE_RE = re.compile(r"^[a-z][a-z_]*$")
PIN_RE = re.compile(r"^[A-Za-z0-9_]+=[A-Za-z0-9][A-Za-z0-9._/-]*$")
PROVIDER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]*$")
GATE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
# The run id `panel.py init` mints, matched in its stdout so h_init reports the run it
# actually created rather than inferring it from a directory listing (which races a
# concurrent init and mis-sorts run-...-9 vs run-...-10).
RUN_ID_RE = re.compile(r"run-\d{8}-\d{6}(?:-\d+)?")
# A Windows drive-letter prefix (C:, \\server) — absolute on Windows but not caught by a
# POSIX leading-"/" check; rejected so a confined relative path cannot be an absolute one.
_DRIVE_RE = re.compile(r"^[A-Za-z]:")


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
    if run is None:  # key omitted (or null) — resolve the newest run ONCE and pin it explicitly
        # so every subprocess (and every helper) binds to the SAME run this server selected.
        # panel.py / aggregate.py resolve "newest" with a lexicographic sort that disagrees with
        # our numeric _run_key once a -N disambiguator exists (run-...-10 vs run-...-9); resolving
        # here and passing --run to each CLI keeps every pipeline phase on one audit record and
        # closes the concurrent-init TOCTOU. If no run exists yet, fall back to no argument so the
        # CLI emits its own "call ar_init first".
        try:
            return ["--run", _run_dir([]).name]
        except ToolError:
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


def _opt_authorizer(args):
    """Resolve the optional 'authorized_by' identity. A present value must be a non-empty
    string: a schema-invalid value (bool, number, list) must NOT be stringified into a named
    authorizer, or a malformed request could waive a gate / authorize a degraded panel and
    still produce an apparently-authorized audit artifact."""
    v = args.get("authorized_by")
    if v is None:
        return None
    if not isinstance(v, str) or not v.strip():
        raise ToolError("authorized_by must be a non-empty string")
    return v.strip()  # normalize: an audit authorizer must not carry incidental surrounding whitespace


def _add_confined_catalog(args, argv):
    """Validate and forward an optional catalog_file. Confined to a relative path inside the
    working tree so a crafted value cannot make the CLI read an arbitrary file: no traversal,
    no POSIX-absolute path, and no Windows-absolute path (drive letter or backslash/UNC)."""
    cf = args.get("catalog_file")
    if cf is None:
        return
    if (not isinstance(cf, str) or not cf or "\x00" in cf or ".." in cf
            or cf.startswith(("/", "\\")) or "\\" in cf or _DRIVE_RE.match(cf)):
        raise ToolError("catalog_file must be a relative path within the repository "
                        "(no traversal, no absolute or drive-letter path, no backslashes)")
    # The string checks above stop only lexical escapes. A relative path can still be a symlink
    # whose target lives outside the tree, so resolve it (following symlinks) and confirm it
    # stays within the working directory before handing it to panel.py — otherwise a crafted
    # symlink could make the CLI read an arbitrary file.
    root = Path.cwd().resolve()
    target = (root / cf).resolve()
    if target != root and root not in target.parents:
        raise ToolError("catalog_file must resolve to a path within the repository "
                        "(its symlink target escapes the working tree)")
    argv.extend(["--catalog-file", cf])


def _require_loadable_catalog(cf):
    """A confined catalog_file forwarded by h_panel_run must also be LOADABLE before context.md is
    overwritten. panel.py loads it lazily (on reviewer substitution), AFTER the write, so a confined-
    but-unusable catalog (missing, unreadable, malformed, or empty after family filtering) would
    leave completed reviewer reports paired with a freshly-written context on a call the host was
    told failed. Validate with panel.py's OWN loader so the check never drifts from the run's filter;
    a file argument takes load_catalog's no-network path. cf is None when no catalog was supplied."""
    if cf is None:
        return
    # Confinement proves WHERE the catalog is, not WHAT it is. A confined path can still be a
    # NON-REGULAR file — a FIFO/device — and load_catalog opens it IN-PROCESS, on a path that no
    # _run_cli timeout guards, so opening a FIFO would block the server forever waiting for a writer.
    # Require a regular file first (is_file() stats without opening, so it never blocks; only open()
    # on a FIFO does), so untrusted repo content cannot hang ar_panel_run. (Codex, fc4a701.)
    if not (Path.cwd() / cf).resolve().is_file():
        raise ToolError("catalog_file must be a regular file")
    try:
        from panel import load_catalog
        load_catalog(cf)
    except (Exception, SystemExit):  # SystemExit = panel's die() on an empty-after-filter catalog
        raise ToolError("catalog_file is not a usable model catalog "
                        "(missing, unreadable, malformed, or empty after filtering)")


def _resolved_high_samples():
    """The corroboration sample count panel.py will actually use, resolved with panel.py's own
    precedence: AR_HIGH_SAMPLES env var > policy ``high_samples`` (.adversarial-review.yml/.json) >
    default "1". Returned unparsed for the caller to int()+clamp. Never raises and never exits — a
    malformed policy makes panel.py itself die when it runs, so here (merely sizing a subprocess
    timeout) we fall back to the default rather than take the server down."""
    env = os.environ.get("AR_HIGH_SAMPLES", "")
    if env != "":            # matches resolve_setting: a set, non-empty env var wins over policy
        return env
    try:
        from _common import load_policy
        pol = load_policy()  # reads the policy file from the server's cwd (the repo under review)
    except (Exception, SystemExit):  # SystemExit = load_policy's die() on a malformed policy
        return "1"
    if pol and "high_samples" in pol["data"]:
        return pol["data"]["high_samples"]
    return "1"


def _panel_timeout():
    """Subprocess wrapper timeout for a reviewer-calling panel run. panel.py can spend up to
    NINE AR_TIMEOUT_S request budgets on a single role before giving up: run_one_role makes two
    outer attempts and each call_reviewer may issue one corrective-JSON retry (2 × 2 = 4 requests);
    a failed role is then substituted, which FIRST reloads the model catalog live — one /models
    fetch, also bounded by AR_TIMEOUT_S whenever no cached --catalog-file was supplied (the MCP
    path leaves it optional) — and THEN repeats the whole run_one_role sequence (4 more): 4 + 1 + 4
    = 9. On top of that, multi-sample corroboration (E4-S3) resamples each flagged role up to
    AR_HIGH_SAMPLES times — (hs-1) extra samples, each a call plus one corrective retry (×2);
    resampling re-calls the SAME model and never substitutes, so it adds no further catalog fetch.
    Across up to 6 roles (SENSITIVE/CRITICAL) run sequentially that is (9 + 2·(hs-1)) × 6 request
    budgets, so derive the outer deadline from that — never from an under-count — so a legitimately
    slow but valid run (including a large corroboration sweep) is not killed before panel.py finishes."""
    try:
        req = max(1, int(os.environ.get("AR_TIMEOUT_S", "240")))
    except (TypeError, ValueError):
        req = 240
    # Resolve high_samples the way panel.py does — env var > policy `high_samples` > default — so a
    # policy-driven corroboration sweep with no env var set is budgeted for, not killed early. The
    # value is capped at 25 by panel.py (MAX_HIGH_SAMPLES); clamp the same way so an out-of-range
    # value cannot inflate the deadline past what a real run could ever use.
    try:
        hs = int(_resolved_high_samples())
    except (TypeError, ValueError):
        hs = 1
    hs = max(1, min(hs, 25))
    return max(1800, req * (9 + 2 * (hs - 1)) * 6 + 600)


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


def _run_key(name):
    """Sort key so run-...-10 orders after run-...-9 (numeric disambiguator), not
    lexicographically. The zero-padded run-YYYYMMDD-HHMMSS base sorts chronologically as
    text; only the optional -N suffix needs numeric ordering."""
    parts = name.split("-")
    if len(parts) == 4 and parts[3].isdigit():
        return ("-".join(parts[:3]), int(parts[3]))
    return (name, 0)


def _run_dir(run_args):
    """Resolve the run directory: the explicit --run id, else the newest run (numeric-suffix
    aware, so run-...-10 beats run-...-9). Raises ToolError if there is no run to resolve."""
    root = Path(os.environ.get("AR_RUN_DIR", ".adversarial-review"))
    if run_args:  # ["--run", "<id>"]
        return root / run_args[1]
    if not root.is_dir():
        raise ToolError(f"no {root}/ directory — call ar_init first")
    runs = sorted((d for d in root.iterdir() if d.is_dir() and RUN_RE.match(d.name)),
                  key=lambda d: _run_key(d.name))
    if not runs:
        raise ToolError(f"no runs under {root}/ — call ar_init first")
    return runs[-1]


def _read_json(run_args):
    """Read verdict.json for the resolved run (explicit id, else newest)."""
    run_dir = _run_dir(run_args)
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
    # Report the EXACT run id init just created by parsing its stdout ("initialized <run-dir
    # path>  …"): take the BASENAME of that path, not the first run-... substring in stdout.
    # A directory scan races a concurrent init and mis-sorts run-...-9 vs run-...-10, and an
    # unanchored substring search would match a run-YYYYMMDD-HHMMSS segment inside AR_RUN_DIR or
    # any ancestor directory rather than the run just created.
    run_id = None
    # \S+ would stop at the first space, truncating a run path that contains one (a Windows
    # "C:\\Users\\Jane Doe\\..." checkout, or a spaced AR_RUN_DIR) and yielding a basename that
    # fails RUN_ID_RE — a null run_id on an otherwise-successful init. Capture up to the " (risk="
    # status suffix panel.py appends, falling back to end-of-line if that suffix is ever absent.
    m = re.search(r"(?m)^initialized\s+(.+?)(?:\s+\(risk=|\s*$)", out or "")
    if m:
        base = os.path.basename(m.group(1).rstrip("/\\"))
        if RUN_ID_RE.fullmatch(base):
            run_id = base
    if run_id is None:
        # init SUCCEEDED (rc == 0) but its stdout could not be parsed for the run id. Do NOT fall back
        # to a directory scan (_run_dir([])) to guess it: a concurrent init would make that return a
        # DIFFERENT caller's newer run, handing back a valid-looking WRONG id the client would then
        # write gates / context / reviewer artifacts into — the very concurrent-scan race the stdout
        # parse exists to avoid. Surface a tool error instead; the run just created is on disk under
        # the run root. (Codex, 9b93b4c.)
        # Name the ACTUAL run root (AR_RUN_DIR, else the .adversarial-review default) — the hint
        # must point where _run_dir looks, or an AR_RUN_DIR override sends the operator to an empty
        # .adversarial-review/. (CodeRabbit, 274b460.)
        root = os.environ.get("AR_RUN_DIR", ".adversarial-review")
        return _result("init succeeded but its run id could not be parsed from panel.py output — "
                       f"the new run is under {root}/; locate it there", is_error=True)
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
    auth = _opt_authorizer(args)
    if auth:
        argv += ["--authorized-by", auth]
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
    auth = _opt_authorizer(args)
    if auth:
        argv += ["--authorized-by", auth]
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
    auth = _opt_authorizer(args)
    if auth:
        argv += ["--authorized-by", auth]
    _add_confined_catalog(args, argv)
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
        runs = sorted((d for d in root.iterdir() if d.is_dir() and RUN_RE.match(d.name)),
                      key=lambda d: _run_key(d.name)) if root.is_dir() else []
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
    # Validate the optional catalog_file BEFORE persisting context: _write_context overwrites
    # <run>/context.md, and a rejected call must not mutate the audit record (which would leave any
    # completed reviewer reports paired with a freshly-overwritten context). Collect the confined
    # catalog args first so an escaping value raises before the write; the CLI argv is then built in
    # the original order. Forward the same confined catalog the assign step may have used: when the
    # router cannot serve /models, a reviewer failure makes panel.py run reload the catalog to pick
    # its mandated substitute — without this it would attempt the unavailable live catalog and block.
    catalog_argv = []
    _add_confined_catalog(args, catalog_argv)
    # Confinement proves only WHERE the catalog is; also require it to be LOADABLE before persisting
    # context, so a confined-but-unusable catalog cannot mutate the audit record on a rejected call.
    _require_loadable_catalog(args.get("catalog_file"))
    cf = _write_context(run_args, context)
    argv = ["run"] + run_args + ["--context-file", cf] + catalog_argv
    if args.get("force"):
        argv.append("--force")
    return _cli_result("panel", argv, timeout=_panel_timeout())


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


def h_panel_rebuttal(args):
    """Run the adversarial rebuttal round. With prepare=True, write per-reviewer rebuttal
    request bodies for a keyless host to execute and ingest; otherwise call the reviewers over
    HTTP using the router key in the environment (with the scaled panel timeout)."""
    run_args = _safe_run(args)
    argv = ["rebuttal", *run_args]
    if args.get("prepare"):
        # Keyless path: write per-reviewer rebuttal request bodies for the host to execute,
        # then ingest each with ar_panel_ingest phase='rebuttal'. No network -> default timeout.
        argv.append("--prepare")
        return _cli_result("panel", argv)
    # Direct path: call the reviewers over HTTP (needs the router key in the environment).
    return _cli_result("panel", argv, timeout=_panel_timeout())


def h_aggregate(args):
    """Aggregate the run into a fresh verdict. _safe_run pins the target run so aggregate.py binds
    to the same run whose freshness is checked here (no lexicographic-vs-numeric or concurrent-init
    split). Freshness is proven by moving any pre-existing verdict.json ASIDE and requiring
    aggregate to write a NEW one — never by an mtime bump, which a coarse-granularity filesystem
    can leave unchanged on a same-quantum rewrite — so a stale PASS is never surfaced as this run's
    result. A failed aggregate restores the prior verdict and surfaces the error."""
    run_args = _safe_run(args)
    # _safe_run returns [] ONLY when no run exists (run omitted and none minted yet). Refuse rather
    # than invoke aggregate.py unpinned: an unpinned aggregate resolves the newest run ITSELF, so a
    # run that a concurrent external caller inits in the meantime would be aggregated — and its
    # verdict.json mutated — by THIS call, altering a run the caller never selected. Nothing can be
    # legitimately aggregated without a run, so require ar_init first. (CodeRabbit merge-risk, 9b93b4c.)
    if not run_args:
        raise ToolError("no run to aggregate — call ar_init first")
    try:
        run_dir = _run_dir(run_args)
    except ToolError:
        run_dir = None
    vf = (run_dir / "verdict.json") if run_dir is not None else None
    # Per-run interprocess lock: the process-wide HTTP dispatch lock does NOT serialize two
    # independently launched ar-mcp processes aggregating the SAME run, so both could move the
    # prior verdict to the one shared .prev and then race the settle below, unlinking each other's
    # verdict with no stash left to restore (reproduced: neither verdict.json nor .prev survives).
    # An O_EXCL lockfile makes the move-aside + aggregate + settle mutually exclusive per run: the
    # second caller refuses here instead of adopting the first's sidecar. verdict.json.lock is NOT
    # *.json, so it never enters the attestation. Held across the whole critical section and released
    # in the enclosing finally on EVERY exit path (accepted, rejected, or raised). (Codex, <FIX19>.)
    lock_fd = None
    lock_path = None
    if run_dir is not None and run_dir.is_dir():
        lock_path = run_dir / "verdict.json.lock"
        try:
            lock_fd = os.open(str(lock_path), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError as e:
            # Another aggregate holds the lock (or a prior one was killed before releasing it). Refuse
            # rather than run concurrently and corrupt the shared sidecar. Do NOT unlink it — this
            # process does not own it. `from e` satisfies Ruff B904.
            raise ToolError(
                "another ar_aggregate is in progress for this run (lock file "
                f"{lock_path.name} is held). If no aggregate is running, a prior one was killed "
                "before releasing it — remove the stale lock file and re-run ar_aggregate") from e
        except OSError as e:
            raise ToolError(
                f"cannot acquire the aggregate lock ({lock_path.name}): {e}") from e
    try:
        # Move any existing verdict aside so a fresh computation is proven by the NEW file's existence.
        # If the move cannot be performed, fall back to an mtime check rather than losing the signal.
        stash = None
        before_mtime = None
        stash_bytes = None
        stash_backup = None  # durable on-disk copy of the prior when the aside-move fell back to bytes
        if vf is not None and vf.is_file():
            cand = vf.parent / (vf.name + ".prev")
            cand_bak = vf.parent / (vf.name + ".bak")
            if (cand.is_file() or cand_bak.is_file()
                    or cand.is_symlink() or cand_bak.is_symlink()):
                # A recovery sidecar (.prev/.bak) is ALREADY present next to verdict.json — a prior
                # aggregate left it unreconciled. (A non-file at that path — e.g. a leftover .prev
                # directory — is not a verdict sidecar; it is left to the move-aside fallback below, which
                # already handles a rename that cannot land.) `is_symlink()` (lstat, does not follow) is
                # checked TOO: a sidecar that is a SYMLINK — including a DANGLING one, which `is_file()`
                # reports as absent — must never be adopted or written through, or the snapshot write
                # below would follow it and create/overwrite an attacker-chosen out-of-run file, and the
                # settle would move an attacker's symlink into verdict.json for ar_get_verdict to read
                # back (a symlinked sidecar in an untrusted run root is an arbitrary read/write vector).
                # (Codex P1 r3930666146.) That state is AMBIGUOUS and unsafe to guess
                # at: it is
                # EITHER a run killed mid-settle (the sidecar is the last accepted verdict and THIS
                # verdict.json is the crashed run's unreliable output) OR a run that SUCCEEDED whose
                # best-effort sidecar cleanup then failed (verdict.json is the NEWER accepted verdict and
                # the sidecar is obsolete). Disk state cannot tell the two apart, and guessing wrong loses
                # data either way: restoring the sidecar on a later rejection would roll a newer accepted
                # verdict BACK to an older one, while overwriting it would destroy the last accepted
                # verdict. So refuse and surface it — the operator reconciles the sidecar and nothing is
                # silently rolled back or lost. This fail-closed guard supersedes fix-16's preserve-and-
                # track of an existing .prev (which rolled back a newer verdict) and removes the .bak
                # overwrite (which clobbered a good backup). (Codex, 274b460.)
                raise ToolError(
                    f"a recovery sidecar ({cand.name} or {cand_bak.name}) from a prior aggregate is "
                    "present (as a regular file or a symlink) next to verdict.json — the prior run did "
                    "not reconcile it, so which file holds the last accepted verdict is ambiguous (and a "
                    "symlinked sidecar is never a valid recovery file). Inspect both and keep the "
                    "accepted verdict (remove the stale/symlinked sidecar), then re-run ar_aggregate")
            try:
                vf.replace(cand)
                stash = cand
            except OSError:
                # Could not move the prior aside under its .prev name. Keep an mtime for the freshness
                # check AND snapshot the prior's bytes (an unchanged mtime is NOT proof the file is
                # intact — a coarse-granularity filesystem can leave st_mtime_ns unchanged on a
                # same-quantum overwrite — so the restore rewrites these bytes rather than trusting
                # mtime). Persist that snapshot to a DURABLE sidecar (verdict.json.bak) BEFORE
                # aggregating: an in-memory copy alone is lost if the process is killed between
                # aggregate's overwrite and the restore, or if the write-back itself fails. No .bak
                # pre-exists here — the guard above refused if one did — so this never overwrites a good
                # backup. If the prior can be neither read NOR durably backed up, abort before aggregation
                # so it is never lost. (.bak, like .prev, is not *.json, so it never enters the
                # attestation.) (Codex, 52c686f & 274b460; CodeRabbit, 60cb2c3.)
                try:
                    before_mtime = vf.stat().st_mtime_ns
                    stash_bytes = vf.read_bytes()
                    cand_bak.write_bytes(stash_bytes)
                    stash_backup = cand_bak
                except OSError as e:
                    # Surface the filesystem cause: the tools/call handler sends only str(ToolError)
                    # to the client, so include {e}; `from e` also satisfies Ruff B904. (CodeRabbit,
                    # 274b460.)
                    raise ToolError("cannot snapshot the prior verdict.json to guarantee a restore "
                                    "(it could be neither moved aside nor durably backed up) — refusing "
                                    f"to aggregate so a prior verdict is never lost: {e}") from e
        elif vf is not None:
            # verdict.json is absent — a prior aggregate was interrupted BEFORE the settle that would have
            # reconciled it, stranding the last accepted verdict at a sidecar. It may sit at .prev (the
            # move-aside path: verdict.json was renamed to .prev, then the run died before settling) OR at
            # .bak (the rename-FALLBACK path: the move-aside failed, so the prior was durably snapshotted to
            # .bak, then the run died — or its restore failed — leaving verdict.json unwritten). The durable
            # .bak MUST stay recoverable here too: ignoring it would aggregate with no stash and, worse, a
            # successful retry would leave the stale .bak behind, so the NEXT call refuses at the entry guard
            # above over an unrecoverable sidecar. Adopt exactly one regular, non-symlink sidecar as this
            # run's stash — restored on a rejected aggregate, discarded once a fresh verdict supersedes it (a
            # .bak restores by the same rename a .prev uses, so no separate bytes path is needed here).
            # (CodeRabbit r3941598640.)
            cand = vf.parent / (vf.name + ".prev")
            cand_bak = vf.parent / (vf.name + ".bak")
            if cand.is_symlink() or cand_bak.is_symlink():
                # A symlinked sidecar in an untrusted run root is an arbitrary read/write vector: adopted, it
                # would be moved into verdict.json for ar_get_verdict to follow (Codex P1 r3930666147). It is
                # never a valid recovery file — refuse rather than adopt or silently ignore it, so this path
                # treats a symlinked sidecar exactly as the entry guard above does.
                raise ToolError(
                    f"a recovery sidecar ({cand.name} or {cand_bak.name}) next to an absent verdict.json is "
                    "a symlink — a symlinked sidecar is never a valid recovery file. Remove it, then re-run "
                    "ar_aggregate")
            prev_ok = cand.is_file()
            bak_ok = cand_bak.is_file()
            if prev_ok and bak_ok:
                # A .prev AND a .bak both hold a candidate last-accepted verdict — which is authoritative is
                # ambiguous, and adopting one could restore a stale verdict over a newer one. Refuse and
                # surface it (as the entry guard does) rather than guess. (CodeRabbit r3941598640.)
                raise ToolError(
                    f"both recovery sidecars ({cand.name} and {cand_bak.name}) are present while "
                    "verdict.json is absent — which holds the last accepted verdict is ambiguous. Inspect "
                    "both and keep the accepted verdict (remove the other), then re-run ar_aggregate")
            if prev_ok:
                stash = cand
            elif bak_ok:
                stash = cand_bak
        # The moved-aside verdict is reconciled in the single finally below, which runs on EVERY exit
        # path — the accepted return, the rejected return, and a raised invocation (e.g. _run_cli's
        # subprocess timeout). Earlier revisions restored the prior in several separate branches and
        # each added branch was a fresh chance to strand or leak one; routing every path through one
        # settle point (the same try/finally shape h_panel_ingest and the http server already use)
        # makes that class of bug unrepresentable. `accepted` flips true only once a fresh, well-formed
        # verdict is actually in hand.
        accepted = False
        try:
            rc, out, err = _run_cli("aggregate", run_args)
            body = (out or "").strip()
            if err and err.strip():
                body = (body + "\n" + err.strip()).strip()
            if vf is None:  # the run dir may not have resolved before the call — resolve it now
                try:
                    vf = _run_dir(run_args) / "verdict.json"
                except ToolError:
                    vf = None
            # aggregate exits 0 PASS / 1 FAIL / 2 BLOCKED for a real verdict and writes verdict.json as
            # its final step. If it exited some other way (e.g. crashed on a malformed artifact) or did
            # NOT write a fresh verdict, never surface a pre-existing verdict as success.
            fresh = bool(vf and vf.is_file()
                         and (before_mtime is None or vf.stat().st_mtime_ns != before_mtime))
            # Reject with a SPECIFIC reason (stale / crashed / malformed / unrecognized / wrong-run) so an
            # operator can tell them apart — WITHOUT changing which verdicts are accepted. `reason` stays
            # "" only when a fresh, recognized verdict for THIS run is in hand.
            reason = ""
            if rc not in (0, 1, 2):
                reason = "exit code is not a verdict result (expected 0, 1, or 2)"
            elif not fresh:
                reason = "aggregate wrote no fresh verdict.json"
            else:
                try:
                    structured = json.loads(vf.read_text(encoding="utf-8"))
                except (OSError, ValueError, RecursionError):
                    # A fresh file that is unreadable, MALFORMED, or pathologically deep (json.loads raises
                    # RecursionError on deep nesting — NOT a ValueError) is not a usable verdict. Guarding
                    # read/parse here (as check_digest does) yields a clean rejected result rather than
                    # crashing h_aggregate past the return below. (CodeRabbit, 7da1420; Codex, 60cb2c3.)
                    structured = None
                # A fresh OBJECT is not enough: accept only a RECOGNIZED verdict value FOR THE PINNED RUN.
                # run_args always carries --run here (h_aggregate refuses an empty run_args at entry), so
                # the fresh verdict aggregate wrote must carry that same run_id — a stray/foreign object
                # (an empty {}, an unknown verdict, or another run's verdict) is rejected below. Attestation
                # PRESENCE is deliberately not gated here — that is check_digest's concern. (CodeRabbit, bdccc64.)
                pinned = run_args[run_args.index("--run") + 1] if "--run" in run_args else None
                # aggregate.py maps its verdict to its exit code (PASS=0, FAIL=1, BLOCKED=2) and writes
                # verdict.json BEFORE the human-readable verdict.md; if it crashes AFTER that write (e.g. an
                # untrusted run has verdict.md as a directory, so the markdown write raises), it exits
                # nonzero while a fresh, well-formed verdict.json is already on disk. Requiring the exit code
                # to MATCH the written verdict (below) makes such a post-write crash a rejection, not an
                # accepted verdict that carries a traceback. (Codex r3941637886.)
                verdict_exit = {"PASS": 0, "FAIL": 1, "BLOCKED": 2}
                if not isinstance(structured, dict):
                    reason = "the fresh verdict.json was unreadable, malformed, or not a JSON object"
                elif structured.get("verdict") not in ("PASS", "FAIL", "BLOCKED"):
                    reason = f"unrecognized verdict value {structured.get('verdict')!r}"
                elif not (pinned is None or structured.get("run_id") == pinned):
                    reason = (f"verdict run_id {structured.get('run_id')!r} does not match the resolved "
                              f"run {pinned!r}")
                elif rc != verdict_exit[structured["verdict"]]:
                    reason = (f"aggregate exit code {rc} does not match the written verdict "
                              f"{structured['verdict']!r} (expected {verdict_exit[structured['verdict']]}) "
                              "— aggregate likely crashed after writing verdict.json, so it is not a "
                              "completed aggregation")
                else:
                    accepted = True  # only now: a fresh, recognized verdict for THIS run is in hand
                    return _result(body or structured.get("verdict", ""), structured=structured)
            return _result(f"aggregate exited {rc} without an accepted verdict ({reason}):\n{body}",
                           is_error=True)
        finally:
            # Single settle point for the moved-aside verdict. On acceptance the stash is a superseded
            # copy — discard it. On ANY non-acceptance (rejected exit, or a raised/timed-out invocation)
            # remove whatever rejected verdict was written and restore the prior — from the .prev stash if
            # the aside-move succeeded, else by rewriting the durable .bak snapshot — so ar_get_verdict
            # always sees either the freshly accepted verdict or the last accepted one, never a
            # rejected/partial verdict, never a stranded sidecar.
            # A restore that FAILS here (a transient OSError — a Windows file lock, a vanished parent)
            # must NOT be swallowed: doing so silently strands the accepted prior at its sidecar while
            # ar_get_verdict sees no verdict, or a rejected one, with no signal. Capture such a failure and
            # surface it, naming the sidecar the prior survives at. On a NORMAL return, raise a ToolError.
            # When ANOTHER exception is already unwinding (e.g. _run_cli's subprocess timeout) do not
            # silently drop it: fold the restore failure INTO that error when it is a ToolError, else log
            # it — so a client is never told only "aggregate timed out" while its accepted verdict sits
            # stranded and ar_get_verdict can no longer return it. (Codex, 13d473f & 60cb2c3.)
            reconcile_err = None
            reconcile_at = None  # sidecar the un-restored prior survives at, for the recovery message
            if accepted:
                for s in (stash, stash_backup):  # at most one is set — drop the superseded copy
                    if s is not None and s.is_file():
                        try:
                            s.unlink()
                        except OSError:
                            pass
            elif stash is not None:
                # Prior was moved aside to .prev — drop any rejected verdict aggregate wrote, then restore
                # the prior from the stash. BOTH steps run under one guard so a failure of EITHER (the
                # unlink or the .prev -> verdict.json move) is recorded, not swallowed.
                try:
                    if vf is not None and vf.is_file():
                        vf.unlink()
                    if stash.is_file():
                        stash.replace(vf)
                except OSError as e:
                    reconcile_err, reconcile_at = e, stash
            elif stash_bytes is not None:
                # The aside-move failed, so the prior was byte-snapshotted (and durably backed up to .bak).
                # Rewrite the bytes verbatim — a write can succeed on the very filesystem whose rename
                # failed, and it overwrites any rejected verdict written in the same mtime quantum (this
                # restore never trusts mtime). On success drop the now-redundant .bak; on failure the prior
                # is NOT lost — it survives at .bak, which the error names.
                if vf is not None:
                    try:
                        vf.write_bytes(stash_bytes)
                    except OSError as e:
                        reconcile_err, reconcile_at = e, stash_backup
                if reconcile_err is None and stash_backup is not None and stash_backup.is_file():
                    try:
                        stash_backup.unlink()
                    except OSError:
                        pass
            else:
                # No prior verdict existed — just remove any rejected verdict aggregate wrote. A failure
                # here loses nothing (there is no prior to strand), so it stays best-effort.
                if vf is not None and vf.is_file():
                    try:
                        vf.unlink()
                    except OSError:
                        pass
            if reconcile_err is not None:
                where = reconcile_at.name if reconcile_at is not None else "verdict.json.prev"
                detail = ("aggregate was rejected but the prior verdict could not be restored "
                          f"({reconcile_err}); the last accepted verdict is preserved at {where} — "
                          "restore it manually before trusting ar_get_verdict")
                exc = sys.exc_info()[1]
                if exc is None:
                    raise ToolError(detail)
                if isinstance(exc, ToolError):
                    # Fold the restore failure INTO the in-flight tool error so the client is told BOTH,
                    # never only the original (e.g. "aggregate timed out") with the prior silently
                    # stranded and unrecoverable via ar_get_verdict. (Codex, 60cb2c3.)
                    raise ToolError(f"{exc}; additionally, {detail}")
                # An unexpected non-ToolError is louder and must not be masked — but still record the
                # stranded prior so a failed restore during that unwind is never fully silent.
                log(f"prior verdict restore failed ({reconcile_err}); preserved at {where} — "
                    "restore it before trusting ar_get_verdict")
    finally:
        # Release the per-run lock on every exit path. Close BEFORE unlink so the removal succeeds on
        # Windows too (an open handle blocks delete there). A failure to unlink leaves a stale lock
        # the operator can clear — never crash the settle over it, and never unlink a lock this
        # process did not create (lock_fd is None then). (Codex, <FIX19>.)
        if lock_fd is not None:
            try:
                os.close(lock_fd)
            except OSError:
                pass
            if lock_path is not None:
                try:
                    os.unlink(str(lock_path))
                except OSError:
                    pass


def h_check_digest(args):
    run_args = _safe_run(args)
    # aggregate.py resolves the run BEFORE --check-digest runs; a missing or typo'd run makes
    # resolve_run die() with exit 1 — the SAME code this wrapper maps to {"intact": false}
    # ("drifted"). That would report "there is no run to verify" as detected TAMPERING. Confirm the
    # run exists here so a genuine exit 1 can only be check_digest's real attestation MISMATCH — the
    # cannot-verify contract this handler exists to keep (a missing run is a tool error, not drift).
    # (Fable, 60cb2c3.)
    try:
        rd = _run_dir(run_args)
    except ToolError:
        raise ToolError("no run to verify — call ar_init and ar_aggregate first")
    if not rd.is_dir():
        raise ToolError(f"run {rd.name} not found — check the run id, or aggregate the run first")
    rc, out, err = _run_cli("aggregate", [*run_args, "--check-digest"])
    body = ((out or "") + (err or "")).strip()
    # aggregate --check-digest exits 0 = intact, 1 = drifted (a definitive mismatch), 2 = the
    # digest could not be checked at all (no verdict.json, or a verdict from before
    # attestations existed). Only 0/1 are a real answer; anything else is a tool error, not a
    # silent "drifted".
    if rc == 0:
        return _result(body or "attestation intact", structured={"intact": True})
    if rc == 1:
        return _result(body or "attestation drifted", structured={"intact": False})
    return _result(body or f"cannot verify attestation (--check-digest exited {rc}); "
                   "aggregate the run first", is_error=True)


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
       "family. Pin models with entries like 'security=<provider>/<model-slug>'.",
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
        "force": {"type": "boolean", "description": "Re-run reviewers even if reports already exist."},
        "catalog_file": {"type": "string", "description": "Path to a cached catalog JSON (the same one passed to ar_panel_assign), so a reviewer substitution can resolve when the live catalog is unavailable."}},
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

    _t("ar_panel_rebuttal",
       "Run the adversarial rebuttal round: each reviewer now sees the others' high/critical "
       "findings and must refute, corroborate, or extend each with evidence. Required (per the "
       "run's rebuttal policy) before a SENSITIVE/CRITICAL run with high/critical findings can "
       "reach a verdict. Set prepare=true to write per-reviewer rebuttal request bodies for your "
       "host to execute, then ingest each with ar_panel_ingest phase='rebuttal' (the keyless "
       "path); omit prepare to have the server call the reviewers directly over HTTP.",
       {"run": _RUN_PROP,
        "prepare": {"type": "boolean", "description": "Write rebuttal request bodies for host "
                    "execution (keyless) instead of calling the reviewers directly over HTTP."}},
       [], _NET, h_panel_rebuttal),

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
    "(or ar_panel_run) -> ar_panel_rebuttal when the run's rebuttal policy requires it "
    "(high/critical findings; prepare+ingest its request bodies the same way) -> "
    "ar_aggregate for the verdict. Launch this server with the "
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
        arguments = params.get("arguments")
        if arguments is None:
            arguments = {}
        elif not isinstance(arguments, dict):
            # A falsy non-dict ([], "", 0, false) must be rejected, not silently defaulted to
            # {} by `or {}` — otherwise a malformed request becomes an empty-argument call.
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


def serve_message(raw):
    """Transport-agnostic core: turn one raw JSON-RPC message string into a response string,
    or ``None`` when there is nothing to send back (a notification, or any message ``handle``
    declines to answer). Parse errors and handler crashes are converted to JSON-RPC error
    responses here, so every transport gets identical error semantics and neither the stdio
    loop nor a future HTTP handler can be killed by a single malformed message."""
    try:
        msg = json.loads(raw)
    except (ValueError, RecursionError):
        # Any malformed message must frame as a parse error rather than escape and kill the
        # transport. json.loads raises JSONDecodeError or UnicodeDecodeError (both ValueError —
        # bad JSON text, or bad UTF-8 once a bytes-oriented transport hands over raw bytes) and
        # RecursionError (pathologically nested input overflowing the decoder). Panel finding
        # correctness-1 + CodeRabbit stability review.
        return json.dumps(_error(None, -32700, "parse error"))
    try:
        response = handle(msg)
    except Exception as e:  # a malformed message must never kill the transport
        log(f"handler crashed on a message: {e}")
        response = _error(msg.get("id") if isinstance(msg, dict) else None,
                          -32603, "internal error")
    return None if response is None else json.dumps(response)


class StdioTransport:
    """Newline-delimited JSON-RPC over stdin/stdout — the *framing* half of the server, kept
    separate from dispatch (``handle`` / ``serve_message``) so a second transport (the
    Streamable-HTTP surface, E3-S2) can reuse the exact same core without touching this loop.
    Streams are injectable so the framing is testable offline; they default to real stdio."""

    def __init__(self, stdin=None, stdout=None):
        self.stdin = stdin if stdin is not None else sys.stdin
        self.stdout = stdout if stdout is not None else sys.stdout

    def serve_forever(self):
        for line in self.stdin:
            line = line.strip()
            if not line:
                continue
            out = serve_message(line)
            if out is not None:
                self.stdout.write(out + "\n")
                self.stdout.flush()


# --- Streamable-HTTP transport (MCP 2026-07-28) — E3-S2a: endpoint + framing only ---------------
# Reuses serve_message()/handle() (the E3-S1 seam), so HTTP inherits stdio's exact dispatch and error
# semantics and stays a framing surface, never a command-execution one. There is NO authentication and
# NO session yet (those are E3-S2c / E3-S2b): the listener binds 127.0.0.1 by default and MUST NOT be
# exposed to a network until auth lands. See the committed threat model in docs/.
HTTP_DEFAULT_HOST = "127.0.0.1"
HTTP_DEFAULT_PORT = 8730
HTTP_DEFAULT_MAX_BYTES = 1_048_576  # 1 MiB: a JSON-RPC control message is tiny; caps an oversized-body DoS


def _http_int_env(name, default, minimum=None, maximum=None):
    """Parse an integer env setting. An unset/blank var takes the default; a NON-BLANK but invalid or
    out-of-range value is a loud error, never a silent fallback — a typo'd cap must not quietly widen the
    oversized-body DoS bound, and a negative/oversized value must not start a broken listener."""
    v = (os.environ.get(name, "") or "").strip()
    if not v:
        return default
    try:
        n = int(v)
    except ValueError:
        raise ValueError("%s must be an integer, got %r" % (name, v)) from None
    if minimum is not None and n < minimum:
        raise ValueError("%s must be >= %d, got %d" % (name, minimum, n))
    if maximum is not None and n > maximum:
        raise ValueError("%s must be <= %d, got %d" % (name, maximum, n))
    return n


def http_config():
    """Resolve HTTP transport config from env — localhost-only and restrictive by default. Invalid
    numeric settings fail loudly (see _http_int_env) rather than silently reverting to a default."""
    host = (os.environ.get("AR_MCP_HTTP_HOST", "").strip() or HTTP_DEFAULT_HOST)
    port = _http_int_env("AR_MCP_HTTP_PORT", HTTP_DEFAULT_PORT, minimum=0, maximum=65535)
    origins = tuple(o.strip() for o in os.environ.get("AR_MCP_HTTP_ORIGINS", "").split(",") if o.strip())
    max_bytes = _http_int_env("AR_MCP_HTTP_MAX_BYTES", HTTP_DEFAULT_MAX_BYTES, minimum=1)
    return host, port, origins, max_bytes


def origin_allowed(origin, allowed):
    """DNS-rebinding defense. A browser page attacking a localhost server ALWAYS sends an Origin
    header on a cross-origin fetch, so a *present* Origin must be in the allowlist; an *absent* Origin
    (curl or a programmatic MCP host — never a browser cross-origin request) is allowed."""
    if origin is None:
        return True
    return origin in allowed


def is_loopback_host(host):
    """True only for a loopback bind target — 'localhost', 127.0.0.0/8, or ::1. E3-S2a has NO auth,
    so binding anywhere else would expose an unauthenticated tool surface to the network; bind()
    refuses it. A hostname other than 'localhost' is treated as non-loopback (refused) — we do not
    resolve DNS to decide safety. An EMPTY host is NOT loopback: the socket layer binds "" to 0.0.0.0
    (all interfaces), so it is refused too — the resolved default (http_config) is always 127.0.0.1."""
    h = (host or "").strip().lower()
    if h == "localhost":
        return True
    try:
        return ipaddress.ip_address(h).is_loopback
    except ValueError:
        return False


# Dispatch is serialized process-wide: the MCP tool handlers are stateful (they write context.md and
# spawn subprocesses under a run dir), and stdio drives them one message at a time. ThreadingHTTPServer
# accepts connections concurrently, so this lock preserves that one-at-a-time invariant for the HTTP
# path and prevents two runs from racing the same on-disk state.
_HTTP_DISPATCH_LOCK = threading.Lock()


class _MCPHTTPHandler(http.server.BaseHTTPRequestHandler):
    """One Streamable-HTTP request. The owning server carries `allowed_origins` and `max_bytes`."""
    protocol_version = "HTTP/1.1"

    def version_string(self):
        return SERVER_NAME  # minimal Server header — do not leak the Python/http.server version

    def log_message(self, fmt, *args):
        return  # quiet; serve_message() already logs handler crashes via log()

    def _json(self, status, payload, extra=None):
        # Every _json() response is a rejection (Origin/version/size) or a non-POST method — none of
        # them drains the request body. On a keep-alive HTTP/1.1 connection an undrained body would
        # desync the next request (request smuggling), and for the 413 path draining an oversized body
        # would itself be the DoS we are refusing. So close the connection after any _json() response.
        # The 200/202 success paths read the full declared body and may keep-alive normally.
        body = json.dumps(payload).encode("utf-8")
        self.close_connection = True
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _not_allowed(self):
        # No GET/SSE server->client stream yet (that is E3-S2b); the endpoint accepts only POST.
        self._json(405, {"error": "method not allowed; the MCP endpoint accepts POST"}, {"Allow": "POST"})

    do_GET = _not_allowed
    do_HEAD = _not_allowed
    do_PUT = _not_allowed
    do_DELETE = _not_allowed
    do_PATCH = _not_allowed
    do_OPTIONS = _not_allowed

    def do_POST(self):
        # (1) DNS-rebinding defense first: reject a disallowed browser Origin before touching the body.
        if not origin_allowed(self.headers.get("Origin"), self.server.allowed_origins):
            self._json(403, {"error": "origin not allowed"})
            return
        # (2) HTTP-level protocol-version negotiation. Absent is fine (the modern per-request _meta path
        #     negotiates in-band); a present-but-unsupported version is rejected with what we speak.
        pv = self.headers.get("MCP-Protocol-Version")
        if pv is not None and pv not in ALL_PROTOCOLS:
            self._json(400, {"error": "unsupported MCP-Protocol-Version",
                             "supportedVersions": list(ALL_PROTOCOLS)})
            return
        # (3) Frame strictly by Content-Length: reject any Transfer-Encoding (chunked et al.), even when
        #     combined with Content-Length. We do not decode a chunked body, so it would sit unread on a
        #     keep-alive connection and desync into the next request (smuggling) — refuse with a closed 400.
        if self.headers.get("Transfer-Encoding") is not None:
            self._json(400, {"error": "Transfer-Encoding not supported; frame the body with Content-Length"})
            return
        # (4) Bound the body (DoS): refuse an oversized or unparseable declared length outright.
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = -1
        if length < 0 or length > self.server.max_bytes:
            self._json(413, {"error": "request body too large"})
            return
        raw = self.rfile.read(length) if length else b""
        # (5) Dispatch through the transport-agnostic core, serialized (see _HTTP_DISPATCH_LOCK) so the
        #     stateful tool handlers keep stdio's one-at-a-time invariant. serve_message() accepts bytes
        #     and never raises: a malformed body frames as -32700, a handler crash as -32603.
        with _HTTP_DISPATCH_LOCK:
            out = serve_message(raw)
        if out is None:
            # A notification (or any message handle() declines to answer) -> 202 Accepted, no body.
            self.send_response(202)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        body = out.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        if pv is not None:
            self.send_header("MCP-Protocol-Version", pv)  # echo the negotiated version
        self.end_headers()
        self.wfile.write(body)


class HttpTransport:
    """Streamable-HTTP framing (MCP 2026-07-28) over stdlib http.server, reusing serve_message() — the
    E3-S2a endpoint. POST only: application/json for a response, 202 for a notification. NO auth and NO
    session yet (E3-S2c / E3-S2b): binds 127.0.0.1 by default and MUST NOT be exposed remotely until
    auth lands. Binding is split from serving so the framing is testable offline on an ephemeral port."""

    def __init__(self, host=None, port=None, origins=None, max_bytes=None):
        h, p, o, m = http_config()
        self.host = h if host is None else host
        self.port = p if port is None else port
        self.origins = tuple(o) if origins is None else tuple(origins)
        self.max_bytes = m if max_bytes is None else max_bytes
        self.httpd = None

    def bind(self):
        """Create + bind the server (no serving yet); return the actual (host, port) — the port is
        OS-assigned when 0 was requested. Split out so offline tests can bind an ephemeral port.
        Refuses a non-loopback host: E3-S2a has no authentication, so a network-reachable bind is
        never allowed here (it becomes possible only once auth lands, E3-S2c)."""
        if not is_loopback_host(self.host):
            raise ValueError(
                "refusing to bind the ar-mcp HTTP transport to non-loopback host %r: E3-S2a has NO "
                "authentication, so a network-reachable bind is refused. Keep AR_MCP_HTTP_HOST on "
                "loopback (127.0.0.1 / ::1 / localhost) until auth lands (E3-S2c)." % (self.host,))
        # Pick the address family from the host so an IPv6 loopback (::1) actually binds — the default
        # ThreadingHTTPServer is AF_INET, which cannot bind an IPv6 address. Defer bind/activate so the
        # family can be set first, and clean up the socket if the bind itself fails.
        httpd = http.server.ThreadingHTTPServer((self.host, self.port), _MCPHTTPHandler,
                                                bind_and_activate=False)
        httpd.address_family = socket.AF_INET6 if ":" in self.host else socket.AF_INET
        httpd.daemon_threads = True
        httpd.allowed_origins = self.origins
        httpd.max_bytes = self.max_bytes
        try:
            httpd.server_bind()
            httpd.server_activate()
        except BaseException:
            httpd.server_close()
            raise
        self.httpd = httpd
        return httpd.server_address

    def serve_forever(self):
        if self.httpd is None:
            self.bind()
        addr = self.httpd.server_address
        log(f"http transport ready on {addr[0]}:{addr[1]} "
            "(localhost-only, NO auth — E3-S2a; do not expose remotely until E3-S2c)")
        try:
            self.httpd.serve_forever()
        finally:
            self.httpd.server_close()

    def shutdown(self):
        if self.httpd is not None:
            self.httpd.shutdown()


def select_transport(argv=None, env=None):
    """stdio unless AR_MCP_TRANSPORT=http or --http is passed. Pure + tiny so main()'s choice is
    unit-testable without starting a server."""
    argv = sys.argv if argv is None else argv
    env = os.environ if env is None else env
    if (env.get("AR_MCP_TRANSPORT", "").strip().lower() == "http") or ("--http" in argv):
        return "http"
    return "stdio"


def main():
    if select_transport() == "http":
        HttpTransport().serve_forever()
    else:
        log(f"v{VERSION} ready on stdio (cwd={os.getcwd()})")
        StdioTransport().serve_forever()


if __name__ == "__main__":
    main()
