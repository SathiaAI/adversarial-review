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

import hashlib
import hmac
import http.server
import ipaddress
import json
import os
import re
import secrets
import select
import socket
import stat
import subprocess
import sys
import tempfile
import threading
from collections import OrderedDict
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


# Ceiling on a snapshotted catalog_file (see _snapshot_confined_catalog). A real model catalog is well
# under a megabyte; this is generous headroom while still refusing a multi-gigabyte DoS file.
_CATALOG_MAX_BYTES = 16 * 1024 * 1024


def _cleanup_snapshot(snapshot):
    """Best-effort removal of the private catalog snapshot _snapshot_confined_catalog created. The caller
    invokes this in a finally once the panel subprocess (which reads the snapshot synchronously within
    _cli_result) has returned — on every path: success, rejection, or timeout."""
    if snapshot is not None:
        try:
            snapshot.unlink()
        except OSError:
            pass


def _snapshot_confined_catalog(args, argv):
    """Validate an optional catalog_file, COPY it to a private server-owned snapshot, and forward the
    SNAPSHOT (not the caller's path) to panel.py. Returns the snapshot Path — the caller MUST remove it
    once the panel subprocess has finished (see _cleanup_snapshot) — or None when no catalog was supplied.

    Confinement (below) proves the catalog is a relative path inside the working tree: no traversal, no
    POSIX-absolute path, no Windows-absolute path (drive letter or backslash/UNC), and no symlink whose
    target escapes the tree. But confinement alone is not enough, because every consumer that opens the
    catalog BY PATH reopens an attacker-controllable location: the in-process loadable check and the
    panel.py subprocess both do, and panel.py reloads it lazily on reviewer substitution. A symlink
    swapped at that path AFTER validation would redirect either open outside the tree (or to a FIFO that
    blocks), and a catalog that aliases any file the run itself writes (context.md, sample_policy.json, ...)
    is destroyed before the substitution reload. So rather than forward the path, open the validated file
    ONCE through a race-safe descriptor and copy its bytes to a private snapshot the server owns; both
    consumers read THAT, which no repo or run activity can change. This closes the check-to-open race and
    removes the need to enumerate every run-written destination (CodeRabbit r3950684588 / Codex
    r3950590290 — superseding the r3950286015 canonical-path forwarding and the r3946169158 context.md
    alias check, both of which still reopened by path)."""
    cf = args.get("catalog_file")
    if cf is None:
        return None
    if (not isinstance(cf, str) or not cf or "\x00" in cf or ".." in cf
            or cf.startswith(("/", "\\")) or "\\" in cf or _DRIVE_RE.match(cf)):
        raise ToolError("catalog_file must be a relative path within the repository "
                        "(no traversal, no absolute or drive-letter path, no backslashes)")
    # Lexical checks stop only textual escapes; a relative path can still be a symlink whose target lives
    # outside the tree, so resolve it (following symlinks) and confirm it stays within the working tree.
    root = Path.cwd().resolve()
    target = (root / cf).resolve()
    if target != root and root not in target.parents:
        raise ToolError("catalog_file must resolve to a path within the repository "
                        "(its symlink target escapes the working tree)")
    # Open the resolved path race-safely, then copy from the OPEN descriptor so no consumer ever reopens
    # the caller's path. O_NOFOLLOW turns a final-component symlink swapped in AFTER resolution into an
    # error instead of an out-of-tree read; O_NONBLOCK keeps the open from blocking on a FIFO (so the
    # fstat below rejects it rather than the read hanging with no _run_cli timeout to guard it); fstat on
    # the descriptor itself — never a separate stat — proves a regular file and bounds the size with no
    # TOCTOU. O_NOFOLLOW is LOAD-BEARING here, not merely defense-in-depth: resolve() canonicalizes the
    # path but does NOT pin the object across this reopen, so between resolve() and os.open() the
    # (now-resolved) leaf can be swapped for an out-of-tree symlink, and only O_NOFOLLOW rejects it. On a
    # platform without O_NOFOLLOW (Windows) getattr(...,0) would silently drop that protection and follow
    # the swap — so FAIL CLOSED instead (matching _read_policy_racesafe, fix-35), letting the caller
    # surface the error rather than snapshot an external catalog (Codex r3952220749). O_NONBLOCK/O_BINARY
    # stay getattr — they are convenience/defense-in-depth, not the confinement guarantee.
    if not hasattr(os, "O_NOFOLLOW"):
        raise ToolError("cannot open catalog_file without following symlinks on this platform "
                        "(os.O_NOFOLLOW unavailable); refusing the confined snapshot")
    flags = (os.O_RDONLY | os.O_NOFOLLOW
             | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0))
    try:
        fd = os.open(str(target), flags)
    except OSError as e:
        raise ToolError(f"catalog_file could not be opened safely: {e}") from e
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise ToolError("catalog_file must be a regular file")
        if info.st_size > _CATALOG_MAX_BYTES:
            raise ToolError(f"catalog_file is too large ({info.st_size} bytes > {_CATALOG_MAX_BYTES}) — a "
                            "model catalog is far smaller; refusing to load it")
        sfd, spath = tempfile.mkstemp(prefix="ar-catalog-", suffix=".json")
        snapshot = Path(spath)
        try:
            remaining = info.st_size
            while remaining > 0:
                chunk = os.read(fd, min(1024 * 1024, remaining))
                if not chunk:
                    break
                os.write(sfd, chunk)
                remaining -= len(chunk)
            os.close(sfd)
        except BaseException:
            os.close(sfd)
            _cleanup_snapshot(snapshot)
            raise
    finally:
        os.close(fd)
    argv.extend(["--catalog-file", str(snapshot)])
    return snapshot


def _require_loadable_snapshot(snapshot):
    """A snapshotted catalog forwarded by h_panel_run must also be LOADABLE before context.md is
    overwritten. panel.py loads it lazily (on reviewer substitution), AFTER the write, so a usable-looking
    but unloadable catalog (malformed, or empty after family filtering) would otherwise leave completed
    reviewer reports paired with a freshly-written context on a call the host was told failed. Validate
    with panel.py's OWN loader so the check never drifts from the run's filter; a file argument takes
    load_catalog's no-network path. `snapshot` is the private path _snapshot_confined_catalog returned
    (None when no catalog) — already a server-owned regular file within the size cap, so only loadability
    is left to decide here."""
    if snapshot is None:
        return
    try:
        from panel import load_catalog
        load_catalog(str(snapshot))
    except (Exception, SystemExit):  # SystemExit = panel's die() on an empty-after-filter catalog
        raise ToolError("catalog_file is not a usable model catalog "
                        "(missing, unreadable, malformed, or empty after filtering)")


# Ceiling on the policy file read IN-PROCESS for timeout budgeting. A real policy is a few lines; this
# bounds an untrusted repo's oversized/sparse policy that would otherwise be pulled whole into the MCP
# process, which no _run_cli timeout guards (Codex r3950830841).
_POLICY_MAX_BYTES = 1024 * 1024


def _read_policy_racesafe():
    """Return the repo policy (load_policy's dict), or None when no policy file is present — read WITHOUT
    reopening the untrusted pathname load_policy would (CodeRabbit r3951172615). A stat-then-reopen was a
    check-to-open race: Path.stat() follows symlinks, so a symlink swapped to a FIFO after the check could
    block the in-process read (no _run_cli timeout guards it), or redirect it outside the tree. This opens
    the policy ONCE through a race-safe descriptor — O_NOFOLLOW rejects a symlink leaf (ELOOP), O_NONBLOCK
    stops a FIFO from blocking the open, and fstat on the descriptor proves a regular file within
    _POLICY_MAX_BYTES with no TOCTOU — copies its bytes to a private server-owned snapshot, and hands
    load_policy THAT snapshot, never the mutable path. Raises on an unsafe/oversized policy; load_policy
    still die()s on a malformed one. (Same race-safe read the catalog uses.)"""
    from _common import POLICY_BASENAMES, load_policy
    root = Path.cwd()
    # lexists (not exists): a DANGLING policy symlink is present-but-unsafe, not "absent" — exists() would
    # drop it and mislead _resolved_high_samples into the non-conservative "1" instead of the max budget;
    # lexists keeps it, and the O_NOFOLLOW open below then fails closed on it (CodeRabbit r3951475453).
    present = [n for n in POLICY_BASENAMES if os.path.lexists(root / n)]  # the open below is race-safe regardless
    if not present:
        return None
    if len(present) > 1:
        # load_policy() rejects a repo that ships BOTH policy files; mirror that here (CodeRabbit
        # r3951335743) so a conflicting pair budgets conservatively via the caller's fallback instead of
        # silently reading whichever we happened to pick first.
        raise ToolError("both %s exist — keep exactly one" % " and ".join(POLICY_BASENAMES))
    name = present[0]
    # O_NOFOLLOW is load-bearing here: the policy path is opened UN-resolved, so without it a symlinked
    # .adversarial-review.yml would be followed to its (possibly out-of-tree) target. It is absent on some
    # platforms (Windows), where getattr(...,0) would silently disable that protection — so FAIL CLOSED
    # (CodeRabbit r3951335750), letting the caller budget conservatively. (The catalog snapshot keeps the
    # getattr fallback because it opens an already-RESOLVED, symlink-free path, so O_NOFOLLOW is only
    # defense-in-depth there, not load-bearing.)
    if not hasattr(os, "O_NOFOLLOW"):
        raise ToolError("cannot open the policy without following symlinks on this platform "
                        "(os.O_NOFOLLOW unavailable); refusing the in-process read")
    flags = (os.O_RDONLY | os.O_NOFOLLOW
             | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0))
    fd = os.open(str(root / name), flags)   # ELOOP if the leaf is a symlink (O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > _POLICY_MAX_BYTES:
            raise ToolError("policy file must be a regular file within the size cap")
        buf = b""
        remaining = info.st_size
        while remaining > 0:
            chunk = os.read(fd, min(1024 * 1024, remaining))
            if not chunk:
                break
            buf += chunk
            remaining -= len(chunk)
    finally:
        os.close(fd)
    snapdir = Path(tempfile.mkdtemp(prefix="ar-policy-"))
    try:
        (snapdir / name).write_bytes(buf)
        return load_policy(root=snapdir)   # parses the SNAPSHOT, never the untrusted path
    finally:
        try:
            (snapdir / name).unlink()
        except OSError:
            pass
        try:
            snapdir.rmdir()
        except OSError:
            pass


def _resolved_high_samples():
    """The corroboration sample count panel.py will actually use, resolved with panel.py's own
    precedence: AR_HIGH_SAMPLES env var > policy ``high_samples`` (.adversarial-review.yml/.json) >
    default "1". Returned unparsed for the caller to int()+clamp. Never raises and never exits — merely
    sizing a subprocess timeout, so any unsafe/oversized/malformed policy falls back to a conservative
    budget rather than taking the server down; panel.py reads and validates the real policy when it runs."""
    env = os.environ.get("AR_HIGH_SAMPLES", "")
    if env != "":            # matches resolve_setting: a set, non-empty env var wins over policy
        return env
    try:
        pol = _read_policy_racesafe()  # race-safe read; never reopens the untrusted policy path
    except (Exception, SystemExit):    # unsafe/oversized policy, or load_policy die() on a malformed one
        return "25"                    # budget the clamp max (never under-counts); panel.py reads it bounded
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
    Returns (returncode, stdout, stderr). The child inherits this process's environment — h_aggregate uses
    that to hand the aggregate child its per-lock re-entrancy token (see there) without exposing it as a
    public CLI flag."""
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
        # RECOVERY_PENDING vs NO_VERDICT: a stranded .prev/.bak means a prior aggregate was interrupted
        # before it settled. Recovery is fail-closed — the sidecar is NEVER promoted to a verdict here
        # (an attacker-writable run dir could plant a forged PASS), so ar_get_verdict does not return it.
        # Re-run ar_aggregate to recompute a fresh verdict. (CodeRabbit r3942141283 / Codex r3942166700.)
        if (run_dir / "verdict.json.prev").is_file() or (run_dir / "verdict.json.bak").is_file():
            raise ToolError(
                f"no accepted verdict for {run_dir.name}: a prior aggregate was interrupted, leaving a "
                "recovery sidecar (verdict.json.prev/.bak) that is NOT promoted automatically. Re-run "
                "ar_aggregate to recompute a fresh verdict; inspect and remove the sidecar if it is stale.")
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
    # panel.py assign opens the catalog_file (to resolve the reviewer pool when the live /models catalog
    # is unavailable), so forward a private snapshot rather than the caller's path — same race-safety as
    # h_panel_run — and remove it once the subprocess has read it.
    snapshot = None
    try:
        snapshot = _snapshot_confined_catalog(args, argv)
        return _cli_result("panel", argv, timeout=300)
    finally:
        _cleanup_snapshot(snapshot)


def _run_context_path(run_args):
    """The server-controlled <run>/context.md path (fixed filename in the run dir) that _write_context
    persists to. Exposed separately so h_panel_run can reject a catalog_file that aliases it BEFORE the
    write overwrites it."""
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
    return run_dir / "context.md"


def _write_context(run_args, context):
    """Persist the caller-provided context to <run>/context.md and return its path.
    The path is server-controlled (fixed filename in the run dir), so the context
    string can never redirect the write elsewhere."""
    cf = _run_context_path(run_args)
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
    # Snapshot the optional catalog_file to a private server-owned path BEFORE persisting context, and
    # forward the snapshot to panel.py. Snapshotting before the write means a rejected/escaping catalog
    # raises before _write_context mutates the audit record, and it decouples the catalog from both the
    # later by-path reopen and any run-written file it might alias (context.md, sample_policy.json, ...),
    # so no separate context.md-alias check is needed. Forward it because, when the router cannot serve
    # /models, a reviewer failure makes panel.py run reload the catalog to pick its mandated substitute.
    catalog_argv = []
    snapshot = None
    try:
        snapshot = _snapshot_confined_catalog(args, catalog_argv)
        # The snapshot must also be LOADABLE before persisting context, so an unusable catalog cannot
        # mutate the audit record on a rejected call.
        _require_loadable_snapshot(snapshot)
        cf = _write_context(run_args, context)
        argv = ["run"] + run_args + ["--context-file", cf] + catalog_argv
        if args.get("force"):
            argv.append("--force")
        return _cli_result("panel", argv, timeout=_panel_timeout())
    finally:
        # panel.py has read the snapshot synchronously within _cli_result by the time control reaches here.
        _cleanup_snapshot(snapshot)


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
    # Validate that `prepare` is an ACTUAL boolean before it selects the transport (Codex r3894216938):
    # this server does not auto-validate tool arguments against the advertised schema, so a truthy
    # non-boolean (e.g. the string "false", or a number/list) would otherwise be treated as enabled and
    # take the keyless prepare path instead of running the direct rebuttal — rejecting it is safer than
    # guessing intent.
    prepare = args.get("prepare", False)
    if not isinstance(prepare, bool):
        raise ToolError("prepare must be a boolean")
    argv = ["rebuttal", *run_args]
    if prepare:
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
    lock_token = None   # per-lock re-entrancy secret handed to the aggregate child (see below)
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
        # Re-entrancy capability for THIS wrapper's aggregate child (CodeRabbit r3951923661). The child
        # (aggregate.py) also takes verdict.json.lock when run standalone, but must NOT re-acquire the lock
        # THIS wrapper already holds. The signal that authorizes the child to skip must be one a standalone
        # invocation cannot forge — an earlier public --lock-already-held flag was accepted from ANY caller,
        # re-opening the very bypass fix-37 closed. So mint a random token, write its SHA-256 HASH into the
        # 0o600 lock file we own, and hand the child the PREIMAGE via env (below). The child skips only when
        # its env token hashes to the stored hash; a standalone caller can read the hash but cannot invert
        # it to a matching preimage, so it always takes the lock and is refused while one is held. (This
        # stays cross-platform — inheriting the lock fd would be POSIX-only and break the Windows MCP path.)
        lock_token = os.urandom(32).hex()
        try:
            os.write(lock_fd, hashlib.sha256(lock_token.encode("ascii")).hexdigest().encode("ascii"))
        except OSError as e:
            try:
                os.close(lock_fd)
            except OSError:
                pass
            try:
                os.unlink(str(lock_path))
            except OSError:
                pass
            raise ToolError(f"cannot write the aggregate lock token ({lock_path.name}): {e}") from e
    try:
        # Move any existing verdict aside so a fresh computation is proven by the NEW file's existence.
        # If the move cannot be performed, fall back to an mtime check rather than losing the signal.
        stash = None
        before_mtime = None
        stash_bytes = None
        stash_backup = None  # durable on-disk copy of the prior when the aside-move fell back to bytes
        stranded = None      # a RECOVERY_PENDING sidecar (verdict.json absent): never promoted here,
                             # only superseded for audit once a fresh verdict is accepted (settle below)
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
                except OSError as e:
                    # Surface the filesystem cause: the tools/call handler sends only str(ToolError)
                    # to the client, so include {e}; `from e` also satisfies Ruff B904. (CodeRabbit, 274b460.)
                    raise ToolError("cannot read the prior verdict.json to guarantee a restore — refusing "
                                    f"to aggregate so a prior verdict is never lost: {e}") from e
                # Create the backup sidecar ATOMICALLY (CodeRabbit r3941991607). lstat-then-write_bytes was
                # TOCTOU: a symlink swapped in at .bak after the lstat would be FOLLOWED by write_bytes and
                # overwrite its target. os.open with O_CREAT|O_EXCL|O_WRONLY fails if ANYTHING already exists
                # at the path — a regular file, symlink, FIFO, socket, or directory — so a pre-existing or
                # raced sidecar can be neither followed nor blocked on; the snapshot is written through the
                # returned fd. (A regular/symlink .bak was already refused by the entry guard; O_EXCL closes
                # the residual race and also rejects a non-regular .bak without opening/blocking on it.)
                try:
                    bak_fd = os.open(str(cand_bak), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
                except FileExistsError as e:
                    raise ToolError(
                        f"the backup sidecar path {cand_bak.name} already exists — refusing to snapshot the "
                        "prior verdict through it so ar_aggregate cannot follow a symlink or clobber a file; "
                        "remove it, then re-run ar_aggregate") from e
                except OSError as e:
                    raise ToolError("cannot create the backup sidecar to guarantee a restore — refusing to "
                                    f"aggregate so a prior verdict is never lost: {e}") from e
                try:
                    with os.fdopen(bak_fd, "wb") as bf:
                        bf.write(stash_bytes)
                except OSError as e:
                    raise ToolError("cannot write the backup sidecar to guarantee a restore — refusing to "
                                    f"aggregate so a prior verdict is never lost: {e}") from e
                stash_backup = cand_bak
                # Prove freshness by EXISTENCE, not mtime (Codex r3942166702). The aside-move failed, so
                # verdict.json is still in place; if aggregate rewrites it within the same coarse mtime
                # quantum, `st_mtime_ns` is unchanged and the freshness check below would mislabel a
                # genuinely fresh verdict as stale and roll it back to .bak. The prior is now durably at
                # .bak, so removing the original loses nothing and forces aggregate to CREATE a new file
                # (existence == fresh), exactly as the move-aside path already does.
                try:
                    vf.unlink()
                    before_mtime = None
                except OSError as e:
                    # The prior can be neither moved aside (the rename above failed) NOR removed — e.g. a
                    # Windows handle that shares writes but not deletes. Freshness-by-existence is then
                    # impossible, and falling back to the mtime check is unsafe: on a coarse-granularity
                    # filesystem aggregate can rewrite verdict.json within the prior's mtime quantum, the
                    # freshness check would read st_mtime_ns as unchanged, mislabel a genuinely fresh verdict
                    # as stale, and the settle would ROLL BACK a fresh FAIL to the prior PASS (Codex
                    # r3945727346, reproduced). Fail closed — refuse to aggregate rather than risk that
                    # rollback. verdict.json is untouched (its unlink failed); the redundant .bak just
                    # snapshotted is best-effort removed so the run dir is left exactly as found. This raise
                    # precedes the inner aggregate try, so only the outer finally runs — the per-run lock is
                    # still released, and no settle/restore runs against the intact prior.
                    try:
                        cand_bak.unlink()
                    except OSError:
                        pass
                    raise ToolError(
                        "cannot move the prior verdict aside or remove it, so a fresh aggregate cannot be "
                        "distinguished from the prior one without trusting filesystem timestamps (which a "
                        "coarse-granularity filesystem can leave unchanged) — refusing to aggregate so a "
                        f"fresh verdict is never rolled back to the prior one: {e}. Resolve the lock on "
                        "verdict.json (or its directory), then re-run ar_aggregate.") from e
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
            # verdict.json is absent with a stranded sidecar: RECOVERY_PENDING. Do NOT adopt it as a
            # promotable stash. Fix-24 validated the sidecar by re-verifying its attestation digest, but
            # compute_attestation() hashes the run's PUBLIC *.json artifacts — all attacker-writable — and
            # never binds the verdict VALUE, so a planted PASS whose (freely recomputable) digest matches
            # passed that check and, on a rejected retry, the settle promoted it to verdict.json for
            # ar_get_verdict to return (CodeRabbit r3942141283 / Codex r3942166700). Recovery is now
            # fail-closed: ar_aggregate only recomputes a FRESH verdict here and NEVER promotes a sidecar.
            # A rejected/crashed retry leaves verdict.json absent (RECOVERY_PENDING persists); a successful
            # one supersedes the stranded sidecar for audit (settle below). Promotion of a stranded sidecar
            # is the sole job of ar_recover, behind a signature-over-the-complete-verdict gate or an
            # explicit operator confirmation bound to the sidecar bytes.
            stranded = cand if prev_ok else (cand_bak if bak_ok else None)
        # The moved-aside verdict is reconciled in the single finally below, which runs on EVERY exit
        # path — the accepted return, the rejected return, and a raised invocation (e.g. _run_cli's
        # subprocess timeout). Earlier revisions restored the prior in several separate branches and
        # each added branch was a fresh chance to strand or leak one; routing every path through one
        # settle point (the same try/finally shape h_panel_ingest and the http server already use)
        # makes that class of bug unrepresentable. `accepted` flips true only once a fresh, well-formed
        # verdict is actually in hand.
        accepted = False
        try:
            # This wrapper holds verdict.json.lock across the whole move-aside -> aggregate -> settle
            # section, so authorize the aggregate child to skip re-acquiring it — otherwise the child's own
            # O_EXCL open would fail against the lock this process already holds and every MCP aggregate
            # would reject. The authorization is the unforgeable token handshake above (CodeRabbit
            # r3951923661): hand the child the PREIMAGE through the environment it inherits (only when we
            # actually took the lock — if the run dir did not resolve we hold none, so the child takes its
            # own). A standalone invocation has no such env token and cannot forge one matching the lock
            # file's stored hash. Set it just for this call and restore after, so the token never leaks to
            # other subprocesses; h_aggregate runs under the serialized dispatch lock, so this transient
            # os.environ mutation is not raced. (Codex r3951566976.)
            _prev_tok = os.environ.get("AR_AGGREGATE_LOCK_TOKEN")
            if lock_fd is not None and lock_token is not None:
                os.environ["AR_AGGREGATE_LOCK_TOKEN"] = lock_token
            try:
                rc, out, err = _run_cli("aggregate", run_args)
            finally:
                if _prev_tok is None:
                    os.environ.pop("AR_AGGREGATE_LOCK_TOKEN", None)
                else:
                    os.environ["AR_AGGREGATE_LOCK_TOKEN"] = _prev_tok
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
            rejected_unremoved = False  # a rejected verdict.json that could not be removed NOR moved aside
            if accepted:
                # Drop the superseded copies: the moved-aside prior (stash / stash_backup), and — on the
                # RECOVERY_PENDING path — the stranded sidecar, now superseded by the fresh authoritative
                # verdict. Leaving the stranded sidecar in place would trip the entry guard on the NEXT
                # aggregate (a sidecar beside verdict.json is refused as unreconciled).
                for s in (stash, stash_backup, stranded):  # at most one of stash/stash_backup is set
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
                        # A concurrent process with write access to the untrusted run dir can replace the
                        # PREDICTABLE .prev with a symlink AFTER this wrapper created it (via vf.replace(cand)
                        # above) but before this settle. os.replace() renames the link itself, so it would
                        # PROMOTE that symlink to verdict.json, after which ar_get_verdict follows it out of
                        # the run dir and returns an external file's contents (Codex r3952220753, reproduced).
                        # is_file() FOLLOWS the link, so guard with an lstat (is_symlink) and refuse to promote
                        # a symlinked stash; the prior is then treated as unrestorable (verdict.json stays
                        # absent -> RECOVERY_PENDING) rather than exposing an out-of-run target as this run's
                        # verdict. (The entry guard already rejects a symlinked .prev present at entry; this
                        # covers the swap that happens AFTER the wrapper creates the stash.)
                        if stash.is_symlink():
                            raise OSError(f"recovery stash {stash.name} was replaced by a symlink after "
                                          "creation; refusing to promote it to verdict.json")
                        stash.replace(vf)
                        # Belt-and-suspenders against a swap in the tiny window between the lstat and the
                        # rename: NEVER leave verdict.json as a symlink for ar_get_verdict to follow.
                        if vf is not None and vf.is_symlink():
                            try:
                                vf.unlink()
                            except OSError:
                                pass
                            raise OSError("restored verdict.json resolved to a symlink; removed it "
                                          "rather than surface an out-of-run target as the verdict")
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
                # No prior verdict was moved aside — remove any rejected verdict aggregate wrote. A leftover
                # here strands no PRIOR, but the rejected verdict.json itself is NOT an accepted verdict, and
                # a later ar_get_verdict would return it as one (Codex r3944027644 reproduced an exit-3/PASS
                # whose cleanup hit a PermissionError, after which ar_get_verdict returned PASS). So do NOT
                # swallow the failure: if the unlink fails (transient OSError / Windows lock), move the file
                # aside to a non-verdict, non-sidecar name (.rejected — not *.json, so never attested; not
                # .prev/.bak, so never a recovery candidate) so it can never be read back as a verdict; only
                # if THAT also fails do we surface the failure so the rejected file is never silently readable.
                if vf is not None and vf.is_file():
                    try:
                        vf.unlink()
                    except OSError:
                        try:
                            vf.replace(vf.parent / (vf.name + ".rejected"))
                        except OSError as e:
                            reconcile_err, reconcile_at, rejected_unremoved = e, vf, True
            if reconcile_err is not None:
                if rejected_unremoved:
                    # A rejected verdict that could be neither removed nor moved aside: warn that the
                    # leftover verdict.json is NOT an accepted verdict and must be removed before it is read.
                    detail = ("aggregate was rejected but the rejected verdict.json could be neither removed "
                              f"nor moved aside ({reconcile_err}); it is NOT an accepted verdict — remove it "
                              "before calling ar_get_verdict, which would otherwise return it as a verdict")
                else:
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
                # reconcile failure so it is never fully silent during that unwind. Log `detail` (always
                # assigned for BOTH the prior-restore and rejected-output branches); the earlier code read
                # `where`, which the rejected_unremoved branch never sets — an UnboundLocalError that would
                # itself mask the original exception (CodeRabbit r3945458785).
                log(detail)
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
       "findings and must refute, corroborate, or extend each with evidence. Required before a run "
       "with high/critical findings can reach a verdict whenever the run's rebuttal policy demands "
       "it: 'critical' (CRITICAL runs), 'contention' (SENSITIVE and CRITICAL; the default), or "
       "'any' (every tier, including NORMAL). Set prepare=true to write per-reviewer rebuttal "
       "request bodies for your host to execute, then ingest each with ar_panel_ingest "
       "phase='rebuttal' (the keyless path); omit prepare to have the server call the reviewers "
       "directly over HTTP.",
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

    # A body that DECLARES the modern era (params._meta carries io.modelcontextprotocol/protocolVersion)
    # has NO `initialize` handshake: the 2026-07-28 revision is stateless and removed it. Serving such a
    # request as the legacy handshake below would negotiate a legacy version and (over HTTP) mint a legacy
    # Mcp-Session-Id for a client that declared modern — a contradictory state its own modern GET/DELETE
    # then 404/405 on (Codex r3949809506). Reject it here in the shared core, so the era is validated from
    # the BODY regardless of transport or whether an HTTP MCP-Protocol-Version header was present.
    if method == "initialize" and is_modern:
        return _error(id_, -32601,
                      "method not found: 'initialize' is the legacy (pre-2026-07-28) handshake; the "
                      "stateless 2026-07-28 revision has no initialize (omit params._meta to use the "
                      "legacy handshake)", {"declared": requested_version})

    # Legacy initialize handshake — selects legacy semantics (the body did not declare the modern era).
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


# --- Dual-era Streamable-HTTP transport — E3-S2a endpoint/framing + E3-S2b sessions ---------------
# Reuses serve_message()/handle() (the E3-S1 seam), so HTTP inherits stdio's exact dispatch and error
# semantics and stays a framing surface, never a command-execution one. The transport routes by
# protocol ERA (CodeRabbit r3941912010): the stateless MCP 2026-07-28 revision is POST-only — it
# removed protocol-level sessions, the Mcp-Session-Id header, and the HTTP GET stream (server->client
# notifications moved to a POST subscriptions/listen stream), so a GET or DELETE pinned to a modern
# version is 405. The session lifecycle (Mcp-Session-Id minted at initialize, validated, DELETE-
# terminable, GET opens the SSE channel, bounded+evicting store) is LEGACY — MCP revisions through
# 2025-11-25 — and each id is bound to the version its initialize negotiated (Codex r3941957895).
# Sessions are OPTIONAL on the legacy path, so a version-less client still works;
# AR_MCP_HTTP_REQUIRE_SESSION makes them mandatory. Bearer-token auth (E3-S2c) gates EVERY request when
# AR_MCP_HTTP_TOKEN is set; with no token the listener binds 127.0.0.1 only (a non-loopback bind is refused).
# A remote bind speaks plaintext HTTP, so it MUST sit behind a TLS terminator. See the threat model in docs/.
HTTP_DEFAULT_HOST = "127.0.0.1"
HTTP_DEFAULT_PORT = 8730
HTTP_DEFAULT_MAX_BYTES = 1_048_576  # 1 MiB: a JSON-RPC control message is tiny; caps an oversized-body DoS
HTTP_DEFAULT_MAX_SESSIONS = 128     # bounded session store: a flood of `initialize`s cannot exhaust memory
HTTP_DEFAULT_MAX_STREAMS = 64       # bounded concurrent GET/SSE streams: each pins a thread+fd, so cap their
                                    # count independently of the session store (one valid id != unlimited streams)
HTTP_DEFAULT_MAX_WORKERS = 128      # bounded worker/connection pool (E3-S2c): stdlib ThreadingHTTPServer spawns
                                    # one thread per connection, unbounded — a connection flood would exhaust
                                    # threads/fds. Cap it. MUST exceed MAX_STREAMS (an SSE GET holds its worker for
                                    # the stream's whole life), else streams starve POST dispatch; bind() enforces it.
HTTP_DEFAULT_READ_TIMEOUT = 30      # per-recv socket read timeout, seconds (E3-S2c): bounds an idle slow-loris on
                                    # the request read + a stalled response write. Dispatch does no socket IO, so it
                                    # never interrupts a running tool. (A sub-timeout dribble still holds a worker —
                                    # the bounded pool caps that blast radius; a true wall-clock deadline is follow-up.)
HTTP_MIN_TOKEN_LEN = 16             # reject a too-short AR_MCP_HTTP_TOKEN: a brute-forceable secret must not be
                                    # allowed to authenticate a network-reachable surface.
AUTH_HEADER = "Authorization"       # bearer-token header (E3-S2c)
SESSION_HEADER = "Mcp-Session-Id"   # LEGACY session id header (revisions through 2025-11-25; issued at initialize)
SSE_KEEPALIVE_SECONDS = 15          # GET/SSE idle keepalive-comment cadence; also the shutdown re-check tick


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


_HTTP_BOOL_TRUE = ("1", "true", "yes", "on")     # explicit affirmatives
_HTTP_BOOL_FALSE = ("0", "false", "no", "off")   # explicit negatives


def _http_bool_env(name):
    """A boolean env flag: true for an explicit affirmative ('1'/'true'/'yes'/'on'), false for an
    explicit negative ('0'/'false'/'no'/'off') or when unset/blank. A NON-BLANK value that is neither
    is a loud error, never a silent fallback — mirroring _http_int_env. Failing *safe* on a typo'd
    AR_MCP_HTTP_REQUIRE_SESSION means refusing to start, NOT silently flipping the security posture to
    off: a value like 'tru' must not quietly disable the session requirement."""
    v = (os.environ.get(name, "") or "").strip().lower()
    if not v:
        return False
    if v in _HTTP_BOOL_TRUE:
        return True
    if v in _HTTP_BOOL_FALSE:
        return False
    raise ValueError("%s must be one of %s (on) or %s (off), got %r"
                     % (name, "/".join(_HTTP_BOOL_TRUE), "/".join(_HTTP_BOOL_FALSE), v))


def http_config():
    """Resolve HTTP transport config from env — localhost-only and restrictive by default. Invalid
    numeric settings fail loudly (see _http_int_env) rather than silently reverting to a default."""
    host = (os.environ.get("AR_MCP_HTTP_HOST", "").strip() or HTTP_DEFAULT_HOST)
    port = _http_int_env("AR_MCP_HTTP_PORT", HTTP_DEFAULT_PORT, minimum=0, maximum=65535)
    origins = tuple(o.strip() for o in os.environ.get("AR_MCP_HTTP_ORIGINS", "").split(",") if o.strip())
    max_bytes = _http_int_env("AR_MCP_HTTP_MAX_BYTES", HTTP_DEFAULT_MAX_BYTES, minimum=1)
    return host, port, origins, max_bytes


def http_token():
    """Resolve the bearer token from AR_MCP_HTTP_TOKEN (E3-S2c). Returns None when the variable is UNSET
    (no auth; the transport then binds loopback-only, same-user trust). A variable that is PRESENT but
    blank, or shorter than HTTP_MIN_TOKEN_LEN, FAILS LOUDLY — it must never silently disable auth or
    authenticate a network-reachable surface with a trivially guessable secret. Surrounding whitespace is
    trimmed (so `TOKEN=$(cat file)` with a trailing newline still works); the trimmed value is the secret."""
    raw = os.environ.get("AR_MCP_HTTP_TOKEN")
    if raw is None:
        return None
    tok = raw.strip()
    if not tok:
        raise ValueError("AR_MCP_HTTP_TOKEN is set but blank: refusing to start (fail closed). Unset it to "
                         "run loopback-only without auth, or set a real token.")
    if len(tok) < HTTP_MIN_TOKEN_LEN:
        raise ValueError("AR_MCP_HTTP_TOKEN must be at least %d characters (got %d): a short token is "
                         "brute-forceable over the network." % (HTTP_MIN_TOKEN_LEN, len(tok)))
    return tok


def origin_allowed(origin, allowed):
    """DNS-rebinding defense. A browser page attacking a localhost server ALWAYS sends an Origin
    header on a cross-origin fetch, so a *present* Origin must be in the allowlist; an *absent* Origin
    (curl or a programmatic MCP host — never a browser cross-origin request) is allowed."""
    if origin is None:
        return True
    return origin in allowed


def is_loopback_host(host):
    """True only for a loopback bind target — 'localhost', 127.0.0.0/8, or ::1. Without a token, binding
    anywhere else would expose an unauthenticated tool surface to the network, so bind() refuses a
    non-loopback host unless AR_MCP_HTTP_TOKEN is set (E3-S2c). A hostname other than 'localhost' is
    treated as non-loopback (refused) — we do not
    resolve DNS to decide safety. An EMPTY host is NOT loopback: the socket layer binds "" to 0.0.0.0
    (all interfaces), so it is refused too — the resolved default (http_config) is always 127.0.0.1."""
    h = (host or "").strip().lower()
    if h == "localhost":
        return True
    try:
        return ipaddress.ip_address(h).is_loopback
    except ValueError:
        return False


def _accepts_event_stream(accept):
    """True iff an HTTP Accept header admits the SSE media type (text/event-stream). An ABSENT Accept
    means "accept anything" (RFC 9110 §12.5.1) and is admitted. Otherwise the MOST SPECIFIC matching
    media range decides — text/event-stream > text/* > */* — and an explicit `q=0` on the winning range
    is honored as "not acceptable". So a GET that excludes SSE with `application/json` OR
    `text/event-stream;q=0` is refused, and is neither handed the stream nor charged a stream slot for a
    representation it declared it cannot consume (Codex r3941957888)."""
    if accept is None:
        return True
    rank = {"text/event-stream": 2, "text/*": 1, "*/*": 0}
    best_rank = -1        # -1 = no range matched SSE
    best_ok = False
    for part in accept.split(","):
        seg = part.strip()
        if not seg:
            continue
        pieces = seg.split(";")
        r = rank.get(pieces[0].strip().lower())
        if r is None:
            continue      # a non-matching range (e.g. application/json) never admits SSE
        q = 1.0           # q defaults to 1; q<=0 means this range is not acceptable
        has_media_param = False  # a non-q parameter BEFORE q constrains the representation (e.g. level=1)
        seen_q = False           # parameters AFTER q are accept-extensions, not media params (RFC 9110)
        for p in pieces[1:]:
            k, _sep, v = p.strip().partition("=")
            key = k.strip().lower()
            if key == "q":
                try:
                    q = float(v.strip())
                except ValueError:
                    q = 0.0
                seen_q = True
            elif key and not seen_q:
                has_media_param = True   # a media parameter before q; extensions after q are ignored
                                         # (so text/event-stream;q=1;foo=bar still matches — Codex r3945470144)
        # A range carrying a media parameter (e.g. text/event-stream;level=1) only matches a
        # representation that has that parameter; this server emits a parameterless text/event-stream, so
        # such a range does NOT match and must not override a later, plainer alternative. Skipping it means
        # e.g. `text/event-stream;level=1;q=0, text/event-stream;q=1` correctly admits the stream via the
        # second range instead of being rejected 406 by the first (Codex r3943958164 / CodeRabbit r3943913914).
        if has_media_param:
            continue
        if r > best_rank:  # a more specific matching range overrides a less specific one (RFC precedence)
            best_rank = r
            best_ok = q > 0
        elif r == best_rank:
            # Equal-specificity alternatives: an ACCEPTABLE one wins regardless of field order, so
            # `text/event-stream;q=0, text/event-stream;q=1` (or the same split across combined Accept field
            # lines) admits the stream instead of the first occurrence permanently deciding it 406 (Codex
            # r3951751953). Only a TIE is OR-merged; a MORE specific range still overrides via the branch
            # above, so `*/*;q=1, text/event-stream;q=0` still correctly refuses (the specific q=0 wins).
            best_ok = best_ok or (q > 0)
    return best_ok


class _SessionStore:
    """Bounded, evicting, thread-safe store of live Streamable-HTTP session ids. Sessions belong to the
    LEGACY session lifecycle (MCP revisions through 2025-11-25: `initialize` mints an id, GET opens the
    SSE channel, DELETE terminates); the stateless 2026-07-28 revision has no sessions. Ids are
    cryptographically random and *server-minted*: a client-supplied id the server never issued is never
    honored (anti-hijack). Each id is BOUND to the protocol version its `initialize` negotiated — a
    request pinning a different version is not honored for it (Codex r3941957895). The store is bounded
    with LRU eviction so a flood of `initialize`s cannot exhaust memory. A terminated or evicted id
    WAKES any SSE stream registered against it (Codex r3941957873) so the stream — and its bounded slot —
    ends at once rather than lingering to the next keepalive tick. All access is under one lock:
    ThreadingHTTPServer dispatches concurrently."""

    def __init__(self, capacity):
        self._cap = max(1, int(capacity))
        self._ids = OrderedDict()  # sid -> negotiated protocol version (the id is bound to it)
        self._wakes = {}           # sid -> list[threading.Event]: SSE streams to wake when it ends
        self._lock = threading.Lock()

    def create(self, protocol=None):
        """Mint a fresh id (256 bits from `secrets`), evicting the least-recently-used if at capacity."""
        sid = secrets.token_urlsafe(32)
        evicted = []
        with self._lock:
            self._ids[sid] = protocol
            self._ids.move_to_end(sid)
            while len(self._ids) > self._cap:
                old, _ = self._ids.popitem(last=False)  # evict least-recently-used
                evicted.append(old)
        for old in evicted:
            self._wake(old)  # an evicted id is dead -> end its stream promptly, don't leak the slot
        return sid

    def _matches(self, sid, version):
        # Caller holds the lock. True iff `sid` is live AND (no version is pinned, or it equals the
        # session's negotiated version). This binding stops a legacy session from being reused under a
        # different protocol version — e.g. a 2025-06-18 session driving a request pinned to 2026-07-28.
        if sid not in self._ids:
            return False
        return version is None or self._ids[sid] == version

    def valid(self, sid, version=None):
        """True iff `sid` is a live, server-minted id whose negotiated version matches `version` (when
        one is pinned); touches it most-recently-used so an active session is not evicted under a client."""
        if not sid:
            return False
        with self._lock:
            if self._matches(sid, version):
                self._ids.move_to_end(sid)
                return True
            return False

    def terminate(self, sid, version=None):
        """Remove a session (client DELETE). True iff it existed AND its negotiated version matches
        `version` (when pinned); a repeat/unknown/version-mismatched terminate is False. Wakes every SSE
        stream bound to the id so its stream slot is released immediately."""
        if not sid:
            return False
        with self._lock:
            if not self._matches(sid, version):
                return False
            del self._ids[sid]
            wakes = self._wakes.pop(sid, ())
        for ev in wakes:
            ev.set()
        return True

    def register_wake(self, sid, version=None):
        """Atomically validate `sid` (bound to `version` when pinned) AND register a wake Event for it,
        under one lock. Returns the Event, fired when `sid` is later terminated, evicted, or wake_all()
        runs — so an open SSE stream stops the instant its session ends. The Event is returned PRE-SET
        when the session is not currently valid, so the GET handler validates-and-registers in a single
        step: a DELETE that lands in the window between a separate check and registration cannot slip a
        200 + ": connected" past for an already-dead session (Codex r3943958149)."""
        ev = threading.Event()
        with self._lock:
            if self._matches(sid, version):
                self._wakes.setdefault(sid, []).append(ev)
            else:
                ev.set()
        return ev

    def unregister_wake(self, sid, ev):
        """Drop a wake Event when its stream ends (the GET handler's finally), so the registry does not
        grow across streams."""
        with self._lock:
            lst = self._wakes.get(sid)
            if lst is not None:
                try:
                    lst.remove(ev)
                except ValueError:
                    pass
                if not lst:
                    self._wakes.pop(sid, None)

    def _wake(self, sid):
        # Caller must NOT hold the lock. Fire and drop every wake for a now-dead id (eviction path).
        with self._lock:
            wakes = self._wakes.pop(sid, ())
        for ev in wakes:
            ev.set()

    def wake_all(self):
        """Fire every registered wake (server shutdown) so all open SSE streams stop waiting at once."""
        with self._lock:
            all_wakes = [ev for lst in self._wakes.values() for ev in lst]
            self._wakes.clear()
        for ev in all_wakes:
            ev.set()

    def __len__(self):
        with self._lock:
            return len(self._ids)


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

    def setup(self):
        # Apply the per-server socket read timeout (E3-S2c) BEFORE the base handler wires rfile/wfile, so a
        # slow-loris dribbling the request line/headers/body — or a peer that stalls reading the response —
        # cannot pin this worker thread indefinitely. self.server is set by BaseRequestHandler before setup();
        # StreamRequestHandler.setup() calls settimeout(self.timeout). The SSE GET path re-sets its own
        # SSE_KEEPALIVE_SECONDS timeout after this. None => no timeout (unchanged default).
        self.timeout = getattr(self.server, "read_timeout", None)
        super().setup()

    def _auth_ok(self):
        # Bearer-token auth (E3-S2c). A no-op PASS when the transport has no token configured (loopback-only,
        # same-user trust — bind() refuses a non-loopback host without a token). When a token IS set, EVERY
        # request must carry exactly one `Authorization: Bearer <token>`; missing / malformed / duplicated /
        # mismatched -> a closed 401 with a generic body (never echoing the supplied credential) and a
        # `WWW-Authenticate: Bearer` challenge. Called AFTER the Origin/protocol boundary checks (a bad-Origin
        # browser is already 403'd, so attacker bytes never reach compare_digest for a request already doomed)
        # and BEFORE any body read or dispatch, so an unauthenticated caller triggers no tool work. The token
        # comes only from the environment (never argv/URL/query) and is never logged.
        token = getattr(self.server, "token", None)
        if token is None:
            return True
        vals = self.headers.get_all(AUTH_HEADER) or []
        if len(vals) != 1:  # missing, or an ambiguous / smuggled duplicate Authorization header
            return self._auth_fail()
        scheme, _sep, param = vals[0].partition(" ")
        provided = param.strip()
        if scheme.strip().lower() != "bearer" or not provided:
            return self._auth_fail()
        # Constant-time compare (hmac.compare_digest) so a mismatch does not leak how many leading bytes
        # matched. Both sides are utf-8 bytes; the operator-side min-length guard (http_token) mitigates the
        # length-equality side channel compare_digest cannot hide.
        if not hmac.compare_digest(provided.encode("utf-8"), token.encode("utf-8")):
            return self._auth_fail()
        return True

    def _auth_fail(self):
        # 401 + a Bearer challenge; the body is a constant that never reflects what the client sent.
        self._json(401, {"error": "authentication required"}, {"WWW-Authenticate": "Bearer"})
        return False

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
        # The MCP endpoint speaks POST (JSON-RPC in), GET (SSE server->client stream, E3-S2b), and
        # DELETE (terminate a session, E3-S2b). Any other method is 405.
        self._json(405, {"error": "method not allowed; the MCP endpoint accepts POST, GET, DELETE"},
                   {"Allow": "POST, GET, DELETE"})

    do_HEAD = _not_allowed
    do_PUT = _not_allowed
    do_PATCH = _not_allowed
    do_OPTIONS = _not_allowed

    def _origin_ok(self):
        # DNS-rebinding defense, shared by every verb: a present browser Origin must be allow-listed
        # (reject -> closed 403); an absent Origin (curl / a programmatic MCP host) is allowed.
        if origin_allowed(self.headers.get("Origin"), self.server.allowed_origins):
            return True
        self._json(403, {"error": "origin not allowed"})
        return False

    def _protocol_ok(self):
        # HTTP-level protocol-version negotiation, shared by EVERY verb (POST, GET, DELETE). Absent is
        # fine (the modern per-request _meta path negotiates in-band); a present-but-unsupported version
        # is rejected (closed 400) with what we speak. GET/DELETE run this too, not just POST — a bogus
        # pinned version must not slip through the session verbs.
        #
        # MCP-Protocol-Version is a SINGLETON control header, but a client/intermediary may split or repeat
        # it across field lines (RFC 9110 §5.3). self.headers.get() reads only the FIRST, so a contradictory
        # LATER value — `2025-06-18` then `1999-01-01`, or a legacy value then the modern revision — would
        # bypass this check and the downstream session-version binding, which read the first value too (Codex
        # r3952163012, reproduced as an initialize with a smuggled second version getting 200 + a session).
        # Reject when the header carries more than one DISTINCT value: an ambiguous pin must not be silently
        # resolved to whichever line came first. Identical repeats are harmless (get()'s first value equals
        # the rest) and pass, so a benign duplicating intermediary is tolerated.
        vals = self.headers.get_all("MCP-Protocol-Version")
        if vals and len({v.strip() for v in vals}) > 1:
            self._json(400, {"error": "conflicting MCP-Protocol-Version headers",
                             "supportedVersions": list(ALL_PROTOCOLS)})
            return False
        pv = self.headers.get("MCP-Protocol-Version")
        if pv is not None and pv not in ALL_PROTOCOLS:
            self._json(400, {"error": "unsupported MCP-Protocol-Version",
                             "supportedVersions": list(ALL_PROTOCOLS)})
            return False
        return True

    def do_POST(self):
        # (1) DNS-rebinding defense first: reject a disallowed browser Origin before touching the body.
        if not self._origin_ok():
            return
        # (2) HTTP-level protocol-version negotiation (shared with GET/DELETE); reject an unsupported
        #     pinned version before touching the body.
        if not self._protocol_ok():
            return
        # (2.5) Bearer auth (E3-S2c): after the cheap boundary checks, before any body read or dispatch, so an
        #       unauthenticated caller triggers no body read and no tool work. A no-op when no token is set.
        if not self._auth_ok():
            return
        pv = self.headers.get("MCP-Protocol-Version")
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
        # (5) Session gating (E3-S2b). Peek the JSON-RPC method to tell an `initialize` (which MINTS a
        #     session) from a subsequent request (which may CARRY one). A present Mcp-Session-Id must be
        #     one the server minted — a forged/terminated id is refused with 404, never silently honored.
        sid = self.headers.get(SESSION_HEADER)
        meta_pv = None
        body_pv = None
        try:
            peeked = json.loads(raw) if raw else None
            method = peeked.get("method") if isinstance(peeked, dict) else None
            if isinstance(peeked, dict):
                _params = peeked.get("params")
                if isinstance(_params, dict):
                    _meta = _params.get("_meta")
                    if isinstance(_meta, dict):
                        meta_pv = _meta.get(META_PROTOCOL_VERSION)  # a modern request's declared version
                    body_pv = _params.get("protocolVersion")        # a legacy initialize's requested version
        except (ValueError, RecursionError):
            method = None  # unparseable -> let serve_message() frame the -32700 (non-strict mode)
        is_initialize = (method == "initialize")
        # Route by protocol era (CodeRabbit r3941912010): a modern request declares its version in
        # params._meta; when the POST ALSO pins an MCP-Protocol-Version header, the two must agree.
        # A legacy header wrapping a modern body (or vice-versa) is contradictory — refuse it rather
        # than serve it under an ambiguous era. (Only fires when BOTH are present; a modern header over
        # a version-less legacy body, as the HTTP-negotiation path already allows, is untouched.)
        if pv is not None and isinstance(meta_pv, str) and meta_pv != pv:
            self._json(400, {"error": "MCP-Protocol-Version header does not match params._meta."
                             + META_PROTOCOL_VERSION, "header": pv, "_meta": meta_pv})
            return
        # A modern MCP-Protocol-Version header requires a modern request BODY (Codex r3943958158 +
        # r3945470142, generalizing the earlier initialize-only guard): the stateless 2026-07-28 revision
        # removed the initialize handshake and carries its version + capabilities in params._meta, and its
        # results must include resultType. A POST that pins a modern header but omits a modern _meta version
        # — a legacy `initialize`, or an ordinary legacy `tools/list`/`tools/call` — would otherwise be
        # dispatched under legacy semantics while echoing the modern version (and, for initialize, minting a
        # legacy Mcp-Session-Id the client can never use), an incoherent protocol state that also bypasses
        # modern capability/resultType handling. Reject a modern header not backed by a modern _meta version.
        # (The header/_meta mismatch above already covers a modern header paired with a DIFFERENT declared
        # version; this covers a modern header with NO modern version declared at all.)
        # `server/discover` is the version-agnostic probe a client sends BEFORE it commits to a version, so
        # a modern header on it is a legitimate hint and is exempt; every other method must back a modern
        # header with a modern body.
        if (pv in MODERN_PROTOCOLS and method != "server/discover"
                and not (isinstance(meta_pv, str) and meta_pv in MODERN_PROTOCOLS)):
            self._json(400, {"error": "a modern MCP-Protocol-Version (" + ", ".join(MODERN_PROTOCOLS)
                             + ") requires a modern request body declaring params._meta."
                             + META_PROTOCOL_VERSION + "; the modern revision is stateless with no "
                             "initialize handshake", "header": pv})
            return
        # A legacy `initialize` must not carry an MCP-Protocol-Version header that disagrees with the version
        # the handshake will actually NEGOTIATE (Codex r3945470135 + CodeRabbit r3945516733): the response
        # echoes the HEADER and the session is bound to the NEGOTIATED version — which handle() derives as
        # the body's protocolVersion when supported, else SUPPORTED_PROTOCOLS[0]. So comparing against the
        # raw body version missed a body that OMITS protocolVersion (or sends an unsupported/non-string one):
        # it negotiates SUPPORTED_PROTOCOLS[0] while echoing a different header, leaving the client with an
        # echoed version its own session id then 404s on. Compare the header to the negotiated version.
        if is_initialize and pv is not None:
            negotiated = body_pv if body_pv in SUPPORTED_PROTOCOLS else SUPPORTED_PROTOCOLS[0]
            if pv != negotiated:
                self._json(400, {"error": "MCP-Protocol-Version header does not match the version the "
                                 "initialize handshake will negotiate", "header": pv, "negotiated": negotiated})
                return
        # A present Mcp-Session-Id must be one the server minted AND must match the version this request
        # speaks (Codex r3941957895) — the pinned header version, else the modern _meta version. So a
        # stateless modern request that rides a legacy session is refused here: its 2026-07-28 version
        # cannot match the legacy version that session negotiated.
        effective_pv = pv if pv is not None else (meta_pv if isinstance(meta_pv, str) else None)
        if sid is not None and not self.server.sessions.valid(sid, effective_pv):
            self._json(404, {"error": "unknown or terminated session"})
            return
        # Strict mode (AR_MCP_HTTP_REQUIRE_SESSION, default off; turned on with the bearer token in
        # E3-S2c): a request other than the `initialize` handshake or the version-agnostic
        # `server/discover` probe must carry a valid session, else 400. Off by default so the stateless
        # 2026-07-28 path keeps working unchanged.
        if (self.server.require_session and sid is None
                and not is_initialize and method != "server/discover"):
            self._json(400, {"error": "Mcp-Session-Id required"})
            return
        # (6) Dispatch through the transport-agnostic core, serialized (see _HTTP_DISPATCH_LOCK) so the
        #     stateful tool handlers keep stdio's one-at-a-time invariant. serve_message() accepts bytes
        #     and never raises: a malformed body frames as -32700, a handler crash as -32603.
        with _HTTP_DISPATCH_LOCK:
            # Re-validate a session-bearing request AFTER acquiring the dispatch lock (Codex r3945470134):
            # the validity check above runs BEFORE this lock, so a request that queues here behind a
            # long-running handler could have had its session terminated (DELETE) or LRU-evicted in the
            # meantime, then resume and execute a (possibly state-mutating) tool for a dead session.
            # Re-check while committing to dispatch. An `initialize` mints its session and carries none, and
            # a sessionless stateless request has nothing to re-check — both have sid is None and skip this.
            if sid is not None and not self.server.sessions.valid(sid, effective_pv):
                self._json(404, {"error": "unknown or terminated session"})
                return
            out = serve_message(raw)
        # In strict mode (require_session) the stateless modern revision cannot be served here: it carries no
        # session, and every non-initialize/non-discover request without one is 400'd above -- and a legacy
        # session cannot back it (it is version-bound). So server/discover must not ADVERTISE a version this
        # configuration will reject, or a client selects it and is turned away (Codex r3951751963). Filter the
        # modern revision out of the discover response on THIS transport posture only; the transport-agnostic
        # _discover_result stays era-complete for stdio and for non-strict HTTP. A client then negotiates a
        # legacy, session-bearing version instead. (server/discover is exempt from the session gate above, so
        # it still answers in strict mode.)
        if out is not None and self.server.require_session and method == "server/discover":
            try:
                _d = json.loads(out)
                _res = _d.get("result") if isinstance(_d, dict) else None
                if isinstance(_res, dict) and isinstance(_res.get("supportedVersions"), list):
                    _res["supportedVersions"] = [v for v in _res["supportedVersions"]
                                                 if v not in MODERN_PROTOCOLS]
                    out = json.dumps(_d)
            except (ValueError, RecursionError):
                pass  # leave the response unchanged if it is not the shape we expect
        if out is None:
            # A notification (or any message handle() declines to answer) -> 202 Accepted, no body.
            self.send_response(202)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        # (7) On a SUCCESSFUL `initialize`, mint and return a session id (rotatable: a fresh id per
        #     handshake). Only on success — an errored initialize starts no session.
        session_id = None
        if is_initialize:
            try:
                resp = json.loads(out)
                if isinstance(resp, dict) and isinstance(resp.get("result"), dict):
                    session_id = self.server.sessions.create(resp["result"].get("protocolVersion"))
            except (ValueError, RecursionError):
                session_id = None
        body = out.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        if pv is not None:
            self.send_header("MCP-Protocol-Version", pv)  # echo the negotiated version
        if session_id is not None:
            self.send_header(SESSION_HEADER, session_id)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        # GET opens the LEGACY server->client SSE channel for a session (MCP revisions through
        # 2025-11-25: initialize -> Mcp-Session-Id -> GET/DELETE). The stateless 2026-07-28 revision
        # REMOVED the HTTP GET stream (server->client notifications now ride a POST subscriptions/listen
        # stream) and Mcp-Session-Id, so a GET pinned to a modern version is 405 (era routing,
        # CodeRabbit r3941912010). Origin defense applies (a browser EventSource sends Origin).
        if not self._origin_ok():
            return
        if not self._protocol_ok():
            return
        if not self._auth_ok():  # bearer auth (E3-S2c), after the boundary checks; a no-op when no token is set
            return
        pv = self.headers.get("MCP-Protocol-Version")
        if pv in MODERN_PROTOCOLS:
            self._json(405, {"error": "the event stream is a legacy session channel; MCP "
                             + ", ".join(MODERN_PROTOCOLS) + " is stateless and POST-only "
                             "(server->client notifications use a POST subscriptions/listen stream)"},
                       {"Allow": "POST"})
            return
        sid = self.headers.get(SESSION_HEADER)
        if sid is None:
            self._json(400, {"error": "Mcp-Session-Id required for the event stream"})
            return
        # Reject a GET that does not accept text/event-stream BEFORE acquiring a stream slot (Codex
        # r3941957888): a client asking only for application/json must neither be handed the SSE body
        # nor charged one of the bounded stream slots for it. An absent Accept means "accept anything".
        # Combine ALL repeated Accept field lines (RFC 9110 §5.3: a list-valued header may be split across
        # lines) so a request whose SSE-admitting value is not on the first line is negotiated on the whole
        # header, not just get("Accept")'s first value (Codex r3951256116).
        _accept_lines = self.headers.get_all("Accept")   # None when absent; a list of field lines otherwise
        if not _accepts_event_stream(", ".join(_accept_lines) if _accept_lines else None):
            self._json(406, {"error": "this endpoint streams text/event-stream; send an Accept that "
                             "admits it (text/event-stream, text/*, or */*)"})
            return
        # Validate the session, BOUND to the version this GET pins (Codex r3941957895): a valid legacy
        # session is not a blank cheque for a GET pinned to a different protocol version.
        if not self.server.sessions.valid(sid, pv):
            self._json(404, {"error": "unknown or terminated session"})
            return
        # Cap concurrent SSE streams (reliability review, PR #54): a valid session does not entitle a
        # client to unbounded parallel streams — each held-open stream pins a server thread + fd, and the
        # session-store bound limits session COUNT, not stream count (N GETs on one valid id = N threads).
        # A global BoundedSemaphore caps live streams; past the cap the GET is refused with a retryable
        # 503, and the slot is released when the stream ends (below).
        if not self.server.sse_streams.acquire(blocking=False):
            self._json(503, {"error": "too many concurrent event streams"}, {"Retry-After": "1"})
            return
        wake = None
        try:
            # Atomically re-validate the session AND register its wake under one store lock (Codex
            # r3943958149): register_wake returns a PRE-SET event when the session is already gone (or its
            # version no longer matches), so a DELETE that lands in the window between a separate check and
            # registration cannot slip a 200 + ": connected" past for a dead session. A DELETE that lands
            # AFTER registration fires the now-registered wake, which is_set() also catches here. This
            # replaces the earlier separate revalidation (Codex r3941957879) with a race-free one.
            wake = self.server.sessions.register_wake(sid, pv)
            # Bound every socket write with a timeout FIRST (reliability review, run-20260824-013958): a peer
            # that stops reading fills the TCP send buffer, and without this `wfile.write` would block
            # forever, pinning this thread + fd. A write timeout turns that into a bounded OSError that ends
            # the handler.
            self.connection.settimeout(SSE_KEEPALIVE_SECONDS)
            # Commit the stream WITHOUT taking _HTTP_DISPATCH_LOCK (E3-S2b round 6, CodeRabbit r3945707197):
            # do_POST holds that lock across serve_message(), which can run a tool for up to ~AR_TIMEOUT_S,
            # so committing the GET under the SAME lock (round 5, Codex r3945547151) let a concurrent GET
            # block for the whole dispatch. register_wake() above is atomic (validity + registration under the
            # store lock) and returns a pre-set event when the session is already gone, so a DELETE landing
            # before this check is caught by wake.is_set(), and a DELETE landing AFTER the 200 wakes the
            # keepalive loop below, which stops at once. What stays best-effort is only the tiny window
            # between this check and the ": connected" write, in which a just-terminated session can still
            # receive that one comment line. Strict "no output after terminate" ordering is a multi-client /
            # revocation property deferred to E3-S2c (auth + remote bind), designed there against the threat
            # model rather than retrofitted onto the dispatch lock; on this localhost-only, single-user,
            # pre-auth transport the only racer is the local user and the worst case is a stray ": connected".
            if wake.is_set():
                self._json(404, {"error": "unknown or terminated session"})
                return
            # This server emits no server-initiated messages yet (the tool surface is request/response), so
            # the stream is a valid, idle channel: an initial comment confirms it is live, then it is held
            # open (periodic keepalives) until the session is terminated, the client disconnects, or the
            # server shuts down (sse_stop). text/event-stream, uncached, closed at end.
            self.close_connection = True
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Connection", "close")
            self.end_headers()
            stop = self.server.sse_stop
            # Free the slot promptly on a CLIENT disconnect too (Codex r3943958155): a peer that closes
            # right after ": connected" fires no wake, so without polling the slot would linger until the
            # next keepalive WRITE detects the dead socket (up to SSE_KEEPALIVE_SECONDS) — making the 503's
            # Retry-After a lie for a disconnect just as it was for a DELETE. Wait on a bounded interval:
            # `wake` fires on server-side termination, and select() reports the socket readable when the
            # peer closes (MSG_PEEK then reads EOF) or sends; keepalives still go out every
            # SSE_KEEPALIVE_SECONDS. select on a socket works on Windows too (sockets only).
            poll = 1.0 if SSE_KEEPALIVE_SECONDS > 1.0 else SSE_KEEPALIVE_SECONDS
            since_keepalive = 0.0
            try:
                self.wfile.write(b": connected\n\n")
                self.wfile.flush()
                while not stop.is_set() and self.server.sessions.valid(sid, pv):
                    if wake.wait(poll):
                        break  # server-side termination / eviction / shutdown -> stop at once
                    try:
                        if select.select([self.connection], [], [], 0)[0]:
                            # An SSE GET is server->client only, so any readability means the client closed
                            # (EOF) OR sent an unexpected byte — either way, end the stream and free the slot
                            # now. (Peeking for EOF alone let a lingering unread client byte mask the close
                            # until the next keepalive write, pinning the slot — Codex r3945470136.)
                            break
                    except OSError:
                        break  # socket already torn down
                    since_keepalive += poll
                    if since_keepalive < SSE_KEEPALIVE_SECONDS:
                        continue
                    since_keepalive = 0.0
                    # Re-check stop/validity AFTER the wait and BEFORE writing: a DELETE that terminated
                    # this session mid-wait must not yield one more keepalive.
                    if stop.is_set() or not self.server.sessions.valid(sid, pv):
                        break
                    self.wfile.write(b": keepalive\n\n")  # a stuck write now raises socket.timeout -> break
                    self.wfile.flush()
            except OSError:
                pass  # client disconnected / stalled mid-stream — end the handler quietly
        finally:
            if wake is not None:
                self.server.sessions.unregister_wake(sid, wake)
            self.server.sse_streams.release()

    def do_DELETE(self):
        # DELETE terminates a LEGACY session (MCP revisions through 2025-11-25). The stateless 2026-07-28
        # revision has no Mcp-Session-Id to terminate, so a DELETE pinned to a modern version is 405 (era
        # routing, CodeRabbit r3941912010). Missing id -> 400; unknown/already-terminated/version-
        # mismatched -> 404; success -> 204 No Content. Once terminated the id is dead: a later request
        # bearing it is refused 404 by the validation in do_POST/do_GET.
        if not self._origin_ok():
            return
        if not self._protocol_ok():
            return
        if not self._auth_ok():  # bearer auth (E3-S2c), after the boundary checks; a no-op when no token is set
            return
        pv = self.headers.get("MCP-Protocol-Version")
        if pv in MODERN_PROTOCOLS:
            self._json(405, {"error": "no session to terminate; MCP " + ", ".join(MODERN_PROTOCOLS)
                             + " is stateless (no Mcp-Session-Id)"}, {"Allow": "POST"})
            return
        sid = self.headers.get(SESSION_HEADER)
        if sid is None:
            self._json(400, {"error": "Mcp-Session-Id required to terminate a session"})
            return
        # Terminate BOUND to the pinned version (Codex r3941957895): a DELETE pinned to a version other
        # than the one the session negotiated does not terminate it (returns 404), so it cannot be used
        # to tear down a session it does not actually speak for.
        # Terminate WITHOUT taking _HTTP_DISPATCH_LOCK (E3-S2b round 6, CodeRabbit r3945707197): round 5
        # (Codex r3945547146 / r3945547151) took that lock here to make termination atomic with a POST's
        # in-lock re-check and a GET's stream commit — but do_POST holds it across serve_message() for up to
        # ~AR_TIMEOUT_S, so a DELETE could then block for the whole tool call before terminating. terminate()
        # is internally synchronized on the session store and O(1) (drop the id, fire wakes), so it is
        # thread-safe on its own and a DELETE now takes effect immediately. What is given up is the strict
        # ordering (a DELETE landing after a POST's re-check may not preempt an already-admitted tool; a GET
        # racing this DELETE may still emit one ": connected") — a multi-client / revocation property whose
        # strict form (including cancelling an in-flight tool) is deferred to E3-S2c, not achievable by mutual
        # exclusion here. On this localhost-only, single-user, pre-auth transport that ordering is best-effort.
        if not self.server.sessions.terminate(sid, pv):
            self._json(404, {"error": "unknown or terminated session"})
            return
        self.close_connection = True
        self.send_response(204)
        self.send_header("Content-Length", "0")
        self.send_header("Connection", "close")
        self.end_headers()


class _BoundedThreadingHTTPServer(http.server.ThreadingHTTPServer):
    """ThreadingHTTPServer with a bounded worker/connection pool (E3-S2c). stdlib ThreadingMixIn spawns one
    (daemon) thread per accepted connection, UNBOUNDED — a connection flood would exhaust threads/fds. A
    BoundedSemaphore caps concurrent worker threads: acquired before the worker thread is spawned
    (process_request) and released exactly once when it ends (process_request_thread's finally) OR if the
    spawn itself raises. Past the cap a new connection is closed immediately (shutdown_request), not framed
    with a 503 body — writing a body to a flood is the work the flood wants. max_workers MUST exceed the SSE
    stream cap (an SSE GET holds its worker for the stream's whole life); HttpTransport.bind() enforces that."""

    def __init__(self, *args, max_workers=HTTP_DEFAULT_MAX_WORKERS, **kwargs):
        self._worker_sem = threading.BoundedSemaphore(max_workers)
        super().__init__(*args, **kwargs)

    def process_request(self, request, client_address):
        if not self._worker_sem.acquire(blocking=False):
            # pool full: refuse fast, without spawning a worker or writing a response body
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)  # ThreadingMixIn: spawns the worker thread
        except BaseException:
            # thread spawn failed AFTER acquire (e.g. RuntimeError: can't start new thread) — the worker
            # will never run its finally, so release the permit here so the pool does not leak a slot.
            self._worker_sem.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._worker_sem.release()


class HttpTransport:
    """Dual-era Streamable-HTTP transport over stdlib http.server, reusing serve_message() — the
    E3-S2a endpoint plus the E3-S2b legacy session lifecycle. POST (JSON-RPC: json response / 202
    notification) serves both eras; GET (per-session SSE channel) and DELETE (terminate a session) are
    the LEGACY verbs and are 405 when pinned to the stateless 2026-07-28 revision, which has no
    sessions. `initialize` mints an Mcp-Session-Id from a bounded, evicting store, bound to the version
    it negotiated. Bearer-token auth (E3-S2c): with AR_MCP_HTTP_TOKEN set, every request must authenticate
    and a non-loopback bind is permitted (behind a TLS terminator — the token is plaintext); with no token
    it binds 127.0.0.1 only. A bounded worker pool caps concurrent connections. Binding is split from
    serving so the framing is testable offline."""

    def __init__(self, host=None, port=None, origins=None, max_bytes=None,
                 max_sessions=None, require_session=None, max_streams=None,
                 token=None, max_workers=None, read_timeout=None):
        h, p, o, m = http_config()
        self.host = h if host is None else host
        self.port = p if port is None else port
        self.origins = tuple(o) if origins is None else tuple(origins)
        self.max_bytes = m if max_bytes is None else max_bytes
        self.max_sessions = (_http_int_env("AR_MCP_HTTP_MAX_SESSIONS", HTTP_DEFAULT_MAX_SESSIONS, minimum=1)
                             if max_sessions is None else max_sessions)
        self.max_streams = (_http_int_env("AR_MCP_HTTP_MAX_STREAMS", HTTP_DEFAULT_MAX_STREAMS, minimum=1)
                            if max_streams is None else max_streams)
        self.max_workers = (_http_int_env("AR_MCP_HTTP_MAX_WORKERS", HTTP_DEFAULT_MAX_WORKERS, minimum=1)
                            if max_workers is None else max_workers)
        self.read_timeout = (_http_int_env("AR_MCP_HTTP_READ_TIMEOUT", HTTP_DEFAULT_READ_TIMEOUT, minimum=1)
                             if read_timeout is None else read_timeout)
        self.require_session = (_http_bool_env("AR_MCP_HTTP_REQUIRE_SESSION")
                                if require_session is None else require_session)
        # E3-S2c bearer token: None => no auth (bind() then refuses a non-loopback host). http_token()
        # fails closed on a blank/too-short env token; an explicitly-passed token (tests) is used as given.
        self.token = http_token() if token is None else token
        self.sessions = _SessionStore(self.max_sessions)
        self.httpd = None

    def bind(self):
        """Create + bind the server (no serving yet); return the actual (host, port) — the port is
        OS-assigned when 0 was requested. Split out so offline tests can bind an ephemeral port. Refuses a
        non-loopback host UNLESS a token is set (E3-S2c): an unauthenticated surface must never be
        network-reachable. A non-loopback bind speaks plaintext HTTP — the bearer token travels in
        cleartext — so it MUST sit behind a TLS-terminating proxy or a trusted network; a startup WARNING
        says so. Also enforces max_workers > max_streams so held-open SSE streams cannot starve dispatch."""
        # E3-S2c: a network-reachable bind requires authentication. Without a token, refuse any non-loopback
        # host (the S2a/S2b posture); with a token, a remote bind is permitted but plaintext (warned below).
        if self.token is None and not is_loopback_host(self.host):
            raise ValueError(
                "refusing to bind the ar-mcp HTTP transport to non-loopback host %r without a token: an "
                "unauthenticated surface must not be network-reachable. Set AR_MCP_HTTP_TOKEN to expose it "
                "(behind a TLS terminator — the bearer token is sent in cleartext), or keep AR_MCP_HTTP_HOST "
                "on loopback (127.0.0.1 / ::1 / localhost)." % (self.host,))
        # The worker pool must exceed the SSE stream cap, or held-open streams (each pins a worker for its
        # whole life) can starve POST dispatch. Fail fast on the misconfiguration rather than deadlock later.
        if self.max_workers <= self.max_streams:
            raise ValueError(
                "AR_MCP_HTTP_MAX_WORKERS (%d) must exceed AR_MCP_HTTP_MAX_STREAMS (%d): an SSE GET holds a "
                "worker for the stream's whole life, so a worker pool no larger than the stream cap lets "
                "held-open streams starve POST dispatch." % (self.max_workers, self.max_streams))
        # Pick the address family from the host so an IPv6 loopback (::1) actually binds — the default
        # ThreadingHTTPServer is AF_INET, which cannot bind an IPv6 address. Defer bind/activate so the
        # family can be set first, and clean up the socket if the bind itself fails.
        httpd = _BoundedThreadingHTTPServer((self.host, self.port), _MCPHTTPHandler,
                                            bind_and_activate=False, max_workers=self.max_workers)
        httpd.address_family = socket.AF_INET6 if ":" in self.host else socket.AF_INET
        httpd.daemon_threads = True
        httpd.allowed_origins = self.origins
        httpd.max_bytes = self.max_bytes
        httpd.sessions = self.sessions
        httpd.require_session = self.require_session
        httpd.token = self.token                # E3-S2c: bearer token (None => no auth; handler _auth_ok)
        httpd.read_timeout = self.read_timeout   # E3-S2c: per-recv socket read timeout applied in handler setup()
        httpd.sse_streams = threading.BoundedSemaphore(self.max_streams)  # cap concurrent GET/SSE streams
        httpd.sse_stop = threading.Event()  # set on shutdown so open SSE streams end promptly
        try:
            httpd.server_bind()
            httpd.server_activate()
        except BaseException:
            httpd.server_close()
            raise
        self.httpd = httpd
        if self.token is not None and not is_loopback_host(self.host):
            log("WARNING: ar-mcp HTTP bound to non-loopback %s over plaintext HTTP — the bearer token is "
                "sent in cleartext. Put a TLS-terminating reverse proxy in front, or use a trusted network."
                % (self.host,))
        return httpd.server_address

    def serve_forever(self):
        if self.httpd is None:
            self.bind()
        addr = self.httpd.server_address
        _auth = "bearer-auth ON" if self.token is not None else "NO auth (loopback-only)"
        log(f"http transport ready on {addr[0]}:{addr[1]} "
            f"({_auth}; sessions E3-S2b; bounded pool {self.max_workers}w/{self.max_streams}s)")
        try:
            self.httpd.serve_forever()
        finally:
            self.httpd.sse_stop.set()          # signal shutdown to open SSE handler threads
            self.httpd.sessions.wake_all()     # ...and wake them: they wait on the per-session wake now
            self.httpd.server_close()

    def shutdown(self):
        if self.httpd is not None:
            self.httpd.sse_stop.set()          # signal shutdown
            self.httpd.sessions.wake_all()     # wake any open SSE stream so it stops promptly (not at
            self.httpd.shutdown()              # the next keepalive tick): the loop waits on `wake` now


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
