#!/usr/bin/env python3
"""ai-defects verify -- closed-arg adapter (port wrapper) for the ai-defects gate.

The `ai-defects` gate catches an AI-code defect class (phantom references, invented
APIs, impossible dependency versions, unfinished stubs) deterministically, before the
reviewer panel spends tokens. This wrapper is the thin ADAPTER between adversarial-
review's gate ledger and a deeper verifier adopted BY COMMAND -- a pinned CLI whose
path is provided on the runner as $AI_DEFECTS_BIN and whose exact version + digest are
pinned via CI secrets. No vendor/brand string appears here by design (the gate is a
category, not a vendor; see references/gates.md).

Closed argv (exactly these two flags, order-independent; anything else -> BLOCKED):

    ai_defects_verify --run-dir <AR run dir> --diff-file <changed-paths file>

Exit taxonomy (the wrapper collapses everything to 0/1/2 so the gate ledger records
PASS/FAIL/BLOCKED honestly):

    0  PASS     verifier completed, no blocking defects, no incomplete flag
    1  FAIL     verifier completed, defects / policy violations found
    2  BLOCKED  anything that cannot honestly complete: missing/empty pin, bad digest,
               missing/non-executable binary, incomplete:true, exit 2, timeout,
               126/127/exec error, unknown nonzero exit, unreadable/undecodable input,
               bad argv, empty/unset run dir

Empty diff (zero changed paths) is PASS with reason `empty-diff` -- nothing to verify
is not a failure. Everything unconfigured or incomplete is BLOCKED, never a silent skip
and never PASS.

Contract with $AI_DEFECTS_BIN (the pinned CLI / operator shim): it is invoked with a
fixed, bounded argv (`--diff-file <f> --run-dir <d>`) -- never a shell, never a
wildcard, never $* passthrough -- exits 0/1/2, and MAY write an optional JSON summary
to <run-dir>/ai-defects.json carrying an `incomplete` boolean. incomplete:true is
BLOCKED even on exit 0 (trust the flag over the exit code).
"""
import hashlib
import json
import math
import os
import subprocess
import sys
from pathlib import Path

LOG = "ai-defects:"
PASS, FAIL, BLOCKED = 0, 1, 2

BIN_ENV = "AI_DEFECTS_BIN"                  # path to the installed pinned CLI on the runner
PIN_VERSION_ENV = "AI_DEFECTS_PIN_VERSION"  # required: exact pinned version
PIN_DIGEST_ENV = "AI_DEFECTS_PIN_DIGEST"    # required: sha256 of the pinned binary
TIMEOUT_ENV = "AI_DEFECTS_TIMEOUT_S"        # optional child watchdog (default 300s)
SUMMARY_NAME = "ai-defects.json"
DEFAULT_TIMEOUT_S = 300.0


def _emit(code, level, msg):
    print("%s %s: %s" % (LOG, level, msg))
    sys.exit(code)


def blocked(msg):
    _emit(BLOCKED, "BLOCKED", msg)


def fail(msg):
    _emit(FAIL, "FAIL", msg)


def ok(msg):
    _emit(PASS, "PASS", msg)


def parse_args(argv):
    """Closed argv: exactly --run-dir X and --diff-file Y, each once, nothing else.

    Extra/unknown tokens, duplicates, missing values, or empty values all BLOCK
    (exit 2). No positional args, no wildcards, no passthrough."""
    wanted = {"--run-dir": None, "--diff-file": None}
    i = 0
    while i < len(argv):
        tok = argv[i]
        if tok not in wanted:
            blocked("unexpected argument %r (closed argv is --run-dir <dir> "
                    "--diff-file <file> only; no wildcards, no passthrough)" % tok)
        if wanted[tok] is not None:
            blocked("duplicate argument %s" % tok)
        if i + 1 >= len(argv):
            blocked("missing value for %s" % tok)
        wanted[tok] = argv[i + 1]
        i += 2
    for key, val in wanted.items():
        if not val:
            blocked("missing required argument %s" % key)
    return wanted["--run-dir"], wanted["--diff-file"]


def _norm_digest(value):
    value = (value or "").strip().lower()
    if value.startswith("sha256:"):
        value = value[len("sha256:"):]
    return value


def _resolve_timeout():
    raw = os.environ.get(TIMEOUT_ENV, "").strip()
    if not raw:
        return DEFAULT_TIMEOUT_S
    try:
        secs = float(raw)
    except ValueError:
        blocked("%s must be a positive, finite number of seconds, got %r" % (TIMEOUT_ENV, raw))
    # Reject nan / inf / overflow: a non-finite watchdog is no watchdog.
    if not math.isfinite(secs) or secs <= 0:
        blocked("%s must be a positive, finite number of seconds, got %r" % (TIMEOUT_ENV, raw))
    return secs


def main(argv):
    run_dir, diff_file = parse_args(argv)

    # Run dir must exist. An unset $AR_RUN_DIR passed as --run-dir "" is already caught
    # as an empty value in parse_args; a non-empty but missing/non-dir path BLOCKS too.
    if not Path(run_dir).is_dir():
        blocked("run dir does not exist or is not a directory: %s" % run_dir)

    # Scope: the changed-paths file. Missing / unreadable / undecodable -> BLOCKED
    # (cannot scope honestly). UnicodeDecodeError is a ValueError, not an OSError, so a
    # non-UTF-8 path list must be caught here or it would escape as an exit-1 FAIL.
    try:
        raw = Path(diff_file).read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        blocked("cannot read diff file %s: %s" % (diff_file, exc))
    paths = [ln.strip() for ln in raw.splitlines() if ln.strip()]

    # Empty diff -> PASS (assumption A12), BEFORE requiring pin/binary: nothing to verify.
    if not paths:
        ok("empty-diff (no changed paths to verify)")

    # Pin preflight -- missing/empty secret BLOCKS before any exec.
    version = os.environ.get(PIN_VERSION_ENV, "").strip()
    digest = _norm_digest(os.environ.get(PIN_DIGEST_ENV, ""))
    if not version:
        blocked("%s is empty/unset -- pinned verifier version required" % PIN_VERSION_ENV)
    if not digest:
        blocked("%s is empty/unset -- pinned verifier digest required" % PIN_DIGEST_ENV)

    # Binary preflight -- missing/non-executable BLOCKS (never fall back to an LLM scan).
    binpath = os.environ.get(BIN_ENV, "").strip()
    if not binpath:
        blocked("%s is empty/unset -- install the pinned verifier on the runner first"
                % BIN_ENV)
    bp = Path(binpath)
    if not bp.is_file():
        blocked("verifier binary not found at %s=%s" % (BIN_ENV, binpath))
    if not os.access(binpath, os.X_OK):
        blocked("verifier binary is not executable: %s" % binpath)

    # Digest verify -- defense in depth with the CI install step; refuse a tampered pin.
    try:
        actual = hashlib.sha256(bp.read_bytes()).hexdigest()
    except OSError as exc:
        blocked("cannot read verifier binary for digest check: %s" % exc)
    if actual != digest:
        blocked("verifier digest mismatch -- refusing to run an unpinned/tampered binary")

    timeout_s = _resolve_timeout()

    # Invoke the pinned CLI with a fixed, bounded argv -- no shell, no wildcards.
    cmd = [binpath, "--diff-file", diff_file, "--run-dir", run_dir]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_s)
    except subprocess.TimeoutExpired:
        blocked("verifier timed out after %gs" % timeout_s)
    except OSError as exc:
        blocked("could not execute verifier (%s)" % exc)

    rc = proc.returncode
    # Surface a short tail of the child's own output (stdout AND stderr) under the prefix.
    combined = ((proc.stdout or "") + "\n" + (proc.stderr or "")).strip()
    for line in combined.splitlines()[-6:]:
        print("%s verifier: %s" % (LOG, line))

    if rc == 1:
        fail("verifier reported defects (exit 1)")
    if rc == 2:
        blocked("verifier could not complete (exit 2)")
    if rc != 0:
        blocked("verifier exited %s -- fail-closed (unknown/exec status)" % rc)

    # Exit 0: honor an optional incomplete flag in the run-dir summary (trust the flag).
    summary = Path(run_dir) / SUMMARY_NAME
    if summary.exists():
        try:
            data = json.loads(summary.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            blocked("verifier summary %s present but unreadable -- fail-closed" % SUMMARY_NAME)
        if isinstance(data, dict) and data.get("incomplete"):
            blocked("verifier reported incomplete:true on exit 0 -- trusting the flag")
    ok("verifier completed with no blocking defects (exit 0)")


if __name__ == "__main__":
    main(sys.argv[1:])
