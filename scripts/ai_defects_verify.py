#!/usr/bin/env python3
"""ai-defects verify -- closed-arg adapter (port wrapper) for the ai-defects gate.

The `ai-defects` gate catches an AI-code defect class (phantom references, invented
APIs, impossible dependency versions, unfinished stubs) deterministically, before the
reviewer panel spends tokens. This wrapper is the thin ADAPTER between adversarial-
review's gate ledger and a deeper verifier adopted BY COMMAND -- a pinned CLI whose
absolute path is provided on the runner as $AI_DEFECTS_BIN and whose exact version +
digest are pinned via CI secrets. No vendor/brand string appears here by design (the
gate is a category, not a vendor; see references/gates.md).

Closed argv (exactly these two flags, order-independent; anything else -> BLOCKED):

    ai_defects_verify --run-dir <AR run dir> --diff-file <changed-paths file>

Exit taxonomy (the wrapper collapses everything to 0/1/2 so the gate ledger records
PASS/FAIL/BLOCKED honestly):

    0  PASS     verifier completed, no blocking defects, no incomplete flag
    1  FAIL     verifier completed, defects / policy violations found
    2  BLOCKED  anything that cannot honestly complete: missing/empty pin, bad digest,
               non-absolute / missing / non-executable binary, incomplete:true, a
               malformed summary, exit 2, timeout, 126/127/exec error, unknown nonzero
               exit, unreadable/undecodable input, bad argv, empty/unset run dir

Empty diff (zero changed paths) is PASS with reason `empty-diff` -- nothing to verify
is not a failure. Everything unconfigured or incomplete is BLOCKED, never a silent skip
and never PASS.

Contract with $AI_DEFECTS_BIN (the pinned CLI / operator shim): it is an ABSOLUTE path
(so the digest-verified file and the executed file are the same -- no PATH/CWD
ambiguity), invoked with a fixed bounded argv (`--diff-file <f> --run-dir <d>`) -- never
a shell, never a wildcard, never $* passthrough -- exits 0/1/2, and MAY write an optional
JSON summary to <run-dir>/ai-defects.json: an object carrying an `incomplete` boolean.
incomplete:true (or a malformed summary) is BLOCKED even on exit 0.
"""
import hashlib
import json
import math
import os
import signal
import subprocess
import sys
from pathlib import Path

LOG = "ai-defects:"
PASS, FAIL, BLOCKED = 0, 1, 2

BIN_ENV = "AI_DEFECTS_BIN"                  # ABSOLUTE path to the installed pinned CLI
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


def _kill_tree(proc):
    """Kill the verifier AND any workers it spawned. The child is started in its own
    process group (POSIX) so a timeout can take down the whole tree, not just the
    immediate process (an orphaned worker could keep writing into the run dir)."""
    try:
        if os.name == "posix":
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        else:
            proc.kill()
    except OSError:
        pass


def _run_verifier(cmd, timeout_s):
    """Run the pinned CLI with a bounded argv, in its own process group, with a watchdog.
    Returns (returncode, combined_output_text). BLOCKS on timeout or exec failure.
    Output is captured as bytes and decoded leniently so a non-UTF-8 byte on the child's
    stdout/stderr can never crash the wrapper into a FAIL."""
    popen_kwargs = {"stdout": subprocess.PIPE, "stderr": subprocess.PIPE}
    if os.name == "posix":
        popen_kwargs["start_new_session"] = True  # own process group for tree-kill
    try:
        proc = subprocess.Popen(cmd, **popen_kwargs)
    except OSError as exc:
        blocked("could not execute verifier (%s)" % exc)
    try:
        out, err = proc.communicate(timeout=timeout_s)
    except subprocess.TimeoutExpired:
        _kill_tree(proc)
        try:
            proc.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            pass
        blocked("verifier timed out after %gs" % timeout_s)
    combined = ((out or b"") + b"\n" + (err or b"")).decode("utf-8", "replace").strip()
    return proc.returncode, combined


def _check_summary(run_dir):
    """Honor an optional <run-dir>/ai-defects.json summary on an exit-0 verifier. A
    present summary must be a JSON object with a boolean `incomplete`; incomplete:true,
    a non-object, a non-boolean `incomplete`, or an unreadable/undecodable file all BLOCK
    (completion cannot be trusted). Absent summary -> exit 0 is PASS."""
    summary = Path(run_dir) / SUMMARY_NAME
    if not summary.exists():
        return
    try:
        data = json.loads(summary.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        blocked("verifier summary %s present but unreadable -- fail-closed" % SUMMARY_NAME)
    if not isinstance(data, dict):
        blocked("verifier summary %s is not a JSON object -- fail-closed" % SUMMARY_NAME)
    inc = data.get("incomplete", False)
    if not isinstance(inc, bool):
        blocked("verifier summary %s has a non-boolean 'incomplete' -- fail-closed" % SUMMARY_NAME)
    if inc:
        blocked("verifier reported incomplete:true on exit 0 -- trusting the flag")


def main(argv):
    run_dir, diff_file = parse_args(argv)

    # Run dir must exist. An unset $AR_RUN_DIR passed as --run-dir "" is already caught
    # as an empty value in parse_args; a non-empty but missing/non-dir path BLOCKS too.
    if not Path(run_dir).is_dir():
        blocked("run dir does not exist or is not a directory: %s" % run_dir)

    # Scope: the changed-paths file. Missing / unreadable / undecodable -> BLOCKED.
    try:
        raw = Path(diff_file).read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        blocked("cannot read diff file %s: %s" % (diff_file, exc))
    # Every non-empty line from `git diff --name-only` IS a path -- do NOT strip, or a
    # valid whitespace-only Git filename would be discarded and read as an empty diff.
    paths = [ln for ln in raw.splitlines() if ln]

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

    # Binary preflight -- must be an ABSOLUTE path so the file we hash is exactly the file
    # we exec (a bare name would hash a CWD file but exec a PATH file -> digest bypass);
    # missing/non-executable BLOCKS (never fall back to an LLM scan).
    binpath = os.environ.get(BIN_ENV, "").strip()
    if not binpath:
        blocked("%s is empty/unset -- install the pinned verifier on the runner first"
                % BIN_ENV)
    if not os.path.isabs(binpath):
        blocked("%s must be an absolute path (got %r) -- refusing PATH/CWD ambiguity "
                "between the hashed and the executed file" % (BIN_ENV, binpath))
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

    # Invoke the pinned CLI (absolute path -> no PATH search) with a fixed, bounded argv.
    rc, combined = _run_verifier([binpath, "--diff-file", diff_file, "--run-dir", run_dir],
                                 timeout_s)
    for line in combined.splitlines()[-6:]:
        print("%s verifier: %s" % (LOG, line))

    if rc == 1:
        fail("verifier reported defects (exit 1)")
    if rc == 2:
        blocked("verifier could not complete (exit 2)")
    if rc != 0:
        blocked("verifier exited %s -- fail-closed (unknown/exec status)" % rc)

    _check_summary(run_dir)  # exit 0: honor/validate an optional incomplete summary
    ok("verifier completed with no blocking defects (exit 0)")


if __name__ == "__main__":
    main(sys.argv[1:])
