#!/usr/bin/env python3
"""Resolve the ai-defects scan scope from a git diff-ref -- fail-closed and CI-testable.

The ai-defects CI job establishes what to scan from a git revision/range. That step used
to live only in the workflow shell, which the `workflow_dispatch` job never runs in CI --
so "a bad diff-ref must not become an empty-diff PASS" was asserted but never tested. This
helper is that step in testable form (see tests/run_tests.py: t_ai_defects_diffscope_*).

    ai_defects_diffscope --run-dir <AR run dir> --diff-ref <revision-or-range>

On a VALID revision/range it writes the changed-path list to <run-dir>/changed_paths.txt
and exits 0 (the list may be empty for a valid range with no changes -- a legitimate
empty-diff that the verify wrapper then PASSes). A bad, missing, empty, option-prefixed,
or pathspec diff-ref -- anything that is not a resolvable revision/range -- prints a reason
and exits 2 (BLOCKED), leaving NO changed_paths.txt behind, so an unresolvable ref can
never silently produce an empty file that downstream reads as an empty-diff PASS.

`--` is appended to the git invocation so the ref is parsed strictly as a revision/range:
a bare pathspec such as "README.md" then fails to resolve instead of diffing that path to
an empty result.
"""
import os
import subprocess
import sys
from pathlib import Path

LOG = "ai-defects:"
CHANGED = "changed_paths.txt"


def blocked(msg):
    print("%s BLOCKED: %s" % (LOG, msg))
    sys.exit(2)


def parse_args(argv):
    wanted = {"--run-dir": None, "--diff-ref": None}
    i = 0
    while i < len(argv):
        tok = argv[i]
        if tok not in wanted:
            blocked("unexpected argument %r (expected --run-dir <dir> --diff-ref <rev/range>)"
                    % tok)
        if wanted[tok] is not None:
            blocked("duplicate argument %s" % tok)
        if i + 1 >= len(argv):
            blocked("missing value for %s" % tok)
        wanted[tok] = argv[i + 1]
        i += 2
    return wanted["--run-dir"], wanted["--diff-ref"]


def main(argv):
    run_dir, diff_ref = parse_args(argv)
    if not run_dir or not Path(run_dir).is_dir():
        blocked("run dir does not exist or is not a directory: %r" % run_dir)

    out = Path(run_dir) / CHANGED
    # Never let a stale/leftover changed_paths.txt survive a failed resolution -- an empty
    # or old file must not become an empty-diff PASS downstream.
    try:
        if out.is_symlink() or out.exists():
            out.unlink()
    except OSError as exc:
        blocked("cannot clear stale %s: %s" % (CHANGED, exc))

    if diff_ref is None or not diff_ref.strip():
        blocked("diff-ref is empty/unset -- cannot establish scan scope")
    if diff_ref.startswith("-"):
        blocked("diff-ref %r is option-prefixed -- refusing (not a revision/range)" % diff_ref)

    # `--` forces revision/range parsing; a bare pathspec fails to resolve instead of
    # diffing to empty. Bytes capture (not text=True) so a non-UTF-8 filename can't crash us.
    proc = subprocess.run(["git", "diff", "--name-only", diff_ref, "--"], capture_output=True)
    if proc.returncode != 0:
        err = (proc.stderr or b"").decode("utf-8", "replace").strip()
        blocked("diff-ref %r is not a resolvable revision/range: %s" % (diff_ref, err[:200]))

    # Publish atomically: write a same-directory temp file, then os.replace it into place.
    # A partial write (e.g. disk exhaustion) then never leaves a truncated changed_paths.txt
    # behind -- upholding the contract that a failed resolution leaves NO scope file.
    tmp = out.with_name(out.name + ".tmp")
    try:
        tmp.write_bytes(proc.stdout or b"")
        os.replace(str(tmp), str(out))
    except OSError as exc:
        try:
            if tmp.exists():
                tmp.unlink()
        except OSError:
            pass
        blocked("cannot write %s: %s" % (CHANGED, exc))
    n = len([ln for ln in (proc.stdout or b"").decode("utf-8", "replace").splitlines() if ln])
    print("%s diff-scope: %d changed path(s) from %r" % (LOG, n, diff_ref))
    sys.exit(0)


if __name__ == "__main__":
    main(sys.argv[1:])
