"""Shared helpers for adversarial-review scripts. Stdlib only, by design."""
import errno
import hashlib
import json
import math
import os
import re
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

RUN_ROOT = Path(os.environ.get("AR_RUN_DIR", ".adversarial-review"))


def now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def resolve_run(run_arg=None):
    """Return the run directory: explicit arg, else newest run-* under the root."""
    if run_arg:
        p = Path(run_arg) if os.sep in str(run_arg) else RUN_ROOT / run_arg
        if not p.is_dir():
            die(f"run directory not found: {p}")
        return p
    if not RUN_ROOT.is_dir():
        die(f"no {RUN_ROOT}/ directory — run `panel.py init` first")
    runs = sorted(d for d in RUN_ROOT.iterdir() if d.is_dir() and d.name.startswith("run-"))
    if not runs:
        die(f"no runs under {RUN_ROOT}/ — run `panel.py init` first")
    return runs[-1]


# security-2 (frontier-gate run pr70-design, 2026-09-21, checklist items 3/5/15/20):
# a run directory is, by design, writable by whatever produced it -- untrusted input in
# the FIFO/symlink/oversize-file sense, not just its JSON contents. Every read of a
# run-directory file (run.json, policy.snapshot.json, policy.absence.json, gates/*.json,
# signature sidecars) goes through read_regular_file_once() so this property is enforced
# exactly once, not re-derived per call site.
_MAX_RUN_FILE_BYTES = 16 * 1024 * 1024  # 16 MiB; generous for any artifact this tool
                                         # writes itself, tight enough to bound memory
                                         # against a maliciously huge planted file.


class NotRegularFileError(OSError):
    """A run-directory path that should be an ordinary file turned out not to be one:
    a FIFO/socket/device, a directory, a symlink at the leaf, or over the size cap.
    An OSError subclass on purpose -- every existing `except (ValueError, OSError):`
    call site in this codebase already treats that as "could not read this artifact,"
    with no call-site changes needed."""


def read_regular_file_once(path):
    """Open, fstat-verify-regular, and read a run-directory file's bytes in ONE
    descriptor's lifetime -- the only way any such file is read from here on. Three
    load-bearing properties (frontier-gate run pr70-design, 2026-09-21, checklist items
    3/5/8/15/20; thread 4055706486 for the FIFO-hang report this closes):

      1. FIFO/socket/device-safe: O_NONBLOCK makes open() on a FIFO with no writer
         return immediately (EAGAIN -> OSError) instead of hanging the process forever.
         It has no effect on an ordinary regular file.
      2. Symlink-safe at the leaf: O_NOFOLLOW refuses to open a path whose FINAL
         component is a symlink (ELOOP), so a run directory an attacker can write into
         cannot redirect e.g. policy.snapshot.json to a file outside the run directory.
         This does NOT protect a symlinked ANCESTOR directory (the run directory itself,
         or gates/, being a symlink) -- callers resolve the run directory with
         Path.resolve() before any file inside it is opened; that is a separate,
         directory-level guarantee this function does not attempt to re-derive.
      3. fstat, not stat: the regular-file check runs against the ALREADY-OPEN
         descriptor, so there is no window between checking "is this a regular file"
         and reading it in which the path could be replaced -- the classic TOCTOU on
         the check itself. O_NOFOLLOW+O_NONBLOCK apply at open()-time, before any
         check could even run.

    O_NOFOLLOW/O_NONBLOCK are not defined on Windows -- getattr(..., 0) degrades to a
    plain, blocking open() there (this codebase's own CI and test harness run on
    Windows). The fstat S_ISREG check and the size cap still apply unconditionally on
    every platform; only the symlink-leaf and non-blocking-FIFO guarantees are
    Windows-specific gaps, disclosed here rather than silently assumed away.

    Returns bytes. Raises NotRegularFileError (OSError subclass) for a FIFO/socket/
    device/directory, a symlinked leaf, or a file over the size cap -- even a lying/
    stale st_size cannot produce more than _MAX_RUN_FILE_BYTES of returned data, since
    the read loop enforces the cap independently as it accumulates, not only from the
    single fstat() snapshot. Raises a plain OSError for a missing/unreadable path,
    unchanged from open()'s ordinary behavior."""
    flags = os.O_RDONLY
    for flag_name in ("O_NOFOLLOW", "O_NONBLOCK"):
        flags |= getattr(os, flag_name, 0)
    try:
        fd = os.open(str(path), flags)
    except OSError as e:
        if e.errno == errno.ELOOP:
            raise NotRegularFileError(f"{path}: refusing to follow a symlink at the leaf") from e
        raise
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise NotRegularFileError(f"{path}: not a regular file (mode {oct(st.st_mode)})")
        if st.st_size > _MAX_RUN_FILE_BYTES:
            raise NotRegularFileError(f"{path}: {st.st_size} bytes exceeds the "
                                       f"{_MAX_RUN_FILE_BYTES}-byte run-file cap")
        chunks, total = [], 0
        while True:
            chunk = os.read(fd, 1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > _MAX_RUN_FILE_BYTES:
                raise NotRegularFileError(f"{path}: exceeded the {_MAX_RUN_FILE_BYTES}-byte "
                                           "run-file cap while reading")
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        os.close(fd)


def read_json(path):
    return json.loads(read_regular_file_once(path).decode("utf-8"))


def write_json(path, obj):
    """Write `obj` to `path` as an atomic replace, not an in-place write. Two properties
    this gets for free, neither present in the previous plain open(path, "w") (frontier-
    gate run pr70-design, 2026-09-21 -- found while testing the read-side FIFO fix above:
    gate.py plan writes gates/<name>.json for the gate it is actively waiving, and a
    plain write-mode open() on an existing FIFO with no reader attached hangs, the
    write-side mirror of the read-side bug read_regular_file_once() closes):

      1. Never blocks on a non-regular file already at `path` (a FIFO, say): the new
         content is written to a fresh temp file in the same directory (tempfile.mkstemp
         -- guaranteed new, so there is nothing at that name to follow or block on), then
         os.replace() swaps the directory entry atomically. replace() never opens the
         DESTINATION path at all, so whatever was there (FIFO, symlink, stale file)
         is atomically replaced, never written through or blocked on.
      2. No reader can ever observe a partially-written file, and a destination that is
         a symlink is replaced as that directory entry rather than followed and written
         through to wherever it points (the old open(path, "w") would follow it).

    Returns the exact encoded bytes written, so a caller that needs to sign/hash them
    (e.g. panel.py's policy-snapshot signing at init) can do so without a second,
    independent read of `path` — see write_bytes_atomic's docstring / Codex 4082681134
    for why re-reading the path back is a TOCTOU gap the return value closes."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    data = (json.dumps(obj, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
    _atomic_replace(path, data)
    return data


def write_bytes_atomic(path, data):
    """The raw-bytes counterpart to write_json — same atomic-replace, no-follow-safe
    semantics (see write_json's docstring for the two properties this gets for free),
    for callers writing non-JSON artifacts (e.g. a detached signature) into a run
    directory an attacker may have write access to. CodeRabbit r4082557528-class fix,
    Codex 4082681153 (P1, valid): the trusted signer used to publish detached signature
    sidecars via Path.write_bytes(), which opens the DESTINATION in truncate mode and
    therefore follows a symlink planted there — an attacker who can write into the run
    directory concurrently with the trusted signer could pre-plant policy.snapshot.sig
    (or policy.absence.sig) as a symlink to any file the signer process can write, and
    have the signer overwrite that target with the signature bytes instead of creating
    the sidecar. Routing the write through the same mkstemp+os.replace pattern write_json
    already uses closes this the same way: the destination path is never opened, so
    whatever is there (including a symlink) is atomically replaced as a directory entry,
    never written through."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    _atomic_replace(path, data)


def _atomic_replace(path, data):
    """Shared by write_json/write_bytes_atomic: write `data` to a fresh temp file in
    `path`'s own directory and os.replace() it into place. `os.fdopen(fd, "wb")` returns
    a buffered stream whose .write() is guaranteed to write the COMPLETE buffer in one
    call (unlike the raw os.write(fd, data) this replaced, which can return a short
    count under disk/quota pressure with no exception — CodeRabbit 4077668503 / Codex
    4077803900, both valid, both reporting the same underlying short-write gap: a
    truncated temp file silently os.replace()'d over a gate manifest, run.json, or
    verdict-adjacent artifact as if the write had fully succeeded). fsync before close so
    the bytes are durable on disk before the rename is visible, not just buffered in the
    OS page cache."""
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    os.replace(tmp, path)


# ---------------------------------------------------------------- signing (shared)
# Generic out-of-process signing/verification primitives, shared by aggregate.py's
# verdict signature (`--sign`/`--verify-signature`, E6-S1) and panel.py's opportunistic
# policy-snapshot signature at init (PR70 provenance-binding fix, Option B: sign only
# waiver/N-A runs). Nothing here is specific to WHAT is being signed — callers pass
# their own message/signature paths — so the identity-pinning rules (panel finding
# security-1: never verify cosign keyless without BOTH AR_COSIGN_IDENTITY and
# AR_COSIGN_ISSUER pinned; never let filesystem state pick the minisign key) live in
# exactly one place for every caller, instead of drifting between two copies.
POLICY_SIG_FILENAME = "policy.snapshot.sig"

# GAP A's signed "explicitly checked, found no policy" escape hatch (frontier-gate run
# pr70-design, 2026-09-21, checklist item 2) — see policy_absence_attest_bytes and
# load_attested_policy_bundle's "not snap_p.is_file()" branch. A SEPARATE file/signature
# pair from policy.snapshot.json/.sig, never the same file with an empty body: keeping
# them distinct means a run can never accidentally satisfy one check by tampering into
# the shape of the other, and policy_absence_attest_bytes uses a different domain-
# separation prefix (see below) so an absence signature can never verify as a snapshot
# signature or vice versa even if the files were swapped.
POLICY_ABSENCE_FILENAME = "policy.absence.json"
POLICY_ABSENCE_SIG_FILENAME = "policy.absence.sig"


POLICY_ATTEST_VERSION = "4"

# v4 (frontier-gate run pr70-round7-v4design, 2026-09-26; panel: Fable 5.1, GPT-6
# Astra, Grok 4.6, Gemini 3.1 Pro, unanimous 4/4, consensus 0.93): closes the 3rd
# independently-discovered instance of "a run.json field that affects the verdict,
# rebuttal requirement, or reviewer independence is never bound into the policy
# signature" -- dev_providers and rebuttal_policy, both attacker-editable in an
# untrusted run directory, neither previously checked against anything the signature
# covers. Also closes a 4th, related gap found while doing this fix's mandated field
# inventory: policy.absence.json's OWN file content was never bound by its signature
# AT ALL (verify_policy_absence_signature took an `absence_bytes` parameter that was
# never actually referenced in its body -- dead code masquerading as a check).
#
# Rather than keep adding named positional fields one at a time -- the exact pattern
# that produced this recurrence twice already (v1->v2 closed run_name/risk; v3's own
# remaining gaps produced round 6 and this round) -- v4 adds ONE canonical-JSON digest
# of an explicitly enumerated, versioned set of policy-relevant run.json fields
# (BOUND_RUN_JSON_KEYS below), plus the full raw bytes of policy.absence.json itself
# for the absence case (mirroring how policy.snapshot.json's full bytes are already
# bound via snap_bytes for the snapshot case). See canonical_json_bytes and
# canonical_policy_fields_bytes below, and the guard test
# t_v4_run_json_key_inventory_is_exhaustive in tests/run_tests.py that fails CI the
# moment a future PR adds a run.json key without classifying it into one of the two
# tuples below.
#
# Deliberate scope decision, disclosed rather than silently made: v4 does NOT add
# dual-version verification (a v3-signed run failing v4 verification is intentional
# fail-closed behavior -- re-init to get a v4-signable/verifiable run -- exactly the
# same "no migration path, bump the version and re-init" shape this module's own v2
# and v3 introductions already used, per their own docstrings' stated rationale that
# no real deployment existed yet with the superseded format). This repo's own status
# as of this fix: viaid's adoption of AR_SIGNING_REQUIRED is itself still being built
# (SAT-1117, docs/... handback), not a mature population of already-signed runs that
# would be broken by a clean version bump. If real v3-signed runs needing continued
# verification are found to already exist, extend this with an explicit
# run.json['attest_version']-keyed dispatch (never a try-v4-then-silently-try-v3
# fallback -- that would be a genuine downgrade oracle: a run whose dev_providers/
# rebuttal_policy really was tampered with would legitimately fail v4 verification,
# and unconditionally retrying under v3 -- which never checked those fields at all --
# would then incorrectly accept it).
#
# Fields from run.json that affect the computed verdict, rebuttal requirement, waiver
# eligibility, or reviewer-independence outcome, and so MUST be bound into the v4
# signature via canonical_policy_fields_bytes() below. risk/run_id/run_nonce/run_name
# are deliberately NOT listed here: they are already separately bound as positional
# arguments to policy_attest_bytes/policy_absence_attest_bytes (unchanged since v2/v3)
# -- including them here too would bind them twice for no benefit and would make the
# "what does v4 add" diff harder to review.
BOUND_RUN_JSON_KEYS = ("dev_providers", "rebuttal_policy")

# Fields from run.json confirmed, by reading every call site in panel.py/aggregate.py/
# gate.py (frontier-gate run pr70-round7-v4design field inventory, 2026-09-26), to
# affect nothing but human-facing display or audit trail -- never branched on by any
# decision path. Deliberately left unbound. This tuple, and the guard test that checks
# it against every key cmd_init actually writes to run.json, is what stops a FUTURE
# field from silently falling into the same gap a 4th time: a new run.json key that
# lands in neither this tuple nor BOUND_RUN_JSON_KEYS fails the test outright.
#   product, diff_ref: interpolated into the human-readable reviewer-prompt text only
#     (panel.py's review-request body) -- never read by any control-flow branch.
#   sources: audit trail of where risk/dev_providers/rebuttal_policy were resolved
#     from (CLI flag / env var / policy file) -- written once at init, never read back.
#   created_at: timestamp for a human reading run.json; no staleness/expiry logic
#     anywhere in this codebase reads it.
#   policy: {file, sha256} pointer to the policy-file snapshot -- redundant with the
#     existing snap_bytes binding, since editing policy.snapshot.json's actual content
#     changes snap_bytes (which the signature already binds directly); this pointer is
#     a same-run cross-check for a wholesale-swapped snapshot file (see
#     load_attested_policy_bundle), not an independent trust boundary of its own.
#   attest_version: NOT written as of this fix (see the scope-decision note above --
#     no dual-version dispatch yet), reserved here so adding it later needs no
#     re-classification of this guard test.
UNBOUND_RUN_JSON_KEYS_BY_DESIGN = ("product", "diff_ref", "sources", "created_at",
                                    "policy", "attest_version")


def canonical_json_bytes(obj):
    """Deterministic, canonical UTF-8 JSON bytes for `obj` -- the ONE serialization
    every v4 signer and verifier must agree on byte-for-byte, or a canonicalization bug
    fails EVERY run's verification identically (loud -- caught by the test suite
    before merge) rather than one field silently not binding (quiet -- exactly what
    v1/v2/v3 each individually missed; see checklist item 8, frontier-gate run
    pr70-round7-v4design).

    Deliberately narrow: only str, bool, None, and list/dict composed of those are
    accepted -- NOT int, and NOT float. int is excluded because nothing this is used
    for today needs it (BOUND_RUN_JSON_KEYS is dev_providers: list[str] and
    rebuttal_policy: str) and adding it back is a one-line change if a future bound
    field needs it. float is excluded permanently: float repr is not guaranteed
    byte-identical across Python versions/platforms for every value, and NaN/Infinity
    have no valid JSON representation at all -- exactly the platform-dependent
    instability checklist item 8 calls out as the failure mode to design against, so
    this function refuses to guess a canonicalization for one rather than risk it.

    `sort_keys=True` plus fixed separators (",", ":") is what makes dict key order
    irrelevant to the output and removes incidental whitespace differences. List order
    is preserved, never sorted -- e.g. dev_providers' configured order is itself part
    of what was actually configured, not an unordered set for this purpose."""
    def _check(x):
        if isinstance(x, bool) or x is None or isinstance(x, str):
            return
        if isinstance(x, list):
            for item in x:
                _check(item)
            return
        if isinstance(x, dict):
            for k, v in x.items():
                if not isinstance(k, str):
                    raise TypeError(
                        f"canonical_json_bytes: dict key {k!r} is not a str")
                _check(v)
            return
        raise TypeError(
            f"canonical_json_bytes: value {x!r} of type {type(x).__name__} is not one "
            "of str/bool/None/list/dict -- refusing to guess a canonicalization for it "
            "(int and float are deliberately unsupported; see this function's "
            "docstring)")
    _check(obj)
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                       ensure_ascii=False).encode("utf-8")


def canonical_policy_fields_bytes(meta):
    """The v4 canonical-digest bytes for run.json's policy-relevant fields
    (BOUND_RUN_JSON_KEYS), extracted from `meta` (an already-parsed run.json dict).
    A key missing from `meta` is bound as JSON null, never simply omitted -- so a
    run.json that HAD e.g. dev_providers at sign time but has the key deleted (not
    merely edited) by verify time still fails to verify, rather than silently matching
    whatever this function would produce for "key absent"."""
    fields = {k: meta.get(k) for k in BOUND_RUN_JSON_KEYS}
    return canonical_json_bytes(fields)

# CI context values with no CI-provided source (a local/dev run, or a CI system that
# doesn't set the GitHub Actions env vars below) fall back to this literal marker rather
# than an empty string, so "no CI context available" is an explicit, visible value in the
# signed payload rather than something that could collide with a blank/missing field.
_NO_CI_CONTEXT = "local"

# GAP B (frontier-gate run pr70-design, 2026-09-21, checklist item unresolved-GitLab):
# GitLab Runner exposes no first-class counterpart to GitHub Actions' GITHUB_RUN_ATTEMPT
# -- retrying a job (or a whole pipeline via "Retry") reuses the SAME CI_PIPELINE_ID,
# never bumping any predefined variable exposed to the job. Rather than fabricate a
# counter GitLab doesn't provide (fragile: GitLab could add/rename one, or a self-hosted
# runner could set something misleadingly similar), this binds a FIXED, clearly-named
# marker instead of GitHub's real per-attempt value. That is not a weaker binding than
# GitHub's: replay protection across pipelines still comes from CI_PROJECT_PATH,
# CI_COMMIT_SHA, and CI_PIPELINE_ID (globally unique, never reused, unlike GitHub's
# per-repository-scoped run id) -- a retry of the SAME pipeline reusing the SAME
# CI_PIPELINE_ID is intentionally treated as the SAME identity, which is correct: nothing
# about the change under review differs between a job and its retry. Distinct from
# _NO_CI_CONTEXT ("local") so a genuinely-identified GitLab run is never confused with an
# unidentified/local one in the signed payload.
_GITLAB_NO_RUN_ATTEMPT = "gitlab-ci-no-run-attempt-counter"


def ci_signing_context():
    """The CI-orchestrator-assigned identity to bind into a v3 policy-attest payload,
    read fresh from THIS process's own environment every time -- never from run.json or
    any other file a copied/replayed run directory could carry along.

    GitLab CI (GAP B, frontier-gate run pr70-design, 2026-09-21): when GITLAB_CI is
    exactly "true" -- GitLab Runner's own, reliably-set indicator, never incidentally
    true by accident -- the four fields come from GitLab's predefined CI/CD variables:
    CI_PROJECT_PATH ("namespace/project", GitHub's GITHUB_REPOSITORY counterpart),
    CI_COMMIT_SHA, CI_PIPELINE_ID (globally unique across the whole GitLab instance,
    never reused -- the correct run-identity counterpart to GITHUB_RUN_ID; CI_PIPELINE_IID
    is only unique WITHIN one project and is deliberately not used here), and the fixed
    _GITLAB_NO_RUN_ATTEMPT marker in place of a per-attempt counter GitLab does not
    expose (see the module-level comment above). CI_JOB_ID (the specific job within the
    pipeline) is deliberately NOT bound here -- it is informational only, since a
    pipeline can retry an individual job without that constituting a different execution
    of the reviewed change; CI_PIPELINE_ID is what actually identifies "this run."

    Fail-closed platform selection: GitLab's fields are read ONLY when GITLAB_CI=="true",
    and (Codex 4099660075) GitHub Actions' fields are read ONLY when GITHUB_ACTIONS==
    "true" -- never merely because a GitLab- or GitHub-named variable happens to be
    present (e.g. stray env inheritance from an unrelated build image, or a local shell
    where someone set CI_PIPELINE_ID, or GITHUB_REPOSITORY/SHA/RUN_ID/RUN_ATTEMPT, for an
    unrelated reason -- or to deliberately mimic a platform this process never actually
    ran on). This keeps the four fields coming from ONE coherent, actually-identified
    platform rather than an unintentional mix of two unrelated CI systems' variables,
    which would weaken what "this specific pipeline" even means. GitHub Actions'
    GITHUB_REPOSITORY ("owner/repo"), GITHUB_SHA (the commit under test), GITHUB_RUN_ID
    (unique per workflow execution, never reused), GITHUB_RUN_ATTEMPT (increments per
    re-run of that same execution) -- runner-provided ambient values a job's own code
    cannot choose or rewrite (unlike a value read from a
    config file or CLI flag). Neither platform identified (local dev, a different CI
    system) -- all four fall back to "local": this still round-trips correctly (sign and
    verify agree, since both read the same live environment) but provides NO cross-run
    identity in that shape, only the pre-existing run_name/run_nonce/risk binding does.

    See docs/THREAT-MODEL.md for what this can and cannot prove on its own, in
    particular that these values only protect against REPLAY (an old, validly-signed
    run's files copied elsewhere) -- they do not stop code running in the SAME job that
    performs the signing from choosing its own policy content to sign; that is what the
    isolated trusted-signer job (see action.yml / ci.yml / examples/.gitlab-ci.yml) is
    for."""
    if os.environ.get("GITLAB_CI", "").strip().lower() == "true":
        return _sanitize_ci_context({
            "repository": os.environ.get("CI_PROJECT_PATH", "").strip() or _NO_CI_CONTEXT,
            "commit": os.environ.get("CI_COMMIT_SHA", "").strip() or _NO_CI_CONTEXT,
            "run_id": os.environ.get("CI_PIPELINE_ID", "").strip() or _NO_CI_CONTEXT,
            "run_attempt": _GITLAB_NO_RUN_ATTEMPT,
        })
    # Codex 4099660075 (P1, valid): mirror the GitLab branch's own fail-closed platform
    # selection immediately above -- GITHUB_REPOSITORY/GITHUB_SHA/GITHUB_RUN_ID/
    # GITHUB_RUN_ATTEMPT must only be trusted when GITHUB_ACTIONS itself is exactly
    # "true" (GitHub Actions' own reliably-set indicator, the direct counterpart to
    # GITLAB_CI above -- GitHub Actions always sets it to the literal string "true" on
    # every run), never merely because those four GitHub-named variables happen to be
    # present. Before this fix, this branch was the unconditional "else": any
    # environment that was not GitLab CI -- a local shell, an unrelated third-party CI
    # system, or a step deliberately crafted to mimic GitHub Actions -- that simply had
    # these four variables set was read by _ci_identity_established() as a genuine
    # GitHub Actions identity, silently granting the trust AR_ALLOW_LOCAL_CI_IDENTITY
    # exists to require an explicit opt-in for (see its docstring and the checks around
    # lines 519-533/653-667 below). Without GITHUB_ACTIONS=="true", fall through to the
    # same all-"local" shape a genuinely unidentified platform already produces.
    if os.environ.get("GITHUB_ACTIONS", "").strip().lower() == "true":
        return _sanitize_ci_context({
            "repository": os.environ.get("GITHUB_REPOSITORY", "").strip() or _NO_CI_CONTEXT,
            "commit": os.environ.get("GITHUB_SHA", "").strip() or _NO_CI_CONTEXT,
            "run_id": os.environ.get("GITHUB_RUN_ID", "").strip() or _NO_CI_CONTEXT,
            "run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT", "").strip() or _NO_CI_CONTEXT,
        })
    return _sanitize_ci_context({
        "repository": _NO_CI_CONTEXT, "commit": _NO_CI_CONTEXT,
        "run_id": _NO_CI_CONTEXT, "run_attempt": _NO_CI_CONTEXT,
    })


def _sanitize_ci_context(ctx):
    """Codex 4077803892 (P2, valid): os.environ decodes a non-UTF-8 env-var byte string
    with surrogateescape, so a field read straight from the environment can be an
    `isinstance(x, str)` value that still raises UnicodeEncodeError the moment
    policy_attest_bytes/policy_absence_attest_bytes .encode("utf-8") it — reproduced with
    GITHUB_REPOSITORY='owner/\\udcff'. Rather than validate this at every one of
    ci_signing_context()'s four call sites (two sign paths in panel.py, two verify paths
    here), sanitize once, centrally, where the values are first read from the live
    environment: a field that fails _encodable_str() is replaced with _NO_CI_CONTEXT
    ("local"), the same value ci_signing_context() already returns for a platform it
    can't identify at all. That is the correct fail-closed shape, not a crash and not a
    silent pass-through of unencodable input — a corrupted CI-reported identity gets
    exactly the same reduced (no-real-identity) trust _ci_identity_established() already
    forces AR_ALLOW_LOCAL_CI_IDENTITY to cover for a genuinely-unidentified platform, so
    a garbled value can never round-trip as if it were a real one."""
    return {k: (v if _encodable_str(v) else _NO_CI_CONTEXT) for k, v in ctx.items()}


def _ci_identity_established(ci_context):
    """True iff `ci_context` (a ci_signing_context() result) reports a REAL,
    CI-provided identity for the fields that actually distinguish one run from another
    -- repository, commit, run_id. `run_attempt` is deliberately excluded: GitLab's
    fixed _GITLAB_NO_RUN_ATTEMPT marker is a legitimate, intentional stand-in for a
    per-attempt counter GitLab does not expose (see its own module-level comment) and
    must not be confused with _NO_CI_CONTEXT ("local"), which means "nothing identified
    this run at all."

    Checklist item 3 (frontier-gate run pr70-trust-model2, 2026-09-22, Finding #7): when
    neither GitLab CI nor GitHub Actions is detected, all four ci_signing_context()
    fields fall back to "local" -- two independently unidentified environments (e.g. two
    different laptops, or a laptop and an unrecognized third-party CI system) then
    compute byte-for-byte identical placeholders. The v3 CI-context binding in
    policy_attest_bytes/policy_absence_attest_bytes still round-trips correctly in that
    shape (sign and verify agree, since both read the same live environment), but
    provides NO actual cross-run identity distinction -- "local" is not an identity, it
    is the absence of one. This predicate is what lets verify_policy_snapshot_signature /
    verify_policy_absence_signature refuse to treat that non-distinction as a real
    guarantee by default (see AR_ALLOW_LOCAL_CI_IDENTITY below)."""
    return (ci_context.get("repository") != _NO_CI_CONTEXT
            and ci_context.get("commit") != _NO_CI_CONTEXT
            and ci_context.get("run_id") != _NO_CI_CONTEXT)


def policy_attest_bytes(run_id, run_nonce, run_name, risk, snap_path=None, ci_context=None,
                         version=POLICY_ATTEST_VERSION, snap_bytes=None,
                         policy_fields_bytes=None):
    """The exact bytes signed/verified for the policy-snapshot signature.

    v4 (current) additionally binds `policy_fields_bytes` -- canonical_policy_fields_
    bytes(meta), i.e. a length-prefixed canonical-JSON digest of run.json's
    BOUND_RUN_JSON_KEYS (dev_providers, rebuttal_policy) -- ahead of the snapshot bytes
    (frontier-gate run pr70-round7-v4design, 2026-09-26; see POLICY_ATTEST_VERSION's
    module comment for the full rationale and the field inventory that produced this
    list). Required as of v4: passing None raises rather than silently signing/
    verifying without it, so no call site can accidentally construct a v4-tagged
    payload that doesn't actually bind these fields. Length-prefixed (not merely
    newline-terminated) so the digest's own bytes can never be confused with what
    follows it even in a pathological input.

    `snap_bytes`, when given, is used verbatim instead of re-reading `snap_path` from
    disk — the TOCTOU fix (frontier-gate run pr70-design, 2026-09-21, checklist item 8):
    a caller that already has the file's bytes in hand (from
    load_attested_policy_bundle(), or from panel.py having just written them at init)
    passes them here so the bytes that get SIGNED/VERIFIED are provably the exact same
    bytes that were content-validated or just written — never a second, independent
    `open()` of the same path that an attacker with write access to the run directory
    could have swapped in between the two reads. `snap_path` stays required when
    `snap_bytes` is omitted (back-compat for any caller that has only a path).

    v3 (superseded) additionally binds the four ci_signing_context() values --
    repository, commit, CI run id, CI run attempt -- ahead of the snapshot bytes
    (frontier-gate run pr70-architecture-review, 2026-09-20, batch 2 of the
    redesign_signing_boundary decision); this binding is unchanged in v4, just joined
    by policy_fields_bytes above. `ci_context` defaults to a fresh ci_signing_context()
    call when omitted,
    so both the signer (panel.py, at init) and the verifier (this module, at aggregate/
    gate time) always bind whatever THEIR OWN live environment reports -- never a value
    carried in run.json or any other file a copied run directory could bring with it.
    This is what closes cross-run, cross-commit, and cross-repository replay: copying an
    older, validly-signed run's policy.snapshot.json/.sig into a new run directory (even
    one matching the original's exact name, defeating v2's run_name check alone) still
    fails verification the moment the current job's repository, commit, or CI run
    identity differs from what was actually signed.

    v2 (superseded) binds: version tag, run_id, run_nonce, run_name (the run directory's
    OWN basename), risk (the resolved tier from run.json), then policy.snapshot.json's
    raw bytes. v1 (further superseded) bound only run_id + run_nonce + snapshot bytes and
    had two gaps a delayed Codex review on PR70 found and reproduced:

      - run_name closes: copying a whole legitimately-signed (run_id, run_nonce,
        policy.snapshot.json, policy.snapshot.sig) tuple from an old, permissive run
        into a NEW run directory used to still verify, because nothing checked the
        self-reported run_id against the one thing cmd_init assigns independently and
        immutably: the directory's own name (RUN_ROOT/run_id, checked for uniqueness,
        never reused -- see cmd_init). v2 signs run_name, and
        verify_policy_snapshot_signature separately cross-checks it against the actual
        resolved run directory before even trying the signature, so a run directory
        under a different name can never present as the one that was signed.
      - risk closes: editing run.json's `risk` field downward AFTER init (e.g. CRITICAL
        -> SENSITIVE) used to leave the policy signature untouched, letting a waiver
        that should have been blocked at the original tier slip through at the lowered
        one, since risk was never part of what got signed.

    Shared by panel.py (signing at init) and aggregate.py/gate.py (verifying) so the
    formats can never drift apart — panel.py and aggregate.py used to rebuild
    this format independently, and any drift between them would make every signed
    snapshot fail verification, BLOCKing every run that records a WAIVED or
    NOT_APPLICABLE gate (CodeRabbit, PR70 review 5258750734).

    Binding to run_id stops a signature minted for one run from being replayed onto a
    different run's policy.snapshot.json. run_id alone is NOT sufficient: it is a
    second-granularity UTC timestamp with no randomness (see panel.py's cmd_init), so
    two runs created within the same wall-clock second — realistic under CI/automation
    throughput, and how a real CI run surfaced this — collide on run_id, and if their
    policy content also matches, the full attest bytes would then be identical too,
    making one run's signature trivially "valid" for the other. run_nonce
    (secrets.token_hex(16), minted fresh per run in cmd_init and recorded in run.json)
    closes that gap deterministically instead of relying on timestamp luck."""
    if ci_context is None:
        ci_context = ci_signing_context()
    if snap_bytes is None:
        snap_bytes = Path(snap_path).read_bytes()
    if policy_fields_bytes is None:
        raise ValueError(
            "policy_attest_bytes: policy_fields_bytes is required as of v4 -- pass "
            "canonical_policy_fields_bytes(meta). There is no dispatch back to v3 (see "
            "POLICY_ATTEST_VERSION's module comment); a v3-signed run intentionally "
            "fails v4 verification rather than silently verifying without this field")
    return (b"ar-policy-attest-v" + str(version).encode("ascii") + b"\n"
            + run_id.encode("utf-8") + b"\n" + run_nonce.encode("utf-8") + b"\n"
            + str(run_name).encode("utf-8") + b"\n" + str(risk).encode("utf-8") + b"\n"
            + ci_context["repository"].encode("utf-8") + b"\n"
            + ci_context["commit"].encode("utf-8") + b"\n"
            + ci_context["run_id"].encode("utf-8") + b"\n"
            + ci_context["run_attempt"].encode("utf-8") + b"\n"
            + str(len(policy_fields_bytes)).encode("ascii") + b"\n"
            + policy_fields_bytes + b"\n"
            + snap_bytes)


def policy_absence_attest_bytes(run_id, run_nonce, run_name, risk, ci_context=None,
                                 version=POLICY_ATTEST_VERSION, absence_bytes=None,
                                 policy_fields_bytes=None):
    """The exact bytes signed/verified for the policy-ABSENCE signature (GAP A, frontier-
    gate run pr70-design, 2026-09-21, checklist item 2) — the signed claim that THIS run,
    at init, explicitly checked for a repo policy file and found none, as distinct from a
    run that simply never wrote policy.snapshot.json (which load_attested_policy_bundle's
    require_signature=True now BLOCKs whenever a verifier is configured — see its
    docstring). Binds the same identity as policy_attest_bytes (run_id, run_nonce, run
    directory name, resolved risk tier, live CI-orchestrator identity) for the same
    replay-closing reasons documented there, but over NO snapshot bytes — there is no
    policy text to bind, only the fact that init looked and found nothing.

    Uses a DIFFERENT domain-separation prefix (b"ar-policy-absence-attest-v...", never
    the snapshot's b"ar-policy-attest-v...") so a signature minted for one can never
    verify as the other even if policy.snapshot.json/.sig and policy.absence.json/.sig
    were swapped between run directories — the two claims ("this text governed the run"
    vs "no policy governed the run") must never be interchangeable.

    v4 (current) additionally binds two length-prefixed fields (frontier-gate run
    pr70-round7-v4design, 2026-09-26): `policy_fields_bytes` -- the same
    canonical_policy_fields_bytes(meta) digest policy_attest_bytes binds, since an
    absence-signed run's run.json carries dev_providers/rebuttal_policy exactly like a
    snapshot-signed run's does, and the same post-signing tamper is possible either
    way -- and `absence_bytes`, the exact raw bytes written for policy.absence.json
    itself. Pre-v4, this function bound NO bytes from policy.absence.json at all: the
    file's own content ({policy_absent, captured_at}) was writable post-signing with
    zero effect on the signature, because nothing here ever hashed it (a previously
    unused `absence_bytes` keyword accepted by verify_policy_absence_signature's
    caller-facing signature was never actually referenced in this function -- dead
    code that looked like a check). Both are required as of v4: passing either as None
    raises rather than silently constructing a payload that doesn't bind them."""
    if ci_context is None:
        ci_context = ci_signing_context()
    if policy_fields_bytes is None:
        raise ValueError(
            "policy_absence_attest_bytes: policy_fields_bytes is required as of v4 -- "
            "pass canonical_policy_fields_bytes(meta). There is no dispatch back to v3")
    if absence_bytes is None:
        raise ValueError(
            "policy_absence_attest_bytes: absence_bytes is required as of v4 -- pass "
            "the exact bytes written for policy.absence.json. Pre-v4 never bound this "
            "file's own content at all; see this function's docstring")
    return (b"ar-policy-absence-attest-v" + str(version).encode("ascii") + b"\n"
            + run_id.encode("utf-8") + b"\n" + run_nonce.encode("utf-8") + b"\n"
            + str(run_name).encode("utf-8") + b"\n" + str(risk).encode("utf-8") + b"\n"
            + ci_context["repository"].encode("utf-8") + b"\n"
            + ci_context["commit"].encode("utf-8") + b"\n"
            + ci_context["run_id"].encode("utf-8") + b"\n"
            + ci_context["run_attempt"].encode("utf-8") + b"\n"
            + str(len(policy_fields_bytes)).encode("ascii") + b"\n"
            + policy_fields_bytes + b"\n"
            + str(len(absence_bytes)).encode("ascii") + b"\n"
            + absence_bytes)


def _encodable_str(s):
    """True iff `s` is a non-surrogate-escaped str -- one that policy_attest_bytes /
    policy_absence_attest_bytes can safely `.encode("utf-8")`. A plain `isinstance(s,
    str)` is not enough: JSON permits lone UTF-16 surrogate code points (`\\ud800`
    etc.) in a string, Python's json module happily decodes them into a `str` that
    passes isinstance, and THAT str raises UnicodeEncodeError the moment `.encode()`
    is called on it. Codex r4055706476 (P2): a tampered run.json's run_id containing
    such a surrogate reached policy_attest_bytes()'s raw `.encode("utf-8")` call
    uncaught, crashing verification with UnicodeEncodeError instead of returning a
    controlled BLOCKED reason. Used to validate run_id, run_nonce, and risk here --
    every field verify_policy_snapshot_signature/verify_policy_absence_signature read
    straight from run.json and later encode -- before they ever reach the attest-bytes
    builder."""
    if not isinstance(s, str):
        return False
    try:
        s.encode("utf-8")
        return True
    except UnicodeEncodeError:
        return False


def verify_policy_absence_signature(run, meta, *, absence_bytes, capture_sig_bytes=None):
    """The policy-ABSENCE counterpart to verify_policy_snapshot_signature — same checks,
    same fail-closed shape (a short BLOCKED-reason string, never raises), same TOCTOU-safe
    required-keyword `absence_bytes` (the caller's already-read policy.absence.json bytes,
    normally load_attested_policy_bundle()'s `.absence_raw`), same optional
    `capture_sig_bytes` (Codex 4099660083 — see verify_policy_snapshot_signature's
    docstring for the full TOCTOU rationale), but verifies POLICY_ABSENCE_SIG_FILENAME
    against policy_absence_attest_bytes(). See verify_policy_snapshot_signature for the
    full rationale of each check; only the signed-bytes builder and the sidecar filename
    differ."""
    run_id = meta.get("run_id")
    run_nonce = meta.get("run_nonce")
    risk = meta.get("risk")
    run_name = Path(run).name
    if not _encodable_str(run_id) or not run_id:
        return "run.json has no valid run_id — cannot verify the policy-absence signature"
    if run_name != run_id:
        return (f"run directory name ({run_name!r}) does not match run.json's run_id "
                f"({run_id!r}) — this run.json does not describe the run being "
                "verified (possible copy from another run); re-init to get a "
                "signable, verifiable absence attestation")
    if not _encodable_str(run_nonce) or not run_nonce:
        return ("run.json has no valid run_nonce — the policy-absence signature cannot "
                "be verified without it (this run predates the nonce fix, or run.json "
                "was tampered with); re-init this run to get a signable, verifiable "
                "absence attestation")
    if not _encodable_str(risk) or not risk:
        return "run.json has no valid risk tier — cannot verify the policy-absence signature"
    sig_p = Path(run) / POLICY_ABSENCE_SIG_FILENAME
    if not sig_p.is_file():
        return (f"no {POLICY_ABSENCE_SIG_FILENAME} — the no-policy attestation was not "
                "signed at init. Configure a signer (AR_SIGNER_CMD, or install cosign "
                "with AR_ALLOW_KEYLESS=1 and AR_COSIGN_IDENTITY/AR_COSIGN_ISSUER pinned, "
                "or minisign with AR_MINISIGN_KEY) before `panel.py init` so any run that "
                "later records a waiver or not-applicable gate can be trusted")
    argv_tmpl, kind, resolve_err = resolve_signing_tool(
        "AR_VERIFIER_CMD",
        [("cosign-keyless", cosign_verify_argv), ("minisign", minisign_verify_argv)],
        fatal=False)
    if argv_tmpl is None:
        if resolve_err:
            return f"verifier configuration error: {resolve_err}"
        return ("no verifier available: set AR_VERIFIER_CMD, or install cosign (with "
                "AR_ALLOW_KEYLESS=1 and AR_COSIGN_IDENTITY/AR_COSIGN_ISSUER pinned) or "
                "minisign (with AR_MINISIGN_PUBKEY or AR_MINISIGN_PUBKEY_FILE)")
    # Finding #7 / checklist item 3 (frontier-gate run pr70-trust-model2, 2026-09-22): a
    # verifier IS configured, but if THIS process's own live CI identity is not actually
    # established (see _ci_identity_established), the v3 CI-context binding this
    # signature also relies on provides no real cross-run distinction -- both sign and
    # verify would just agree on "local". Fail closed by default; AR_ALLOW_LOCAL_CI_
    # IDENTITY=1 is the explicit, named opt-in for a deliberately local/offline signing
    # setup that accepts this reduced guarantee (same "explicit opt-in" shape
    # AR_ALLOW_KEYLESS already uses elsewhere in this module).
    ci_context = ci_signing_context()
    if (not _ci_identity_established(ci_context)
            and not _policy_bool_env("AR_ALLOW_LOCAL_CI_IDENTITY")):
        return (
            "no CI-provided identity (repository/commit/run id) is available in this "
            "environment -- the v3 signature binding cannot distinguish this run from "
            "any other unidentified run, since both would sign/verify against the same "
            "'local' placeholder. Run this under a recognized CI provider (GitHub "
            "Actions or GitLab CI), or set AR_ALLOW_LOCAL_CI_IDENTITY=1 to explicitly "
            "accept this reduced guarantee for a local/offline signing setup")
    # Codex 4099660083 (P2, valid): same single-read-then-materialize treatment as
    # verify_policy_snapshot_signature — see its matching comment for the full rationale.
    try:
        sig_bytes = read_regular_file_once(sig_p)
    except (OSError, ValueError) as e:
        return f"{POLICY_ABSENCE_SIG_FILENAME} could not be read safely: {e}"
    if capture_sig_bytes is not None:
        capture_sig_bytes[POLICY_ABSENCE_SIG_FILENAME] = sig_bytes
    with tempfile.TemporaryDirectory() as td:
        msg_tmp = Path(td) / "policy.absence.attest"
        msg_tmp.write_bytes(policy_absence_attest_bytes(
            run_id, run_nonce, run_name, risk, ci_context=ci_context,
            absence_bytes=absence_bytes,
            policy_fields_bytes=canonical_policy_fields_bytes(meta)))
        sig_tmp = Path(td) / POLICY_ABSENCE_SIG_FILENAME
        sig_tmp.write_bytes(sig_bytes)
        proc, err = run_signing_tool(argv_tmpl, msg_tmp, sig_tmp, fatal=False)
    if err:
        return f"verifier '{kind}' could not run: {err}"
    if proc.returncode != 0:
        stderr = (proc.stderr or b"").decode("utf-8", "replace").strip()[-300:]
        detail = f" — {stderr}" if stderr else ""
        return f"signature did not verify (verifier: {kind}, exit {proc.returncode}){detail}"
    return None


def verify_policy_snapshot_signature(run, meta, *, snap_bytes, capture_sig_bytes=None):
    """PR70 provenance-binding fix (Option B / require_signing_for_exceptions_only —
    Paul's decision, frontier-gate run pr70-provenance, 2026-09-19; hardened against 3
    further P1 findings from a delayed Codex review, frontier-gate run
    pr70-provenance-2, 2026-09-19 — Paul chose fix_all_six_now).

    `capture_sig_bytes` (Codex 4099660083, P2, valid): optional, keyword-only, default
    None — every existing caller is unaffected. When a dict is passed, this function
    stores the EXACT bytes it read from POLICY_SIG_FILENAME into
    `capture_sig_bytes[POLICY_SIG_FILENAME]` before verifying, so a caller that also
    computes an attestation digest over this run's files (aggregate.py's
    compute_attestation, within the SAME process invocation) can hash those same bytes
    instead of independently re-`read_regular_file_once()`-ing the sidecar moments
    later. Without this, the verifier subprocess and compute_attestation() each read
    POLICY_SIG_FILENAME from its live, attacker-writable path at a different instant —
    a TOCTOU window in which an actor with concurrent write access to the run directory
    could swap the sidecar between the two reads, so the digest baked into verdict.json
    (and anything later signed over it, via --sign) would silently reflect different
    bytes than the ones that were actually verified. Reading the sidecar ONCE here (into
    a temp-file copy the verifier reads instead of the live path) closes that window for
    the verifier itself too, the same way `snap_bytes` already closes it for the
    message content (see this docstring's own TOCTOU-fix paragraph below).

    Shared by aggregate.py (verifying at aggregate time) and gate.py (verifying at plan/
    record time, so `plan`/`record` can never report success on a waiver `aggregate`
    will later BLOCK as unsigned or invalid — see gate.py's cmd_plan/cmd_record).

    `run` is the run's resolved directory (a real Path — see resolve_run), `meta` is
    run.json's already-parsed dict, and `snap_bytes` (keyword-only, REQUIRED — no
    default, so no call site can silently reintroduce a second read) is
    policy.snapshot.json's exact bytes as already read by the caller — normally
    load_attested_policy_bundle()'s `.raw`. This is the TOCTOU fix (frontier-gate run
    pr70-design, 2026-09-21, checklist item 8; Fable's TOCTOU design, adopted): the
    signature is verified over the SAME bytes the caller already content-validated,
    never a second, independent `open()` of policy.snapshot.json that an attacker with
    write access to the run directory could have swapped in between the two reads.
    Checks, in order, ALL fail-closed (return a short BLOCKED-reason string; never raise
    or exit):

      1. run.name must equal meta['run_id']. cmd_init assigns a run's directory name
         ONCE, from a UTC timestamp, checking existence to guarantee it is never reused
         (see cmd_init) — it is the one identity in this scheme an attacker who can only
         edit FILES inside a run directory cannot also forge, because it is the name of
         the directory they are writing into, not something read from those files. A
         mismatch means this run.json was copied from (or edited to claim) a different
         run than the one actually being verified — exactly the directory-copy replay a
         delayed Codex review reproduced against the v1 payload (run_id + run_nonce +
         snapshot bytes only, no independent identity check).
      2. run_nonce must be a non-empty string (closes the run_id-collision replay gap;
         unchanged from the original nonce fix).
      3. POLICY_SIG_FILENAME must exist, and a verifier must be configured.
      4. The signature must verify over policy_attest_bytes(run_id, run_nonce, run.name,
         meta['risk'], snap_bytes=snap_bytes) with NO explicit ci_context — the default fetches a FRESH
         ci_signing_context() from this process's own environment, the same call panel.py
         makes at sign time. This is the v3 payload (frontier-gate run
         pr70-architecture-review, 2026-09-20): beyond v2's run_name and risk binding, it
         additionally binds the live repository/commit/CI-run-id/CI-run-attempt at BOTH
         sign and verify time, independently — never a value carried in run.json or any
         other file a copied run directory could bring with it. A run directory copied
         wholesale into a different repository, onto a different commit, or into a
         different CI execution now fails verification even when run_name coincidentally
         matches (v2 alone could not catch that; only the directory name was checked).
      5. The live CI identity must actually be ESTABLISHED (see _ci_identity_established)
         -- not merely present and self-consistent. Checklist item 3 (frontier-gate run
         pr70-trust-model2, 2026-09-22, Finding #7): check 4 above proves sign-time and
         verify-time CI context MATCH, but says nothing about whether either side had a
         real CI-provided identity at all. Two independently unidentified environments
         both compute "local" for all four fields, so check 4 alone trivially passes
         with zero actual cross-run distinction. This check refuses that by default;
         AR_ALLOW_LOCAL_CI_IDENTITY=1 is the explicit opt-in for local/offline signing.

    A v1- or v2-format signature (from a run initialized before this fix) cannot verify
    against the v3 payload — this is intentional fail-closed behavior, not a bug: the
    BLOCKED reason it produces (an ordinary "signature did not verify") tells the
    operator to re-init, exactly like any other invalid signature. There is no real
    deployment with v1 or v2 signatures yet (no repo's CI currently configures
    AR_SIGNER_CMD or AR_ALLOW_KEYLESS), so no migration path is needed; if that ever
    changes, bump POLICY_ATTEST_VERSION again and extend this function to recognize the
    version tag it can no longer verify, the same pattern aggregate.py's
    _ATTESTATION_ALGO/_LEGACY_ALGOS already use for the run's overall attestation
    digest.

    Scope: callers only invoke this when the run contains a WAIVED or NOT_APPLICABLE gate
    record — the common no-exception path stays completely infrastructure-free."""
    run_id = meta.get("run_id")
    run_nonce = meta.get("run_nonce")
    risk = meta.get("risk")
    run_name = Path(run).name
    if not _encodable_str(run_id) or not run_id:
        return "run.json has no valid run_id — cannot verify the policy-snapshot signature"
    if run_name != run_id:
        return (f"run directory name ({run_name!r}) does not match run.json's run_id "
                f"({run_id!r}) — this run.json does not describe the run being "
                "verified (possible copy from another run); re-init to get a "
                "signable, verifiable snapshot")
    if not _encodable_str(run_nonce) or not run_nonce:
        return ("run.json has no valid run_nonce — the policy-snapshot signature cannot "
                "be verified without it (this run predates the nonce fix, or run.json "
                "was tampered with); re-init this run to get a signable, verifiable "
                "snapshot")
    if not _encodable_str(risk) or not risk:
        return "run.json has no valid risk tier — cannot verify the policy-snapshot signature"
    sig_p = Path(run) / POLICY_SIG_FILENAME
    if not sig_p.is_file():
        return (f"no {POLICY_SIG_FILENAME} — the policy snapshot was not signed at init. "
                "Configure a signer (AR_SIGNER_CMD, or install cosign with AR_ALLOW_KEYLESS=1 "
                "and AR_COSIGN_IDENTITY/AR_COSIGN_ISSUER pinned, or minisign with "
                "AR_MINISIGN_KEY) before `panel.py init` so any run that later records a "
                "waiver or not-applicable gate can be trusted")
    argv_tmpl, kind, resolve_err = resolve_signing_tool(
        "AR_VERIFIER_CMD",
        [("cosign-keyless", cosign_verify_argv), ("minisign", minisign_verify_argv)],
        fatal=False)
    if argv_tmpl is None:
        if resolve_err:
            return f"verifier configuration error: {resolve_err}"
        return ("no verifier available: set AR_VERIFIER_CMD, or install cosign (with "
                "AR_ALLOW_KEYLESS=1 and AR_COSIGN_IDENTITY/AR_COSIGN_ISSUER pinned) or "
                "minisign (with AR_MINISIGN_PUBKEY or AR_MINISIGN_PUBKEY_FILE)")
    # Finding #7 / checklist item 3 (frontier-gate run pr70-trust-model2, 2026-09-22): a
    # verifier IS configured, but if THIS process's own live CI identity is not actually
    # established (see _ci_identity_established), the v3 CI-context binding this
    # signature also relies on provides no real cross-run distinction -- both sign and
    # verify would just agree on "local". Fail closed by default; AR_ALLOW_LOCAL_CI_
    # IDENTITY=1 is the explicit, named opt-in for a deliberately local/offline signing
    # setup that accepts this reduced guarantee (same "explicit opt-in" shape
    # AR_ALLOW_KEYLESS already uses elsewhere in this module).
    ci_context = ci_signing_context()
    if (not _ci_identity_established(ci_context)
            and not _policy_bool_env("AR_ALLOW_LOCAL_CI_IDENTITY")):
        return (
            "no CI-provided identity (repository/commit/run id) is available in this "
            "environment -- the v3 signature binding cannot distinguish this run from "
            "any other unidentified run, since both would sign/verify against the same "
            "'local' placeholder. Run this under a recognized CI provider (GitHub "
            "Actions or GitLab CI), or set AR_ALLOW_LOCAL_CI_IDENTITY=1 to explicitly "
            "accept this reduced guarantee for a local/offline signing setup")
    # Codex 4099660083 (P2, valid): read POLICY_SIG_FILENAME's bytes ONCE, right here,
    # rather than handing the verifier the live `sig_p` path to open itself — see
    # `capture_sig_bytes`'s docstring paragraph above for the TOCTOU this closes. The
    # verifier gets a materialized temp-file copy of exactly what was read (same
    # no-follow/size-capped hardening read_regular_file_once already applies to every
    # other untrusted run-directory artifact in this module), and any caller that asked
    # to capture these bytes (for reuse in an attestation digest computed moments later)
    # gets the identical bytes the verifier actually checked, never a second read of a
    # path an attacker with concurrent write access to the run directory could have
    # swapped in between.
    try:
        sig_bytes = read_regular_file_once(sig_p)
    except (OSError, ValueError) as e:
        return f"{POLICY_SIG_FILENAME} could not be read safely: {e}"
    if capture_sig_bytes is not None:
        capture_sig_bytes[POLICY_SIG_FILENAME] = sig_bytes
    with tempfile.TemporaryDirectory() as td:
        msg_tmp = Path(td) / "policy.snapshot.attest"
        msg_tmp.write_bytes(policy_attest_bytes(
            run_id, run_nonce, run_name, risk, snap_bytes=snap_bytes,
            ci_context=ci_context,
            policy_fields_bytes=canonical_policy_fields_bytes(meta)))
        sig_tmp = Path(td) / POLICY_SIG_FILENAME
        sig_tmp.write_bytes(sig_bytes)
        proc, err = run_signing_tool(argv_tmpl, msg_tmp, sig_tmp, fatal=False)
    if err:
        return f"verifier '{kind}' could not run: {err}"
    if proc.returncode != 0:
        stderr = (proc.stderr or b"").decode("utf-8", "replace").strip()[-300:]
        detail = f" — {stderr}" if stderr else ""
        return f"signature did not verify (verifier: {kind}, exit {proc.returncode}){detail}"
    return None


def sign_fail(msg):
    """Loud, non-zero failure for the signing/verifying TOOLING path (no signer
    configured, a malformed command template, or the external tool could not start /
    timed out / errored). Exit 3 keeps it distinct from the verdict codes (0 PASS /
    1 FAIL / 2 BLOCKED) and from a verify mismatch (1). Never a silent skip."""
    print(f"ERROR: {msg}", file=sys.stderr)
    sys.exit(3)


def sign_timeout():
    """Bounded subprocess timeout (seconds) for signer/verifier calls; AR_SIGN_TIMEOUT
    overrides. A non-positive or non-numeric override falls back to the default rather
    than crashing the gate."""
    raw = os.environ.get("AR_SIGN_TIMEOUT", "120").strip()
    try:
        t = int(raw)
    except ValueError:
        return 120
    return t if t > 0 else 120


def resolve_signing_tool(env_cmd, builders, fatal=True):
    """Resolve a signing/verifying command as an argv TEMPLATE carrying `{msg}`/`{sig}`
    tokens. Precedence: an explicit env override (`env_cmd`, e.g. AR_SIGNER_CMD) wins;
    otherwise the first auto-detected tool whose builder returns a non-None argv
    (cosign keyless primary, minisign fallback). Returns (argv, kind, err) — `err` is
    populated only when `fatal=False` and the explicit env override is present but
    malformed (unbalanced shell quoting); it is always None on every other path
    (resolution succeeded, or nothing resolved at all because the override was unset
    and no builder matched).

    `fatal` (default True) preserves this function's original, unconditional behavior
    for every pre-existing caller: a malformed override is a hard configuration error
    that exits the process via sign_fail() (exit 3) and never returns. Codex
    r4055706494 (P2): some callers — the policy-signature VERIFY path
    (verify_policy_snapshot_signature / verify_policy_absence_signature /
    load_attested_policy_bundle's require_signature check in this module) invoked
    during ordinary `gate.py plan --waive` / `aggregate.py` runs, and panel.py's
    opportunistic init-time signing, which is documented as "never fatal to init" —
    must instead report a malformed AR_VERIFIER_CMD/AR_SIGNER_CMD as a normal,
    controlled failure (a BLOCKED verdict, or an unsigned-but-non-fatal init note) so
    one operator's typo in a command template cannot crash the whole CI process or
    silently violate panel.py's own never-fatal contract. Pass `fatal=False` there and
    surface `err` in the caller's own error/BLOCKED message."""
    cmd = os.environ.get(env_cmd, "").strip()
    if cmd:
        try:
            return shlex.split(cmd), "custom", None
        except ValueError as e:
            msg = f"{env_cmd} is not a valid command template ({e}): {cmd!r}"
            if fatal:
                sign_fail(msg)
            return None, None, msg
    for kind, build in builders:
        argv = build()
        if argv is not None:
            return argv, kind, None
    return None, None, None


def _policy_bool_env(name):
    """True iff env var `name` is set to a non-empty value other than '0'/'false'/'no'
    (case-insensitive) -- the same "explicit opt-in" shape AR_ALLOW_KEYLESS uses. Unset
    or blank is False, matching every other AR_* env toggle in this module."""
    v = os.environ.get(name, "").strip().lower()
    return bool(v) and v not in ("0", "false", "no")


def _signing_required_anchor():
    """True iff this repository has declared, via a source its own working tree (and
    therefore a same-repo PR's own diff) cannot control, that signing is mandatory.

    Checklist item 1 (frontier-gate run pr70-item6-scope, 2026-09-23, refined Option A /
    scope_down_never_break_unsigned): relying solely on "does a verifier resolve in this
    process's own environment" (_verifier_configured_here, the pre-existing GAP-A check)
    is not enough on its own to close the downgrade-to-exempt gap the panel flagged --
    an attacker able to influence the workflow file that launches this process (e.g. a
    same-repo PR editing .github/workflows/*, or simply removing AR_VERIFIER_CMD/
    AR_ALLOW_KEYLESS from the job env) could make the verifier silently fail to resolve,
    which would make a previously-signed repository look exactly like one that was never
    signed and fall through to the infrastructure-free exemption instead of BLOCKING.

    AR_SIGNING_REQUIRED is meant to be set exactly once, out of band, as a repository
    secret / Action input on the CALLING reusable workflow (the same place action.yml's
    `signing: keyless` input already wires AR_ALLOW_KEYLESS -- see roadmap Phase 2 item
    10) or an environment-protection-rule variable -- NOT inside a workflow file a
    same-repo PR's own diff can edit, and never inside anything read from the run
    directory itself. Same explicit-opt-in _policy_bool_env() shape as
    AR_ALLOW_KEYLESS/AR_ALLOW_LOCAL_CI_IDENTITY. Operators who cannot yet anchor this
    outside their own workflow file are no worse off than before this change -- the
    pre-existing _verifier_configured_here() check still applies on its own."""
    return _policy_bool_env("AR_SIGNING_REQUIRED")


def _verifier_configured_here():
    """True iff a signature verifier resolves in THIS process's own environment (cosign
    keyless via AR_VERIFIER_CMD or its defaults, or minisign). Factored out of
    load_attested_policy_bundle's GAP-A file-absence branch so that branch and
    authenticate_risk_tier's own pre-check (checklist item 1) can never drift out of
    sync with each other by each re-implementing this resolution differently. Never
    invokes the verifier itself, only resolves its argv template -- offline, cheap, no
    network or subprocess call, safe to call on every `gate.py plan`/`aggregate.py`
    invocation regardless of whether this repository signs anything."""
    argv_tmpl, _kind, resolve_err = resolve_signing_tool(
        "AR_VERIFIER_CMD",
        [("cosign-keyless", cosign_verify_argv), ("minisign", minisign_verify_argv)],
        fatal=False)
    # Codex 4089779550 (P2): a partially-pinned cosign keyless identity resolves to
    # bare None above (no resolve_err) -- treat it as "configured" too, for the same
    # reason a malformed AR_VERIFIER_CMD already is (see docstring).
    return (argv_tmpl is not None or bool(resolve_err)
            or _cosign_keyless_partially_configured())


_UNTRUSTED_GITHUB_EVENTS = frozenset({"pull_request"})

# GAP B (frontier-gate run pr70-design, 2026-09-21): GitLab's counterpart to GitHub
# Actions' `pull_request` event -- a pipeline whose CI_PIPELINE_SOURCE is
# "merge_request_event" runs against merge-request-author-controlled code (including,
# for an MR from a fork, code the repository's own maintainers did not write), the same
# risk profile GitHub's pull_request refusal exists to catch. GitLab's own two-job
# template (examples/.gitlab-ci.yml) keeps the keyed ar-panel job's trust independent of
# this check by never checking out MR-author-controlled refs for the signing step in the
# first place, but this guard stays defense-in-depth for any adopter's own topology.
_UNTRUSTED_GITLAB_PIPELINE_SOURCES = frozenset({"merge_request_event"})


def _pr_author_controlled_trigger():
    """True iff THIS process is running inside a job whose trigger is one
    trusted_signer_guard_error() would refuse to sign under (GitHub Actions
    GITHUB_EVENT_NAME=='pull_request', or GitLab CI_PIPELINE_SOURCE==
    'merge_request_event' when GITLAB_CI=='true') -- i.e. a job an adversarial PR/MR's
    own code controls, checked out at HEAD. Factored out of trusted_signer_guard_error
    so it and authenticate_risk_tier's own pre-check (Codex/CodeRabbit r4082557512, "Do
    not force unsigned pull_request runs to CRITICAL") can never drift out of sync --
    same shape as _verifier_configured_here's own extraction from GAP-A's file-absence
    branch. Deliberately does NOT check AR_TRUSTED_SIGNER (unlike
    trusted_signer_guard_error) -- that flag decides whether THIS job may attempt to
    sign; this function answers a narrower, purely factual question (can a job with
    this trigger structurally sign AT ALL, regardless of what it's opted into) that
    authenticate_risk_tier needs independently of any signing intent.

    Codex 4110155767 (P1, valid): the GitHub-branch check below is now only read when
    GITHUB_ACTIONS=="true" -- the exact fail-closed platform-selection gate round 5.5
    (commit 567f558) already added to ci_signing_context()'s own GitHub Actions branch,
    backported here to this second, independent call site. Before this fix,
    GITHUB_EVENT_NAME=='pull_request' alone was trusted regardless of GITHUB_ACTIONS --
    so any process that simply had that one variable set (a local shell, an unrelated
    third-party CI system, or a step deliberately crafted to mimic a GitHub Actions
    pull_request run) was read by authenticate_risk_tier() as "this run structurally
    cannot have been signed," taking its fast, unsigned-exempt path even when
    AR_SIGNING_REQUIRED=1 explicitly demanded strict authentication -- an attacker who
    can set one env var (never touching real GitHub Actions) could silently downgrade a
    signing-required repository to the same no-infrastructure-configured path a
    never-signed repository takes. Requiring GITHUB_ACTIONS=="true" first closes that
    gap the same way it already closes it for ci_signing_context(): a real GitHub
    Actions runner always sets it, so this narrows trust, never widens it -- every
    existing test that simulates a genuine pull_request-triggered job already sets
    GITHUB_ACTIONS: "true" via _stub_signer_env() (round 5.5's own fixture default) and
    is unaffected."""
    if os.environ.get("GITHUB_ACTIONS", "").strip().lower() == "true":
        event = os.environ.get("GITHUB_EVENT_NAME", "").strip()
        if event in _UNTRUSTED_GITHUB_EVENTS:
            return True
    if os.environ.get("GITLAB_CI", "").strip().lower() == "true":
        source = os.environ.get("CI_PIPELINE_SOURCE", "").strip()
        if source in _UNTRUSTED_GITLAB_PIPELINE_SOURCES:
            return True
    return False


def trusted_signer_guard_error():
    """Best-effort, defense-in-depth check that the CURRENT process is not obviously
    running inside a job an adversarial PR's own code controls, called immediately
    before any attempt to SIGN policy.snapshot.json (never before verifying -- ordinary
    review and signature verification must keep working everywhere, unsigned included).
    Returns a short reason string to refuse signing, or None to allow it. (frontier-gate
    run pr70-architecture-review, 2026-09-20, batch 3 of the redesign_signing_boundary
    decision -- checklist items 6/9; extended to GitLab by GAP B, frontier-gate run
    pr70-design, 2026-09-21.)

    Two checks, both fail-closed:

      1. AR_TRUSTED_SIGNER must be explicitly set (_policy_bool_env) -- signing a policy
         snapshot is never attempted "opportunistically" merely because a working signer
         happens to be configured, the way it always has been before this fix. An
         adopter must deliberately mark the job that runs `panel.py init` as the trusted
         signer, exactly like AR_ALLOW_KEYLESS requires an explicit opt-in for cosign
         keyless (frontier-gate run pr70-provenance, batch 1, commit 6ac59c0) -- same
         shape, different gap: that one closed an accidental auto-activation of ONE
         signer kind; this one closes ALL signer kinds being invoked in the wrong job.

      2. The CI orchestrator's own trigger must not be one whose job runs with
         contributor-controlled code checked out and (for a fork) a read-only/scoped
         token. On GitHub Actions that trigger is GITHUB_EVENT_NAME=="pull_request"; a
         trusted signer job should instead run from `workflow_run` (triggered by
         completion of the untrusted review job, checking out the BASE ref), `push`,
         `schedule`, or `workflow_dispatch` -- see docs/THREAT-MODEL.md and the worked
         example in docs/ci-integration.md. On GitLab CI (GITLAB_CI=="true") the
         equivalent trigger is CI_PIPELINE_SOURCE=="merge_request_event" -- a trusted
         signer job should instead run from `push`, `schedule`, `web`, or
         `pipeline`/`trigger`, per examples/.gitlab-ci.yml. Neither variable set to its
         platform's "untrusted" value (local dev, a non-GitHub/GitLab CI, or this test
         suite) passes this check -- it cannot protect what it cannot see, and refusing
         all local/offline signing outright would break every existing signer-configured
         workflow and test that predates this fix.

    NOT a substitute for actual job/workflow separation -- see docs/THREAT-MODEL.md for
    what this can and cannot prove on its own. In particular: this cannot detect a
    trusted `workflow_run` job that itself executes a tampered copy of panel.py /
    _common.py checked out from the PR's own ref instead of a pinned action ref or the
    base branch (checklist item 3) -- that is a workflow-configuration guarantee this
    code has no way to verify about itself, disclosed as an adopter responsibility in
    docs/THREAT-MODEL.md, not a gap silently left unmentioned."""
    if not _policy_bool_env("AR_TRUSTED_SIGNER"):
        return ("AR_TRUSTED_SIGNER is not set -- policy-snapshot signing must be "
                "explicitly opted into from the job you have designated as the trusted "
                "signer (never opportunistically just because a signer happens to be "
                "configured); see docs/THREAT-MODEL.md")
    if _pr_author_controlled_trigger():
        event = os.environ.get("GITHUB_EVENT_NAME", "").strip()
        if event in _UNTRUSTED_GITHUB_EVENTS:
            return (f"GITHUB_EVENT_NAME={event!r} is a PR-author-controlled trigger -- "
                    "the trusted signer must run from workflow_run, push, schedule, or "
                    "workflow_dispatch instead, in a job the PR cannot modify; see "
                    "docs/THREAT-MODEL.md")
        source = os.environ.get("CI_PIPELINE_SOURCE", "").strip()
        return (f"CI_PIPELINE_SOURCE={source!r} is a merge-request-author-controlled "
                "trigger -- the trusted signer must run from push, schedule, web, or "
                "pipeline/trigger instead, in a job the MR cannot modify; see "
                "docs/THREAT-MODEL.md")
    return None


def cosign_sign_argv():
    # sigstore/cosign KEYLESS. An ephemeral Fulcio certificate (from an ambient OIDC
    # identity) plus a Rekor transparency-log entry; no long-lived private key. `--yes`
    # suppresses the confirmation prompt; `--bundle` packs signature + certificate + log
    # proof into ONE self-contained sidecar an outside verifier consumes with
    # `verify-blob --bundle`.
    #
    # EXPLICIT OPT-IN ONLY (frontier-gate run pr70-architecture-review, 2026-09-20,
    # Paul: option A). Paul's original decision on this exact mechanism (frontier-gate
    # run pr70-provenance, 2026-09-19) was "let's not go keyless" -- yet this
    # auto-detect builder used to activate the moment the `cosign` binary happened to be
    # on PATH, with no signal that anyone had actually chosen it. AR_ALLOW_KEYLESS must
    # be explicitly set (any non-empty, non-"0"/"false" value) before keyless is even
    # attempted; minisign (or a custom AR_SIGNER_CMD) stays the only thing that activates
    # by default. This does not by itself make keyless a real per-run identity boundary
    # -- see docs/THREAT-MODEL.md for what does.
    if not _policy_bool_env("AR_ALLOW_KEYLESS"):
        return None
    if not shutil.which("cosign"):
        return None
    return ["cosign", "sign-blob", "--yes", "--bundle", "{sig}", "{msg}"]


def minisign_sign_argv():
    # Fallback: minisign (Ed25519). Requires a configured secret key (AR_MINISIGN_KEY);
    # `-x` writes the detached signature to the given path. Use a password-less key for
    # non-interactive runs.
    key = os.environ.get("AR_MINISIGN_KEY", "").strip()
    if not (shutil.which("minisign") and key):
        return None
    return ["minisign", "-S", "-s", key, "-m", "{msg}", "-x", "{sig}"]


_GITHUB_ACTIONS_OIDC_ISSUER = "https://token.actions.githubusercontent.com"


def _auto_github_cosign_identity():
    """Derive (certificate_identity_regexp, issuer) scoped to the current GitHub
    repository from GITHUB_REPOSITORY (e.g. "octo-org/octo-repo"), for use ONLY as a
    fallback when the operator has set NEITHER AR_COSIGN_IDENTITY NOR AR_COSIGN_ISSUER
    (see cosign_verify_argv). Returns (None, None) when GITHUB_REPOSITORY is unset/blank
    -- nothing to scope to, and auto-derivation must not guess.

    security-3 (frontier-gate run pr70-design-crypto-ci-identity, 2026-09-21, Paul:
    "Yes to stronger cryptographic CI Identity check"): before this, AR_COSIGN_IDENTITY /
    AR_COSIGN_ISSUER were purely operator-typed strings with ZERO cross-validation
    against ci_signing_context()'s live CI-context binding -- WHO cosign will accept as
    the signer (the certificate identity) and WHAT the payload itself claims about its CI
    context (repository/commit/run_id/run_attempt, bound into policy_attest_bytes /
    policy_absence_attest_bytes via ci_signing_context) were two independently-configured
    checks that could silently drift apart: an operator could paste in the wrong issuer,
    or an identity regexp scoped to a different repository than the one actually running,
    and nothing would catch the mismatch. Deriving the issuer and an ANCHORED identity
    regexp from the SAME GITHUB_REPOSITORY value ci_signing_context() itself reads closes
    that gap for the common case (GitHub Actions, no custom OIDC federation) without
    requiring the operator to hand-copy a federation URL, while an explicit
    AR_COSIGN_IDENTITY/AR_COSIGN_ISSUER pair (both set) still always wins unchanged --
    this is a fallback, never an override.

    The regexp is anchored with a leading ^ and a trailing / specifically so
    "octo-org/octo-repo" cannot match a workflow identity for "octo-org/octo-repo-evil"
    or any other repository/org -- re.escape() further neutralizes any regex
    metacharacter the repository slug itself might contain.

    GitLab's OIDC keyless-signing equivalent is deliberately NOT extended here --
    GitLab's cosign keyless flow uses a different, CI_SERVER_URL-relative OIDC issuer
    shape this PR does not derive (kept PR-sized; see GAP B for what WAS extended to
    GitLab, the CI-identity payload binding in ci_signing_context/trusted_signer_guard).
    A GitLab operator using cosign keyless must still set AR_COSIGN_IDENTITY/
    AR_COSIGN_ISSUER explicitly, exactly as before this change."""
    repo = os.environ.get("GITHUB_REPOSITORY", "").strip()
    if not repo:
        return None, None
    return "^https://github\\.com/" + re.escape(repo) + "/", _GITHUB_ACTIONS_OIDC_ISSUER


def cosign_verify_argv():
    # Keyless verification is only meaningful against an expected signer identity +
    # issuer: `cosign verify-blob` WITHOUT --certificate-identity/--certificate-oidc-issuer
    # accepts ANY valid Fulcio certificate, so it must not be auto-selected as the
    # verifier unless both are resolved -- explicitly by the operator, or auto-derived
    # below. When neither resolves we return None and fall through (to minisign, or to a
    # loud "no verifier available" naming AR_COSIGN_IDENTITY/AR_COSIGN_ISSUER) rather than
    # silently verifying against an unconstrained identity (panel finding security-1).
    #
    # EXPLICIT OPT-IN ONLY (frontier-gate run pr70-architecture-review, 2026-09-20) --
    # same AR_ALLOW_KEYLESS gate as cosign_sign_argv above, and for the same reason:
    # Paul said not keyless for this mechanism, and auto-detection contradicted that the
    # moment `cosign` was merely present with ambient identity/issuer env vars set.
    if not _policy_bool_env("AR_ALLOW_KEYLESS"):
        return None
    if not shutil.which("cosign"):
        return None
    ident = os.environ.get("AR_COSIGN_IDENTITY", "").strip()
    issuer = os.environ.get("AR_COSIGN_ISSUER", "").strip()
    if ident and issuer:
        # Operator-specified exact identity always wins, unchanged from before this
        # change -- an explicit pair is never second-guessed or replaced by the
        # auto-derived regexp below, even when GITHUB_REPOSITORY also happens to be set.
        return ["cosign", "verify-blob", "--bundle", "{sig}",
                "--certificate-identity", ident, "--certificate-oidc-issuer", issuer, "{msg}"]
    if not ident and not issuer:
        # Neither set explicitly: fall back to an auto-derived, anchored identity
        # (security-3, see _auto_github_cosign_identity docstring). A PARTIAL explicit
        # config (exactly one of the two set) is left alone here and falls through to
        # None below -- silently combining one operator-chosen value with one
        # auto-derived value could pair an intentional custom issuer with an identity
        # regexp scoped to the wrong OIDC federation, or vice versa.
        auto_regexp, auto_issuer = _auto_github_cosign_identity()
        if auto_regexp and auto_issuer:
            return ["cosign", "verify-blob", "--bundle", "{sig}",
                    "--certificate-identity-regexp", auto_regexp,
                    "--certificate-oidc-issuer", auto_issuer, "{msg}"]
    return None


def _cosign_keyless_partially_configured():
    """True iff the operator has taken a concrete step toward cosign keyless
    verification (AR_ALLOW_KEYLESS set and the cosign binary present) but pinned only
    ONE of the two identity constraints cosign_verify_argv requires (AR_COSIGN_IDENTITY
    XOR AR_COSIGN_ISSUER) -- distinct from BOTH unset (cosign_verify_argv's own
    auto-derive fallback) and BOTH set (fully pinned), neither of which is a
    misconfiguration.

    Codex 4089779550 (P2, valid): cosign_verify_argv() has no error channel for this
    case -- a partial pair makes it fall through to a bare `None`, indistinguishable
    from "keyless was never attempted at all." That made _verifier_configured_here()
    report False for an operator who had clearly started configuring a verifier, the
    same silent-degrade-to-exempt shape the pre-existing "a malformed AR_VERIFIER_CMD
    counts as 'a verifier IS configured here'" handling (see resolve_signing_tool's
    `err`, consumed just below) already closes for the env-override path. Without this,
    AR_ALLOW_KEYLESS=1 plus e.g. only AR_COSIGN_IDENTITY set let a SENSITIVE/CRITICAL
    run with no policy.snapshot.json and no signed policy.absence.json take the
    infrastructure-free exemption (load_attested_policy_bundle's GAP-A branch,
    authenticate_risk_tier's own pre-check) instead of being BLOCKED/escalated -- an
    operator's incomplete config silently bought the same pass as never configuring
    verification at all."""
    if not _policy_bool_env("AR_ALLOW_KEYLESS"):
        return False
    if not shutil.which("cosign"):
        return False
    ident = bool(os.environ.get("AR_COSIGN_IDENTITY", "").strip())
    issuer = bool(os.environ.get("AR_COSIGN_ISSUER", "").strip())
    return ident != issuer


def minisign_verify_argv():
    # AR_MINISIGN_PUBKEY_FILE names a public-key FILE (minisign `-p`); AR_MINISIGN_PUBKEY
    # carries an INLINE key value (minisign `-P`). They are SEPARATE vars by design:
    # choosing `-p` vs `-P` by whether the value happens to name an existing file (an
    # earlier os.path.exists heuristic) let an attacker who can drop a file into the
    # verifier's working directory — named exactly the operator's PUBLIC inline key —
    # make minisign read an attacker-chosen key file, so a verdict signed with the
    # attacker's key would verify (panel finding security-1). Filesystem state must
    # never select the verification key. An explicit key file wins when both are set.
    if not shutil.which("minisign"):
        return None
    keyfile = os.environ.get("AR_MINISIGN_PUBKEY_FILE", "").strip()
    if keyfile:
        return ["minisign", "-V", "-p", keyfile, "-m", "{msg}", "-x", "{sig}"]
    inline = os.environ.get("AR_MINISIGN_PUBKEY", "").strip()
    if inline:
        return ["minisign", "-V", "-P", inline, "-m", "{msg}", "-x", "{sig}"]
    return None


def run_signing_tool(argv_tmpl, msg_path, sig_path, *, fatal=True):
    """Substitute `{msg}`/`{sig}` in the argv template and run the external
    signer/verifier. Always returns (proc, error) — `proc` is the CompletedProcess on a
    successful invocation (regardless of its exit code; a nonzero exit is the CALLER's
    failure to interpret, not a tooling failure) and `error` is a short message when the
    tool could not even be started or timed out.

    fatal=True (the default — matches the existing opt-in aggregate.py --sign /
    --verify-signature contract): a tooling failure calls sign_fail() (loud, exit 3)
    and this never returns with `error` set.
    fatal=False (a best-effort caller, e.g. panel.py's opportunistic policy-snapshot
    signature at init): a tooling failure is returned instead of exiting, so the caller
    can warn and continue rather than aborting a command that has nothing else to do
    with signing."""
    argv = [a.replace("{msg}", str(msg_path)).replace("{sig}", str(sig_path)) for a in argv_tmpl]
    if not any("{msg}" in a for a in argv_tmpl):
        argv.append(str(msg_path))
    try:
        return subprocess.run(argv, capture_output=True, timeout=sign_timeout()), None
    except OSError as e:
        msg = f"could not start signer/verifier {argv[0]!r}: {e}"
        if fatal:
            sign_fail(msg)
        return None, msg
    except subprocess.TimeoutExpired:
        msg = (f"signer/verifier {argv[0]!r} timed out after {sign_timeout()}s "
               "(set AR_SIGN_TIMEOUT to adjust)")
        if fatal:
            sign_fail(msg)
        return None, msg


def die(msg, code=1):
    print(f"ERROR: {msg}", file=sys.stderr)
    sys.exit(code)


# Provider-family normalization. Family = the model AUTHOR's organization — the unit of
# independence. Slug prefixes vary across routers; map known variants to one family key.
FAMILY_ALIASES = {
    "anthropic": "anthropic",
    "openai": "openai",
    "google": "google",
    "x-ai": "xai", "xai": "xai",
    "qwen": "qwen", "alibaba": "qwen",
    "mistralai": "mistral", "mistral": "mistral",
    "deepseek": "deepseek",
    "meta-llama": "meta", "meta": "meta",
    "moonshotai": "moonshot", "moonshot": "moonshot",
    "z-ai": "zai", "zai": "zai", "zhipu": "zai",
    "cohere": "cohere",
    "amazon": "amazon",
    "microsoft": "microsoft",
    "nvidia": "nvidia",
    "ai21": "ai21",
}


def family_of(slug):
    prefix = slug.split("/", 1)[0].lower()
    return FAMILY_ALIASES.get(prefix, prefix)


def canonical_finding_digest(finding):
    """A content-derived identity for a reviewer finding, independent of its 'id' field.
    Reviewer-assigned ids are convenient labels, not stable or unique across separate
    `panel.py run --force` re-runs of the same run directory -- a re-run can reuse a
    conventional id (e.g. 'security-1') for what is, in substance, a completely different
    finding. Anything that binds coverage/trust to an id alone (see aggregate.py's
    check_rebuttal / _rebuttal_jev_gate) can then be satisfied by a stale record that
    never actually evaluated the new content. This hashes the fields that describe WHAT
    the finding actually claims -- title, file, line, severity, evidence, scenario, and
    the reporting role -- after normalizing line endings (CRLF/CR -> LF) and trimming, so
    the same substantive text produces the same digest regardless of how it was
    transcribed, and joins the fields with an ASCII record-separator byte (0x1E) that
    cannot appear in ordinary text, so two different field-boundary splits can never
    collide onto the same joined string. The 'file' field is additionally normalized to
    forward-slash separators (Windows backslash paths and POSIX forward-slash paths for
    the same file must hash identically) -- this only rewrites the separator character,
    it does not touch case or resolve '.'/'..' segments, since doing so could silently
    fold two genuinely different paths on a case-sensitive filesystem into one digest."""
    def norm(v):
        if not isinstance(v, str):
            return ""
        return v.replace("\r\n", "\n").replace("\r", "\n").strip()

    def norm_path(v):
        return norm(v).replace("\\", "/")

    line = finding.get("line")
    parts = [
        norm(finding.get("title")),
        norm_path(finding.get("file")),
        str(line) if isinstance(line, int) and not isinstance(line, bool) else "",
        norm(finding.get("severity")),
        norm(finding.get("evidence")),
        norm(finding.get("scenario")),
        norm(finding.get("author_role")),
    ]
    canonical = "\x1e".join(parts)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


# ------------------------------------------------------------------- policy as code
# Repo-versioned defaults (issue #6): `.adversarial-review.yml` (strict minimal YAML
# subset) or `.adversarial-review.json` at the reviewed repo's root. Precedence
# everywhere: CLI flag > env var > policy file > built-in default. A malformed policy
# is a loud error — never a silent fallback — even when CLI flags would have sufficed.

POLICY_BASENAMES = (".adversarial-review.yml", ".adversarial-review.json")
POLICY_KEYS = ("risk", "dev_providers", "rebuttal_policy", "required_gates", "pins",
               "mutation", "max_cost_usd", "high_samples",
               "allow_critical_waivers", "max_waiver_days")
VALID_RISKS = ("NORMAL", "SENSITIVE", "CRITICAL")
VALID_REBUTTAL = ("critical", "contention", "any")
MAX_HIGH_SAMPLES = 25  # practical upper bound on corroboration samples (E4-S3): bounds the
                       # cost blast radius and the not_run list built on a cost-abort.
# Scoped/bounded mutation budget — a repo-tunable cost cap so mutation testing survives
# large or resource-constrained repos. A flat mapping (the strict YAML subset allows one
# nested level); every field is optional. The configured budget is snapshotted into the
# run's policy record, so a bounded run's coverage reduction is on the record, never
# silent. See references/gates.md.
MUTATION_KEYS = ("scope", "threshold", "max_mutants", "sample_pct",
                 "concurrency", "timeout_s", "exclude_files", "exclude_tests")


def _strip_comment(line):
    """Drop a trailing comment: '#' at start-of-line or preceded by whitespace,
    outside single/double quotes."""
    quote = None
    for j, ch in enumerate(line):
        if quote:
            if ch == quote:
                quote = None
        elif ch in "'\"":
            quote = ch
        elif ch == "#" and (j == 0 or line[j - 1] in " \t"):
            return line[:j]
    return line


def _parse_policy_yaml(text, name):
    """Parse the documented strict YAML subset: 'key: value' scalars, inline
    [a, b] lists, '{}' empty maps, 'key:' followed by '- item' block lists or ONE
    nested mapping level, comments. No coercion — every scalar stays a string.
    Anything outside the subset dies loudly; .adversarial-review.json is the
    escape hatch for richer needs."""
    def perr(ln, msg):
        die(f"{name}:{ln}: {msg}\n  supported subset: 'key: value', 'key:' + "
            "'- item' lists, one nested mapping level, inline [a, b] lists, '{}' "
            "for an empty map, '#' comments. For anything richer use "
            ".adversarial-review.json")

    def scalar(tok, ln):
        tok = tok.strip()
        if not tok:
            perr(ln, "missing value")
        if tok[0] in "&*!|>" or tok.startswith("---"):
            perr(ln, f"unsupported YAML construct {tok!r}")
        if len(tok) >= 2 and tok[0] == tok[-1] and tok[0] in "'\"":
            tok = tok[1:-1].strip()
            if not tok:
                perr(ln, "empty quoted value")
        if any(c in tok for c in "{}[],"):
            perr(ln, f"unexpected flow character in scalar {tok!r}")
        return tok

    def value_of(tok, ln):
        tok = tok.strip()
        if tok == "{}":
            return {}
        if tok == "[]":
            return []
        if tok.startswith("["):
            if not tok.endswith("]"):
                perr(ln, f"unterminated flow list {tok!r}")
            inner = tok[1:-1].strip()
            return [scalar(p, ln) for p in inner.split(",")] if inner else []
        if tok.startswith("{"):
            perr(ln, "non-empty {…} flow mappings are not supported")
        return scalar(tok, ln)

    items = []
    for ln, raw in enumerate(text.splitlines(), 1):
        s = _strip_comment(raw).rstrip()
        if not s.strip():
            continue
        stripped = s.lstrip(" ")
        if stripped.startswith("\t"):
            perr(ln, "tab characters are not allowed in indentation")
        items.append((ln, len(s) - len(stripped), stripped))
    if not items:
        die(f"{name}: policy file exists but is empty — delete it or add settings")

    idx = 0

    def parse_list(parent_indent):
        nonlocal idx
        base = items[idx][1]
        out = []
        while idx < len(items) and items[idx][1] >= base and items[idx][2].startswith("-"):
            ln, ind, s = items[idx]
            if ind != base:
                perr(ln, f"inconsistent indentation (expected column {base})")
            if not s.startswith("- "):
                perr(ln, f"list items must be '- value', got {s!r}")
            out.append(scalar(s[2:], ln))
            idx += 1
        if idx < len(items) and items[idx][1] > parent_indent \
                and not items[idx][2].startswith("-"):
            perr(items[idx][0], "unexpected line after list items")
        return out

    def parse_map(depth):
        nonlocal idx
        base = items[idx][1]
        if depth == 0 and base != 0:
            perr(items[idx][0], "top-level keys must start at column 0")
        out = {}
        while idx < len(items) and items[idx][1] >= base:
            ln, ind, s = items[idx]
            if ind != base:
                perr(ln, f"inconsistent indentation (expected column {base})")
            if s.startswith("-"):
                perr(ln, "list item found where a key was expected")
            if ":" not in s:
                perr(ln, f"expected 'key:' or 'key: value', got {s!r}")
            key, _, rest = s.partition(":")
            key = scalar(key, ln)
            if key in out:
                perr(ln, f"duplicate key {key!r}")
            rest = rest.strip()
            idx += 1
            if rest:
                out[key] = value_of(rest, ln)
                continue
            if idx >= len(items) or items[idx][1] <= base:
                perr(ln, f"key {key!r} has no value (use '{{}}' or '[]' for empty)")
            if items[idx][2].startswith("-"):
                out[key] = parse_list(base)
            elif depth >= 1:
                perr(items[idx][0],
                     "nesting beyond one mapping level is not supported")
            else:
                out[key] = parse_map(depth + 1)
        return out

    data = parse_map(0)
    return data


def _policy_number(v):
    """A policy scalar is a string under the YAML subset but a real number under JSON.
    Return it as a finite float, or None when it is not a usable finite number: a bool is
    not a number here, and inf/nan/over-large magnitudes are rejected so downstream range
    and integer checks never crash on them (int(inf)/int(nan) would raise)."""
    if isinstance(v, bool):
        return None
    if isinstance(v, (int, float)):
        try:
            n = float(v)
        except OverflowError:
            return None
    elif isinstance(v, str):
        try:
            n = float(v.strip())
        except ValueError:
            return None
    else:
        return None
    return n if math.isfinite(n) else None


def meta_cost(meta):
    """Billed USD from one reviewer-meta mapping as a finite float (0.0 if absent/malformed).
    Prefers the top-level ``cost``; falls back to nested ``usage.cost`` — the MCP ingest path
    records cost only under ``usage``. A missing, non-finite, or negative cost counts as 0: a
    provider that omits or corrupts cost can neither be charged against the cap nor drive the
    running total down, and cannot poison the sum or the coverage JSON."""
    if not isinstance(meta, dict):
        return 0.0
    c = _policy_number(meta.get("cost"))
    if c is None and isinstance(meta.get("usage"), dict):
        c = _policy_number(meta["usage"].get("cost"))
    return c if c is not None and c >= 0 else 0.0


def merge_usage(prior, current):
    """Sum the billed numeric fields of two usage objects so a malformed-JSON retry — a second
    paid call — is fully counted, not just the final attempt. Only finite numbers accumulate;
    non-numeric metadata from the latest response is preserved. ``prior`` None means first call."""
    current = current if isinstance(current, dict) else {}
    if not prior:
        return dict(current)
    out = dict(prior)
    for k, v in current.items():
        cv = _policy_number(v)
        if cv is not None:
            pv = _policy_number(out.get(k))
            out[k] = (pv or 0.0) + cv
        elif k not in out:
            out[k] = v
    return out


def _validate_mutation(v, name):
    if not isinstance(v, dict):
        die(f"{name}: mutation must be a mapping of budget settings "
            f"(allowed: {', '.join(MUTATION_KEYS)})")
    unknown = sorted(set(v) - set(MUTATION_KEYS))
    if unknown:
        die(f"{name}: mutation has unknown key(s): {', '.join(unknown)} "
            f"(allowed: {', '.join(MUTATION_KEYS)})")
    if "scope" in v and v["scope"] not in ("changed", "all"):
        die(f"{name}: mutation.scope must be 'changed' or 'all', got {v['scope']!r}")
    for k in ("max_mutants", "concurrency", "timeout_s"):
        if k in v:
            n = _policy_number(v[k])
            # 2**53 is float64's exact-integer ceiling: at or above it a fractional
            # value (e.g. 9007199254740992.5) rounds to a whole float and would slip
            # the `n != int(n)` check, and such a budget is absurd anyway.
            if n is None or n < 1 or n >= 2 ** 53 or n != int(n):
                die(f"{name}: mutation.{k} must be a positive integer, got {v[k]!r}")
    for k in ("sample_pct", "threshold"):
        if k in v:
            n = _policy_number(v[k])
            if n is None or not 0 <= n <= 100:
                die(f"{name}: mutation.{k} must be a number in [0, 100], got {v[k]!r}")
    for k in ("exclude_files", "exclude_tests"):
        if k in v:
            lst = v[k]
            if not isinstance(lst, list) or not all(
                    isinstance(x, str) and x.strip() for x in lst):
                die(f"{name}: mutation.{k} must be a list of non-empty path/glob strings")


def _policy_bool(v):
    """A policy boolean: a real bool (JSON), or the literal string 'true'/'false' (the YAML
    subset never coerces scalars). Anything else is not a usable boolean here."""
    if isinstance(v, bool):
        return v
    if isinstance(v, str) and v.strip().lower() in ("true", "false"):
        return v.strip().lower() == "true"
    return None


# --------------------------------------------------------------- gate waivers (M1)
# A waiver is a time-boxed, accountable exception, never a permanent hole: it must name an
# authorizer, give a real reason, and expire — and it is independently re-validated from the
# gates/<name>.json record itself at aggregate time, never trusted just because gate.py wrote
# it (a hand-edited/tampered record is caught exactly like a fresh one). See references/gates.md.
WAIVER_REASON_PLACEHOLDERS = {"tbd", "n/a", "na", "temp", "fixme", "todo", "none", ""}
WAIVER_REASON_MIN_LEN = 16
DEFAULT_MAX_WAIVER_DAYS = 14
# Hard ceiling on any configured waiver lifetime. Bounds max_waiver_days at policy-load
# time so an absurd value (a typo, or a deliberate 10**12) can neither pass validation nor
# reach timedelta(days=...) and raise OverflowError, which would leave a run with no verdict.
MAX_WAIVER_DAYS_CAP = 365

# A gate identifier becomes a filename: gates/<name>.json. It must therefore be a strict,
# path-safe slug with NO leading underscore — gates/_required.json is the run manifest, and
# waiving or requiring a name like '_required' (or '../x', 'a/b', 'x.json') would overwrite
# the manifest or escape the gates dir, blanking the required set into a silent all-pass.
GATE_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")


def validate_gate_name(name):
    """Return an error string, or None when `name` is a safe gate identifier. Rejects
    leading-underscore/reserved names (gates/_required.json is the manifest), path
    separators, dots, and anything outside a strict lowercase slug — so gates/<name>.json
    can never escape the gates dir or overwrite the manifest."""
    if not isinstance(name, str):
        return "gate name must be a string"
    if not name.strip():
        return "gate name is required"
    # Match the RAW name with fullmatch (NOT match): a name with surrounding whitespace passes
    # a stripped check but the caller writes gates/<raw name>.json, so 'unit ' would be recorded
    # as 'unit .json' while the required set looks for 'unit'. `re.match` also lets a trailing
    # newline slip through ('unit\n' — the `$` anchor matches before the final \n), so fullmatch
    # is required to reject the whole tampered string.
    if not GATE_NAME_RE.fullmatch(name):
        return (f"gate name {name!r} is invalid — must match [a-z0-9][a-z0-9_-]{{0,63}} "
                "(lowercase alphanumerics, '-' or '_', no leading underscore, no whitespace, "
                "path separators, or dots); leading-underscore names such as '_required' are reserved")
    return None


def validate_waiver_reason(reason):
    """Return an error string, or None when `reason` is an acceptable justification: a
    non-empty string, long enough to be a real explanation, and not a placeholder."""
    if not isinstance(reason, str):
        return "reason must be a string"
    r = reason.strip()
    if not r:
        return "reason is required"
    if not _encodable_str(r):
        # Codex 4099660088 (P2, valid): a reason containing a lone UTF-16 surrogate
        # (e.g. "\ud800") passes every check below (non-empty, not a placeholder, long
        # enough) -- isinstance(r, str) is true and len() counts surrogates like any
        # other code point. But this exact string is later embedded verbatim into
        # verdict.json's gcov["waived"] entry (aggregate.py's check_gates) and rendered
        # into verdict.md's next-steps guidance, and both eventually .encode("utf-8")
        # the whole document -- which raises UnicodeEncodeError on a lone surrogate,
        # uncaught, crashing aggregation (exit 3, no verdict.json at all) instead of the
        # controlled BLOCKED verdict every other malformed-waiver-metadata case in this
        # module produces. Structurally the same "JSON permits it, UTF-8 encoding of it
        # later crashes" gap _encodable_str() already exists to close for run_id/
        # run_nonce/risk (see its own docstring) -- reject it here, at the same
        # validation point already responsible for catching every other malformed
        # reason shape.
        return "reason contains characters that cannot be represented in UTF-8"
    if r.lower() in WAIVER_REASON_PLACEHOLDERS:
        return f"reason {r!r} is a placeholder, not a real justification"
    if len(r) < WAIVER_REASON_MIN_LEN:
        return f"reason must be at least {WAIVER_REASON_MIN_LEN} characters, got {len(r)}"
    return None


def parse_waiver_expiry(expires):
    """Strict YYYY-MM-DD only (no datetimes, no other separators) — returns a `date`, or
    None when `expires` is missing, malformed, or not that exact shape."""
    if not isinstance(expires, str):
        return None
    s = expires.strip()
    if len(s) != 10 or s[4] != "-" or s[7] != "-":
        return None
    y, m, d = s[0:4], s[5:7], s[8:10]
    if not (y.isdigit() and m.isdigit() and d.isdigit()):
        return None
    try:
        return date(int(y), int(m), int(d))
    except ValueError:
        return None


def _date_from_iso(value):
    """The date part of an ISO-8601 datetime (or bare date) string, or None if `value`
    is not a string or is not parseable."""
    if not isinstance(value, str) or not value.strip():
        return None
    s = value.strip()
    if s[-1:] in ("Z", "z"):
        s = s[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(s).date()
    except ValueError:
        return None


def resolve_waiver_clock():
    """The 'now' date waiver expiries are compared against: the LATER of today in UTC and the
    date part of GITHUB_RUN_STARTED_AT (when that env var is set). Returns (clock_date, error).
    When the env var is set but cannot be parsed, returns (None, <message>) — fail closed:
    callers must BLOCK rather than fall back to today, since silently guessing the clock would
    defeat the whole expiry check. Taking the later of the two means a run clock rolled BACKWARD
    (a stale/forged GITHUB_RUN_STARTED_AT) cannot un-expire a waiver — real UTC still applies —
    while a forward run clock is still honored."""
    today = datetime.now(timezone.utc).date()
    raw = os.environ.get("GITHUB_RUN_STARTED_AT", "")
    if not raw.strip():
        return today, None
    d = _date_from_iso(raw)
    if d is None:
        return None, (f"GITHUB_RUN_STARTED_AT={raw!r} could not be parsed as a date/time — "
                       "the run is BLOCKED rather than guessing the current date")
    return max(d, today), None


def _validate_gate_exception_common(kind, gate_name, tier, authorized_by, reason, pol_data,
                                    strict_reason=True):
    """Checks shared by a WAIVED and a NOT_APPLICABLE gate record: the CRITICAL-tier
    restrictions, a named authorizer, and a justification. `kind` is 'WAIVED' or
    'NOT_APPLICABLE', used only for messages. `strict_reason` selects the justification
    contract: True (WAIVED) applies the full waiver-reason rule (>=16 chars, not a
    placeholder); False (NOT_APPLICABLE) only requires a non-empty summary — its original
    contract, which the shared 16-char rule had inadvertently tightened. Returns an error
    string, or None."""
    # Mutation on CRITICAL can NEVER be waived or marked not-applicable, regardless of policy:
    # CRITICAL mutation coverage stays BLOCKED by design until the mutation-runner milestone
    # (M4) implements it for real — a green verdict must never be reachable by waiving/N-A'ing
    # the one gate meant to catch that gap.
    if tier == "CRITICAL" and gate_name == "mutation":
        return ("mutation cannot be waived or marked NOT_APPLICABLE on CRITICAL tier — "
                "CRITICAL mutation coverage stays BLOCKED by design until the mutation-runner "
                "milestone (M4); run and record the real gate instead")
    if tier == "CRITICAL" and not (_policy_bool(pol_data.get("allow_critical_waivers")) or False):
        return (f"{kind} of a CRITICAL-tier gate requires policy allow_critical_waivers: true "
                "(default false) — CRITICAL waivers/NOT_APPLICABLE are disabled by default")
    who = authorized_by.strip() if isinstance(authorized_by, str) else ""
    if not who:
        return f"{kind} without a named authorizer"
    if not _encodable_str(who):
        # Codex 4099660088 (P2, valid): same lone-UTF-16-surrogate gap as
        # validate_waiver_reason's matching check below (see its docstring for the full
        # rationale) -- authorized_by is embedded verbatim into verdict.json's
        # gcov["waived"]/["not_applicable"] entries and verdict.md just like reason/
        # summary is, and crashes the same way at write_json()/markdown-render time if
        # it carries one.
        return f"{kind} authorizer contains characters that cannot be represented in UTF-8"
    if strict_reason:
        err = validate_waiver_reason(reason)
        if err:
            return f"{kind} with an invalid reason: {err}"
    elif not (isinstance(reason, str) and reason.strip()):
        return f"{kind} requires a non-empty summary"
    elif not _encodable_str(reason):
        # Codex 4099660088 (P2, valid): the NOT_APPLICABLE `summary` field (passed in as
        # `reason` here — see this function's own docstring) isn't run through
        # validate_waiver_reason's stricter checks, so it needs its own encodability
        # check for the same crash this whole fix closes.
        return f"{kind} summary contains characters that cannot be represented in UTF-8"
    return None


def validate_waived_gate(gate_name, tier, rec, pol_data, clock_date, manifest_planned_at=None):
    """Independently re-validate a gates/<name>.json record with status WAIVED (never
    trusting that gate.py's own plan-time checks ran, or ran correctly): named authorizer,
    real reason, CRITICAL restrictions, a strict future YYYY-MM-DD expiry, and the
    max_waiver_days cap measured from the RUN's planning time. `tier` is the run's ACTUAL
    current tier (never the record's own claim); `clock_date` is the resolved 'now' from
    resolve_waiver_clock (the caller must already have handled its error case);
    `manifest_planned_at` is the authoritative planning timestamp from the run's
    gates/_required.json manifest — the cap is anchored to it, not to the record's own
    planned_at, so editing only the record's planned_at cannot slide the whole window
    forward. Returns an error string, or None when the waiver is valid."""
    err = _validate_gate_exception_common("WAIVED", gate_name, tier,
                                          rec.get("authorized_by"), rec.get("reason"), pol_data)
    if err:
        return err
    expires = parse_waiver_expiry(rec.get("expires"))
    if expires is None:
        return f"expires {rec.get('expires')!r} is missing or not a valid YYYY-MM-DD date"
    if not (expires > clock_date):
        return f"waiver expired {expires.isoformat()} (as of {clock_date.isoformat()})"
    rec_planned = _date_from_iso(rec.get("planned_at"))
    if rec_planned is None:
        return "waiver record is missing a valid planned_at date — cannot verify the waiver-lifetime cap"
    man_planned = _date_from_iso(manifest_planned_at) if manifest_planned_at is not None else rec_planned
    if man_planned is None:
        return "run plan is missing a valid planned_at date — cannot anchor the waiver-lifetime cap"
    # A planning timestamp cannot be after the effective clock — a run is not planned in the
    # future. Reject ANY future record or manifest planned_at as tampered (no day of slack:
    # advancing both timestamps by a day together would otherwise defeat the min() anchor).
    if rec_planned > clock_date:
        return (f"waiver planned_at {rec_planned.isoformat()} is in the future "
                f"(clock {clock_date.isoformat()}) — record tampered")
    if man_planned > clock_date:
        return (f"run plan planned_at {man_planned.isoformat()} is in the future "
                f"(clock {clock_date.isoformat()}) — plan manifest tampered")
    # Anchor the cap to the EARLIEST planning evidence of the two timestamps, so advancing
    # EITHER the record's or the manifest's planned_at forward cannot widen the window (in the
    # honest flow both are the same value gate.py wrote in one plan call).
    anchor = min(rec_planned, man_planned)
    n = _policy_number(pol_data.get("max_waiver_days"))
    max_days = (int(n) if n is not None and 1 <= n <= MAX_WAIVER_DAYS_CAP
                else DEFAULT_MAX_WAIVER_DAYS)
    try:
        deadline = anchor + timedelta(days=max_days)
    except (OverflowError, ValueError):
        return "waiver-lifetime cap is too large to evaluate — run BLOCKED"
    if expires > deadline:
        return (f"waiver expires {expires.isoformat()}, more than {max_days} days after the "
                f"run was planned ({anchor.isoformat()}) — waivers are capped at {max_days} days")
    return None


def validate_not_applicable_gate(gate_name, tier, rec, pol_data):
    """Independently re-validate a gates/<name>.json record with status NOT_APPLICABLE:
    named authorizer, a non-empty summary, and the CRITICAL restrictions. N/A keeps its
    original non-empty-summary contract (it is not a time-boxed waiver, so the >=16-char /
    no-placeholder waiver-reason rule does not apply). Returns an error string, or None."""
    return _validate_gate_exception_common("NOT_APPLICABLE", gate_name, tier,
                                           rec.get("authorized_by"), rec.get("summary"), pol_data,
                                           strict_reason=False)


def _validate_policy(data, name):
    if not isinstance(data, dict):
        die(f"{name}: top level must be a mapping of settings")
    unknown = sorted(set(data) - set(POLICY_KEYS))
    if unknown:
        die(f"{name}: unknown key(s): {', '.join(unknown)} "
            f"(allowed: {', '.join(POLICY_KEYS)})")
    if "risk" in data and data["risk"] not in VALID_RISKS:
        die(f"{name}: invalid risk {data['risk']!r} ({'|'.join(VALID_RISKS)})")
    if "rebuttal_policy" in data and data["rebuttal_policy"] not in VALID_REBUTTAL:
        die(f"{name}: invalid rebuttal_policy {data['rebuttal_policy']!r} "
            f"({'|'.join(VALID_REBUTTAL)})")
    if "dev_providers" in data:
        v = data["dev_providers"]
        if not isinstance(v, list) or not v \
                or not all(isinstance(x, str) and x.strip() for x in v):
            die(f"{name}: dev_providers must be a non-empty list of provider families")
    if "required_gates" in data:
        v = data["required_gates"]
        if not isinstance(v, dict):
            die(f"{name}: required_gates must be a mapping of tier -> gate list")
        bad = sorted(set(v) - set(VALID_RISKS))
        if bad:
            die(f"{name}: required_gates has unknown tier(s): {', '.join(bad)}")
        for tier, gates in v.items():
            if not isinstance(gates, list) \
                    or not all(isinstance(g, str) and g.strip() for g in gates):
                die(f"{name}: required_gates.{tier} must be a list of gate names")
    if "pins" in data:
        v = data["pins"]
        if not isinstance(v, dict):
            die(f"{name}: pins must be a mapping of role -> provider/model-slug")
        for role, slug in v.items():
            if not isinstance(slug, str) or "/" not in slug:
                die(f"{name}: pins.{role} must be a provider/model-slug, "
                    f"got {slug!r}")
    if "mutation" in data:
        _validate_mutation(data["mutation"], name)
    if "allow_critical_waivers" in data:
        if _policy_bool(data["allow_critical_waivers"]) is None:
            die(f"{name}: allow_critical_waivers must be true or false, got "
                f"{data['allow_critical_waivers']!r}")
    if "max_waiver_days" in data:
        v = data["max_waiver_days"]
        n = _policy_number(v)
        if n is None or n < 1 or n > MAX_WAIVER_DAYS_CAP or n != int(n):
            die(f"{name}: max_waiver_days must be an integer from 1 to "
                f"{MAX_WAIVER_DAYS_CAP}, got {v!r}")
    if "max_cost_usd" in data:
        v = data["max_cost_usd"]
        # A documented disable token, or a finite non-negative number. Reject at load so a bare
        # NaN/inf/negative can't pass validation and silently disable the cap at resolution time.
        tok = v.strip().lower() if isinstance(v, str) else None
        if tok not in ("", "none", "off", "unlimited"):
            n = _policy_number(v)
            if n is None or n < 0:
                die(f"{name}: max_cost_usd must be a finite non-negative number or "
                    f"'none'/'off'/'unlimited', got {v!r}")
    if "high_samples" in data:
        # Multi-sample corroboration count (E4-S3), informational-only: an integer in
        # [1, MAX_HIGH_SAMPLES]; 1 (the default) disables resampling. Validate EXACTLY as
        # panel.high_samples() resolves it — int(str(value)) — so an integral-looking float ("3.0",
        # 1e1) or any non-integer that `init` would accept here cannot be rejected later at `run`
        # time; the two must agree (panel/Codex E4-S3).
        hv = data["high_samples"]
        try:
            n = int(str(hv).strip())
        except (TypeError, ValueError):
            n = None
        if n is None or n < 1 or n > MAX_HIGH_SAMPLES:
            die(f"{name}: high_samples must be an integer in [1, {MAX_HIGH_SAMPLES}], "
                f"got {hv!r}")


def load_policy(root=None):
    """Load and validate the repo policy file. Returns None when absent, else
    {'data': dict, 'path': Path, 'sha256': hex, 'text': str}. Malformed input
    dies loudly (exit 1) — a policy is never silently ignored."""
    root = Path(root) if root else Path.cwd()
    found = [root / n for n in POLICY_BASENAMES if (root / n).is_file()]
    if not found:
        return None
    if len(found) > 1:
        die(f"both {' and '.join(POLICY_BASENAMES)} exist — keep exactly one")
    path = found[0]
    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError as e:
        die(f"{path.name}: not valid UTF-8: {e}")
    if path.suffix == ".json":
        try:
            data = json.loads(text)
        except ValueError as e:
            die(f"{path.name}: invalid JSON: {e}")
    else:
        data = _parse_policy_yaml(text, path.name)
    _validate_policy(data, path.name)
    return {"data": data, "path": path,
            "sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
            "text": text}


@dataclass(frozen=True)
class AttestedPolicy:
    """The result of a successful load_attested_policy_bundle() call — everything a
    caller needs about the run's init-time policy, read and validated exactly once.

      data              {} for an authenticated no-policy run, else the validated policy dict.
      sha256            policy.snapshot.json's recorded sha256, or None when there is no
                         snapshot (a no-policy run, whether attested or not).
      raw               policy.snapshot.json's exact bytes, as read ONCE by this call.
                         Pass this to verify_policy_snapshot_signature's snap_bytes= so the
                         signature is checked over the SAME bytes that were content-
                         validated here, never a second, independently re-read copy (the
                         TOCTOU this closes). None when there is no snapshot.
      absence_raw       policy.absence.json's exact bytes, as read ONCE by this call —
                         the content-validated (but, under require_signature=False, NOT
                         yet signature-checked) "this run explicitly found no policy at
                         init" claim. Mirrors `raw` exactly: pass this to
                         verify_policy_absence_signature's absence_bytes= so the
                         signature is checked over the SAME bytes that were content-
                         validated here. None when there is no absence attestation (either
                         a snapshot governed the run, or neither file exists).
      run_meta          run.json's already-parsed dict, so callers needing e.g. meta['risk']
                         never re-read run.json themselves."""
    data: dict
    sha256: "str | None"
    raw: "bytes | None"
    absence_raw: "bytes | None"
    run_meta: dict


def read_run_risk(run):
    """The risk tier ALONE, from a single TOCTOU-safe read of run.json — deliberately
    does NOT touch policy.snapshot.json at all, unlike load_attested_policy_bundle.

    Checklist item 5 (frontier-gate run pr70-trust-model2, 2026-09-22, Finding #11):
    gate.py cmd_plan's ordinary, no-waiver path used to read run.json["risk"] via a
    second, independent `read_json()` call — an uncontrolled second read of the same
    file load_attested_policy_bundle also reads, and a bare dict subscript that raised
    an uncaught KeyError if "risk" were ever missing. This gives that path the same
    single-read discipline load_attested_policy_bundle uses for run.json, WITHOUT also
    coupling ordinary gate planning to whether a policy snapshot happens to be present
    or valid — deliberately kept separate from load_attested_policy_bundle (rather than
    calling it with require_signature=False and discarding the rest) specifically so a
    corrupt/tampered policy.snapshot.json cannot block the no-waiver path, which must
    stay exactly as infrastructure-free as it always has been; only a run that actually
    goes on to record a waiver or NOT_APPLICABLE gate needs the full bundle (and does,
    via its own load_attested_policy_bundle call further down cmd_plan).

    Returns (risk_str, None) on success, (None, error_message) on any failure — never
    raises."""
    run = Path(run)
    try:
        runjson_bytes = read_regular_file_once(run / "run.json")
    except (ValueError, OSError) as e:
        return None, f"run.json is unreadable ({e})"
    try:
        runjson = json.loads(runjson_bytes.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as e:
        return None, f"run.json is not valid JSON/UTF-8 ({e})"
    if not isinstance(runjson, dict):
        return None, "run.json is not a JSON object"
    risk = runjson.get("risk")
    if not isinstance(risk, str) or not risk:
        return None, "run.json has no valid risk tier recorded"
    return risk, None


def load_attested_policy_bundle(run, *, require_signature):
    """The single, TOCTOU-safe way to learn what policy governed a run at init — replaces
    the old load_attested_policy() as the primitive every caller should reach for going
    forward (frontier-gate run pr70-design, 2026-09-21, checklist items 3/7/8; Fable's
    TOCTOU design §2, adopted, extended here with the GAP-A-closing require_signature
    contract).

    Reads run.json and (if present) policy.snapshot.json EXACTLY ONCE EACH, via
    read_regular_file_once(), and returns an AttestedPolicy carrying the raw bytes
    alongside the validated data — so a caller that also needs the cryptographic
    signature checked (this function does that itself when require_signature=True; see
    below) never triggers a second, independent read of the same path that an attacker
    with write access to the run directory could have swapped in between two reads.

    require_signature=False — content-only; matches the pre-fix load_attested_policy()
    contract exactly (see the back-compat shim below). Validates policy.snapshot.json's
    content (sha256, schema) but does NOT invoke an external verifier — works without
    cosign/minisign installed, for read-only inspection tooling that has nothing to sign
    or waive. A run with no snapshot and no policy recorded at init returns the
    unauthenticated {} fallback, exactly as before.

    require_signature=True — every caller that is about to accept a WAIVED or
    NOT_APPLICABLE gate (gate.py cmd_plan/cmd_record, aggregate.py's verdict path) must
    use this. Beyond the content checks above, this ALSO verifies the cryptographic
    signature (over the identical already-read bytes — see verify_policy_snapshot_
    signature's snap_bytes= contract) before returning success. This is the GAP-A fix:
    previously, a run with NO policy.snapshot.json at all silently fell through to an
    UNAUTHENTICATED ({}, None) "no restrictions" pass — file absence itself was never an
    authenticated claim, so an attacker (or a broken pipeline) that simply deleted or
    never wrote the snapshot got the same free pass as a genuinely policy-free run. Under
    require_signature=True that same no-file case is now BLOCKED, not passed:
    policy.absence.json is the signed escape hatch a genuinely no-policy run uses to
    still pass this check — see the "not snap_p.is_file()" branch below and
    policy_absence_attest_bytes / verify_policy_absence_signature.

    Returns (AttestedPolicy, None) on success, (None, error_message) on any failure —
    never raises; every failure mode is a caller-facing BLOCKED-reason string."""
    run = Path(run)
    try:
        runjson_bytes = read_regular_file_once(run / "run.json")
    except (ValueError, OSError) as e:
        return None, f"run.json is unreadable — cannot determine the attested policy; run BLOCKED ({e})"
    try:
        # RecursionError included alongside ValueError/UnicodeDecodeError: a JSON decoder
        # is a recursive-descent parser, so a file inside the size cap but nested tens of
        # thousands of levels deep (e.g. "[[[[...]]]]" at ~2 bytes/level, far under
        # _MAX_RUN_FILE_BYTES) exceeds Python's recursion limit -- not a syntax error, so
        # ValueError alone does not catch it. Left uncaught, this function's own
        # docstring promise ("never raises; every failure mode is a caller-facing
        # BLOCKED-reason string") would be broken by a crash instead of a controlled
        # BLOCKED verdict (Codex 4089779557, P2, reported against the sibling
        # policy.absence.json parse just below -- this file is read by the same
        # function under the same "never raises" contract, so it gets the same guard).
        runjson = json.loads(runjson_bytes.decode("utf-8"))
    except (ValueError, UnicodeDecodeError, RecursionError) as e:
        return None, (f"run.json is not valid JSON/UTF-8 — cannot determine the attested "
                      f"policy; run BLOCKED ({e})")
    if not isinstance(runjson, dict):
        return None, "run.json is not a JSON object — cannot determine the attested policy; run BLOCKED"
    init_pol = runjson.get("policy")
    init_sha = init_pol.get("sha256") if isinstance(init_pol, dict) else None
    snap_p = run / "policy.snapshot.json"

    if not snap_p.is_file():
        if init_sha:
            # A policy governed the run at init but its attested snapshot is gone — falling
            # back to built-in defaults could accept a waiver the attested policy would
            # have rejected.
            return None, ("run.json records a policy at init but policy.snapshot.json is "
                          "missing — the attested policy cannot be recovered; run BLOCKED")
        # No policy governed this run at init. Before falling through to the verifier-
        # availability gate below, check for GAP A's signed escape hatch: a
        # policy.absence.json that explicitly attests "init looked for a policy and found
        # none." Content-validated here exactly once (mirrors the snapshot's own
        # read-once-via-read_regular_file_once discipline below); the signature itself is
        # only checked when require_signature=True, exactly like the snapshot path, so a
        # require_signature=False content-only caller never needs a verifier installed
        # just to see that an absence claim exists.
        absence_p = run / POLICY_ABSENCE_FILENAME
        if absence_p.is_file():
            try:
                absence_raw = read_regular_file_once(absence_p)
            except (ValueError, OSError) as e:
                return None, f"policy.absence.json is unreadable/corrupt: {e}"
            try:
                # Codex 4089779557 (P2, valid): a policy.absence.json nested tens of
                # thousands of levels deep (e.g. "[[[[...]]]]", well under the 16 MiB
                # read_regular_file_once cap at ~2 bytes/level) exceeds Python's json
                # decoder's recursion limit -- RecursionError, not a ValueError this
                # except clause already caught -- and would otherwise propagate past
                # aggregate.py's normal BLOCKED-verdict path and crash the run (exit 3,
                # no verdict.json written) instead of failing closed the way every other
                # malformed-input case in this function does.
                absence_data = json.loads(absence_raw.decode("utf-8"))
            except (ValueError, UnicodeDecodeError, RecursionError) as e:
                return None, f"policy.absence.json is not valid JSON/UTF-8: {e}"
            if not isinstance(absence_data, dict) or absence_data.get("policy_absent") is not True:
                return None, ("policy.absence.json is malformed (missing "
                              "'policy_absent: true') — cannot trust this run's no-policy "
                              "claim; run BLOCKED")
            if require_signature:
                sig_err = verify_policy_absence_signature(run, runjson, absence_bytes=absence_raw)
                if sig_err:
                    return None, f"policy.absence.json is not verifiably signed: {sig_err}"
            return AttestedPolicy({}, None, None, absence_raw, runjson), None
        if require_signature:
            # Checklist item 19's explicit alternative ("always-on when signer/verifier
            # configured", frontier-gate run pr70-design, 2026-09-21): whether "no policy
            # artifact at all" BLOCKS here is driven by whether a VERIFIER resolves in
            # THIS (the verifying) process's own environment — never by anything read
            # from the run directory itself, which is exactly what an attacker with
            # write access to it could forge to look like "no signer was ever
            # configured." A repo that has never configured any verification at all
            # keeps the original, documented, infrastructure-free exemption (matches
            # Option B's original scope, Paul's decision, frontier-gate run
            # pr70-provenance, 2026-09-19) — there is no cryptographic mechanism to
            # enforce this policy without one, so nothing is lost by staying exempt. A
            # repo that HAS configured verification, though, can no longer be fooled by
            # simple file absence: if this run predates the signed-init fix, or its own
            # init never configured a signer while THIS environment nonetheless expects
            # one, that is exactly the ambiguity GAP A closes — re-init under a
            # configured signer to get a verifiable run.
            # A malformed AR_VERIFIER_CMD counts as "a verifier IS configured here" for
            # this decision, not as "none configured" (fail OPEN into the infra-free
            # exemption would be worse than fail-closed: an operator who clearly
            # intended verification, but typo'd the command, must not silently lose
            # protection). Codex r4055706494 (P2) — resolve_signing_tool no longer
            # exits the process on a malformed override from this non-fatal call, so
            # this BLOCK path is what reports the misconfiguration instead of a crash.
            #
            # Checklist item 1 (frontier-gate run pr70-item6-scope, 2026-09-23): ALSO
            # block when this repository's own out-of-band AR_SIGNING_REQUIRED anchor
            # says signing is mandatory, even if no verifier happens to resolve in this
            # particular environment right now (e.g. cosign was uninstalled, or
            # AR_VERIFIER_CMD was stripped from the job env by a same-repo PR editing
            # the workflow file) — see _signing_required_anchor()'s docstring for why
            # this closes the downgrade-to-exempt gap the frontier panel flagged.
            verifier_here = _verifier_configured_here()
            signing_required = _signing_required_anchor()
            if verifier_here or signing_required:
                resolve_err = None
                if verifier_here:
                    _argv_tmpl, _kind, resolve_err = resolve_signing_tool(
                        "AR_VERIFIER_CMD",
                        [("cosign-keyless", cosign_verify_argv), ("minisign", minisign_verify_argv)],
                        fatal=False)
                    # Codex 4089779550 (P2): the partial-keyless-identity signal has no
                    # resolve_err of its own (see _cosign_keyless_partially_configured) --
                    # name it explicitly here so the BLOCKED message is actionable rather
                    # than a generic "a verifier IS configured here" for a run where no
                    # verifier tool actually resolved.
                    if resolve_err is None and _cosign_keyless_partially_configured():
                        resolve_err = ("AR_ALLOW_KEYLESS is set and cosign is on PATH, "
                                       "but only one of AR_COSIGN_IDENTITY/"
                                       "AR_COSIGN_ISSUER is set -- cosign verify-blob "
                                       "requires both, or neither (to auto-derive); set "
                                       "the missing one or unset both")
                detail = f" ({resolve_err})" if resolve_err else ""
                reason = ("a verifier IS configured here" if verifier_here
                          else "AR_SIGNING_REQUIRED is set for this repository")
                return None, ("no policy.snapshot.json and no signed no-policy "
                              f"attestation for this run, but {reason} and a signature "
                              "is required to accept a waiver or NOT_APPLICABLE gate — "
                              "this run predates the signed-init fix, or no signer was "
                              "configured at its own init; re-init this run under a "
                              "configured signer (AR_TRUSTED_SIGNER=1 plus "
                              f"AR_SIGNER_CMD / cosign / minisign){detail}")
        return AttestedPolicy({}, None, None, None, runjson), None

    try:
        raw = read_regular_file_once(snap_p)
    except (ValueError, OSError) as e:
        return None, f"policy.snapshot.json is unreadable/corrupt: {e}"
    try:
        # Same RecursionError gap as run.json/policy.absence.json above (Codex
        # 4089779557) -- this is the third of load_attested_policy_bundle's three
        # untrusted-file JSON parses, under the same "never raises" contract.
        snap = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError, RecursionError) as e:
        return None, f"policy.snapshot.json is not valid JSON/UTF-8: {e}"
    if not isinstance(snap, dict):
        return None, "policy.snapshot.json is not a JSON object"
    text = snap.get("text")
    sha = snap.get("sha256", "")
    fname = snap.get("file", "")
    if not isinstance(fname, str):
        return None, "policy.snapshot.json 'file' field is not a string"
    if not isinstance(text, str):
        return None, "policy.snapshot.json has no captured policy text"
    # A syntactically valid JSON string can still contain an unpaired UTF-16 surrogate
    # (e.g. an escaped "\ud800" with no matching low surrogate) — json.loads() accepts
    # it, but .encode("utf-8") raises UnicodeEncodeError. Without this guard that
    # exception would propagate past aggregate.py's normal BLOCKED-verdict path and crash
    # the run instead of failing closed (Codex, PR70 review, frontier-gate run
    # pr70-provenance-2). Treat it exactly like any other corrupt snapshot: BLOCK, never
    # crash.
    try:
        text_sha = hashlib.sha256(text.encode("utf-8")).hexdigest()
    except UnicodeEncodeError as e:
        return None, f"policy.snapshot.json text is not valid UTF-8 ({e}) — corrupt/tampered"
    if text_sha != sha:
        return None, "policy.snapshot.json text does not match its recorded sha256 — tampered"
    # The snapshot's OWN sha256 is not tamper-proof (an attacker can rewrite text AND sha
    # together). Cross-check it against the digest recorded in run.json at init — the
    # authoritative init-time provenance — and BLOCK if the snapshot was swapped wholesale.
    # (A run.json edit too is caught by the run's attestation digest / signature layer.)
    if init_sha != sha:
        return None, ("policy.snapshot.json sha256 does not match the policy digest recorded in "
                      "run.json at init — the snapshot was replaced")
    try:
        # Fourth and last of this function's untrusted-file JSON parses (Codex
        # 4089779557) -- the captured policy TEXT itself, when fname is a .json file.
        data = (json.loads(text) if fname.endswith(".json")
                else _parse_policy_yaml(text, "policy.snapshot.json"))
        _validate_policy(data, "policy.snapshot.json")
    except (ValueError, SystemExit, RecursionError):
        return None, "policy.snapshot.json failed to parse/validate against the current schema"
    if not isinstance(data, dict):
        return None, "policy.snapshot.json did not parse to a mapping"

    if require_signature:
        sig_err = verify_policy_snapshot_signature(run, runjson, snap_bytes=raw)
        if sig_err:
            return None, f"attested policy snapshot is not verifiably signed: {sig_err}"

    return AttestedPolicy(data, sha, raw, None, runjson), None


def load_attested_policy(run):
    """Back-compat shim over load_attested_policy_bundle(require_signature=False) — the
    exact (pol_data, error) two-tuple shape every pre-TOCTOU-fix caller and test already
    expects (({}, None) / (data, None) / (None, msg), same as before). New code that is
    about to accept a waiver or NOT_APPLICABLE gate should call
    load_attested_policy_bundle(run, require_signature=True) directly instead, both for
    the stronger authenticated-absence guarantee and to get the bundle's `raw` bytes for
    signature reuse rather than triggering a second read."""
    bundle, err = load_attested_policy_bundle(run, require_signature=False)
    if err:
        return None, err
    return bundle.data, None


# Checklist item 7 (frontier-gate run pr70-item6-scope, 2026-09-23): two distinct
# stamps, never conflated. UNSIGNED EXEMPT means "nothing to check, self-reported tier
# stands, non-blocking" (the pre-existing infrastructure-free exemption). UNAUTHENTICATED
# means "signing was expected here and could not be verified — CRITICAL, unwaivable,
# BLOCKED" (the literal item-6 fallback, now correctly scoped — see
# authenticate_risk_tier's docstring for what "expected here" means).
RISK_LABEL_UNSIGNED_EXEMPT = "RISK TIER UNSIGNED EXEMPT"
RISK_LABEL_UNAUTHENTICATED = "RISK TIER UNAUTHENTICATED"

AUTH_STATUS_AUTHENTICATED = "AUTHENTICATED"
AUTH_STATUS_UNSIGNED_EXEMPT = "UNSIGNED_EXEMPT"
AUTH_STATUS_UNAUTHENTICATED = "UNAUTHENTICATED"


@dataclass(frozen=True)
class AuthResult:
    """authenticate_risk_tier()'s return value.

      status  one of AUTH_STATUS_AUTHENTICATED / AUTH_STATUS_UNSIGNED_EXEMPT /
              AUTH_STATUS_UNAUTHENTICATED.
      risk    the risk tier callers should actually use. Authoritative
              (cryptographically-backed) for AUTHENTICATED; self-reported for
              UNSIGNED_EXEMPT; "CRITICAL" for UNAUTHENTICATED when signing genuinely was
              expected and failed — callers must never fall back to a self-reported
              value in that case. None for UNAUTHENTICATED specifically when run.json's
              risk tier itself could not be determined at all (a data-integrity
              problem, not a signing event) and no crypto signal is available to fail
              closed to — callers must die()/BLOCK on risk is None exactly as they did
              before this function existed.
      label   the exact verdict stamp to record/print (RISK_LABEL_*), or None for
              AUTHENTICATED, which needs no stamp.
      detail  plain-English explanation. For UNAUTHENTICATED this includes a recovery
              instruction (checklist item 6) — how to re-sign/rotate keys/re-init under
              a configured signer to clear the block.
      bundle  the AttestedPolicy on AUTHENTICATED, else None."""
    status: str
    risk: "str | None"
    label: "str | None"
    detail: str
    bundle: "AttestedPolicy | None"


def _unauthenticated_recovery_detail(att_err):
    """Wraps a load_attested_policy_bundle failure with a plain-English, actionable
    recovery instruction (checklist item 6) — the raw error already says what failed;
    this adds what to DO about it, matching the "re-init this run under a configured
    signer" phrasing load_attested_policy_bundle itself already uses elsewhere in this
    module for consistency."""
    return (f"{att_err}. To clear this: re-run this repository's init step "
            "(panel.py init) under a working, correctly-configured signer "
            "(AR_TRUSTED_SIGNER=1 plus AR_SIGNER_CMD, or cosign with AR_ALLOW_KEYLESS=1 "
            "and AR_COSIGN_IDENTITY/AR_COSIGN_ISSUER pinned, or minisign) so this run "
            "produces a freshly signed policy.snapshot.json or policy.absence.json — "
            "see docs/THREAT-MODEL.md.")


def authenticate_risk_tier(run):
    """The single entry point gate.py and aggregate.py both call to learn (a) whether
    this run's risk tier can be trusted, and (b) what tier to actually use for gate
    planning and the final verdict.

    Checklist items 1-5/13 (frontier-gate run pr70-item6-scope, 2026-09-23, refined
    Option A / scope_down_never_break_unsigned, panel consensus 0.97): this is the
    narrowed, non-breaking form of the original trust-model panel's item 6
    ("unauthenticated risk tier defaults to CRITICAL, mutation waivers disabled"). The
    original wording would CRITICAL-default every repository with no signing
    infrastructure configured at all — as of 2026-09-22, 0 of 40 repositories across
    Paul's two GitHub accounts, including the confirmed production consumer `viaid` —
    which would permanently block them all on CRITICAL's unwaivable `mutation` gate
    (M4, real CRITICAL-tier mutation testing, is not yet built). This function instead
    only escalates to CRITICAL when signing was actually EXPECTED for this repository:
    a verifier resolves in this environment (_verifier_configured_here — the
    pre-existing GAP-A signal), or the repository's own out-of-band AR_SIGNING_REQUIRED
    anchor says so (_signing_required_anchor — the checklist item 1 addition that
    closes the downgrade-to-exempt gap the panel's own reviewers flagged: an attacker
    who can strip a verifier out of the job env must not be able to make a signed
    repository look exactly like one that was never signed) -- AND signing was actually
    POSSIBLE for this specific run (_pr_author_controlled_trigger being false).

    CodeRabbit r4082557512 (Major, valid, "Do not force unsigned pull_request runs to
    CRITICAL"): panel.py init already refuses to sign under a PR/MR-author-controlled
    trigger (trusted_signer_guard_error) -- there is no production hand-off mechanism
    yet for a separate trusted job to sign on behalf of a PR-triggered run's own
    directory (see docs/THREAT-MODEL.md's open items). Forcing CRITICAL on every such
    run regardless would close no actual gap -- that job can never produce the
    signature being demanded, no matter how it's configured -- while permanently
    blocking PR-gating CI for any repository whose runner happens to have a verifier
    binary on PATH or that sets AR_SIGNING_REQUIRED. That is exactly the silent,
    undisclosed breaking change Option A exists to avoid, just relocated from "any
    unsigned repo" to "any PR-triggered run of a repo with a verifier available." A
    WAIVED or NOT_APPLICABLE gate on a PR-triggered run is still independently required
    to carry a valid signature by the separate, pre-existing GAP-A check further down
    aggregate.py -- unaffected by this exemption, which only concerns the unconditional,
    no-waiver-required check this function performs.

    A repository where NONE of the three signals is present -- no verifier resolves, no
    AR_SIGNING_REQUIRED anchor, or (regardless of the other two) this run's own trigger
    could never have signed in the first place -- takes a fast, infrastructure-free path
    that never calls load_attested_policy_bundle(require_signature=True) at all — this
    is deliberate, not an optimization: calling that with require_signature=True would
    re-coathe the ordinary no-signing path to policy.snapshot.json's content validity,
    exactly the regression Finding #11's read_run_risk() fix (frontier-gate run
    pr70-trust-model2, 2026-09-22) was written to avoid. A repository with a stray or
    corrupt policy.snapshot.json left over from an unrelated experiment, but no
    verifier configured and no AR_SIGNING_REQUIRED anchor, must stay exactly as
    infrastructure-free as it always has been.

    Returns an AuthResult (see its own docstring). Never raises."""
    self_risk, self_err = read_run_risk(run)
    pr_triggered = _pr_author_controlled_trigger()
    if pr_triggered or not (_verifier_configured_here() or _signing_required_anchor()):
        # Fast, infrastructure-free path — see the docstring above for why this must
        # not touch load_attested_policy_bundle(require_signature=True) at all.
        #
        # A missing/corrupt risk tier here is a plain data-integrity problem (run.json
        # itself is broken), not a signing-authentication event — there is no crypto
        # signal available on this path to fail closed TO, so risk is None (distinct
        # from the "CRITICAL" this function returns when signing genuinely was expected
        # and failed below): callers must die()/BLOCK on risk is None exactly as they
        # did before this function existed, rather than silently treating "we don't
        # know the tier" the same as "we know it must be the strictest tier."
        if self_err:
            return AuthResult(AUTH_STATUS_UNAUTHENTICATED, None,
                               RISK_LABEL_UNAUTHENTICATED,
                               f"cannot determine risk tier for this run: {self_err}",
                               None)
        if pr_triggered:
            detail = ("this run's own trigger is PR/MR-author-controlled "
                      "(GITHUB_EVENT_NAME=pull_request or GitLab's "
                      "merge_request_event) — panel.py init refuses to sign under "
                      "such triggers by design (trusted_signer_guard_error), and no "
                      "hand-off exists yet for a separate trusted job to sign on this "
                      "run's behalf, so this run is exempt from the signing-expected "
                      "escalation even if a verifier resolves or AR_SIGNING_REQUIRED "
                      "is set for this repository; risk tier is self-reported. A "
                      "WAIVED or NOT_APPLICABLE gate on this run still independently "
                      "requires a valid signature (see docs/THREAT-MODEL.md)")
        else:
            detail = ("no signing infrastructure is configured for this "
                      "repository (no verifier resolves here, and "
                      "AR_SIGNING_REQUIRED is not set) — risk tier is "
                      "self-reported under the infrastructure-free exemption "
                      "(see docs/THREAT-MODEL.md)")
        return AuthResult(AUTH_STATUS_UNSIGNED_EXEMPT, self_risk,
                           RISK_LABEL_UNSIGNED_EXEMPT, detail, None)
    # Signing IS expected here — demand full cryptographic authentication. This is the
    # existing require_signature=True failure branch (checklist item 13): the anchor
    # check above only widens WHEN this branch is reached, never what happens inside it.
    bundle, att_err = load_attested_policy_bundle(run, require_signature=True)
    if att_err:
        return AuthResult(AUTH_STATUS_UNAUTHENTICATED, "CRITICAL",
                           RISK_LABEL_UNAUTHENTICATED,
                           _unauthenticated_recovery_detail(att_err), None)
    b_risk = bundle.run_meta.get("risk")
    if not b_risk:
        return AuthResult(AUTH_STATUS_UNAUTHENTICATED, "CRITICAL",
                           RISK_LABEL_UNAUTHENTICATED,
                           _unauthenticated_recovery_detail(
                               "run.json has no risk tier recorded even though "
                               "signing is expected for this repository"),
                           bundle)
    if self_err or b_risk != self_risk:
        return AuthResult(AUTH_STATUS_UNAUTHENTICATED, "CRITICAL",
                           RISK_LABEL_UNAUTHENTICATED,
                           _unauthenticated_recovery_detail(
                               "risk tier is not internally consistent between two "
                               f"reads of run.json ({b_risk!r} vs {self_risk!r}) — "
                               "possible tampering or a concurrent write"),
                           bundle)
    return AuthResult(AUTH_STATUS_AUTHENTICATED, b_risk, None,
                       "risk tier is cryptographically authenticated", bundle)


def resolve_setting(cli_value, env_var, pol, key, default=None):
    """One value through the precedence chain: CLI flag > env var > policy file >
    built-in default. Returns (value, source); (None, 'unset') when nothing
    provides one — callers decide whether that is fatal. An empty env var
    counts as unset."""
    if cli_value not in (None, ""):
        return cli_value, "cli"
    env_val = os.environ.get(env_var, "")
    if env_val != "":
        return env_val, "env"
    if pol is not None and key in pol["data"]:
        return pol["data"][key], "policy"
    if default is not None:
        return default, "default"
    return None, "unset"


# --- Model capability profiles (E0-S2) ---------------------------------------------
# A per-model profile governs how a request is shaped. Catalog-derived defaults (from
# `supported_parameters`) merge with an optional repo file
# `.adversarial-review.capabilities.yml`/`.json` and an `AR_CAP_OVERRIDES` env path, so
# quirks the catalog can't express (temperature-forbidden, mandatory reasoning, a
# min-token floor) are declared once and recorded. Precedence: catalog < file < env.
# NOTE: this only resolves the profile; wiring it into request-building is a later story.
CAP_BASENAMES = (".adversarial-review.capabilities.yml", ".adversarial-review.capabilities.json")
CAP_KEYS = ("temperature", "structured_outputs", "reasoning", "max_tokens_floor",
            "latency_class", "notes")
CAP_ENUMS = {"temperature": ("supported", "forbidden", "default"),
             "reasoning": ("none", "optional", "mandatory"),
             "latency_class": ("fast", "slow")}


def capability_defaults(catalog_entry):
    """Per-model capability profile derived from the live catalog entry alone."""
    sp = (catalog_entry or {}).get("supported_parameters") or []
    return {"temperature": "supported" if "temperature" in sp else "default",
            "structured_outputs": "structured_outputs" in sp,
            "reasoning": "none", "max_tokens_floor": None,
            "latency_class": None, "notes": ""}


def _cap_bool(v):
    if isinstance(v, bool):
        return v
    if isinstance(v, str) and v.strip().lower() in ("true", "false"):
        return v.strip().lower() == "true"
    return None


def _cap_pos_int(v):
    if isinstance(v, bool):
        return None
    if isinstance(v, int):
        return v if v > 0 else None
    if isinstance(v, str) and v.strip().isdigit():
        n = int(v.strip())
        return n if n > 0 else None
    return None


def _validate_cap_block(slug, block, name):
    if not isinstance(block, dict):
        die(f"{name}: capabilities['{slug}'] must be a mapping of capability settings")
    unknown = sorted(set(block) - set(CAP_KEYS))
    if unknown:
        die(f"{name}: capabilities['{slug}'] has unknown keys {unknown} "
            f"(allowed: {', '.join(CAP_KEYS)})")
    out = {}
    for k, allowed in CAP_ENUMS.items():
        if k in block:
            v = block[k]
            # latency_class is nullable (its catalog default is None); an explicit
            # null resets it rather than tripping the enum check below.
            if k == "latency_class" and v in (None, "", "null"):
                out[k] = None
                continue
            if v not in allowed:
                die(f"{name}: capabilities['{slug}'].{k}={v!r} not in {list(allowed)}")
            out[k] = v
    if "structured_outputs" in block:
        b = _cap_bool(block["structured_outputs"])
        if b is None:
            die(f"{name}: capabilities['{slug}'].structured_outputs must be true/false")
        out["structured_outputs"] = b
    if "max_tokens_floor" in block:
        # An explicit null resets the floor (its catalog default is None); any other
        # value must be a positive integer.
        if block["max_tokens_floor"] in (None, "", "null"):
            out["max_tokens_floor"] = None
        else:
            n = _cap_pos_int(block["max_tokens_floor"])
            if n is None:
                die(f"{name}: capabilities['{slug}'].max_tokens_floor must be a positive integer")
            out["max_tokens_floor"] = n
    if "notes" in block:
        out["notes"] = str(block["notes"])
    return out


def _load_cap_file(path):
    p = Path(path)
    text = p.read_text(encoding="utf-8")
    if p.suffix == ".json":
        try:
            data = json.loads(text)
        except ValueError as e:
            die(f"{p.name}: invalid JSON: {e}")
    else:
        data = _parse_policy_yaml(text, p.name)
    if not isinstance(data, dict):
        die(f"{p.name}: top level must be a mapping of model-slug -> capability settings")
    out = {}
    for slug, block in data.items():
        if not isinstance(slug, str) or "/" not in slug:
            die(f"{p.name}: capability key must be a provider/model-slug, got {slug!r}")
        out[slug] = _validate_cap_block(slug, block, p.name)
    return out


def load_capabilities(root=None):
    """Merged capability overrides {model_slug: {...}} from the repo file and the
    AR_CAP_OVERRIDES env path (env wins per key). Empty dict when neither is present.
    Malformed input dies loudly, exactly like the policy loader."""
    root = Path(root) if root else Path.cwd()
    found = [root / n for n in CAP_BASENAMES if (root / n).is_file()]
    if len(found) > 1:
        die(f"both {' and '.join(CAP_BASENAMES)} exist — keep exactly one")
    overrides = _load_cap_file(found[0]) if found else {}
    env_path = os.environ.get("AR_CAP_OVERRIDES", "")
    if env_path:
        if not Path(env_path).is_file():
            die(f"AR_CAP_OVERRIDES points to a missing file: {env_path}")
        for slug, block in _load_cap_file(env_path).items():
            overrides.setdefault(slug, {}).update(block)  # env wins per key
    return overrides


def capability_of(model_slug, catalog_entry, overrides=None):
    """Effective profile for a model: catalog defaults with file/env overrides applied.
    Returns (profile, source) where source is 'catalog' (no override) or 'override'."""
    prof = capability_defaults(catalog_entry)
    ov = (overrides or {}).get(model_slug)
    if not ov:
        return prof, "catalog"
    prof.update(ov)
    return prof, "override"
