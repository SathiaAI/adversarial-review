"""Shared helpers for adversarial-review scripts. Stdlib only, by design."""
import hashlib
import json
import math
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
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


def read_json(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def write_json(path, obj):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, ensure_ascii=False)
        f.write("\n")


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


POLICY_ATTEST_VERSION = "2"

def policy_attest_bytes(run_id, run_nonce, run_name, risk, snap_path,
                         version=POLICY_ATTEST_VERSION):
    """The exact bytes signed/verified for the policy-snapshot signature.

    v2 (current) binds: version tag, run_id, run_nonce, run_name (the run directory's
    OWN basename), risk (the resolved tier from run.json), then policy.snapshot.json's
    raw bytes. v1 (superseded, see verify_policy_snapshot_signature) bound only run_id +
    run_nonce + snapshot bytes and had two gaps a delayed Codex review on PR70 found and
    reproduced:

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
    return (b"ar-policy-attest-v" + str(version).encode("ascii") + b"\n"
            + run_id.encode("utf-8") + b"\n" + run_nonce.encode("utf-8") + b"\n"
            + str(run_name).encode("utf-8") + b"\n" + str(risk).encode("utf-8") + b"\n"
            + Path(snap_path).read_bytes())


def verify_policy_snapshot_signature(run, snap_p, meta):
    """PR70 provenance-binding fix (Option B / require_signing_for_exceptions_only —
    Paul's decision, frontier-gate run pr70-provenance, 2026-09-19; hardened against 3
    further P1 findings from a delayed Codex review, frontier-gate run
    pr70-provenance-2, 2026-09-19 — Paul chose fix_all_six_now).

    Shared by aggregate.py (verifying at aggregate time) and gate.py (verifying at plan/
    record time, so `plan`/`record` can never report success on a waiver `aggregate`
    will later BLOCK as unsigned or invalid — see gate.py's cmd_plan/cmd_record).

    `run` is the run's resolved directory (a real Path — see resolve_run), `snap_p` is
    policy.snapshot.json's path, and `meta` is run.json's already-parsed dict. Checks, in
    order, ALL fail-closed (return a short BLOCKED-reason string; never raise or exit):

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
         meta['risk'], snap_p) — the v2 payload, which additionally binds run_name (so a
         signature is unusable outside the exact run directory it was made for, per #1)
         and risk (so downgrading run.json's risk tier post-init no longer leaves a
         waiver's governing signature intact — the second Codex P1: risk was previously
         unsigned, so a CRITICAL run whose waivers should be blocked could be relabeled
         SENSITIVE after signing and pass).

    A v1-format signature (from a run initialized before this fix) cannot verify against
    the v2 payload — this is intentional fail-closed behavior, not a bug: the BLOCKED
    reason it produces (an ordinary "signature did not verify") tells the operator to
    re-init, exactly like any other invalid signature. There is no real deployment with
    v1 signatures yet (no repo's CI currently configures AR_SIGNER_CMD), so no migration
    path is needed; if that ever changes, bump POLICY_ATTEST_VERSION again and extend
    this function to recognize the version tag it can no longer verify, the same pattern
    aggregate.py's _ATTESTATION_ALGO/_LEGACY_ALGOS already use for the run's overall
    attestation digest.

    Scope: callers only invoke this when the run contains a WAIVED or NOT_APPLICABLE gate
    record — the common no-exception path stays completely infrastructure-free."""
    run_id = meta.get("run_id")
    run_nonce = meta.get("run_nonce")
    risk = meta.get("risk")
    run_name = Path(run).name
    if not isinstance(run_id, str) or not run_id:
        return "run.json has no run_id — cannot verify the policy-snapshot signature"
    if run_name != run_id:
        return (f"run directory name ({run_name!r}) does not match run.json's run_id "
                f"({run_id!r}) — this run.json does not describe the run being "
                "verified (possible copy from another run); re-init to get a "
                "signable, verifiable snapshot")
    if not isinstance(run_nonce, str) or not run_nonce:
        return ("run.json has no run_nonce — the policy-snapshot signature cannot be "
                "verified without it (this run predates the nonce fix, or run.json was "
                "tampered with); re-init this run to get a signable, verifiable snapshot")
    if not isinstance(risk, str) or not risk:
        return "run.json has no risk tier — cannot verify the policy-snapshot signature"
    sig_p = Path(run) / POLICY_SIG_FILENAME
    if not sig_p.is_file():
        return (f"no {POLICY_SIG_FILENAME} — the policy snapshot was not signed at init. "
                "Configure a signer (AR_SIGNER_CMD, or install cosign / minisign with "
                "AR_MINISIGN_KEY) before `panel.py init` so any run that later records a "
                "waiver or not-applicable gate can be trusted")
    argv_tmpl, kind = resolve_signing_tool(
        "AR_VERIFIER_CMD",
        [("cosign-keyless", cosign_verify_argv), ("minisign", minisign_verify_argv)])
    if argv_tmpl is None:
        return ("no verifier available: set AR_VERIFIER_CMD, or install cosign (with "
                "AR_COSIGN_IDENTITY/AR_COSIGN_ISSUER pinned) or minisign (with "
                "AR_MINISIGN_PUBKEY or AR_MINISIGN_PUBKEY_FILE)")
    with tempfile.TemporaryDirectory() as td:
        msg_tmp = Path(td) / "policy.snapshot.attest"
        msg_tmp.write_bytes(policy_attest_bytes(run_id, run_nonce, run_name, risk, snap_p))
        proc, err = run_signing_tool(argv_tmpl, msg_tmp, sig_p, fatal=False)
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


def resolve_signing_tool(env_cmd, builders):
    """Resolve a signing/verifying command as an argv TEMPLATE carrying `{msg}`/`{sig}`
    tokens. Precedence: an explicit env override (`env_cmd`, e.g. AR_SIGNER_CMD) wins;
    otherwise the first auto-detected tool whose builder returns a non-None argv
    (cosign keyless primary, minisign fallback). Returns (argv, kind) or (None, None)
    when nothing resolves. The command is only ever executed via subprocess — nothing
    here imports the signer."""
    cmd = os.environ.get(env_cmd, "").strip()
    if cmd:
        try:
            return shlex.split(cmd), "custom"
        except ValueError as e:
            sign_fail(f"{env_cmd} is not a valid command template ({e}): {cmd!r}")
    for kind, build in builders:
        argv = build()
        if argv is not None:
            return argv, kind
    return None, None


def cosign_sign_argv():
    # Primary: sigstore/cosign KEYLESS. An ephemeral Fulcio certificate (from an ambient
    # OIDC identity) plus a Rekor transparency-log entry; no long-lived private key.
    # `--yes` suppresses the confirmation prompt; `--bundle` packs signature +
    # certificate + log proof into ONE self-contained sidecar an outside verifier
    # consumes with `verify-blob --bundle`.
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


def cosign_verify_argv():
    # Keyless verification is only meaningful against an expected signer identity +
    # issuer: `cosign verify-blob` WITHOUT --certificate-identity/--certificate-oidc-issuer
    # accepts ANY valid Fulcio certificate, so it must not be auto-selected as the
    # verifier unless BOTH are set. When they are missing we return None and fall
    # through (to minisign, or to a loud "no verifier available" naming
    # AR_COSIGN_IDENTITY/AR_COSIGN_ISSUER) rather than silently verifying against an
    # unconstrained identity (panel finding security-1).
    if not shutil.which("cosign"):
        return None
    ident = os.environ.get("AR_COSIGN_IDENTITY", "").strip()
    issuer = os.environ.get("AR_COSIGN_ISSUER", "").strip()
    if not (ident and issuer):
        return None
    return ["cosign", "verify-blob", "--bundle", "{sig}",
            "--certificate-identity", ident, "--certificate-oidc-issuer", issuer, "{msg}"]


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
    if strict_reason:
        err = validate_waiver_reason(reason)
        if err:
            return f"{kind} with an invalid reason: {err}"
    elif not (isinstance(reason, str) and reason.strip()):
        return f"{kind} requires a non-empty summary"
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


def load_attested_policy(run):
    """Return (pol_data, error) from the run's attested policy.snapshot.json — the exact
    policy text captured at init — NEVER the mutable working-tree policy, so a post-init edit
    cannot widen a waiver that is absent from the audit record (#3).

      ({}, None)     no policy at init (no snapshot) → strict built-in defaults apply.
      (data, None)   snapshot present, its text matches its recorded sha256, and it parses
                     and validates against the current schema.
      (None, msg)    snapshot present but unreadable, sha-mismatched (tampered), or no longer
                     valid — the caller must BLOCK (fail closed), never fall back to the
                     working tree."""
    # The init-time provenance: run.json.policy.sha256 records whether a policy governed the
    # run at init. Read it first so a DELETED snapshot can be told apart from 'no policy'.
    # Fail closed on unreadable/corrupt provenance — never treat it as 'no policy at init', or a
    # damaged run.json could silently widen a waiver from an attested limit to the default.
    try:
        runjson = read_json(Path(run) / "run.json")
    except (ValueError, OSError):
        return None, "run.json is unreadable — cannot determine the attested policy; run BLOCKED"
    if not isinstance(runjson, dict):
        return None, "run.json is not a JSON object — cannot determine the attested policy; run BLOCKED"
    init_pol = runjson.get("policy")
    init_sha = init_pol.get("sha256") if isinstance(init_pol, dict) else None
    snap_path = Path(run) / "policy.snapshot.json"
    if not snap_path.is_file():
        if init_sha:
            # A policy governed the run at init but its attested snapshot is gone — falling back
            # to built-in defaults could accept a waiver the attested policy would have rejected.
            return None, ("run.json records a policy at init but policy.snapshot.json is missing "
                          "— the attested policy cannot be recovered; run BLOCKED")
        return {}, None
    try:
        snap = read_json(snap_path)
    except (ValueError, OSError) as e:
        return None, f"policy.snapshot.json is unreadable/corrupt: {e}"
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
    # (e.g. an escaped "\ud800" with no matching low surrogate) — json.load() accepts it,
    # but .encode("utf-8") raises UnicodeEncodeError. Without this guard that exception
    # would propagate out of load_attested_policy(), past aggregate.py's normal BLOCKED-
    # verdict path, and crash the run instead of failing closed (Codex, PR70 review,
    # frontier-gate run pr70-provenance-2). Treat it exactly like any other corrupt
    # snapshot: BLOCK, never crash.
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
        data = json.loads(text) if fname.endswith(".json") else _parse_policy_yaml(
            text, "policy.snapshot.json")
        _validate_policy(data, "policy.snapshot.json")
    except (ValueError, SystemExit):
        return None, "policy.snapshot.json failed to parse/validate against the current schema"
    if not isinstance(data, dict):
        return None, "policy.snapshot.json did not parse to a mapping"
    return data, None


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
