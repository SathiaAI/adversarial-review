#!/usr/bin/env python3
"""Deterministic verdict for adversarial-review.

Computes PASS / FAIL / BLOCKED purely from recorded artifacts and writes verdict.json.
No model — including the one operating this pipeline — can emit a verdict; only this
script can, which is the point.

Exit codes: 0 PASS, 1 FAIL, 2 BLOCKED. The optional detached-signature path
(`--sign` / `--verify-signature`, E6-S1) reuses 0/1/2 for verify results and adds 3 for
a signer/verifier that is unavailable or fails to start — signing never changes the
verdict, only whether a separate signature sidecar is produced or checked.

  PASS    all tier-required gates recorded & passing; panel complete & independent;
          every high/critical finding validated with a compliant record.
  FAIL    a recorded gate failed, or a confirmed-unfixed / unresolved /
          improperly-accepted high/critical finding exists.
  BLOCKED required verification is missing: absent gates or gate plan, incomplete or
          non-independent panel, unvalidated findings, missing concurrence, expired
          suppressions, missing rebuttal at CRITICAL, unauthorized degraded mode.
"""
import argparse
import hashlib
import html
import json
import os
import shlex
import shutil
import subprocess
import sys
import tempfile
from datetime import date
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _common import family_of, meta_cost, now_iso, read_json, resolve_run, write_json

HIGH = ("critical", "high")


def load_reports(run, plan):
    reports = {}
    for role in plan.get("roles", {}):
        p = run / "panel" / f"{role}.json"
        if p.exists():
            reports[role] = read_json(p)
    return reports


def check_gates(run, tier, fail, blocked, notes):
    """Returns (results, gates_coverage). Coverage is derived from the same records
    the verdict uses — an unrecorded fact stays invisible in both."""
    gcov = {"plan_recorded": False, "required": [], "recorded": [], "passed": [],
            "failed": [], "blocked": [], "not_applicable": [], "missing": [],
            "waived": []}
    req_path = run / "gates" / "_required.json"
    if not req_path.exists():
        blocked.append("gate plan missing — run `gate.py plan` after detecting the stack")
        return {}, gcov
    gplan = read_json(req_path)
    gcov["plan_recorded"] = True
    gcov["required"] = list(gplan.get("required", []))
    for w in gplan.get("waived", []):
        gcov["waived"].append({"name": w.get("name"), "authorized_by": w.get("authorized_by")})
        if not w.get("authorized_by"):
            blocked.append(f"gate '{w['name']}' waived without an authorizer")
        else:
            notes.append(f"gate '{w['name']}' waived by {w['authorized_by']}")
    results = {}
    for name in gplan.get("required", []):
        p = run / "gates" / f"{name}.json"
        if not p.exists():
            gcov["missing"].append(name)
            blocked.append(f"required gate '{name}' has no recorded result")
            continue
        rec = read_json(p)
        results[name] = rec
        gcov["recorded"].append(name)
        # Tri-state: BLOCKED means the check could not be run/verified — unknown, not
        # pass and not fail. Absent status falls back to the exit code (older records).
        status = rec.get("status")
        if status == "BLOCKED":
            reason = rec.get("summary", "could not verify")
            gcov["blocked"].append({"name": name, "reason": reason})
            blocked.append(f"gate '{name}' blocked: {reason}")
        elif status == "NOT_APPLICABLE":
            # A gate that genuinely does not apply to this stack does NOT restrict the
            # verdict — but it is an accountable, on-record determination, so an N/A
            # without a named authorizer and a reason is itself a BLOCK (unaccountable
            # skips are exactly what this pipeline exists to prevent).
            # Guard against non-string values (JSON null, numbers, objects): a
            # `null` authorizer must read as absent, not as the string "None". Only a
            # non-empty *string* counts as accountable.
            who = rec.get("authorized_by")
            reason = rec.get("summary")
            who = who.strip() if isinstance(who, str) else ""
            reason = reason.strip() if isinstance(reason, str) else ""
            if not who or not reason:
                gcov["blocked"].append(
                    {"name": name, "reason": "NOT_APPLICABLE without an authorizer and reason"})
                blocked.append(f"gate '{name}' marked NOT_APPLICABLE without a named "
                               "authorizer and reason — an inapplicable gate must still "
                               "be accountable")
            else:
                gcov["not_applicable"].append(
                    {"name": name, "authorized_by": who, "reason": reason})
                notes.append(f"gate '{name}' not applicable (authorized by {who}): {reason}")
        elif rec.get("exit_code") is None:
            gcov["blocked"].append({"name": name, "reason": "recorded without an exit code"})
            blocked.append(f"gate '{name}' recorded without an exit code")
        elif status == "FAIL" or rec["exit_code"] != 0:
            gcov["failed"].append(name)
            fail.append(f"gate '{name}' failed (exit {rec['exit_code']}): {rec.get('summary', '')}")
        else:
            gcov["passed"].append(name)
    return results, gcov


def check_panel(run, meta, plan, reports, blocked):
    """Returns panel coverage. roles_required is reconstructed from artifacts only:
    the assigned roles plus any roles a recorded degraded authorization dropped."""
    roles = list(plan.get("roles", {}))
    deg = plan.get("degraded")
    pcov = {"roles_required": roles + list((deg or {}).get("missing_roles", [])),
            "roles_filled": [r for r in roles if r in reports],
            "substitutions": len(plan.get("substitutions", [])),
            "degraded": deg,
            "dev_families_excluded": sorted(set(meta.get("dev_providers", [])))}
    if not roles:
        blocked.append("panel plan missing or empty — run `panel.py assign`")
        return pcov
    dev = set(meta.get("dev_providers", []))
    fams = [plan["roles"][r]["family"] for r in roles]
    if len(set(fams)) != len(fams):
        blocked.append("provider-family collision in panel plan — independence violated")
    leaked = [f for f in fams if f in dev]
    if leaked:
        blocked.append(f"development family present in panel: {', '.join(leaked)}")
    missing = [r for r in roles if r not in reports]
    if missing:
        blocked.append(f"reviewer reports missing for: {', '.join(missing)}")
    if deg and not deg.get("authorized_by"):
        blocked.append("degraded panel without recorded authorization")
    return pcov


REBUTTAL_SCOPE = {
    "critical": {"CRITICAL"},
    "contention": {"SENSITIVE", "CRITICAL"},
    "any": {"NORMAL", "SENSITIVE", "CRITICAL"},
}


def check_rebuttal(run, meta, plan, reports, blocked, notes):
    """Rebuttal is required when the tier is in the policy's scope AND there is
    something to contest (high/critical findings). Cost scales with contention.
    Returns rebuttal coverage."""
    policy = meta.get("rebuttal_policy", "contention")
    scope = REBUTTAL_SCOPE.get(policy, REBUTTAL_SCOPE["contention"])
    contested = any(f["severity"] in HIGH
                    for rep in reports.values() for f in rep.get("findings", []))
    required = meta["risk"] in scope and contested
    ran = bool(plan.get("roles")) and all(
        (run / "rebuttal" / f"{r}.json").exists() for r in plan.get("roles", {}))
    rcov = {"policy": policy, "required": required, "ran": ran}
    if not required:
        if contested:
            notes.append(f"rebuttal not required at {meta['risk']} under policy '{policy}'")
        return rcov
    missing = [r for r in plan.get("roles", {})
               if not (run / "rebuttal" / f"{r}.json").exists()]
    if missing:
        blocked.append(f"rebuttal round required (policy '{policy}', risk {meta['risk']}, "
                       f"high/critical findings present); missing for: {', '.join(missing)}")
    return rcov


def compute_attestation(run):
    """Reproducible SHA-256 over every recorded JSON artifact that can feed the
    verdict — everything except verdict.json, which is the output (#5).

    Each artifact is canonicalized (sorted keys, compact separators) so cosmetic
    re-serialization does not read as tampering; a .json file that fails UTF-8
    decoding or JSON parsing — both treated identically, by design — is hashed over
    its raw bytes instead of crashing the enforcement point. The
    per-file hashes are folded into one manifest digest, and returned alongside it
    so --check-digest can name exactly which artifact drifted.
    Same untouched run in, same digest out — bit for bit."""
    files = {}
    for p in sorted(run.rglob("*.json")):
        rel = p.relative_to(run).as_posix()
        if rel == "verdict.json":
            continue
        raw = p.read_bytes()
        try:
            canon = json.dumps(json.loads(raw.decode("utf-8")), sort_keys=True,
                               separators=(",", ":"), ensure_ascii=False)
            files[rel] = hashlib.sha256(canon.encode("utf-8")).hexdigest()
        except (ValueError, UnicodeDecodeError):
            files[rel] = "raw:" + hashlib.sha256(raw).hexdigest()
    manifest = "\n".join(f"{sha}  {rel}" for rel, sha in sorted(files.items()))
    digest = hashlib.sha256(manifest.encode("utf-8")).hexdigest()
    return {"algorithm": "sha256-canonical-json-v1", "inputs": len(files),
            "digest": digest, "files": files}


def check_digest(run):
    """Recompute the attestation and compare to the one stored in verdict.json.
    Exit 0 on match; on mismatch, name every drifted artifact and exit 1."""
    vpath = run / "verdict.json"
    if not vpath.exists():
        print("no verdict.json in run — aggregate first")
        sys.exit(2)
    stored = read_json(vpath).get("attestation")
    if not stored:
        print("verdict.json carries no attestation (computed before #5) — re-aggregate")
        sys.exit(2)
    att = compute_attestation(run)
    if att["digest"] == stored.get("digest"):
        print(f"attestation OK: sha256 {att['digest']} over {att['inputs']} artifacts")
        sys.exit(0)
    old = stored.get("files", {})
    for rel in sorted(set(old) | set(att["files"])):
        a, b = old.get(rel), att["files"].get(rel)
        if a != b:
            tag = "added" if a is None else ("removed" if b is None else "modified")
            print(f"  DRIFT {tag:9s}{rel}")
    print(f"attestation MISMATCH: stored {stored.get('digest')}, "
          f"recomputed {att['digest']} — this run's artifacts changed after the "
          "verdict was computed")
    sys.exit(1)


# --- Detached signature over the run verdict (E6-S1) --------------------------------
# `--sign` writes a DETACHED signature SIDECAR (attestation.sig) over the run's canonical verdict.json,
# out-of-process. It signs verdict.json — not merely the attestation digest — so the signature binds
# the COMPUTED VERDICT (verdict/reasons/coverage) and its attestation digest together: a relabeled
# verdict ("BLOCKED"->"PASS") no longer verifies. `--sign` and `--verify-signature` are STANDALONE
# post-verdict modes (like --check-digest): they operate on the EXISTING verdict.json and never
# re-aggregate, and both first RECOMPUTE the attestation from the on-disk artifacts and refuse unless
# it still matches the recorded digest — so signing never silently re-attests drift, and a tampered
# input artifact fails verification even when the sidecar is untouched. The sidecar is deliberately NOT
# a `.json` file, so compute_attestation() (globbing `*.json`) never folds it into the digest. Signing
# is strictly OUT-OF-PROCESS via subprocess: cosign / minisign are invoked, never imported, so the
# stdlib-only runtime import contract is preserved. Adding a signature changes no verdict/attestation
# state; the verdict never depends on whether a signature exists.
SIG_FILENAME = "attestation.sig"


def _sign_fail(msg):
    """Loud, non-zero failure for the signing/verifying TOOLING path (no signer configured, a
    malformed command template, or the external tool could not start / timed out / errored). Exit 3
    keeps it distinct from the verdict codes (0 PASS / 1 FAIL / 2 BLOCKED) and from a verify mismatch
    (1). Never a silent skip."""
    print(f"ERROR: {msg}", file=sys.stderr)
    sys.exit(3)


def _sign_timeout():
    """Bounded subprocess timeout (seconds) for signer/verifier calls; AR_SIGN_TIMEOUT overrides.
    A non-positive or non-numeric override falls back to the default rather than crashing the gate."""
    raw = os.environ.get("AR_SIGN_TIMEOUT", "120").strip()
    try:
        t = int(raw)
    except ValueError:
        return 120
    return t if t > 0 else 120


def _resolve_tool(env_cmd, builders):
    """Resolve a signing/verifying command as an argv TEMPLATE carrying `{msg}`/`{sig}` tokens.
    Precedence: an explicit env override (`env_cmd`, e.g. AR_SIGNER_CMD) wins; otherwise the first
    auto-detected tool whose builder returns a non-None argv (cosign keyless primary, minisign
    fallback). Returns (argv, kind) or (None, None) when nothing resolves. The command is only ever
    executed via subprocess — nothing here imports the signer."""
    cmd = os.environ.get(env_cmd, "").strip()
    if cmd:
        try:
            return shlex.split(cmd), "custom"
        except ValueError as e:
            _sign_fail(f"{env_cmd} is not a valid command template ({e}): {cmd!r}")
    for kind, build in builders:
        argv = build()
        if argv is not None:
            return argv, kind
    return None, None


def _cosign_sign_argv():
    # Primary: sigstore/cosign KEYLESS. An ephemeral Fulcio certificate (from an ambient OIDC
    # identity) plus a Rekor transparency-log entry; no long-lived private key. `--yes` suppresses
    # the confirmation prompt; `--bundle` packs signature + certificate + log proof into ONE
    # self-contained sidecar an outside verifier consumes with `verify-blob --bundle`.
    if not shutil.which("cosign"):
        return None
    return ["cosign", "sign-blob", "--yes", "--bundle", "{sig}", "{msg}"]


def _minisign_sign_argv():
    # Fallback: minisign (Ed25519). Requires a configured secret key (AR_MINISIGN_KEY); `-x` writes
    # the detached signature to the given path. Use a password-less key for non-interactive runs.
    key = os.environ.get("AR_MINISIGN_KEY", "").strip()
    if not (shutil.which("minisign") and key):
        return None
    return ["minisign", "-S", "-s", key, "-m", "{msg}", "-x", "{sig}"]


def _cosign_verify_argv():
    # Keyless verification is only meaningful against an expected signer identity + issuer:
    # `cosign verify-blob` WITHOUT --certificate-identity/--certificate-oidc-issuer accepts ANY
    # valid Fulcio certificate, so it must not be auto-selected as the verifier unless BOTH are
    # set. When they are missing we return None and fall through (to minisign, or to a loud
    # "no verifier available" naming AR_COSIGN_IDENTITY/AR_COSIGN_ISSUER) rather than silently
    # verifying against an unconstrained identity (panel finding security-1).
    if not shutil.which("cosign"):
        return None
    ident = os.environ.get("AR_COSIGN_IDENTITY", "").strip()
    issuer = os.environ.get("AR_COSIGN_ISSUER", "").strip()
    if not (ident and issuer):
        return None
    return ["cosign", "verify-blob", "--bundle", "{sig}",
            "--certificate-identity", ident, "--certificate-oidc-issuer", issuer, "{msg}"]


def _minisign_verify_argv():
    # AR_MINISIGN_PUBKEY_FILE names a public-key FILE (minisign `-p`); AR_MINISIGN_PUBKEY carries an
    # INLINE key value (minisign `-P`). They are SEPARATE vars by design: choosing `-p` vs `-P` by
    # whether the value happens to name an existing file (an earlier os.path.exists heuristic) let an
    # attacker who can drop a file into the verifier's working directory — named exactly the operator's
    # PUBLIC inline key — make minisign read an attacker-chosen key file, so a verdict signed with the
    # attacker's key would verify (panel finding security-1). Filesystem state must never select the
    # verification key. An explicit key file wins when both are set.
    if not shutil.which("minisign"):
        return None
    keyfile = os.environ.get("AR_MINISIGN_PUBKEY_FILE", "").strip()
    if keyfile:
        return ["minisign", "-V", "-p", keyfile, "-m", "{msg}", "-x", "{sig}"]
    inline = os.environ.get("AR_MINISIGN_PUBKEY", "").strip()
    if inline:
        return ["minisign", "-V", "-P", inline, "-m", "{msg}", "-x", "{sig}"]
    return None


def _load_verdict(run):
    """Read the run's EXISTING verdict.json (READ, never recomputed). Exits 2 when there is no verdict
    or no attestation digest to sign/verify (a missing prerequisite, not a signer failure)."""
    vpath = run / "verdict.json"
    if not vpath.exists():
        print("no verdict.json in run — aggregate first")
        sys.exit(2)
    verdict = read_json(vpath)
    digest = (verdict.get("attestation") or {}).get("digest")
    if not isinstance(digest, str) or not digest:
        print("verdict.json carries no attestation digest — re-aggregate")
        sys.exit(2)
    return verdict, digest


def _canonical_verdict_bytes(verdict):
    """The exact bytes signed/verified: verdict.json canonicalized (sorted keys, compact separators),
    with the non-reproducible `computed_at` timestamp excluded so re-aggregating an untouched run
    reproduces the same signable bytes. Signing verdict.json — not just its attestation digest — binds
    the computed verdict decision (verdict/reasons/coverage) to the signature."""
    core = {k: v for k, v in verdict.items() if k != "computed_at"}
    return json.dumps(core, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def _run_tool(argv_tmpl, msg_path, sig_path):
    """Substitute `{msg}`/`{sig}` in the argv template and run the external tool. When the template
    references `{msg}` the canonical verdict.json (the signed bytes) is substituted there, else it is
    appended as the final arg.
    Returns the completed process; exits 3 (loud) if the tool cannot even be started."""
    argv = [a.replace("{msg}", str(msg_path)).replace("{sig}", str(sig_path)) for a in argv_tmpl]
    if not any("{msg}" in a for a in argv_tmpl):
        argv.append(str(msg_path))
    try:
        return subprocess.run(argv, capture_output=True, timeout=_sign_timeout())
    except OSError as e:
        _sign_fail(f"could not start signer/verifier {argv[0]!r}: {e}")
    except subprocess.TimeoutExpired:
        _sign_fail(f"signer/verifier {argv[0]!r} timed out after {_sign_timeout()}s "
                   "(set AR_SIGN_TIMEOUT to adjust)")


def sign_attestation(run):
    """Write a DETACHED signature sidecar (`attestation.sig`) over the run's EXISTING, canonical
    verdict.json, out-of-process. STANDALONE: it does not re-aggregate (a prior `aggregate.py` must
    have written verdict.json) and it REFUSES to sign a run whose artifacts drifted from the recorded
    attestation digest, so signing can never silently re-attest changed state. Signer resolution:
    AR_SIGNER_CMD override > cosign keyless > minisign (AR_MINISIGN_KEY). Exit 0 signed, 1 drift,
    2 nothing to sign, 3 no signer / signer failure — opt-in signing is never silently skipped."""
    verdict, digest = _load_verdict(run)
    att = compute_attestation(run)
    if att["digest"] != digest:
        print(f"refusing to sign: run artifacts drifted — recomputed attestation {att['digest']} "
              f"!= recorded {digest}; re-aggregate before signing", file=sys.stderr)
        sys.exit(1)
    argv_tmpl, kind = _resolve_tool(
        "AR_SIGNER_CMD",
        [("cosign-keyless", _cosign_sign_argv), ("minisign", _minisign_sign_argv)])
    if argv_tmpl is None:
        _sign_fail("no signer available: set AR_SIGNER_CMD to a signing command (using the {msg} "
                   "and {sig} tokens), or install cosign (keyless) or minisign (with AR_MINISIGN_KEY "
                   "set). --sign is opt-in and never silently skipped.")
    want_sig_out = any("{sig}" in a for a in argv_tmpl)
    with tempfile.TemporaryDirectory() as td:
        msg = Path(td) / "verdict.canonical.json"
        msg.write_bytes(_canonical_verdict_bytes(verdict))
        sig_tmp = Path(td) / "sig.out"
        proc = _run_tool(argv_tmpl, msg, sig_tmp)
        if proc.returncode != 0:
            _sign_fail(f"signer '{kind}' exited {proc.returncode}: "
                       + (proc.stderr or b"").decode("utf-8", "replace").strip()[-500:])
        if want_sig_out:
            if not sig_tmp.exists():
                _sign_fail(f"signer '{kind}' exited 0 but wrote no signature file")
            sig = sig_tmp.read_bytes()
        else:
            sig = proc.stdout or b""
    if not sig:
        _sign_fail(f"signer '{kind}' produced an empty signature")
    (run / SIG_FILENAME).write_bytes(sig)                 # sidecar; not a *.json, so never attested
    print(f"signed: {run / SIG_FILENAME} over verdict.json of run {verdict.get('run_id')} "
          f"(attestation sha256 {digest}, signer: {kind})")
    sys.exit(0)


def verify_signature(run):
    """Verify the detached `attestation.sig` sidecar against the run's verdict.json, then exit:
    0 valid, 1 not verified (a tampered verdict.json, a tampered signature, or drifted input
    artifacts), 2 a missing prerequisite (no verdict / no sidecar; an absent sidecar exits 2, not 1), 3 no verifier available / verifier
    tooling error. Verification is COMPLETE: it (a) recomputes the attestation from the on-disk
    artifacts and requires it matches the digest recorded in verdict.json — so a tampered input
    artifact is caught even though the sidecar is untouched — and (b) verifies the signature over the
    canonical verdict.json — so a relabeled verdict decision no longer verifies. Verifier resolution
    mirrors the signer: AR_VERIFIER_CMD override > cosign verify-blob > minisign -V."""
    verdict, digest = _load_verdict(run)
    sigpath = run / SIG_FILENAME
    if not sigpath.exists():
        print(f"no signature sidecar ({SIG_FILENAME}) — run `aggregate.py --sign` first")
        sys.exit(2)
    att = compute_attestation(run)
    if att["digest"] != digest:
        print(f"signature INVALID: run artifacts drifted — recomputed attestation {att['digest']} "
              f"!= recorded {digest}; the signed verdict no longer describes this run's inputs")
        sys.exit(1)
    argv_tmpl, kind = _resolve_tool(
        "AR_VERIFIER_CMD",
        [("cosign-keyless", _cosign_verify_argv), ("minisign", _minisign_verify_argv)])
    if argv_tmpl is None:
        _sign_fail("no verifier available: set AR_VERIFIER_CMD (using the {msg} and {sig} tokens), "
                   "or install cosign (keyless; set AR_COSIGN_IDENTITY/AR_COSIGN_ISSUER) or minisign "
                   "(with AR_MINISIGN_PUBKEY inline or AR_MINISIGN_PUBKEY_FILE set).")
    with tempfile.TemporaryDirectory() as td:
        msg = Path(td) / "verdict.canonical.json"
        msg.write_bytes(_canonical_verdict_bytes(verdict))
        proc = _run_tool(argv_tmpl, msg, sigpath)
    if proc.returncode == 0:
        print(f"signature OK: {SIG_FILENAME} verifies the verdict.json of run "
              f"{verdict.get('run_id')} (attestation sha256 {digest}, verifier: {kind})")
        sys.exit(0)
    print(f"signature INVALID: {SIG_FILENAME} did not verify (verifier: {kind}, exit "
          f"{proc.returncode}) — a bad or absent signature, a relabeled verdict, or a verifier "
          "configuration error; see stderr below")
    err = (proc.stderr or b"").decode("utf-8", "replace").strip()
    if err:
        print("  " + err[-500:])
    sys.exit(1)


def author_families(finding_ids, plan):
    fams = set()
    for fid in finding_ids:
        role = fid.rsplit("-", 1)[0]
        info = plan.get("roles", {}).get(role)
        if info:
            fams.add(info["family"])
    return fams


def check_findings(run, meta, plan, reports, fail, blocked, counts):
    findings = {}
    # Reports are semi-trusted; ingest normally validates them, but a hand-recorded or
    # bypassed artifact can carry malformed shapes. Guard every container/item here so a
    # crafted report degrades to a BLOCK reason rather than crashing before verdict.json is
    # written (3rd-panel correctness-1: `findings` null/non-list/[null] raised TypeError).
    for role, rep in reports.items():
        rfind = rep.get("findings")
        if rfind is None:
            continue
        if not isinstance(rfind, list):
            blocked.append(f"reviewer '{role}' findings is malformed (not a list) — cannot assess findings")
            continue
        for f in rfind:
            if (not isinstance(f, dict) or not isinstance(f.get("id"), str)
                    or f.get("severity") not in ("critical", "high", "medium", "low")):
                blocked.append(f"reviewer '{role}' has a malformed finding (needs a string id and a "
                               "valid severity) — cannot assess it")
                continue
            if f["id"] in findings:
                # Last-write-wins previously let a later report reuse an id and overwrite (hide) an
                # earlier finding — e.g. a low finding clobbering a real high one so it drops out of
                # the high/critical coverage check and the run reaches PASS (4th-panel security-2,
                # reproduced). ids are attacker-controllable and ingest has no cross-report namespace
                # rule, so a collision must BLOCK rather than silently overwrite.
                blocked.append(f"duplicate finding id '{_snippet(f['id'])}' (within or across reports) "
                               "— an id must not be reused to overwrite (hide) an earlier finding")
                continue
            findings[f["id"]] = f
            if f["severity"] in HIGH:
                counts["findings_high_critical"] += 1
            else:
                counts["findings_medium_low"] += 1

    records = []
    vdir = run / "validation"
    if vdir.is_dir():
        for p in sorted(vdir.glob("*.json")):
            if p.name.startswith("concur-request"):
                continue
            records.append((p.name, read_json(p)))

    suppressions = {}
    spath = run / "suppressions.json"
    if spath.exists():
        # suppressions.json is operator-authored but may be hand-edited/malformed; a non-list
        # document or a non-dict entry previously crashed here (TypeError / AttributeError) before
        # verdict.json was written (4th-panel security-3/correctness-2). Malformed -> BLOCK, no crash.
        sup_doc = read_json(spath)
        if not isinstance(sup_doc, list):
            blocked.append("suppressions.json is malformed (not a list) — cannot assess "
                           "accepted-risk suppressions")
        else:
            for s in sup_doc:
                if not isinstance(s, dict):
                    blocked.append("suppressions.json has a malformed entry (not an object) "
                                   "— cannot assess it")
                    continue
                fid = s.get("finding_id", "")
                if not isinstance(fid, str):
                    # finding_id becomes a dict key below; an unhashable value (e.g. []) crashed
                    # here before verdict.json (5th-panel security-1/correctness-1). Guard the id
                    # type, matching the own_ids/findings-map guards (malformed -> BLOCK, no crash).
                    blocked.append("suppressions.json has an entry with a non-string finding_id "
                                   "— malformed, cannot assess it")
                    continue
                suppressions[fid] = s

    covered = set()
    dev = set(meta.get("dev_providers", []))
    sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    for name, rec in records:
        if not isinstance(rec, dict):
            blocked.append(f"validation/{name}: malformed record (not an object)")
            continue
        ids = rec.get("finding_ids")
        if not isinstance(ids, list):
            blocked.append(f"validation/{name}: finding_ids is malformed (not a list)")
            continue
        # A non-string member was previously filtered silently. That is fail-SAFE (a dropped id
        # leaves its finding uncovered, which itself BLOCKs) — not the fail-open the reviewer
        # described — but silence diverges from the sibling non-list guard above. Make malformed ->
        # BLOCK uniform so a garbled record is surfaced, never quietly reinterpreted (4th-panel
        # correctness-3).
        if not all(isinstance(i, str) for i in ids):
            blocked.append(f"validation/{name}: finding_ids has a non-string member — malformed")
            continue
        cls = rec.get("classification")
        sev = rec.get("severity") or min(
            (findings[i]["severity"] for i in ids if i in findings),
            key=lambda s: sev_rank.get(s, 9), default="low")
        covered.update(ids)
        if cls not in ("confirmed", "false_positive", "unresolved", "accepted_risk"):
            blocked.append(f"validation/{name}: invalid classification '{cls}'")
            continue
        is_high = sev in HIGH or any(findings.get(i, {}).get("severity") in HIGH for i in ids)
        if cls == "unresolved" and is_high:
            fail.append(f"validation/{name}: high/critical finding unresolved ({', '.join(ids)})")
            counts["unresolved"] += 1
        elif cls == "confirmed":
            counts["confirmed"] += 1
            res = rec.get("resolution") or {}
            if not (res.get("fixed") is True and res.get("gates_rerun")):
                fail.append(f"validation/{name}: confirmed finding not fixed with gates rerun")
        elif cls == "false_positive" and is_high:
            conc = rec.get("concurrence") or {}
            if not rec.get("evidence"):
                blocked.append(f"validation/{name}: false_positive without evidence")
            if conc.get("agrees_false_positive") is not True:
                blocked.append(f"validation/{name}: false_positive on high/critical "
                               "without an agreeing concurrence from an uninvolved model")
            else:
                cfam = family_of(conc.get("model_id", "unknown/unknown"))
                bad = author_families(ids, plan) | dev
                if cfam in bad:
                    blocked.append(f"validation/{name}: concurrence model family "
                                   f"'{cfam}' is not independent of the finding/dev")
        elif cls == "accepted_risk":
            today = date.today().isoformat()
            for fid in ids:
                s = suppressions.get(fid)
                if not s:
                    fail.append(f"validation/{name}: accepted_risk '{fid}' has no suppression entry")
                elif not all(s.get(k) for k in ("evidence", "owner", "expires")):
                    fail.append(f"suppression for '{fid}' incomplete (needs evidence, owner, expires)")
                elif s["expires"] < today:
                    fail.append(f"suppression for '{fid}' expired {s['expires']}")

    uncovered = [i for i, f in findings.items()
                 if f["severity"] in HIGH and i not in covered]
    if uncovered:
        blocked.append("high/critical findings with no validation record: "
                       + ", ".join(sorted(uncovered)))
    # A reviewer explicitly flagged these as release-blocking; severity alone does not
    # exempt them from triage. Untriaged = verification incomplete = BLOCKED.
    flagged = [i for i, f in findings.items()
               if f["severity"] not in HIGH and f.get("release_blocking")
               and i not in covered]
    if flagged:
        blocked.append("reviewer-flagged release-blocking findings without triage: "
                       + ", ".join(sorted(flagged)))
    untriaged = [i for i, f in findings.items()
                 if f["severity"] not in HIGH and i not in covered]
    if untriaged:
        counts["medium_low_untriaged"] = len(untriaged)

    # Output-fidelity attestation gate. A reviewer that recorded a human-facing statement as
    # false (states_truth=false) must link it — via finding_id — to a finding in ITS OWN report
    # (membership in this reviewer's findings, not a role-prefix match against the cross-report
    # map) that is RESOLVED (a triage decision was made: confirmed / false_positive /
    # accepted_risk; a merely `unresolved` record does not clear it). An unlinked, foreign,
    # dangling, or unresolved link is unverified false output reaching release, so it BLOCKS
    # regardless of the linked finding's severity — this is what makes the forced attestation
    # actually gate the verdict. Fail-safe by construction: a missing/garbled/foreign link (or a
    # malformed non-list container) blocks, never passes. finding_id and the rendered snippet are
    # reviewer-supplied (untrusted) and are escaped before interpolation so a crafted value cannot
    # forge markdown/HTML in the rendered verdict.
    # Membership + resolution still do not prove the linked finding is ABOUT this statement — a
    # reviewer could link a false statement to an unrelated, real, resolved finding of its own (2nd
    # panel security-2). Rather than content-match the reviewer's own text (fragile, false-blocks
    # paraphrases), the clear requires the TRUSTED operator to name this specific statement: the
    # resolving validation record for the linked finding must echo the rendered text (whitespace-
    # normalized) in `output_statements_confirmed`. The binding thus lives on the trusted side —
    # the party a semi-trusted reviewer cannot forge — so a recorded falsehood cannot clear on a
    # reviewer-chosen link alone.
    resolved = set()
    confirmed_by_fid = {}   # finding_id -> {operator-confirmed rendered statements, normalized}
    for _, rec in records:
        if not isinstance(rec, dict) or rec.get("classification") not in (
                "confirmed", "false_positive", "accepted_risk"):
            continue
        rfids = rec.get("finding_ids")
        fids = [i for i in rfids if isinstance(i, str)] if isinstance(rfids, list) else []
        resolved.update(fids)
        # A malformed (non-list) output_statements_confirmed yields no confirmations, so any
        # false statement linked to this finding fails safe to BLOCK on the unconfirmed branch
        # below — never crashes, never fail-opens (3rd-panel correctness-2/output_fidelity-1).
        oconf = rec.get("output_statements_confirmed")
        stmts = ({" ".join(s.split()) for s in oconf if isinstance(s, str)}
                 if isinstance(oconf, list) else set())
        for f in fids:
            confirmed_by_fid.setdefault(f, set()).update(stmts)
    false_stmts = 0
    for role, rep in reports.items():
        osc = rep.get("output_statements_checked")
        if osc is None:
            continue
        if not isinstance(osc, list):
            # Malformed attestation from an artifact that bypassed ingest validation.
            # Fail safe (BLOCK) rather than crash so a verdict is still written — a truthy
            # non-list here previously raised TypeError before verdict.json existed, the
            # same no-crash contract the areas_not_reviewed gather already honors (2nd panel
            # finding correctness-2).
            blocked.append(f"reviewer '{role}' output_statements_checked is malformed "
                           "(not a list) — output fidelity cannot be verified")
            continue
        # Ownership is membership in THIS reviewer's own report, not a role-prefix match
        # against the cross-report findings map: another report can name a finding under
        # this role's prefix, which the global map would then satisfy (2nd panel finding
        # security-1/correctness-1 — a planted id let a false statement reach PASS).
        rfind = rep.get("findings")
        # The id must be a str, not merely present: an unhashable id (e.g. []) on a dict finding
        # crashed the set comprehension with TypeError before verdict.json (4th-panel
        # security-1/correctness-1). Mirror the str guard the top findings loop already applies.
        own_ids = ({f["id"] for f in rfind
                    if isinstance(f, dict) and isinstance(f.get("id"), str)}
                   if isinstance(rfind, list) else set())
        for it in osc:
            if not isinstance(it, dict):
                blocked.append(f"reviewer '{role}' has a malformed output_statements_checked item "
                               "(not an object) — output fidelity cannot be verified")
                continue
            st = it.get("states_truth")
            if not isinstance(st, bool):
                # Not the exact boolean False vs a malformed value: a non-bool (string 'false',
                # None, missing) must BLOCK, not be silently skipped as if it were a true statement
                # (3rd-panel correctness-4 — malformed items were fail-open).
                blocked.append(f"reviewer '{role}' output attestation has a non-boolean states_truth "
                               "— malformed, cannot verify output fidelity")
                continue
            if st is not False:
                continue   # a genuine true statement; nothing to gate
            false_stmts += 1
            rendered = it.get("rendered")
            if not isinstance(rendered, str):
                # No str() coercion: a non-string rendered (e.g. int 1) must not be coerced to
                # match a confirmed "1" (3rd-panel correctness-3). Malformed -> BLOCK.
                blocked.append(f"reviewer '{role}' recorded a false output statement with a "
                               "non-string rendered value — malformed, cannot verify")
                continue
            fid = it.get("finding_id")
            fid = fid.strip() if isinstance(fid, str) else ""
            snip = _snippet(rendered)
            sfid = _snippet(fid)  # untrusted — escape before interpolating into a reason
            if not fid:
                blocked.append(f"reviewer '{role}' recorded false human-facing output "
                               f"(\"{snip}\") with no finding_id — a false statement must be "
                               "raised as a finding so it enters triage")
            elif not fid.startswith(role + "-") or fid not in own_ids:
                blocked.append(f"reviewer '{role}' linked false output to finding '{sfid}', "
                               "which is not a finding this reviewer raised — a false statement "
                               "must be linked to the reviewer's own finding, not an unrelated one")
            elif fid not in resolved:
                blocked.append(f"false-output finding '{sfid}' (reviewer '{role}') is untriaged "
                               "or unresolved — a reviewer-attested false statement must be "
                               "validated (confirmed/false_positive/accepted_risk) before release")
            elif " ".join(rendered.split()) not in confirmed_by_fid.get(fid, set()):
                blocked.append(f"false-output finding '{sfid}' (reviewer '{role}') is resolved but no "
                               f"validation record confirms this specific statement (\"{snip}\") in "
                               "output_statements_confirmed — resolving an own finding does not prove "
                               "it is about this statement; the operator must confirm it (2nd panel "
                               "security-2)")
    counts["false_output_statements"] = false_stmts

    return {"raised": len(findings),
            "triaged": sum(1 for i in findings if i in covered),
            "untriaged_release_blocking": len(flagged)}


# Plain-language guidance for a non-expert reading the verdict ("what does this even
# mean, and what do I do now?"). Each entry: (what the gate proves, what to do if it is
# the blocker). The `mutation` entry deliberately explains what the score/threshold mean,
# since that number is the most opaque to someone who did not write the pipeline.
GATE_HELP = {
    "build": ("the code compiles and imports cleanly",
              "run the build locally, fix the syntax/import error it prints, and start a new review"),
    "unit": ("your automated tests pass",
             "run the test suite locally, fix the failing test (or the bug it caught), and re-review"),
    "secrets": ("no credential, key, or token is committed",
                "remove the secret from the diff AND its history, rotate the exposed credential, then re-review"),
    "deps": ("no dependency has a known security vulnerability",
             "upgrade the flagged package to a patched version; a findings suppression will NOT clear a failed "
             "gate — to ship without upgrading, the gate must be waived or recorded not-applicable by a named "
             "authorizer"),
    "sast": ("a static analyzer found no likely security bug in the code",
             "open the flagged line and fix it; a findings suppression will NOT clear a failed gate — to ship "
             "without fixing, the gate must be waived or recorded not-applicable by a named authorizer"),
    "mutation": ("your tests actually catch bugs rather than just run. The score is the percent of injected "
                 "bugs (\"mutants\") your tests killed; BELOW the threshold means the tests are thin on the code "
                 "they cover — it does NOT mean the code is wrong",
                 "open the surviving-mutant list: each file:line is a spot where a bug would slip past every "
                 "test. Add a test that would fail there, then re-run. Equivalent (behaviour-preserving) "
                 "mutants can't be killed and are just noise"),
    "iac": ("your infrastructure config (Terraform/K8s/Docker) has no misconfiguration",
            "fix the flagged setting and re-review"),
    "e2e": ("the app works end to end",
            "reproduce the failing flow locally, fix it, and re-review"),
    "migration": ("the schema change applies AND rolls back cleanly",
                  "fix the migration so both directions succeed against a scratch database"),
    "dast": ("a running staging instance shows no obvious vulnerability",
             "triage the scanner report against staging and fix the real issues"),
    "enforcement": ("the protected branch actually enforces this review (required checks, no force-push)",
                    "enable the required branch protections, or grant access so they can be verified"),
}


def _oneline(s):
    """Collapse whitespace/newlines AND HTML-escape so an untrusted reason string cannot forge
    extra markdown bullets/headings, nor inject raw HTML (which Markdown renderers pass through),
    when it is interpolated into the guidance. Trade-off: a legitimate reason containing <, >, or
    & renders as an entity — acceptable for a safety-first, audience-facing section."""
    return html.escape(" ".join(str(s).split()), quote=False)


def _snippet(s, n=80):
    """One-lined, length-capped, HTML-escaped excerpt of a reviewer-supplied string for safe
    interpolation into a blocked reason (same injection concern as _oneline)."""
    s = " ".join(str(s).split())
    if len(s) > n:
        s = s[:n - 1] + "…"
    return html.escape(s, quote=False)


def next_steps(verdict, fail, blocked, gcov, fcov, counts):
    """Plain-language 'what this means and what to do next', for someone who did not write
    the pipeline. DERIVED ONLY from the already-computed verdict and coverage — it reads
    them and never writes them, so it cannot change a gate, threshold, or verdict. Coverage
    shapes are normalized defensively so malformed/None input degrades rather than crashing
    (the verdict file must still be written), and every fail/blocked reason not rephrased as
    a specific gate line is passed through verbatim (one-lined) so a blocker is never hidden."""
    fail = [r for r in (fail or []) if isinstance(r, str)]
    blocked = [r for r in (blocked or []) if isinstance(r, str)]
    # Normalize by TYPE, not truthiness: a truthy-but-wrong-typed shape (gcov a list, or a
    # coverage field carrying an int/str) must degrade to empty, not crash downstream.
    gcov = gcov if isinstance(gcov, dict) else {}
    fcov = fcov if isinstance(fcov, dict) else {}
    counts = counts if isinstance(counts, dict) else {}

    def _list(x):
        return x if isinstance(x, list) else []
    steps = []
    if verdict == "PASS":
        steps.append("Cleared: every required check passed and independent review ran with its blocking "
                     "findings resolved. A human still owns the actual merge decision.")
        if counts.get("confirmed"):
            steps.append(f"{counts['confirmed']} issue(s) were caught during review and already fixed before "
                         "this passed — see the Findings section of the report for what changed.")
        mlu = counts.get("medium_low_untriaged", 0)
        if mlu:
            steps.append(f"{mlu} lower-severity note(s) were left untriaged. They do not block release, but "
                         "skim them in the report before you merge.")
        steps.append("Before you merge: if this change was pushed to a remote (branch or PR), verify the pushed "
                     "bytes match what was reviewed here — a blob-sha or sha256 round-trip — because a "
                     "success-reporting transport is not proof the bytes arrived.")
        return steps

    steps.append("Not ready to merge yet. Work through the items below, then start a FRESH review "
                 "(a re-review is a new run — never an edit of this one).")
    # A plain-language line per failing/unverified GATE. Coverage lists may be absent, None,
    # or (defensively) carry non-string/dict elements — normalize before use so guidance
    # degrades rather than crashing.
    seen = set()
    for g in _list(gcov.get("failed")):
        if not isinstance(g, str):
            continue
        proves, action = GATE_HELP.get(
            g, ("a required check", "read its output above and fix what it reports"))
        # State the failure first, then what a PASSING check would prove — never
        # "failed — it proves <success condition>", which reads as an inversion.
        steps.append(f"The '{_oneline(g)}' check failed. Passing it proves {proves}. What to do: {action}.")
        seen.add(g)
    blocked_names = [b["name"] for b in _list(gcov.get("blocked"))
                     if isinstance(b, dict) and isinstance(b.get("name"), str)]
    missing = [g for g in _list(gcov.get("missing")) if isinstance(g, str)]
    for g in blocked_names + missing:
        if g in seen:
            continue
        proves = GATE_HELP.get(g, ("a required check", ""))[0]
        steps.append(f"The '{_oneline(g)}' check could not be verified. Passing it proves {proves}. It must "
                     "run and pass (or be recorded as not-applicable, with a reason) before release.")
        seen.add(g)
    if counts.get("unresolved"):
        steps.append(f"{counts['unresolved']} serious (high/critical) finding(s) are unresolved. Each must be "
                     "fixed and its checks re-run, or formally accepted via an owner-signed, expiring suppression.")
    if any("confirmed finding not fixed" in r for r in fail):
        steps.append("Confirmed issue(s) were not fixed (or their checks were not re-run). Fix each and re-run "
                     "the affected checks — a confirmed issue cannot simply be left in place.")
    if fcov.get("untriaged_release_blocking"):
        steps.append(f"{fcov['untriaged_release_blocking']} finding(s) a reviewer marked release-blocking are "
                     "untriaged. Inspect each and either fix it or record a decision — silence blocks release.")
    # Never hide a blocker: show every raw reason verbatim EXCEPT one already rephrased above
    # as a specific gate line. "Covered" means the reason names that exact gate ("gate '<g>'")
    # — an exact match, so an unrelated blocker that merely contains the characters "gate '"
    # is still shown. Each reason is one-lined so untrusted text cannot inject markdown.
    for r in fail + blocked:
        if any(f"gate '{g}'" in r for g in seen):
            continue
        steps.append(f"Also resolve: {_oneline(r)}.")
    return steps


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--run")
    ap.add_argument("--check-digest", action="store_true",
                    help="verify the stored attestation against the run directory "
                         "and exit (0 intact, 1 drifted); does not rewrite anything")
    ap.add_argument("--sign", action="store_true",
                    help="sign the EXISTING verdict.json with a detached sidecar (attestation.sig) "
                         "via an out-of-process signer (cosign keyless / minisign / AR_SIGNER_CMD) "
                         "and exit; standalone (does not re-aggregate), refuses to sign a drifted "
                         "run, and fails loudly (exit 3) if no signer is configured")
    ap.add_argument("--verify-signature", action="store_true",
                    help="verify the detached attestation.sig sidecar against verdict.json — "
                         "recomputing the attestation from artifacts and checking the signed verdict "
                         "— and exit (0 valid, 1 not verified, 2 missing prerequisite, 3 no verifier)")
    args = ap.parse_args()
    run = resolve_run(args.run)
    if args.check_digest:
        check_digest(run)
    if args.verify_signature:
        verify_signature(run)
    if args.sign:
        sign_attestation(run)
    meta = read_json(run / "run.json")

    fail, blocked, notes = [], [], []
    counts = {"gates": 0, "reviewers": 0, "findings_high_critical": 0,
              "findings_medium_low": 0, "confirmed": 0, "unresolved": 0}

    gates, gcov = check_gates(run, meta["risk"], fail, blocked, notes)
    counts["gates"] = len(gates)

    plan_path = run / "panel" / "plan.json"
    plan = read_json(plan_path) if plan_path.exists() else {}
    reports = load_reports(run, plan)
    counts["reviewers"] = len(reports)
    pcov = check_panel(run, meta, plan, reports, blocked)
    rcov = check_rebuttal(run, meta, plan, reports, blocked, notes)
    fcov = check_findings(run, meta, plan, reports, fail, blocked, counts)

    # First-class coverage: one machine-readable manifest of what this run did and
    # did not verify, assembled from the same recorded artifacts as the verdict (#8).
    # Ingest-validated reports always carry a list here, but a hand-recorded artifact
    # can carry null or a non-list; skip those rather than crash the enforcement
    # point (run-20260807-210733 panel, correctness-5).
    areas = set()
    for rep in reports.values():
        vals = rep.get("areas_not_reviewed")
        if isinstance(vals, list):
            areas.update(str(a) for a in vals)
    # Cost accounting + cap enforcement, read from the same recorded artifacts (E4-S2). A run
    # that panel.py aborted on the cost cap BLOCKS — the missing reviewers already do, but name
    # the cost reason explicitly so it is not mistaken for an ordinary incomplete panel.
    panel_cost_usd = 0.0
    mdir = run / "panel" / "meta"
    if mdir.is_dir():
        for p in sorted(mdir.glob("*.json")):
            panel_cost_usd += meta_cost(read_json(p))
    cost_abort = read_json(run / "cost_abort.json") if (run / "cost_abort.json").exists() else None
    if isinstance(cost_abort, dict):
        blocked.append(
            f"{cost_abort.get('phase') or 'panel'} phase aborted on cost cap "
            f"${cost_abort.get('cap_usd')} (spent ${cost_abort.get('spent_usd')}); not run: "
            f"{', '.join(str(r) for r in (cost_abort.get('not_run') or [])) or 'none'}")
    # Surface the enforced ceiling + its source (recorded by panel.py at run time) so the audit
    # shows which cap actually applied, not just total spend.
    cpol = read_json(run / "cost_policy.json") if (run / "cost_policy.json").exists() else None
    cpol = cpol if isinstance(cpol, dict) else {}
    coverage = {"risk": meta["risk"], "gates": gcov, "panel": pcov,
                "rebuttal": rcov, "findings": fcov,
                "cost_usd": round(panel_cost_usd, 6), "cost_aborted": bool(cost_abort),
                "cost_cap_usd": cpol.get("cap_usd"), "cost_cap_source": cpol.get("source"),
                "areas_not_reviewed": sorted(areas)}

    verdict = "FAIL" if fail else ("BLOCKED" if blocked else "PASS")
    # Plain-language next steps are derived from the verdict + coverage above; they are
    # read-only over that state and cannot change it (guidance, not gate).
    steps = next_steps(verdict, fail, blocked, gcov, fcov, counts)
    # Tamper-evident attestation over every recorded input, computed before the
    # verdict file exists so re-aggregating an untouched run reproduces it (#5).
    attestation = compute_attestation(run)
    out = {"verdict": verdict, "reasons": fail + blocked, "notes": notes,
           "next_steps": steps,
           "counts": counts, "coverage": coverage, "attestation": attestation,
           "risk": meta["risk"], "run_id": meta["run_id"], "computed_at": now_iso()}
    write_json(run / "verdict.json", out)

    md = [f"# Release verdict: {verdict}", "",
          f"Run `{meta['run_id']}`, risk {meta['risk']}, computed {out['computed_at']}.", ""]
    md += [f"- FAIL: {r}" for r in fail]
    md += [f"- BLOCKED: {r}" for r in blocked]
    md += [f"- note: {n}" for n in notes]
    # Plain-language guidance up top, where a non-expert will actually read it — before
    # the technical counts/coverage that follow.
    md += ["", "## Next steps", ""]
    md += [f"- {s}" for s in steps]
    md += ["", "Counts: " + ", ".join(f"{k}={v}" for k, v in counts.items())]
    reb = ("ran" if rcov["ran"] else
           ("required but missing" if rcov["required"] else "not required"))
    md += ["", f"Coverage: gates {len(gcov['passed'])}/{len(gcov['required'])} passed "
           f"({len(gcov['missing'])} missing, {len(gcov['blocked'])} blocked, "
           f"{len(gcov['not_applicable'])} n/a, {len(gcov['waived'])} waived); "
           f"panel {len(pcov['roles_filled'])}/{len(pcov['roles_required'])} roles; "
           f"rebuttal policy '{rcov['policy']}' {reb}; "
           f"findings {fcov['triaged']}/{fcov['raised']} triaged; "
           f"{len(coverage['areas_not_reviewed'])} reviewer-attested unreviewed areas"]
    # Surface every not-applicable determination and its authorizer distinctly — a
    # skipped gate must never be silent, even when it does not restrict the verdict.
    md += [f"- not applicable: gate '{na['name']}' (authorized by "
           f"{na['authorized_by']}): {na['reason']}" for na in gcov["not_applicable"]]
    md += ["", f"Attestation: sha256 {attestation['digest']} over "
           f"{attestation['inputs']} recorded artifacts "
           "(verify with `aggregate.py --check-digest`)"]
    (run / "verdict.md").write_text("\n".join(md) + "\n", encoding="utf-8")

    print(f"VERDICT: {verdict}  (risk={meta['risk']}, run={meta['run_id']})")
    for r in fail:
        print(f"  FAIL    - {r}")
    for r in blocked:
        print(f"  BLOCKED - {r}")
    for n in notes:
        print(f"  note    - {n}")
    print(f"written: {run / 'verdict.json'} and verdict.md")
    sys.exit({"PASS": 0, "FAIL": 1, "BLOCKED": 2}[verdict])


if __name__ == "__main__":
    main()
