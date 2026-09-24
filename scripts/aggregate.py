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
import re
import sys
import tempfile
from datetime import date
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _common import (POLICY_ABSENCE_SIG_FILENAME, POLICY_SIG_FILENAME, _policy_bool,
                     authenticate_risk_tier, canonical_finding_digest,
                     cosign_sign_argv as _cosign_sign_argv,
                     cosign_verify_argv as _cosign_verify_argv, family_of,
                     load_attested_policy_bundle, meta_cost,
                     minisign_sign_argv as _minisign_sign_argv,
                     minisign_verify_argv as _minisign_verify_argv, now_iso,
                     read_json, read_regular_file_once, resolve_run,
                     resolve_signing_tool as _resolve_tool, resolve_waiver_clock,
                     verify_policy_absence_signature,
                     verify_policy_snapshot_signature,
                     run_signing_tool as _run_tool, sign_fail as _sign_fail,
                     sign_timeout as _sign_timeout, validate_gate_name,
                     validate_not_applicable_gate, validate_waived_gate, write_json)

HIGH = ("critical", "high")


def load_reports(run, plan):
    reports = {}
    for role in plan.get("roles", {}):
        p = run / "panel" / f"{role}.json"
        if p.exists():
            reports[role] = read_json(p)
    return reports


def check_gates(run, tier, fail, blocked, notes, pol_data=None, clock=(None, None)):
    """Returns (results, gates_coverage). Coverage is derived from the same records
    the verdict uses — an unrecorded fact stays invisible in both.

    A waived gate stays a member of `required` (it is never dropped from the set this
    checks) and is represented as its own gates/<name>.json record with status WAIVED,
    exactly like a NOT_APPLICABLE record — so both are independently re-validated here
    from what is actually on disk (expiry, cap, authorizer, reason, CRITICAL rules),
    never trusted just because gate.py's own plan-time checks passed. `pol_data` is the
    loaded repo policy's data mapping (or {} when there is none); `clock` is the
    (clock_date, error) pair from resolve_waiver_clock, resolved once by the caller."""
    pol_data = pol_data or {}
    clock_date, clock_err = clock
    gcov = {"plan_recorded": False, "required": [], "recorded": [], "passed": [],
            "failed": [], "blocked": [], "not_applicable": [], "missing": [],
            "waived": []}
    req_path = run / "gates" / "_required.json"
    if not req_path.exists():
        blocked.append("gate plan missing — run `gate.py plan` after detecting the stack")
        return {}, gcov
    # Reject a malformed manifest document itself before treating it as a mapping: invalid
    # JSON (ValueError from json.load) or valid JSON that isn't an object (null/number/string/
    # array — read_json returns whatever json.load parses to, with no type restriction) would
    # otherwise raise AttributeError on the very next line's gplan.get(...), which check_gates'
    # caller (aggregate.py's main()) only catches at the top level as an unexpected exit-3
    # crash — never reaching the code that writes a BLOCKED verdict.json (CodeRabbit,
    # aggregate.py:73-75, "Handle malformed _required.json as BLOCKED").
    try:
        gplan = read_json(req_path)
    except (ValueError, OSError) as e:
        blocked.append(f"gate plan (_required.json) is unreadable or not valid JSON: {e}")
        return {}, gcov
    if not isinstance(gplan, dict):
        blocked.append(
            f"gate plan (_required.json) is not a JSON object (got {type(gplan).__name__}) — "
            "malformed or tampered manifest")
        return {}, gcov
    gcov["plan_recorded"] = True
    manifest_planned_at = gplan.get("planned_at")
    # The manifest `required` must be a list of safe string gate names before it is turned into
    # a list/set — a non-list ("required": 1) or an unhashable member ("required": [[]]) would
    # otherwise raise a TypeError before a BLOCKED verdict is written. Malformed entries become
    # blocking reasons; each surviving name is validated (so a tampered path/newline name is
    # rejected here, not used to build a gates/<name>.json path later).
    raw_required = gplan.get("required", [])
    if not isinstance(raw_required, list):
        blocked.append("gate plan 'required' is not a list — malformed or tampered manifest")
        raw_required = []
    required_names = []
    for g in raw_required:
        nerr = validate_gate_name(g) if isinstance(g, str) else "gate name must be a string"
        if nerr:
            # g is an untrusted, unvalidated manifest entry (that is WHY it is here — it just
            # failed validate_gate_name) — repr() escapes Python string syntax (quotes,
            # backslashes, newlines) but never HTML, so a crafted entry like
            # "<img src=x onerror=alert(1)>" still rendered its tag raw into verdict.md before
            # this fix (Codex finding #6, "a crafted waiver name renders unescaped into
            # verdict.md" — security-4, frontier-gate run pr70-design-crypto-ci-identity,
            # 2026-09-21). _oneline() HTML-escapes the whole repr'd form.
            blocked.append(f"gate plan has a malformed required entry {_oneline(repr(g))}: {nerr}")
            continue
        required_names.append(g)
    gcov["required"] = list(required_names)
    required_set = set(required_names)
    # The manifest's `waived` list must be well-formed before anything is built from it — a
    # non-list, or an entry that is not an object with a safe string `name` (an unhashable value
    # such as {"name": []}, or a newline/markdown name that could forge output, would otherwise
    # raise or leak), is a malformed/tampered manifest that must BLOCK, never crash aggregation.
    raw_waived = gplan.get("waived", [])
    manifest_waived = {}   # gate name -> its manifest waiver entry (bound against the record)
    if not isinstance(raw_waived, list):
        blocked.append("gate plan 'waived' is not a list — malformed or tampered manifest")
        raw_waived = []
    for w in raw_waived:
        if not isinstance(w, dict):
            # Same repr()-is-not-HTML-safe gap as the required-entry loop above.
            blocked.append(f"gate plan has a malformed waiver entry {_oneline(repr(w))} — expected "
                           "an object with a string 'name'")
            continue
        wn = w.get("name")
        nerr = validate_gate_name(wn) if isinstance(wn, str) else "gate name must be a string"
        if nerr:
            blocked.append(f"gate plan has a malformed waiver entry {_oneline(repr(w))}: {nerr}")
            continue
        manifest_waived[wn] = w
    manifest_waived_names = set(manifest_waived)
    # Legacy/tampered-plan guard: pre-M1 plans DROPPED a waived gate from `required` and
    # recorded it only in the manifest's `waived` list, so the loop below never checked it —
    # a SENSITIVE run could pass with no mutation gate at all. Any waived entry whose gate is
    # absent from `required` means the manifest predates the waiver-hardening (or was edited
    # to drop a gate); BLOCK and require re-planning rather than honoring it.
    for wname in manifest_waived_names:
        if wname not in required_set:
            blocked.append(
                f"legacy or tampered gate plan: gate '{wname}' is waived but missing from the "
                "required set — pre-M1 waivers that drop the gate are not honored; re-run "
                "`gate.py plan` with the current version to migrate (waived gates now stay "
                "required and are independently re-validated)")
    results = {}
    for name in required_names:   # already validated as safe gate-name strings above
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
        if status == "WAIVED":
            # A WAIVED record must be authorized by the plan manifest's `waived` list. A record
            # present without a matching manifest entry is an orphan — e.g. a stale record a
            # concurrent replan failed to revoke, or one dropped from the final manifest — and
            # honoring it would be a hollow-green result, so BLOCK.
            if name not in manifest_waived_names:
                reason = ("WAIVED record is not authorized by the plan manifest's waived list "
                          "(orphaned or raced waiver) — re-run `gate.py plan`")
                gcov["blocked"].append({"name": name, "reason": reason})
                blocked.append(f"gate '{name}': {_oneline(reason)}")
                continue
            # Bind the record to the manifest entry's METADATA, not just the name: gate.py writes
            # the manifest and the record separately, so a concurrent replan could pair a short
            # manifest entry with a longer stale record. Its authorizer/reason/expiry must match
            # what the final manifest authorized, or the record is raced/tampered → BLOCK.
            m = manifest_waived.get(name, {})
            if (rec.get("expires") != m.get("expires")
                    or rec.get("authorized_by") != m.get("authorized_by")
                    or rec.get("reason") != m.get("reason")):
                reason = ("WAIVED record does not match the plan manifest's waiver entry "
                          "(authorizer/reason/expiry mismatch — raced or tampered) — "
                          "re-run `gate.py plan`")
                gcov["blocked"].append({"name": name, "reason": reason})
                blocked.append(f"gate '{name}': {_oneline(reason)}")
                continue
            # A waiver's expiry can only be judged against a trustworthy clock — if the
            # CI-provided clock itself could not be parsed, no waiver can be honestly
            # evaluated, so every waived gate is BLOCKED rather than silently guessing
            # 'today' (fail closed; see resolve_waiver_clock).
            err = (f"cannot verify waiver expiry: {clock_err}" if clock_date is None
                   else validate_waived_gate(name, tier, rec, pol_data, clock_date,
                                             manifest_planned_at=manifest_planned_at))
            if err:
                gcov["blocked"].append({"name": name, "reason": err})
                # security-4 (frontier-gate run pr70-design-crypto-ci-identity, 2026-09-21,
                # Codex finding #6): `err` can embed RAW rec-supplied content (e.g.
                # validate_waived_gate's `expires {rec.get('expires')!r} is missing or not a
                # valid...` message repr()s the untrusted `expires` field verbatim -- repr()
                # only escapes Python string syntax, never HTML) -- HTML-escape before this
                # reaches verdict.md, which renders `blocked` entries raw (unlike the
                # `notes`/waived/not_applicable display dicts elsewhere in this function,
                # which are already escaped at md-render time via _oneline).
                blocked.append(f"gate '{name}': {_oneline(err)}")
            else:
                who = rec.get("authorized_by").strip()
                reason = rec.get("reason").strip()
                expires = rec.get("expires")
                gcov["waived"].append({"name": name, "authorized_by": who, "reason": reason,
                                       "expires": expires, "tier": tier})
                notes.append(f"gate '{name}' waived by {who} until {expires}: {reason}")
        elif status == "BLOCKED":
            reason = rec.get("summary", "could not verify")
            gcov["blocked"].append({"name": name, "reason": reason})
            # security-4 (Codex finding #6): `summary` is free-text from an untrusted
            # gates/<name>.json record (an adversarial run directory can write anything
            # here) and was previously interpolated into `blocked` -- which verdict.md
            # renders RAW -- with no escaping at all, letting a crafted summary like
            # "<img src=x onerror=alert(1)>" render as live markup in the report.
            blocked.append(f"gate '{name}' blocked: {_oneline(reason)}")
        elif status == "NOT_APPLICABLE":
            # A gate that genuinely does not apply to this stack does NOT restrict the
            # verdict — but it is an accountable, on-record determination, so an invalid
            # N/A record (missing authorizer/reason, or one of the CRITICAL restrictions)
            # is itself a BLOCK (unaccountable skips are exactly what this pipeline exists
            # to prevent).
            err = validate_not_applicable_gate(name, tier, rec, pol_data)
            if err:
                gcov["blocked"].append({"name": name, "reason": err})
                blocked.append(f"gate '{name}': {_oneline(err)}")
            else:
                # Guard against non-string values (JSON null, numbers, objects): a `null`
                # authorizer must read as absent, not as the string "None" — already
                # enforced by validate_not_applicable_gate, re-derived here only to build
                # the coverage entry from the same (now known-good) strings.
                who = rec.get("authorized_by").strip()
                reason = rec.get("summary").strip()
                gcov["not_applicable"].append(
                    {"name": name, "authorized_by": who, "reason": reason})
                notes.append(f"gate '{name}' not applicable (authorized by {who}): {reason}")
        elif rec.get("exit_code") is None:
            gcov["blocked"].append({"name": name, "reason": "recorded without an exit code"})
            blocked.append(f"gate '{name}' recorded without an exit code")
        elif status == "FAIL" or rec["exit_code"] != 0:
            gcov["failed"].append(name)
            # security-4 (Codex finding #6): same untrusted, unescaped `summary` gap as the
            # BLOCKED branch above -- a crafted gates/<name>.json FAIL record's summary
            # previously rendered raw into verdict.md's `- FAIL:` bullet.
            fail.append(f"gate '{name}' failed (exit {rec['exit_code']}): {_oneline(rec.get('summary', ''))}")
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


# A finding id is reviewer-model output, not trusted input. jev_triage.py's own
# _safe_finding_id() only ever writes triage/<id>.json under this exact charset
# (rejecting path separators, "..", and the reserved "_summary" name) -- this MUST
# stay identical to jev_triage.py's _SAFE_FID_RE, or a legitimate id could be
# silently skipped here, or (if ever loosened) a traversal-shaped id could read a
# file outside triage/.
_SAFE_TRIAGE_FID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_RESERVED_TRIAGE_NAME = "_summary"


def collect_jev_priors(run, reports):
    """{finding_id: triage-record} for every finding with a recorded
    triage/<finding-id>.json (`jev_triage.py triage` ran for this run). Missing or
    malformed records are simply absent from the result — this is display-only for
    verdict.md; it never feeds fail/blocked/notes, so a bad or absent triage record
    changes nothing about the computed verdict. An id outside jev_triage.py's own
    safe charset (or the reserved _summary name) is skipped, never used as a path —
    jev_triage.py would have written such a finding's record under a fallback
    filename, never under the untrusted id itself."""
    tdir = run / "triage"
    out = {}
    if not tdir.is_dir():
        return out
    for rep in reports.values():
        for f in rep.get("findings", []) if isinstance(rep.get("findings"), list) else []:
            if not isinstance(f, dict):
                continue
            fid = f.get("id")
            if (not isinstance(fid, str) or not fid or fid in out
                    or not _SAFE_TRIAGE_FID_RE.match(fid)
                    or fid == _RESERVED_TRIAGE_NAME):
                continue
            p = tdir / f"{fid}.json"
            if not p.exists():
                continue
            try:
                rec = read_json(p)
            except (OSError, ValueError):
                continue
            if not (isinstance(rec, dict) and isinstance(rec.get("jev"), dict)):
                continue
            jv = rec["jev"]
            # A triage/<id>.json file is on-disk data, not this process's own recent
            # output (it could be from an older schema, hand-edited, or corrupted) -- the
            # verdict.md renderer below indexes into severity/duplicate_of as dicts, so
            # validate that shape here rather than let a malformed field crash aggregate.py
            # entirely (this function's own contract is "malformed records are simply
            # absent from the result").
            if jv.get("severity") is not None and not isinstance(jv["severity"], dict):
                continue
            if jv.get("duplicate_of") is not None and not isinstance(jv["duplicate_of"], dict):
                continue
            if jv.get("is_real") is not None and not isinstance(jv["is_real"], (int, float)):
                continue
            out[fid] = rec
    return out


REBUTTAL_SCOPE = {
    "critical": {"CRITICAL"},
    "contention": {"SENSITIVE", "CRITICAL"},
    "any": {"NORMAL", "SENSITIVE", "CRITICAL"},
}


def _rebuttal_jev_gate(run, reports):
    """The recorded decision from `jev_triage.py rebuttal-gate` (rebuttal/plan.json), if
    present, well-formed, AND covering every real high/critical finding in this run's own
    panel reports -- else None, which means "fall back to the pre-Jev blanket rule"
    exactly (see check_rebuttal). Jev's own numbers never reach here: this reads only the
    CLI-recorded 'required_finding_ids'/'skipped_finding_ids' lists (plus their digest
    counterparts, see below), and that recording is itself fail-closed (any Jev error ->
    the finding lands in required_finding_ids) — so a malformed or tampered file can only
    ever make MORE rebuttal required, never less, once it fails validation and is treated
    as absent.

    Coverage is bound to a canonical CONTENT digest per finding
    (_common.canonical_finding_digest: title/file/line/severity/evidence/scenario/
    author_role, normalized) — not to the finding's 'id' alone. Ids are reviewer-model
    output, not guaranteed stable or unique across a `panel.py run --force` re-run of the
    SAME run directory: an id-only coverage check let a stale rebuttal/plan.json from an
    earlier invocation "cover" a completely different finding that happened to reuse the
    same conventional id (e.g. 'security-1'), with no Jev call ever having evaluated the
    new content. A plan.json written before this digest binding existed (missing
    required_finding_digests/skipped_finding_digests, or a digest list whose length
    doesn't match its id list) cannot be verified this way and is treated as absent —
    fall back to the pre-Jev blanket rule, same as any other malformed/incomplete gate
    file. The id lists are still returned (rcov reads them for the audit trail) but the
    coverage DECISION below is made on digests alone."""
    path = run / "rebuttal" / "plan.json"
    if not path.exists():
        return None
    try:
        g = read_json(path)
    except (OSError, ValueError):
        return None
    if not isinstance(g, dict):
        return None
    ids = g.get("required_finding_ids")
    if not isinstance(ids, list) or not all(isinstance(x, str) for x in ids):
        return None
    skipped = g.get("skipped_finding_ids")
    if not isinstance(skipped, list) or not all(isinstance(x, str) for x in skipped):
        skipped = []
    req_digests = g.get("required_finding_digests")
    if not isinstance(req_digests, list) or not all(isinstance(x, str) for x in req_digests) \
            or len(req_digests) != len(ids):
        return None
    skip_digests = g.get("skipped_finding_digests")
    if not isinstance(skip_digests, list) or not all(isinstance(x, str) for x in skip_digests) \
            or len(skip_digests) != len(skipped):
        return None
    real_hc = [dict(f, author_role=role) for role, rep in reports.items()
               for f in (rep.get("findings") or []) if isinstance(f, dict)
               and f.get("severity") in HIGH and isinstance(f.get("id"), str)]
    real_digests = {canonical_finding_digest(f) for f in real_hc}
    covered = set(req_digests) | set(skip_digests)
    if not real_digests <= covered:
        return None  # gate doesn't account, by content, for every real high/critical finding
    return {"required_finding_ids": ids, "skipped_finding_ids": skipped,
            "required_finding_digests": req_digests, "skipped_finding_digests": skip_digests}


def check_rebuttal(run, meta, plan, reports, blocked, notes):
    """Rebuttal is required when the tier is in the policy's scope AND there is
    something to contest. Cost scales with contention. Returns rebuttal coverage.

    "Something to contest" is, by default, every high/critical finding raised by the
    panel — unchanged from before Jev triage existed. When `jev_triage.py rebuttal-gate`
    has run, its recorded decision (rebuttal/plan.json) narrows this to the specific
    findings it flagged contested/outcome-changing (fail-closed: any Jev error keeps a
    finding in the required set) — Jev only reduces which findings must be contested,
    never whether the rebuttal MECHANISM (per-role reproduction/evidence, Step 4) still
    applies to every one of them. Absent or malformed rebuttal/plan.json is byte-identical
    to a run that never used Jev triage at all."""
    policy = meta.get("rebuttal_policy", "contention")
    scope = REBUTTAL_SCOPE.get(policy, REBUTTAL_SCOPE["contention"])
    any_high_critical = any(f["severity"] in HIGH
                            for rep in reports.values() for f in rep.get("findings", []))
    gate = _rebuttal_jev_gate(run, reports)
    contested = bool(gate["required_finding_ids"]) if gate is not None else any_high_critical
    required = meta["risk"] in scope and contested
    ran = bool(plan.get("roles")) and all(
        (run / "rebuttal" / f"{r}.json").exists() for r in plan.get("roles", {}))
    rcov = {"policy": policy, "required": required, "ran": ran}
    if gate is not None:
        rcov["jev_gate"] = gate
    if not required:
        if contested:
            notes.append(f"rebuttal not required at {meta['risk']} under policy '{policy}'")
        elif gate is not None and any_high_critical:
            notes.append(f"rebuttal gated by jev triage: {len(gate['skipped_finding_ids'])} "
                         "high/critical finding(s) did not require contest")
        return rcov
    missing = [r for r in plan.get("roles", {})
               if not (run / "rebuttal" / f"{r}.json").exists()]
    if missing:
        # `policy` is meta['rebuttal_policy'] (attacker-editable run.json in an untrusted run
        # dir) looked up with .get(policy, default) -- no charset restriction -- so it can
        # carry arbitrary text; escape it before this reaches `blocked`, which verdict.md
        # renders raw (security-4, same class as Codex finding #6). `missing` role names come
        # from panel.py's fixed role catalog, not free-form attacker text.
        # CodeRabbit 4077668514 (Minor, valid): `meta['risk']` is the same class of
        # attacker-editable run.json value as `policy` right above it, but was rendered
        # raw here — repr() escapes Python syntax, not HTML, so a crafted risk value
        # could forge markup in verdict.md exactly like the un-escaped `policy` case
        # this comment already guards against. _oneline() it the same way.
        blocked.append(f"rebuttal round required (policy '{_oneline(policy)}', risk "
                       f"{_oneline(repr(meta['risk']))}, high/critical findings present); "
                       f"missing for: {', '.join(missing)}")
    return rcov


# Canonicalizing an artifact requires json.loads, whose RecursionError threshold on a deeply nested
# document is VERSION-DEPENDENT: the same artifact can parse (and be canonical-hashed) on one Python
# but raise RecursionError (and be raw-hashed) on another, so a portable verdict would report false
# DRIFT across versions. Decide raw-vs-canonical from a FIXED, version-independent nesting cap measured
# from the bytes instead of from whether json.loads happens to raise. The cap sits far below the default
# recursion limit (so any artifact at or under it parses on every supported Python) and far above any
# legitimate artifact's depth (the tool's own records are a handful of levels deep), so real artifacts
# are always canonicalized and only pathologically deep ones take the raw path — identically on every
# version. (Codex, 8c999b9.)
_MAX_CANON_DEPTH = 200

# Algorithm id stamped into every attestation. It is bumped whenever the canonical-vs-raw REPRESENTATION
# changes, so --check-digest can date a stored attestation from the id alone (never by re-parsing an
# artifact, which is runtime-dependent). "v4" additionally folds POLICY_ABSENCE_SIG_FILENAME
# (policy.absence.sig, GAP A part 2 -- the signed no-policy attestation) into the digest as a raw-hashed
# input, the same way "v3" already did for POLICY_SIG_FILENAME (policy.snapshot.sig): GAP A introduced a
# SECOND non-JSON, pre-verdict signature sidecar without ever teaching compute_attestation() to hash it,
# reintroducing under a new filename the exact gap a delayed Codex review on PR70 found and closed for
# policy.snapshot.sig (deleting the sidecar destroyed the evidence a PASS with a WAIVED/NOT_APPLICABLE
# gate relied on, invisibly to --check-digest, because the pre-v3 *.json-only glob never saw it). "v3"
# covers policy.snapshot.sig; "v2" marks the byte-based raw policy (depth AND integer-width caps); "v1"
# verdicts predate all of that. The id is metadata, NOT folded into the digest, so bumping it does not
# change any digest for a run that doesn't have the new input — an unchanged run with no
# policy.absence.sig verifies identically under v3 or v4. (Codex r3930239157 / security-3 follow-up,
# frontier-gate run pr70-design-crypto-ci-identity, 2026-09-21.)
_ATTESTATION_ALGO = "sha256-canonical-json-v4"

# Attestation algorithm ids this version can interpret in --check-digest: the current one plus recognized
# PREDECESSORS. "sha256-canonical-json-v1" is the pre-byte-cap representation (a deep/wide artifact it
# canonicalized, this version hashes "raw:"). "sha256-canonical-json-v2" predates policy.snapshot.sig
# coverage. "sha256-canonical-json-v3" predates policy.absence.sig coverage. An id OUTSIDE this set — a
# newer tool's format, or a malformed/non-string value — is not interpretable, so on a digest mismatch it
# is cannot-verify, never classified as a legacy transition or as drift. (CodeRabbit r3930631485.)
_LEGACY_ALGOS = ("sha256-canonical-json-v1", "sha256-canonical-json-v2", "sha256-canonical-json-v3")
_RECOGNIZED_ALGOS = _LEGACY_ALGOS + (_ATTESTATION_ALGO,)

# Ordering of every algorithm id this version has ever produced or still recognizes, oldest first — used
# ONLY by _sidecar_newly_covered_transition() below to tell "this predecessor algorithm never covered this
# sidecar artifact at all" apart from "this predecessor covered it and the hash changed" (real drift).
_ALGO_ORDER = _LEGACY_ALGOS + (_ATTESTATION_ALGO,)

# The two non-JSON, pre-verdict signature sidecars this tool has ever hashed into the attestation, mapped
# to the FIRST algorithm id whose compute_attestation() began covering each one. This table only feeds the
# legacy-transition classifier in check_digest() — compute_attestation() itself always hashes whichever of
# these exist on disk right now, unconditionally, regardless of this table.
_SIDECAR_COVERAGE_INTRODUCED_AT = {
    POLICY_SIG_FILENAME: "sha256-canonical-json-v3",
    POLICY_ABSENCE_SIG_FILENAME: "sha256-canonical-json-v4",
}

# A JSON integer literal wider than this many digits is routed to the raw path, for the same
# version-independence reason as the depth cap: whether json.loads ACCEPTS a very long integer depends on
# the runtime's integer-string-conversion limit (sys.get_int_max_str_digits / PYTHONINTMAXSTRDIGITS) — a
# per-interpreter CONFIG, not a property of the bytes — so the same artifact canonicalizes under one
# configuration and raises ValueError (-> raw) under another, and a portable verdict would report false
# DRIFT across configurations. The cap sits far below the smallest limit the runtime permits
# (sys.int_info.str_digits_check_threshold, 640) so any artifact at or under it parses on EVERY
# configuration, and far above any legitimate artifact's integers (the tool's own records hold small
# counts and timestamps), so real artifacts are always canonicalized and only pathologically wide ones
# take the raw path — identically everywhere. (Codex r3930239161.)
_MAX_INT_DIGITS = 256


def _max_int_digit_run(raw):
    """Longest run of consecutive ASCII decimal digits OUTSIDE JSON strings, computed purely from the
    bytes so it is identical on every runtime. A JSON integer literal is a digit run, so this bounds the
    widest integer the artifact can ask json.loads to build; digits inside strings never become integers
    and are skipped. Over-counting a long fraction or exponent run only routes an already-pathological
    artifact to the (deterministic) raw path, which is harmless. Mirrors _json_nesting_depth's string
    handling; structural/quote bytes are ASCII, so a byte scan is correct despite multi-byte UTF-8 in
    strings."""
    run = maxrun = 0
    in_str = escaped = False
    for b in raw:
        c = chr(b)
        if in_str:
            run = 0
            if escaped:
                escaped = False
            elif c == "\\":
                escaped = True
            elif c == '"':
                in_str = False
        elif c == '"':
            run = 0
            in_str = True
        elif "0" <= c <= "9":
            run += 1
            if run > maxrun:
                maxrun = run
        else:
            run = 0
    return maxrun


def _json_nesting_depth(raw):
    """Maximum [/{ nesting depth of JSON bytes, ignoring brackets inside strings. Computed purely from
    the bytes, so it is identical on every Python version. Structural characters are ASCII, so a byte
    scan is correct regardless of multi-byte UTF-8 sequences inside strings (their bytes are all >=
    0x80 and never match a structural character)."""
    depth = maxd = 0
    in_str = escaped = False
    for b in raw:
        c = chr(b)
        if in_str:
            if escaped:
                escaped = False
            elif c == "\\":
                escaped = True
            elif c == '"':
                in_str = False
        elif c == '"':
            in_str = True
        elif c in "[{":
            depth += 1
            if depth > maxd:
                maxd = depth
        elif c in "]}":
            if depth > 0:
                depth -= 1
    return maxd


def compute_attestation(run):
    """Reproducible SHA-256 over every recorded JSON artifact that can feed the
    verdict — everything except verdict.json, which is the output (#5).

    Each artifact is canonicalized (sorted keys, compact separators) so cosmetic
    re-serialization does not read as tampering; a .json file that fails UTF-8
    decoding or JSON parsing — both treated identically, by design — or whose bytes
    exceed a fixed cap on nesting depth OR integer-literal width is hashed over its
    raw bytes instead of crashing the enforcement point. The
    per-file hashes are folded into one manifest digest, and returned alongside it
    so --check-digest can name exactly which artifact drifted.
    Same untouched run in, same digest out — bit for bit, from the BYTES, so the raw-vs-canonical choice
    never depends on a per-runtime parser limit (recursion depth or integer-string width)."""
    files = {}
    # POLICY_SIG_FILENAME (policy.snapshot.sig) and POLICY_ABSENCE_SIG_FILENAME
    # (policy.absence.sig) are non-JSON, PRE-verdict artifacts — both are written by panel.py
    # at init, well before this function ever runs, so hashing them here is not circular
    # (unlike SIG_FILENAME/attestation.sig below, which signs THIS digest and so must stay
    # excluded). Hash each as raw bytes, same as any other artifact that can't be
    # JSON-canonicalized, so deleting either one (destroying the evidence a WAIVED/
    # NOT_APPLICABLE PASS, or a no-policy PASS, relied on) changes the digest instead of being
    # invisible to it. (Codex, PR70 review, frontier-gate run pr70-provenance-2 for
    # policy.snapshot.sig; the same gap reappeared for policy.absence.sig when GAP A introduced
    # it without extending this coverage, closed here — frontier-gate run
    # pr70-design-crypto-ci-identity, 2026-09-21.)
    #
    # Codex 4077803884 (P2, valid): Path.is_file()/.read_bytes() both follow a symlink at
    # the leaf, with no size cap — an actor with concurrent write access to the run
    # directory could replace either sidecar with a symlink to an arbitrary large regular
    # file this process can read, and this loop would hash (and, for --check-digest,
    # accept) that external content with no bound on how much it reads. Read it the
    # hardened way instead (read_regular_file_once: no-follow at the leaf, size-capped,
    # the same reader every other artifact in this codebase already uses) — a symlinked/
    # oversized sidecar then raises NotRegularFileError (an OSError), which this
    # function's own caller already treats as "cannot verify" (exit 2), exactly like any
    # other artifact it cannot safely read; only a genuinely MISSING sidecar (the
    # ordinary case for most runs) is still silently skipped, same as before this fix.
    for sig_filename in (POLICY_SIG_FILENAME, POLICY_ABSENCE_SIG_FILENAME):
        try:
            raw = read_regular_file_once(run / sig_filename)
        except FileNotFoundError:
            continue
        files[sig_filename] = "raw:" + hashlib.sha256(raw).hexdigest()
    for p in sorted(run.rglob("*.json")):
        rel = p.relative_to(run).as_posix()
        if rel == "verdict.json":
            continue
        # Same hardening as the sidecar loop above, for the same reason — a symlinked
        # tracked-JSON artifact must not be read through, and reading it the hardened way
        # here also closes a second symlink bypass beyond what Codex 4077803884 named:
        # rglob("*.json") matches by name, so it can list a symlink too, and the previous
        # plain p.read_bytes() would have followed it exactly like the two sidecars did. A
        # refusal here is an OSError, which propagates to this function's own caller and is
        # already treated as "cannot verify," never silently absorbed or misread as drift.
        raw = read_regular_file_once(p)
        if _json_nesting_depth(raw) > _MAX_CANON_DEPTH or _max_int_digit_run(raw) > _MAX_INT_DIGITS:
            # Nested beyond the depth cap, OR carrying an integer literal wider than the digit cap:
            # whether json.loads accepts either hinges on a PER-RUNTIME limit (the RecursionError
            # threshold, or the integer-string-conversion limit), so canonicalizing would make the same
            # artifact hash canonically on one runtime/config and raw on another — a portable verdict
            # would then report false DRIFT. Decide raw-vs-canonical from the BYTES, before parsing, so
            # the choice is identical everywhere. (Codex, 8c999b9 & r3930239161.)
            files[rel] = "raw:" + hashlib.sha256(raw).hexdigest()
            continue
        try:
            canon = json.dumps(json.loads(raw.decode("utf-8")), sort_keys=True,
                               separators=(",", ":"), ensure_ascii=False)
            files[rel] = hashlib.sha256(canon.encode("utf-8")).hexdigest()
        except (ValueError, UnicodeDecodeError, RecursionError):
            # A .json artifact that fails UTF-8 decoding or JSON parsing is hashed over its RAW bytes
            # rather than crashing the enforcement point. The byte caps above already route a deep or
            # wide-integer artifact to the raw path BEFORE this parse, so for those known runtime-limited
            # cases which branch is taken no longer depends on the Python version or config; this stays
            # as a defensive net for any other parse failure. (Codex, 60cb2c3 & 8c999b9 & r3930239161.)
            files[rel] = "raw:" + hashlib.sha256(raw).hexdigest()
    manifest = "\n".join(f"{sha}  {rel}" for rel, sha in sorted(files.items()))
    digest = hashlib.sha256(manifest.encode("utf-8")).hexdigest()
    return {"algorithm": _ATTESTATION_ALGO, "inputs": len(files),
            "digest": digest, "files": files}


def _canon_to_raw_transition(stored_hash, recomputed_hash):
    """True iff one attestation entry differs in exactly the shape of the canonical->raw REPRESENTATION
    change: the stored hash is a plain canonical hash (a str not prefixed "raw:") and the recomputed hash
    is a "raw:" hash. Purely a comparison of the two recorded strings — it never re-reads or re-parses the
    artifact, so it is identical on every runtime (that runtime-independence is the whole point; the
    earlier positive-proof re-canonicalization was itself runtime-dependent). Real tampering that changes
    an artifact's CONTENT while it stays canonical (canonical->different-canonical) is not this shape, so
    it is never mistaken for the benign transition. (Codex r3930239157 / CodeRabbit r3930172612.)"""
    return (isinstance(stored_hash, str) and not stored_hash.startswith("raw:")
            and isinstance(recomputed_hash, str) and recomputed_hash.startswith("raw:"))


def _sidecar_newly_covered_transition(rel, stored_algo, stored_hash, recomputed_hash):
    """True iff one attestation entry differs in exactly the shape of "a known non-JSON
    signature sidecar that the CURRENT algorithm hashes was not tracked as an input AT ALL
    under stored_algo" -- i.e. `rel` is a key in _SIDECAR_COVERAGE_INTRODUCED_AT, stored_algo
    predates the algorithm version that introduced that sidecar's coverage, the artifact was
    simply ABSENT from the OLD manifest (stored_hash is None -- never hashed under that
    algorithm, not hashed-and-then-different), and the recompute now has a raw: hash for it.

    Deliberately narrow, same shape as _canon_to_raw_transition above: never true for an
    existing key whose hash changed, and never true for a key stored_algo already knew to
    hash (a genuine change there is real drift, exit 1, exactly as before this function
    exists). Real tampering that DELETES a sidecar stored_algo already covered, or that
    modifies one while keeping the filename, is not this shape.

    Codex finding #7 (frontier-gate run pr70-design, 2026-09-21 status-correction review): a
    legitimate algorithm-version transition that starts covering an artifact which simply did
    not exist as a tracked input under the old algorithm was misreported as tampering ("DRIFT
    added policy.snapshot.sig", exit 1) instead of cannot-verify (exit 2) -- the exact same
    class of false positive _canon_to_raw_transition already prevents for the byte-cap
    representation change, generalized here to cover "a whole new tracked artifact" rather
    than only "an existing one's hash format changed"."""
    introduced_at = _SIDECAR_COVERAGE_INTRODUCED_AT.get(rel)
    if introduced_at is None:
        return False
    try:
        stored_idx = _ALGO_ORDER.index(stored_algo)
        introduced_idx = _ALGO_ORDER.index(introduced_at)
    except ValueError:
        return False
    return (stored_idx < introduced_idx and stored_hash is None
            and isinstance(recomputed_hash, str) and recomputed_hash.startswith("raw:"))


def check_digest(run):
    """Recompute the attestation and compare to the one stored in verdict.json.
    Exit 0 on match; exit 1 (DRIFT) when artifacts changed after the verdict was computed; exit 2
    (cannot-verify) when the stored attestation cannot be read or compared, when its algorithm id is not
    one this version recognizes (a newer/unknown/malformed id), OR when the id is a recognized predecessor
    AND every differing artifact is a canonical->raw representation transition (unverifiable from the
    recorded hashes) — re-aggregate under the current algorithm, then re-check."""
    vpath = run / "verdict.json"
    if not vpath.exists():
        print("no verdict.json in run — aggregate first")
        sys.exit(2)
    try:
        verdict = read_json(vpath)
    except (OSError, ValueError, RecursionError) as e:
        # A malformed/unreadable verdict.json means the stored attestation cannot even be READ, so
        # nothing was compared: that is "cannot verify" (exit 2), never a definitive mismatch (exit
        # 1). Exit 1 is reserved for a recomputed attestation that DID compare and differed — the MCP
        # wrapper maps exit 1 to {"intact": false}, so leaking a read failure as 1 would report an
        # unreadable verdict as detected tampering. A pathologically deep verdict.json makes json.loads
        # raise RecursionError (a RuntimeError subclass, NOT ValueError); catch it here too so that
        # distinct parser failure is cannot-verify, not a crash the wrapper reads as drift. (Codex,
        # 60cb2c3.)
        print(f"cannot read verdict.json ({e}) — re-aggregate before checking the digest",
              file=sys.stderr)
        sys.exit(2)
    if not isinstance(verdict, dict):
        # Valid JSON that is not an object (e.g. a list) has no attestation to compare — that is
        # cannot-verify (exit 2), not a crash that would leak to the wrapper as exit 1 "drifted".
        print("verdict.json is not a JSON object — re-aggregate before checking the digest",
              file=sys.stderr)
        sys.exit(2)
    stored = verdict.get("attestation")
    if not stored or not isinstance(stored, dict):
        # Missing, empty, OR a present-but-wrong-shape attestation (a truthy non-dict would otherwise
        # crash on stored.get(...) below and leak as exit 1). All are "cannot verify" (exit 2).
        print("verdict.json carries no attestation (computed before #5) — re-aggregate")
        sys.exit(2)
    if not isinstance(stored.get("digest"), str) or not isinstance(stored.get("files"), dict):
        # `attestation` being a dict is not enough: the equality below needs a string `digest` to
        # compare, and the drift report needs a dict `files` for set()/`.get()`. A record lacking a
        # string digest (e.g. legacy, "computed before #5") makes that equality false and falls through
        # to the exit-1 mismatch path — misreporting an UNVERIFIABLE record as drift — and a non-dict
        # `files` makes set(old)/old.get() raise and leak to the wrapper as exit 1 too. Neither is a
        # real recomputed mismatch, so both are cannot-verify (exit 2), never 1.
        print("verdict.json attestation lacks a string digest or dict files (computed before #5, or "
              "malformed) — re-aggregate before checking the digest", file=sys.stderr)
        sys.exit(2)
    try:
        att = compute_attestation(run)
    except OSError as e:
        # Recomputing the attestation reads every recorded .json artifact (compute_attestation ->
        # p.read_bytes). An OSError here — a broken symlink, a vanished file, a permission denial —
        # means the CURRENT artifacts could not even be READ, so nothing was compared. That is
        # cannot-verify (exit 2), never a definitive mismatch (exit 1). compute_attestation folds a
        # bytes-undecodable file INTO the digest (ValueError/UnicodeDecodeError), but an OSError is a
        # read failure, not undecodable content; leaving it unguarded exited the process 1 and the MCP
        # wrapper maps exit 1 to {"intact": false} — reporting an unreadable artifact as detected drift.
        print(f"cannot recompute attestation ({e}) — a recorded artifact could not be read; "
              "re-aggregate before checking the digest", file=sys.stderr)
        sys.exit(2)
    # Validate the stored algorithm id BEFORE comparing digests. Only _ATTESTATION_ALGO (current) and the
    # recognized predecessors in _LEGACY_ALGOS are interpretable; an unknown, FUTURE, or malformed id (a
    # newer tool's format, or a non-string) means this version cannot interpret the stored representation.
    # Checking it AHEAD of the digest-equality exit-0 below is required: a record whose algorithm id was
    # changed to an unrecognized value while its digest still equals the recompute would otherwise report
    # "attestation OK" (exit 0) for a representation this version does not understand. An unrecognized id is
    # ALWAYS cannot-verify (exit 2) — whether or not the digest matches — and is never classified as a known
    # legacy transition or as drift. (CodeRabbit r3930631485; matching-digest case, Codex r3941637877.)
    stored_algo = stored.get("algorithm")
    if stored_algo not in _RECOGNIZED_ALGOS:
        print(f"attestation CANNOT BE VERIFIED: the stored attestation's algorithm id ({stored_algo!r}) "
              f"is not one this version recognizes ({', '.join(_RECOGNIZED_ALGOS)}) — it was produced by "
              "a different (newer or unknown) tool version, so this tool cannot interpret its "
              "representation. Re-aggregate under the current algorithm, then re-check.", file=sys.stderr)
        sys.exit(2)
    if att["digest"] == stored.get("digest"):
        print(f"attestation OK: sha256 {att['digest']} over {att['inputs']} artifacts")
        sys.exit(0)
    old = stored.get("files", {})
    drifted = [(rel, old.get(rel), att["files"].get(rel))
               for rel in sorted(set(old) | set(att["files"]))
               if old.get(rel) != att["files"].get(rel)]
    # Legacy-compat (version-gated, runtime-INDEPENDENT): a verdict written by a RECOGNIZED PREDECESSOR
    # (_LEGACY_ALGOS — before the byte-based raw policy) stored a plain canonical hash for a deep or
    # wide-integer artifact that this version now hashes "raw:", so the manifest differs. Gate on the id
    # being a recognized predecessor PLUS the canonical->raw hash-prefix shape — NEVER by re-parsing the
    # artifact to prove byte-equality, which would reintroduce the exact runtime dependence this avoids
    # (canonicalizing a deep artifact RecursionErrors on a lower-limit runtime; a wide integer trips the
    # integer-string limit). A canonical->raw transition is UNVERIFIABLE, not proven-unchanged: from the
    # recorded hashes alone this tool cannot tell a benign representation change from a real modification
    # that kept the artifact beyond the cap (deep -> different-deep is still canonical->"raw:"). So report
    # cannot-verify (exit 2) — which is a tool error, NEVER an "intact" pass, so tampering is never let
    # through; re-aggregation then yields a fresh, fully-verifiable current-algorithm verdict. Reporting
    # DRIFT here instead would false-alarm on an UNCHANGED legacy artifact (the case fix-19 was created to
    # fix), and a runtime-independent re-canonicalization of a deep artifact does not exist. A CURRENT
    # -algorithm verdict is NEVER routed here: a canonical->raw mismatch on it is real DRIFT (exit 1).
    # (Codex r3930666148 / CodeRabbit r3930631493, <FIX21>; corrects fix-20's "unchanged" overstatement.)
    #
    # A SECOND, independent legacy shape is checked alongside it: _sidecar_newly_covered_transition
    # (Codex finding #7, frontier-gate run pr70-design, 2026-09-21) — a differing artifact that is a known
    # signature sidecar the CURRENT algorithm hashes, but that stored_algo never tracked as an input at
    # all (added, not hash-format-changed). Both shapes are per-artifact and mutually exclusive by
    # construction (one requires an existing old hash, the other requires none), so `any()` per item is
    # correct — but EVERY differing artifact must match one shape or the other for the whole record to be
    # legacy-unverifiable; a single artifact outside both shapes still routes the entire record to DRIFT.
    if (drifted and stored_algo in _LEGACY_ALGOS
            and all(_canon_to_raw_transition(a, b) or _sidecar_newly_covered_transition(rel, stored_algo, a, b)
                    for rel, a, b in drifted)):
        for rel, a, b in drifted:
            if _sidecar_newly_covered_transition(rel, stored_algo, a, b):
                print(f"  LEGACY   {rel} (not covered by the attestation algorithm that produced this "
                      "record; unverifiable from the recorded hashes)")
            else:
                print(f"  LEGACY   {rel} (canonical->raw transition from a pre-{_ATTESTATION_ALGO} "
                      "attestation; unverifiable from the recorded hashes)")
        print("attestation CANNOT BE VERIFIED: the stored attestation was produced by an earlier "
              "algorithm and every differing artifact is either a canonical->raw representation "
              "transition or a signature sidecar that algorithm never tracked as an input at all. The "
              "recorded hashes cannot establish whether the content is unchanged (a benign version "
              "transition) or was modified — this tool cannot tell them apart without a runtime-dependent "
              "re-parse, or (for a newly-covered sidecar) without ever having hashed it in the first "
              "place. Re-aggregate under the current algorithm to obtain a verifiable verdict, then "
              "re-check.", file=sys.stderr)
        sys.exit(2)
    for rel, a, b in drifted:
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

# _sign_fail, _sign_timeout, _resolve_tool, _cosign_sign_argv, _minisign_sign_argv,
# _cosign_verify_argv, _minisign_verify_argv, and _run_tool (below) are the generic
# out-of-process signing/verification primitives — nothing in them is specific to
# verdict.json. They now live in _common.py (as sign_fail / sign_timeout /
# resolve_signing_tool / cosign_sign_argv / minisign_sign_argv / cosign_verify_argv /
# minisign_verify_argv / run_signing_tool) so panel.py's opportunistic policy-snapshot
# signature at init (PR70 provenance-binding fix, Option B) reuses the exact same
# identity-pinning logic instead of a second, potentially-drifting copy. Imported above
# under their original underscore names so every call site below is unchanged.


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


def sign_attestation(run):
    """Write a DETACHED signature sidecar (`attestation.sig`) over the run's EXISTING, canonical
    verdict.json, out-of-process. STANDALONE: it does not re-aggregate (a prior `aggregate.py` must
    have written verdict.json) and it REFUSES to sign a run whose artifacts drifted from the recorded
    attestation digest, so signing can never silently re-attest changed state. Signer resolution:
    AR_SIGNER_CMD override > cosign keyless > minisign (AR_MINISIGN_KEY). Exit 0 signed, 1 drift,
    2 nothing to sign, 3 no signer / signer failure — opt-in signing is never silently skipped."""
    verdict, digest = _load_verdict(run)
    # Only a CURRENT-algorithm attestation can be validly signed. compute_attestation ALWAYS recomputes
    # under _ATTESTATION_ALGO, so the drift comparison below is a meaningful freshness check ONLY when the
    # recorded attestation was itself produced under that algorithm. A record whose algorithm id is a
    # legacy predecessor, or an unrecognized/forged value whose digest happens to equal the current
    # recompute, would otherwise be signed as if current — vouching for a representation this version never
    # actually re-attested. Gate on it BEFORE the digest compare, mirroring check_digest's algorithm gate
    # ahead of its digest-equality. Exit 1 (the "re-aggregate before signing" refusal family, alongside
    # drift) — NOT exit 3, which is reserved for a missing/failed signer, an unrelated tooling error.
    # (Codex r3945556742.)
    stored_algo = (verdict.get("attestation") or {}).get("algorithm")
    if stored_algo != _ATTESTATION_ALGO:
        print(f"refusing to sign: recorded attestation algorithm {stored_algo!r} is not the current "
              f"{_ATTESTATION_ALGO!r} — re-aggregate under the current algorithm before signing",
              file=sys.stderr)
        sys.exit(1)
    try:
        att = compute_attestation(run)
    except OSError as e:
        # CodeRabbit 4088318850 / Codex 4088467040 (P2, valid): compute_attestation can now
        # raise OSError (a symlinked/oversized/non-regular sidecar or tracked *.json — see its
        # docstring) where it used to follow the link or crash the process with an uncaught
        # exception. check_digest already catches this as cannot-verify (exit 2); this call
        # site did not. A symlinked sidecar planted after aggregation would otherwise make
        # --sign exit 1 via an unhandled traceback, which the documented exit code (1 = a
        # definitive drift comparison) does not actually describe — nothing was compared.
        # Treat it the same as "nothing verifiable to sign," exit 2, never 1 or an uncaught
        # crash.
        print(f"cannot recompute attestation ({e}) — a recorded artifact could not be read "
              "safely; re-aggregate before signing", file=sys.stderr)
        sys.exit(2)
    if att["digest"] != digest:
        print(f"refusing to sign: run artifacts drifted — recomputed attestation {att['digest']} "
              f"!= recorded {digest}; re-aggregate before signing", file=sys.stderr)
        sys.exit(1)
    # fatal=True (default): --sign is a standalone, explicit CLI invocation -- a malformed
    # AR_SIGNER_CMD here should exit 3 immediately, exactly as before resolve_signing_tool()
    # grew the fatal= parameter (see t_sign_malformed_command_template_exits_3). `_err` is
    # unreachable here: sign_fail() inside the resolver exits the process before returning.
    argv_tmpl, kind, _err = _resolve_tool(
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
        proc, _err = _run_tool(argv_tmpl, msg, sig_tmp)  # fatal=True default: a tooling
        # failure already exited via sign_fail(), so proc is never None here.
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
    # A signature can be checked only against a CURRENT-algorithm attestation. verify recomputes the
    # attestation under _ATTESTATION_ALGO (below), so a recorded algorithm id that is legacy or
    # unrecognized/forged cannot be meaningfully re-checked — and a forged id whose digest coincides with
    # the current recompute must NOT be allowed to reach the "signature OK" exit 0. This is cannot-verify
    # (exit 2, the missing-prerequisite family), NEVER "not verified" (exit 1), which the CLI contract and
    # downstream consumers read as a detected tamper — matching check_digest's exit-2 treatment of an
    # unrecognized algorithm. (Codex r3945556742.)
    stored_algo = (verdict.get("attestation") or {}).get("algorithm")
    if stored_algo != _ATTESTATION_ALGO:
        print(f"signature CANNOT BE VERIFIED: recorded attestation algorithm {stored_algo!r} is not the "
              f"current {_ATTESTATION_ALGO!r} — this version cannot re-check that representation; "
              "re-aggregate under the current algorithm, then re-verify", file=sys.stderr)
        sys.exit(2)
    sigpath = run / SIG_FILENAME
    if not sigpath.exists():
        print(f"no signature sidecar ({SIG_FILENAME}) — run `aggregate.py --sign` first")
        sys.exit(2)
    try:
        att = compute_attestation(run)
    except OSError as e:
        # CodeRabbit 4088318850 / Codex 4088467040 (P2, valid): same gap as sign_attestation
        # above. A symlinked/oversized/non-regular sidecar or tracked *.json means the CURRENT
        # artifacts cannot even be read, so nothing was compared — that is a missing
        # prerequisite (exit 2, this function's own "cannot re-check" family, see the
        # algorithm-mismatch branch just above), never "not verified" (exit 1, which the CLI
        # contract and downstream consumers read as a detected tamper) and never an uncaught
        # crash.
        print(f"signature CANNOT BE VERIFIED: a recorded artifact could not be read safely "
              f"({e}) — re-aggregate before re-verifying", file=sys.stderr)
        sys.exit(2)
    if att["digest"] != digest:
        print(f"signature INVALID: run artifacts drifted — recomputed attestation {att['digest']} "
              f"!= recorded {digest}; the signed verdict no longer describes this run's inputs")
        sys.exit(1)
    # fatal=True (default): --verify-signature is a standalone, explicit CLI invocation --
    # same rationale as the --sign call site above.
    argv_tmpl, kind, _err = _resolve_tool(
        "AR_VERIFIER_CMD",
        [("cosign-keyless", _cosign_verify_argv), ("minisign", _minisign_verify_argv)])
    if argv_tmpl is None:
        _sign_fail("no verifier available: set AR_VERIFIER_CMD (using the {msg} and {sig} tokens), "
                   "or install cosign (keyless; set AR_ALLOW_KEYLESS -- on GitHub Actions "
                   "AR_COSIGN_IDENTITY/AR_COSIGN_ISSUER then auto-derive from GITHUB_REPOSITORY, "
                   "otherwise set them explicitly) or minisign "
                   "(with AR_MINISIGN_PUBKEY inline or AR_MINISIGN_PUBKEY_FILE set).")
    with tempfile.TemporaryDirectory() as td:
        msg = Path(td) / "verdict.canonical.json"
        msg.write_bytes(_canonical_verdict_bytes(verdict))
        proc, _err = _run_tool(argv_tmpl, msg, sigpath)  # fatal=True: never returns with
        # an error unresolved, so proc is never None here.
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
        # security-4 (frontier-gate run pr70-design-crypto-ci-identity, 2026-09-21, same class
        # as Codex finding #6): `name` is a raw FILESYSTEM filename under validation/ in an
        # untrusted run directory — nothing validates it against a safe charset the way
        # validate_gate_name() does for gate names — and every message below interpolates it
        # into `fail`/`blocked`, which verdict.md renders RAW. HTML-escape it once, here, and
        # use the escaped form in every message; `name` itself is never used as a path or key
        # anywhere else in this loop, so this changes only what gets displayed.
        ename = _oneline(name)
        if not isinstance(rec, dict):
            blocked.append(f"validation/{ename}: malformed record (not an object)")
            continue
        ids = rec.get("finding_ids")
        if not isinstance(ids, list):
            blocked.append(f"validation/{ename}: finding_ids is malformed (not a list)")
            continue
        # A non-string member was previously filtered silently. That is fail-SAFE (a dropped id
        # leaves its finding uncovered, which itself BLOCKs) — not the fail-open the reviewer
        # described — but silence diverges from the sibling non-list guard above. Make malformed ->
        # BLOCK uniform so a garbled record is surfaced, never quietly reinterpreted (4th-panel
        # correctness-3).
        if not all(isinstance(i, str) for i in ids):
            blocked.append(f"validation/{ename}: finding_ids has a non-string member — malformed")
            continue
        cls = rec.get("classification")
        sev = rec.get("severity") or min(
            (findings[i]["severity"] for i in ids if i in findings),
            key=lambda s: sev_rank.get(s, 9), default="low")
        covered.update(ids)
        if cls not in ("confirmed", "false_positive", "unresolved", "accepted_risk"):
            # cls is untrusted rec content too (any JSON value/string) — escape before display.
            blocked.append(f"validation/{ename}: invalid classification '{_oneline(cls)}'")
            continue
        is_high = sev in HIGH or any(findings.get(i, {}).get("severity") in HIGH for i in ids)
        if cls == "unresolved" and is_high:
            # ids are reviewer-supplied finding identifiers — same untrusted-string concern,
            # escaped as a whole (this list is display-only here; the raw `ids` list, never this
            # joined string, is what still drives covered/is_high/etc. above and below).
            fail.append(f"validation/{ename}: high/critical finding unresolved "
                       f"({_oneline(', '.join(ids))})")
            counts["unresolved"] += 1
        elif cls == "confirmed":
            counts["confirmed"] += 1
            res = rec.get("resolution") or {}
            if not (res.get("fixed") is True and res.get("gates_rerun")):
                fail.append(f"validation/{ename}: confirmed finding not fixed with gates rerun")
        elif cls == "false_positive" and is_high:
            conc = rec.get("concurrence") or {}
            if not rec.get("evidence"):
                blocked.append(f"validation/{ename}: false_positive without evidence")
            if conc.get("agrees_false_positive") is not True:
                blocked.append(f"validation/{ename}: false_positive on high/critical "
                               "without an agreeing concurrence from an uninvolved model")
            else:
                # family_of() falls back to echoing the untrusted model_id's own prefix
                # verbatim when it is not a recognized alias — so cfam itself can carry
                # attacker-chosen text, same as cls/ids above.
                cfam = family_of(conc.get("model_id", "unknown/unknown"))
                bad = author_families(ids, plan) | dev
                if cfam in bad:
                    blocked.append(f"validation/{ename}: concurrence model family "
                                   f"'{_oneline(cfam)}' is not independent of the finding/dev")
        elif cls == "accepted_risk":
            today = date.today().isoformat()
            for fid in ids:
                # fid stays RAW for the suppressions dict lookup (its key namespace is
                # independent of display safety); only the rendered message is escaped.
                efid = _oneline(fid)
                s = suppressions.get(fid)
                if not s:
                    fail.append(f"validation/{ename}: accepted_risk '{efid}' has no suppression entry")
                elif not all(s.get(k) for k in ("evidence", "owner", "expires")):
                    fail.append(f"suppression for '{efid}' incomplete (needs evidence, owner, expires)")
                elif s["expires"] < today:
                    # s["expires"] is likewise an untrusted suppressions.json field.
                    fail.append(f"suppression for '{efid}' expired {_oneline(s['expires'])}")

    uncovered = [i for i, f in findings.items()
                 if f["severity"] in HIGH and i not in covered]
    if uncovered:
        # Finding ids are reviewer-supplied (untrusted) — escape the joined display list, same
        # concern as the validation/{name} block above; `uncovered`/`sorted()` themselves are
        # unaffected (they sort/compare the raw ids, only the rendered string is escaped).
        blocked.append("high/critical findings with no validation record: "
                       + _oneline(", ".join(sorted(uncovered))))
    # A reviewer explicitly flagged these as release-blocking; severity alone does not
    # exempt them from triage. Untriaged = verification incomplete = BLOCKED.
    flagged = [i for i, f in findings.items()
               if f["severity"] not in HIGH and f.get("release_blocking")
               and i not in covered]
    if flagged:
        blocked.append("reviewer-flagged release-blocking findings without triage: "
                       + _oneline(", ".join(sorted(flagged))))
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


def next_steps(verdict, fail, blocked, gcov, fcov, counts, risk=None, allow_critical_waivers=False):
    """Plain-language 'what this means and what to do next', for someone who did not write
    the pipeline. DERIVED ONLY from the already-computed verdict and coverage — it reads
    them and never writes them, so it cannot change a gate, threshold, or verdict. Coverage
    shapes are normalized defensively so malformed/None input degrades rather than crashing
    (the verdict file must still be written), and every fail/blocked reason not rephrased as
    a specific gate line is passed through verbatim (one-lined) so a blocker is never hidden.
    `allow_critical_waivers` mirrors the SAME attested-policy flag _common.py's
    _validate_gate_exception_common() enforces — it must never be sourced from anywhere
    else, or this guidance could recommend an action the gate will actually reject."""
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
        waived = [w for w in _list(gcov.get("waived")) if isinstance(w, dict)]
        na = [x for x in _list(gcov.get("not_applicable")) if isinstance(x, dict)]
        if waived or na:
            # Name BOTH kinds of exception — a waived gate and a not-applicable gate each did
            # not "pass", so the guidance must not claim every remaining check passed.
            parts = []
            if waived:
                parts.append("waived: " + ", ".join(str(w.get("name", "?")) for w in waived))
            if na:
                parts.append("not applicable: " + ", ".join(str(x.get("name", "?")) for x in na))
            steps.append("Cleared, with accountable exception(s): every required check passed except "
                         + "; ".join(parts) + " — each authorized and on record, not a pass or a "
                         "silent skip. Independent review ran with its blocking findings resolved. "
                         "A human still owns the actual merge decision.")
            for w in waived:
                steps.append(f"Waived gate '{w.get('name', '?')}' — authorized by "
                             f"{_oneline(w.get('authorized_by', '?'))}, expires "
                             f"{_oneline(w.get('expires', '?'))}: {_oneline(w.get('reason', ''))}. "
                             "It expires; do not treat it as permanently green.")
        else:
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
        if risk == "CRITICAL" and g == "mutation":
            # N/A (and waiving) is forbidden for mutation on CRITICAL regardless of policy —
            # don't recommend an action the gate will reject; it must actually run and pass.
            steps.append(f"The 'mutation' check could not be verified. Passing it proves {proves}. On "
                         "CRITICAL tier it must actually run and pass — it cannot be waived or marked "
                         "not-applicable — before release.")
        elif risk == "CRITICAL" and not allow_critical_waivers:
            # Every OTHER gate on CRITICAL is waivable/N-A-able only when policy opts in
            # (allow_critical_waivers: true); the default is false, so by default the gate
            # will reject a NOT_APPLICABLE record here too — the guidance must not suggest it.
            steps.append(f"The '{_oneline(g)}' check could not be verified. Passing it proves {proves}. On "
                         "CRITICAL tier, with this policy, it must actually run and pass — waiving or "
                         "marking it not-applicable requires policy allow_critical_waivers: true "
                         "(currently not set) before release.")
        else:
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
    # Wrap the whole aggregation so an UNEXPECTED error maps to exit 3 for BOTH entry points: `python
    # aggregate.py` (the __main__ block below) AND the installed `ar-aggregate` console script, which
    # pyproject points straight at THIS callable (`adversarial_review.aggregate:main`) and so never runs
    # __main__. A crash after verdict.json is written (e.g. an untrusted run has verdict.md as a directory,
    # so the markdown write raises) must exit 3 — a code OUTSIDE the verdict set {0,1,2} — for the installed
    # CLI too, else ar_aggregate cannot tell a crashed FAIL from a completed one (both would exit 1).
    # Intentional sys.exit(...) raises SystemExit (not Exception) and passes through unchanged, so a
    # subcommand's own codes (e.g. --sign's exit 3 for "no signer") are unaffected. (Codex r3942035551;
    # extends CodeRabbit r3941710394, which added the exit-3 mapping only on the __main__/file path.)
    try:
        _aggregate_cli()
    except Exception:
        import traceback
        traceback.print_exc()
        sys.exit(3)


def _aggregate_cli():
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
    # fix-39 (Codex r3952220744): acquire the per-run lock BEFORE reading any run artifacts and hold it
    # through the writes, so the WHOLE read -> compute -> write is one atomic critical section. fix-37/38
    # took the lock only around the writes; a direct aggregate that had already READ stale artifacts could
    # then acquire the lock (after a concurrent aggregation committed a fresher verdict) and overwrite it
    # with the stale computation — replacing a fresh FAIL with an earlier PASS whose attestation omits the
    # newer artifacts (Codex reproduced this). Holding the lock across the reads makes any concurrent
    # aggregate of the same run refuse (O_EXCL) rather than interleave, so a stale computation never lands.
    #
    # The MCP wrapper (mcp_server.h_aggregate) spawns THIS file as its child while ALREADY holding the lock,
    # so the child must skip re-acquiring it (else every MCP aggregate would fail against its own held lock).
    # The re-entrancy signal is an UNFORGEABLE parent-child capability, not a CLI flag a standalone caller
    # could pass (CodeRabbit r3951923661): the wrapper mints a random token, writes its SHA-256 HASH into the
    # 0o600 lock file it owns, and hands THIS child the PREIMAGE via AR_AGGREGATE_LOCK_TOKEN. We skip the
    # lock ONLY when our env token hashes to the lock file's stored hash. A standalone caller has no such
    # token and, seeing only the hash in the owner-only lock file, cannot invert it — so it always takes the
    # lock here and is refused while one is held. (verdict.json.lock is not *.json, so it never attests.)
    lock_path = run / "verdict.json.lock"
    parent_holds_lock = False
    _tok = os.environ.get("AR_AGGREGATE_LOCK_TOKEN")
    if _tok:
        try:
            with open(str(lock_path), "r", encoding="utf-8") as _lf:
                _stored = _lf.read().strip()
            if _stored and _stored == hashlib.sha256(_tok.encode("ascii")).hexdigest():
                parent_holds_lock = True   # only the wrapper that owns the lock holds the preimage
        except OSError:
            parent_holds_lock = False      # no lock file / unreadable -> acquire below (fail closed)
    lock_fd = None
    if not parent_holds_lock:
        try:
            lock_fd = os.open(str(lock_path), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            print("another aggregate is in progress for this run (lock file "
                  f"{lock_path.name} is held). If none is running, a prior aggregate was killed before "
                  "releasing it — remove the stale lock file and re-run.", file=sys.stderr)
            sys.exit(3)
        except OSError as e:
            print(f"cannot acquire the aggregate lock ({lock_path.name}): {e}", file=sys.stderr)
            sys.exit(3)
    try:
        meta = read_json(run / "run.json")

        fail, blocked, notes = [], [], []
        counts = {"gates": 0, "reviewers": 0, "findings_high_critical": 0,
                  "findings_medium_low": 0, "confirmed": 0, "unresolved": 0}

        # Waiver limits (max_waiver_days, allow_critical_waivers) come ONLY from the policy
        # attested at init (policy.snapshot.json / policy.absence.json), NEVER the mutable
        # working-tree policy — a post-init edit must not be able to widen a waiver that is
        # absent from the audit record. A snapshot/absence that is present but untrustworthy
        # (unreadable / sha-mismatched / no longer valid) fails closed to strict built-in
        # defaults AND blocks the run.
        #
        # TOCTOU-safe (frontier-gate run pr70-design, 2026-09-21, checklist item 8): this
        # require_signature=False call is the ONLY read of run.json/policy.snapshot.json for
        # the whole policy-attestation question in this function. `bundle` keeps the
        # already-read raw bytes so the conditional signature check below (only needed once
        # gcov, computed after this, reveals an actual waiver/NOT_APPLICABLE) verifies over
        # the SAME bytes just content-validated here — never a second, independent read of
        # policy.snapshot.json that a concurrent, attacker-controlled step in the same job
        # could race between the two reads.
        bundle, att_err = load_attested_policy_bundle(run, require_signature=False)
        pol_data = bundle.data if bundle else {}
        attested_policy_sha = bundle.sha256 if bundle else None
        if att_err:
            # The rejected snapshot did NOT govern the verdict (strict defaults did), so its
            # sha must not be reported as the governing-policy provenance.
            pol_data = {}
            attested_policy_sha = None
            blocked.append(f"attested policy snapshot could not be trusted: {att_err}")
        # Finding #11 / checklist items 5 & 9 (frontier-gate run pr70-trust-model2,
        # 2026-09-22): `meta` above and `bundle.run_meta` here are two INDEPENDENT reads
        # of run.json. Every downstream use of meta["risk"] in this function (check_gates'
        # required-gate-set lookup, the rebuttal-required check, next_steps guidance,
        # coverage/verdict.json's own `risk` field) must be driven by
        # load_attested_policy_bundle()'s read, not the separate one above — an attacker
        # able to change what the second read sees (a race, a partial/corrupted write)
        # could otherwise make gating disagree with what actually got recorded. Rather
        # than hunt down and update every individual meta["risk"] call site below (and
        # risk missing one), overwrite meta["risk"] in place, once, right here, so every
        # existing call site picks up the authenticated value automatically. Only done
        # when the bundle load itself succeeded (bundle is not None) — when it failed,
        # `att_err` is already reported above and meta["risk"] is left as the sole
        # available reading rather than discarded.
        if bundle is not None:
            b_risk = bundle.run_meta.get("risk")
            if not b_risk:
                blocked.append("load_attested_policy_bundle's read of run.json had no "
                                "risk tier recorded — cannot confirm the risk tier used "
                                "for gating is authenticated")
                # Downstream code (check_gates, coverage, next_steps, the print/report
                # below) all index meta["risk"] unconditionally and predate this fix —
                # this run is already BLOCKED above; only fill in a clearly-labeled
                # placeholder here so a genuinely missing key degrades to that BLOCKED
                # verdict rendering normally, never an uncaught KeyError crash.
                meta.setdefault("risk", "UNKNOWN")
            elif b_risk != meta.get("risk"):
                # CodeRabbit 4077668514 (Minor, valid): both values come straight from
                # attacker-editable run.json; repr() (!r) does not HTML-escape, so
                # _oneline(repr(...)) them the same way every other untrusted string this
                # function interpolates into `blocked` already is.
                blocked.append(
                    f"risk tier mismatch: load_attested_policy_bundle's read of "
                    f"run.json saw risk {_oneline(repr(b_risk))}, but a separate read in "
                    f"this function saw {_oneline(repr(meta.get('risk')))} — this run's "
                    "risk tier is not internally consistent (possible tampering between "
                    "two reads of run.json, or a concurrent write); re-run aggregate")
            else:
                meta["risk"] = b_risk
        else:
            meta.setdefault("risk", "UNKNOWN")

        # Checklist item 6 (frontier-gate run pr70-item6-scope, 2026-09-23, refined
        # Option A / scope_down_never_break_unsigned, panel consensus 0.97): the checks
        # above are unchanged and still govern policy CONTENT (pol_data/
        # attested_policy_sha) and, further below, a waived/NOT_APPLICABLE gate's
        # signature specifically. This check is broader and runs UNCONDITIONALLY,
        # whether or not this run recorded any waiver at all — it must run BEFORE
        # check_gates() below so a forced CRITICAL escalation actually changes which
        # gates are required (MINIMUM_GATES), not just adds a note after the fact. See
        # authenticate_risk_tier's own docstring for the full state machine; in short: a
        # repository where signing was expected (a verifier resolves here, or its own
        # AR_SIGNING_REQUIRED anchor says so) but cannot be cryptographically verified is
        # forced to CRITICAL and BLOCKED here, regardless of what tier it self-reported
        # — CRITICAL's `mutation` floor gate can never be waived, which is what actually
        # makes this un-bypassable. A never-configured repository is unaffected.
        auth = authenticate_risk_tier(run)
        if auth.status == "UNAUTHENTICATED":
            meta["risk"] = auth.risk or "CRITICAL"
            # auth.detail may embed a configured verifier's raw, attacker-influenceable
            # stderr (via load_attested_policy_bundle's att_err) — _oneline() it before
            # it reaches verdict.md, same as every other untrusted string this function
            # interpolates into `blocked` (see the sig_err handling just below).
            blocked.append(f"{auth.label}: {_oneline(auth.detail)}")
        elif auth.status == "AUTHENTICATED":
            # CodeRabbit r4082557528 (Major, valid): auth.risk here is the CRYPTOGRAPHICALLY
            # AUTHENTICATED tier (verified against the signed bundle inside
            # authenticate_risk_tier itself), but meta["risk"] at this point still holds
            # whatever the EARLIER, require_signature=False read above (lines ~1559-1602)
            # saw — unsigned content only. An attacker with concurrent write access to the
            # run directory could lower run.json's risk between that first read and this
            # one, then restore it, so the two reads disagree and only the unsigned one
            # would otherwise reach check_gates/check_rebuttal below. Prefer the
            # authenticated value and BLOCK (not silently overwrite) on any disagreement,
            # exactly like the require_signature=False block already does for its own two
            # reads a few lines up — this is the same TOCTOU class, just against the
            # signature-backed reading instead of the unsigned one.
            if auth.risk != meta.get("risk"):
                # Same _oneline(repr(...)) treatment as the require_signature=False
                # mismatch block above (CodeRabbit 4077668514, Minor, valid, caught here
                # too on review — this branch is this session's own new code and had the
                # same unescaped-repr gap).
                blocked.append(
                    f"risk tier mismatch: authenticated read saw "
                    f"{_oneline(repr(auth.risk))}, but an earlier unsigned read of "
                    f"run.json saw {_oneline(repr(meta.get('risk')))} — this run's risk "
                    "tier is not internally consistent (possible tampering between reads "
                    "of run.json, or a concurrent write); re-run aggregate")
            meta["risk"] = auth.risk
        elif auth.status == "UNSIGNED_EXEMPT":
            notes.append(f"{auth.label}: {auth.detail}")

        # Resolved once per aggregate run: GITHUB_RUN_STARTED_AT's date if set (else today
        # UTC). A set-but-unparseable value is fail-closed — every waiver is BLOCKED rather
        # than silently falling back to today (see check_gates/resolve_waiver_clock).
        clock = resolve_waiver_clock()
        if clock[1]:
            # Codex 4082681166 (P2, valid): clock[1]'s error text embeds the raw,
            # attacker-influenceable GITHUB_RUN_STARTED_AT env value (see
            # resolve_waiver_clock's docstring in _common.py); _oneline() it before it
            # reaches `blocked`, same as every other untrusted string appended here.
            blocked.append(_oneline(clock[1]))

        gates, gcov = check_gates(run, meta["risk"], fail, blocked, notes, pol_data, clock)
        counts["gates"] = len(gates)

        # PR70 provenance-binding fix (Option B / require_signing_for_exceptions_only,
        # Paul's decision), extended by the GAP A fix (frontier-gate run pr70-design,
        # 2026-09-21, checklist item 2): the no-exception path above stays
        # infrastructure-free, but the moment this run recorded a WAIVED or NOT_APPLICABLE
        # gate, the policy that governed it must be AUTHENTICATED — either a verifiably-
        # signed policy.snapshot.json, or a verifiably-signed policy.absence.json explicitly
        # attesting that no policy governed this run. `not att_err` so this never re-blocks a
        # run already BLOCKED above for the same underlying reason.
        if (gcov["waived"] or gcov["not_applicable"]) and not att_err:
            if bundle.absence_raw is not None:
                sig_err = verify_policy_absence_signature(run, bundle.run_meta,
                                                           absence_bytes=bundle.absence_raw)
                if sig_err:
                    # _oneline(): sig_err may embed a configured verifier's raw, attacker-
                    # influenceable stderr (see verify_policy_absence_signature's `detail`).
                    # Collapse/HTML-escape it before it reaches verdict.md, same as every
                    # other untrusted string this function interpolates into `blocked`.
                    # Codex r4055706481 (P2).
                    blocked.append(
                        "run recorded a waived or not-applicable gate but its signed "
                        f"no-policy attestation is not verifiably signed: {_oneline(sig_err)}")
            elif bundle.raw is not None:
                sig_err = verify_policy_snapshot_signature(run, bundle.run_meta,
                                                            snap_bytes=bundle.raw)
                if sig_err:
                    blocked.append(
                        "run recorded a waived or not-applicable gate but its attested "
                        f"policy snapshot is not verifiably signed: {_oneline(sig_err)}")
            else:
                # No policy.snapshot.json and no policy.absence.json were present at the
                # content-only (require_signature=False) load above. Re-derive the
                # authoritative answer via require_signature=True — this decides, based
                # SOLELY on whether a verifier is configured in THIS environment (never
                # on anything read from the run directory itself, which is exactly what
                # an attacker with write access to it could forge to look like "no
                # signer was ever configured" — see load_attested_policy_bundle's own
                # docstring), whether this is the historically exempt "no verification
                # infra configured at all" case or the GAP-A hole this fix closes (a run
                # whose environment DOES expect authentication getting an unauthenticated
                # free pass merely because both artifacts are absent). This second call
                # costs only a second run.json read — there is no snapshot/absence FILE
                # here to re-read, so it does not reintroduce the TOCTOU this refactor
                # exists to eliminate.
                _, sig_err = load_attested_policy_bundle(run, require_signature=True)
                if sig_err:
                    blocked.append(
                        "run recorded a waived or not-applicable gate but there is no "
                        f"attested policy snapshot for this run: {_oneline(sig_err)}")

        plan_path = run / "panel" / "plan.json"
        plan = read_json(plan_path) if plan_path.exists() else {}
        reports = load_reports(run, plan)
        counts["reviewers"] = len(reports)
        jev_priors = collect_jev_priors(run, reports)
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
        # Tamper-evident attestation over every recorded input, computed before the verdict
        # file exists so re-aggregating an untouched run reproduces it (#5). Computed here,
        # ahead of the verdict/steps decision below (not right before write_json as before),
        # so a read failure can actually BLOCK rather than crash past it.
        #
        # CodeRabbit 4088318850 / Codex 4088467040 (P2, valid): compute_attestation can raise
        # OSError (a symlinked/oversized/non-regular sidecar or tracked *.json — see its
        # docstring) since the Codex-4077803884 hardening. check_digest already catches this as
        # cannot-verify (exit 2); this, the MAIN aggregate path, did not — an attacker with
        # write access to the run directory could plant such a file and crash aggregation with
        # an uncaught traceback before verdict.json is ever written, exiting 1 (which the exit
        # map reads as FAIL) with no verdict recorded at all. That breaks this module's own
        # design rule (see the AGENTS.md-documented contract and the comment on `blocked`
        # above): ordinary aggregation always writes a verdict, and an unreadable/untrusted
        # input is a BLOCKER, never a crash. Fold it into `blocked` like every other
        # attacker-reachable failure this function already handles, and fall back to a
        # digest-less attestation record (digest=None mirrors the existing "computed before #5 /
        # malformed" shape check_digest and verify_signature already treat as unverifiable,
        # never as a false PASS or false drift).
        try:
            attestation = compute_attestation(run)
        except OSError as e:
            blocked.append(
                "run artifacts could not be attested safely — a recorded artifact is a "
                f"symlink, not a regular file, or exceeds the size cap: {_oneline(e)}")
            attestation = {"algorithm": _ATTESTATION_ALGO, "inputs": 0, "digest": None, "files": {}}
        coverage = {"risk": meta["risk"], "gates": gcov, "panel": pcov,
                    "rebuttal": rcov, "findings": fcov,
                    "cost_usd": round(panel_cost_usd, 6), "cost_aborted": bool(cost_abort),
                    "cost_cap_usd": cpol.get("cap_usd"), "cost_cap_source": cpol.get("source"),
                    # The sha256 of the policy attested at init, whose waiver limits governed
                    # this verdict — so the audit shows exactly which policy the waiver checks
                    # ran against (null when the run had no policy file).
                    "policy_snapshot_sha256": attested_policy_sha,
                    "areas_not_reviewed": sorted(areas)}

        verdict = "FAIL" if fail else ("BLOCKED" if blocked else "PASS")
        # Plain-language next steps are derived from the verdict + coverage above; they are
        # read-only over that state and cannot change it (guidance, not gate). The
        # allow_critical_waivers flag comes from the SAME attested pol_data the gates
        # themselves were just checked against (never the mutable working-tree policy),
        # so the guidance can never suggest an action the gate above it already rejected.
        steps = next_steps(verdict, fail, blocked, gcov, fcov, counts, risk=meta["risk"],
                           allow_critical_waivers=_policy_bool(pol_data.get("allow_critical_waivers")) or False)
        out = {"verdict": verdict, "reasons": fail + blocked, "notes": notes,
               "next_steps": steps,
               "counts": counts, "coverage": coverage, "attestation": attestation,
               "risk": meta["risk"], "run_id": meta["run_id"], "computed_at": now_iso()}
        write_json(run / "verdict.json", out)

        md = [f"# Release verdict: {verdict}", "",
              f"Run `{meta['run_id']}`, risk {meta['risk']}, computed {out['computed_at']}.", ""]
        # fail/blocked reasons are already escaped where they interpolate untrusted text (reviewer
        # strings via _snippet; tampered gate names are rejected by validate_gate_name; a malformed
        # manifest entry is shown via repr, which escapes newlines; and, as of security-4/Codex
        # finding #6, every gates/<name>.json-sourced summary/validation-error text check_gates()
        # appends to `fail`/`blocked` is now _oneline()-escaped at that append site, closing the gap
        # where a crafted BLOCKED/FAIL record summary rendered raw markup into this report) — so
        # they are NOT re-escaped here (that would double-escape, e.g. &lt; -> &amp;lt;). Notes are
        # raw, so they are escaped at render.
        md += [f"- FAIL: {r}" for r in fail]
        md += [f"- BLOCKED: {r}" for r in blocked]
        md += [f"- note: {_oneline(n)}" for n in notes]
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
               # CodeRabbit 4077668514 (Minor, valid): rcov['policy'] is the same
               # attacker-editable meta['rebuttal_policy'] string that's already
               # _oneline()'d when it reaches `blocked` above — this summary line
               # rendered it raw instead.
               f"rebuttal policy '{_oneline(rcov['policy'])}' {reb}; "
               f"findings {fcov['triaged']}/{fcov['raised']} triaged; "
               f"{len(coverage['areas_not_reviewed'])} reviewer-attested unreviewed areas"]
        # Surface every not-applicable determination and its authorizer distinctly — a
        # skipped gate must never be silent, even when it does not restrict the verdict.
        # Authorizer/reason/expiry are operator-supplied — HTML-escape (via _oneline) before
        # interpolating into verdict.md so a crafted value cannot forge markup in the report.
        md += [f"- not applicable: gate '{na['name']}' (authorized by "
               f"{_oneline(na['authorized_by'])}): {_oneline(na['reason'])}"
               for na in gcov["not_applicable"]]
        # Surface every active waiver and its authorizer/expiry distinctly too — a waived
        # gate must never be silent, even though (like N/A) it does not restrict the verdict.
        md += [f"- waived: gate '{w['name']}' (authorized by {_oneline(w['authorized_by'])}, "
               f"expires {_oneline(w['expires'])}): {_oneline(w['reason'])}"
               for w in gcov["waived"]]
        if jev_priors:
            # Informational only, read straight from the recorded triage/<id>.json files —
            # never fed back into fail/blocked/notes above. Showing it here, next to the
            # verdict this run actually computed, makes the (advisory) prior visible without
            # letting it anywhere near the gate.
            md += ["", f"## Jev triage priors ({len(jev_priors)}/{counts.get('findings_high_critical', 0) + counts.get('findings_medium_low', 0)} finding(s) triaged)", ""]
            for fid in sorted(jev_priors):
                jv = jev_priors[fid]["jev"]
                sev_obj = jv.get("severity")
                dup_obj = jv.get("duplicate_of")
                sev = sev_obj.get("label") if isinstance(sev_obj, dict) else None
                dup = dup_obj.get("choice") if isinstance(dup_obj, dict) else None
                bits = [f"is_real={jv.get('is_real'):.2f}" if isinstance(jv.get("is_real"), (int, float)) else "is_real=?"]
                if sev:
                    bits.append(f"jev_severity={sev}")
                if dup and dup != "none":
                    bits.append(f"duplicate_of={dup}")
                if jv.get("error"):
                    bits.append("jev_error")
                md.append(f"- `{_snippet(fid)}`: " + ", ".join(bits))
        md += ["", f"Attestation: sha256 {attestation['digest']} over "
               f"{attestation['inputs']} recorded artifacts "
               "(verify with `aggregate.py --check-digest`)"]
        (run / "verdict.md").write_text("\n".join(md) + "\n", encoding="utf-8")
    finally:
        # Release the per-run lock on every exit path. Close BEFORE unlink so the removal succeeds on
        # Windows too (an open handle blocks delete there); a failed unlink leaves a stale lock the
        # operator can clear rather than crashing the write. Never unlink a lock this process did not
        # create (lock_fd is None when the parent's token authorized skipping acquisition — the MCP
        # wrapper owns and releases it).
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
