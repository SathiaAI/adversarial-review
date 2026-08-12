#!/usr/bin/env python3
"""Deterministic verdict for adversarial-review.

Computes PASS / FAIL / BLOCKED purely from recorded artifacts and writes verdict.json.
No model — including the one operating this pipeline — can emit a verdict; only this
script can, which is the point.

Exit codes: 0 PASS, 1 FAIL, 2 BLOCKED.

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
import sys
from datetime import date
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _common import family_of, now_iso, read_json, resolve_run, write_json

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
    for role, rep in reports.items():
        for f in rep.get("findings", []):
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
        for s in read_json(spath):
            suppressions[s.get("finding_id", "")] = s

    covered = set()
    dev = set(meta.get("dev_providers", []))
    sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    for name, rec in records:
        ids = rec.get("finding_ids", [])
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
    # false (states_truth=false) must link it — via finding_id — to a finding IT raised that is
    # RESOLVED (a triage decision was made: confirmed / false_positive / accepted_risk; a merely
    # `unresolved` record does not clear it). An unlinked, foreign, dangling, or unresolved link
    # is unverified false output reaching release, so it BLOCKS regardless of the linked finding's
    # severity — this is what makes the forced attestation actually gate the verdict. Fail-safe by
    # construction: a missing/garbled/foreign link blocks, never passes. finding_id and the
    # rendered snippet are reviewer-supplied (untrusted) and are escaped before interpolation so a
    # crafted value cannot forge markdown/HTML in the rendered verdict (panel finding security-1).
    resolved = set()
    for _, rec in records:
        if rec.get("classification") in ("confirmed", "false_positive", "accepted_risk"):
            resolved.update(rec.get("finding_ids", []))
    false_stmts = 0
    for role, rep in reports.items():
        for it in rep.get("output_statements_checked") or []:
            if not isinstance(it, dict) or it.get("states_truth") is not False:
                continue
            false_stmts += 1
            fid = it.get("finding_id")
            fid = fid.strip() if isinstance(fid, str) else ""
            snip = _snippet(it.get("rendered", ""))
            sfid = _snippet(fid)  # untrusted — escape before interpolating into a reason
            if not fid:
                blocked.append(f"reviewer '{role}' recorded false human-facing output "
                               f"(\"{snip}\") with no finding_id — a false statement must be "
                               "raised as a finding so it enters triage")
            elif not fid.startswith(role + "-") or fid not in findings:
                blocked.append(f"reviewer '{role}' linked false output to finding '{sfid}', "
                               "which is not a finding this reviewer raised — a false statement "
                               "must be linked to the reviewer's own finding, not an unrelated one")
            elif fid not in resolved:
                blocked.append(f"false-output finding '{sfid}' (reviewer '{role}') is untriaged "
                               "or unresolved — a reviewer-attested false statement must be "
                               "validated (confirmed/false_positive/accepted_risk) before release")
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
    args = ap.parse_args()
    run = resolve_run(args.run)
    if args.check_digest:
        check_digest(run)
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
    coverage = {"risk": meta["risk"], "gates": gcov, "panel": pcov,
                "rebuttal": rcov, "findings": fcov,
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
