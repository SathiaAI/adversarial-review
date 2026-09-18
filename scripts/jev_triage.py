#!/usr/bin/env python3
"""TypeSafe Jev finding-triage layer for adversarial-review.

Jev (`typesafe/jev-1.13`, via OpenRouter's `/alpha/decisions` endpoint) is a fast, cheap
structured-decision model -- not a chat model. This script uses it to REDUCE the operator's
workload between the panel and Step 4 (validate findings), and between rounds. It never
gates the verdict itself and never dismisses a finding: `aggregate.py` still computes
PASS/FAIL/BLOCKED from recorded artifacts alone, Claude still writes every
`validation/<slug>.json`, and the existing rule that a high/critical false-positive needs
uninvolved-model concurrence is untouched.

  jev_triage.py triage        [<run-dir>] [--context-file context.md]
      One Jev call per finding in panel/<role>.json. Writes triage/<finding-id>.json and
      prints a ranked worklist (high/critical likely-real first, possible duplicates,
      candidate false positives). Run after `panel.py run`, before Step 4.

  jev_triage.py rebuttal-gate [<run-dir>] [--context-file context.md]
      One Jev call per high/critical finding (the same digest `panel.py rebuttal` would
      contest). Writes rebuttal/plan.json (a decision `aggregate.py`'s check_rebuttal()
      reads) and rebuttal/digest.json (a filtered digest for `panel.py rebuttal
      --digest-file`). Findings where neither "contested" nor "would_change_outcome"
      clears 0.5 are skipped from the rebuttal round; everything else -- including any
      Jev error -- still goes through it.

  jev_triage.py patch-check   [<run-dir>] <patch>
      For the next round: one Jev call per `confirmed` validation record, checking the
      given patch/diff file. Writes patch_check/round-N.json and prints a one-screen
      summary (resolved / still open / new risk) for a non-coder. Findings Jev marks
      resolved are PROPOSALS -- Claude still confirms and still updates the validation
      record; nothing here closes a finding.

Fail-closed throughout: any Jev error (no key, transport failure, malformed response) is
treated as "real" / "needs a human" / "not resolved" / "rebuttal needed" -- never as a
free pass. Jev is never asked with more than ~25k tokens of state (diff excerpts are
truncated to the hunk the finding cites; approximated in characters -- stdlib has no
tokenizer, so the char budget deliberately overestimates tokens-per-char to stay under the
real limit even when the estimate is wrong).

Credentials: reused unchanged from `panel.api_config()` (`OPENROUTER_API_KEY` /
`AR_KEY_FILE` -- see references/config.md). Jev has no MCP/keyless path: these commands
require a direct key and refuse to run a partial triage without one.

Stdlib only. Exit codes: 0 ok, 2 BLOCKED (bad input / no key / missing run artifacts).
"""
import argparse
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _common import die, now_iso, read_json, resolve_run, write_json
import panel  # reuses api_config()/http_json()/high_critical_digest() -- see references/config.md

JEV_MODEL_DEFAULT = "typesafe/jev-1.13"
JEV_BASE_DEFAULT = "https://openrouter.ai/api"
JEV_PATH = "/alpha/decisions"
JEV_TIMEOUT_DEFAULT = 60  # seconds; Jev calls run ~0.3s, this is a generous ceiling

# No tokenizer available (stdlib only): approximate the ~25k-token state budget in
# characters at a conservative (i.e. LOW) chars-per-token ratio, so the estimate
# overshoots the real token count and the char cap keeps the actual call under budget
# even when this guess is wrong.
JEV_CHARS_PER_TOKEN_ESTIMATE = 3
JEV_MAX_STATE_CHARS = 25000 * JEV_CHARS_PER_TOKEN_ESTIMATE

CONTEXT_SUMMARY_CHARS = 3000
SEVERITY_CRITERIA = ["low", "medium", "high", "critical"]
HIGH = ("critical", "high")


# ---------------------------------------------------------------- Jev transport / config

def jev_config():
    import os
    model = os.environ.get("AR_JEV_MODEL", "") or JEV_MODEL_DEFAULT
    base = (os.environ.get("AR_JEV_BASE_URL", "") or JEV_BASE_DEFAULT).rstrip("/")
    try:
        timeout = int(os.environ.get("AR_JEV_TIMEOUT_S", "") or JEV_TIMEOUT_DEFAULT)
    except ValueError:
        timeout = JEV_TIMEOUT_DEFAULT
    return model, base, timeout


def require_jev_key():
    """Fail loudly, before any partial work, if Jev has no key. Jev has no MCP/keyless
    path (unlike the reviewer panel) -- a triage run with no key must refuse cleanly
    rather than silently produce empty/fabricated records."""
    _, key = panel.api_config()
    if not key:
        die("no API key configured for Jev (OPENROUTER_API_KEY or AR_KEY_FILE) -- Jev has "
            "no MCP/keyless transport, so this command refuses to run a partial triage. "
            "Skip Jev and continue Step 4 by hand, or configure a key (references/config.md).",
            2)
    return key


def call_jev(state, questions, model=None, base=None, timeout=None):
    """One Jev decision call. Returns (result, error) -- exactly one is not-None/falsy.
    NEVER raises: every caller here is fail-closed and applies its own default on error,
    so a raised exception would be exactly the kind of silent-crash-as-pass this pipeline
    exists to prevent."""
    model = model or JEV_MODEL_DEFAULT
    base = (base or JEV_BASE_DEFAULT).rstrip("/")
    timeout = timeout or JEV_TIMEOUT_DEFAULT
    _, key = panel.api_config()
    if not key:
        return None, "no API key configured for Jev"
    body = {"model": model, "state": state, "questions": questions}
    try:
        resp = panel.http_json(f"{base}{JEV_PATH}", payload=body, key=key, timeout=timeout)
    except Exception as e:  # noqa: BLE001 -- fail-closed: any transport/HTTP failure is an error
        return None, f"{type(e).__name__}: {e}"
    if not isinstance(resp, dict):
        return None, "malformed Jev response (not a JSON object)"
    if "error" in resp:
        return None, str(resp["error"])[:400]
    answers = resp.get("answers")
    if not isinstance(answers, dict):
        return None, "malformed Jev response (missing 'answers')"
    missing = [name for name in questions if name not in answers]
    if missing:
        return None, f"Jev response missing answer(s) for: {', '.join(missing)}"
    cost = None
    usage = resp.get("usage")
    if isinstance(usage, dict):
        c = usage.get("cost")
        if isinstance(c, (int, float)):
            cost = float(c)
    return {"answers": answers, "cost": cost}, None


def _noul(answers, name, default):
    """A 'noul' (0..1) answer. Returns (value, ok); on any shape problem, value is the
    caller's fail-closed default and ok is False."""
    try:
        v = float(answers[name]["noul"])
    except (KeyError, TypeError, ValueError):
        return default, False
    if not (0.0 <= v <= 1.0):
        return default, False
    return v, True


def _choice(answers, name):
    try:
        obj = answers[name]
        return {"choice": obj["choice"], "confidence": obj.get("confidence"),
                "probabilities": obj.get("probabilities")}, True
    except (KeyError, TypeError):
        return None, False


def _score(answers, name, criteria):
    try:
        obj = answers[name]
        score = float(obj["score"])
    except (KeyError, TypeError, ValueError):
        return None, False
    legend = obj.get("legend") if isinstance(obj, dict) else None
    idx = max(0, min(len(criteria) - 1, int(round(score))))
    label = legend.get(str(idx)) if isinstance(legend, dict) else None
    return {"score": score, "label": label or criteria[idx], "legend": legend}, True


# ---------------------------------------------------------------- state budgeting

def _budget_state(state, max_chars=JEV_MAX_STATE_CHARS,
                  shrinkable=("diff_excerpt", "patch", "context_summary", "evidence")):
    """Fit `state`'s JSON serialization under max_chars by progressively truncating the
    named shrinkable string fields (head+tail kept, middle cut) -- never the identity
    fields (finding id/title/severity). Order matters: earlier names shrink first."""
    state = dict(state)

    def total_len():
        return len(json.dumps(state, ensure_ascii=False))

    for key in shrinkable:
        if total_len() <= max_chars:
            break
        val = state.get(key)
        if not isinstance(val, str) or not val:
            continue
        overflow = total_len() - max_chars
        keep = max(200, len(val) - overflow - 60)
        if keep < len(val):
            head_n = keep // 2
            tail_n = keep - head_n
            marker = f"\n...[truncated {len(val) - keep} chars]...\n"
            state[key] = val[:head_n] + marker + (val[-tail_n:] if tail_n > 0 else "")
    return state


# ---------------------------------------------------------------- diff-hunk extraction

_DIFF_FILE_RE = re.compile(r"^diff --git a/(.+?) b/(.+?)$")
_HUNK_HEADER_RE = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")


def extract_cited_hunk(diff_text, file_path, line):
    """Best-effort: the unified-diff hunk for `file_path` covering `line` in the new file.
    Returns '' on anything it can't confidently locate -- this only narrows what Jev sees;
    a miss here makes the state less scoped, never wrong, so it fails open by design
    (unlike the Jev call itself, which fails closed)."""
    if not diff_text or not file_path:
        return ""
    lines = diff_text.splitlines()
    file_start = None
    for i, ln in enumerate(lines):
        m = _DIFF_FILE_RE.match(ln)
        if m and (m.group(2) == file_path
                  or m.group(2).endswith("/" + file_path.lstrip("/"))
                  or file_path.endswith("/" + m.group(2))):
            file_start = i
            break
    if file_start is None:
        return ""
    file_end = len(lines)
    for i in range(file_start + 1, len(lines)):
        if lines[i].startswith("diff --git "):
            file_end = i
            break
    section = lines[file_start:file_end]
    hunk_starts = [i for i, ln in enumerate(section) if _HUNK_HEADER_RE.match(ln)]
    if not hunk_starts:
        return ""
    chosen = None
    for idx, hi in enumerate(hunk_starts):
        m = _HUNK_HEADER_RE.match(section[hi])
        new_start, new_len = int(m.group(3)), int(m.group(4) or 1)
        hend = hunk_starts[idx + 1] if idx + 1 < len(hunk_starts) else len(section)
        if line and new_start <= line < new_start + max(new_len, 1):
            chosen = (hi, hend)
            break
    if chosen is None:
        hend = hunk_starts[1] if len(hunk_starts) > 1 else len(section)
        chosen = (hunk_starts[0], hend)
    hi, hend = chosen
    return "\n".join(section[hi:hend])


def _read_text(path):
    p = Path(path)
    if not p.is_file():
        return ""
    try:
        return p.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _context_summary(text):
    text = text.strip()
    if len(text) <= CONTEXT_SUMMARY_CHARS:
        return text
    cut = len(text) - CONTEXT_SUMMARY_CHARS
    return text[:CONTEXT_SUMMARY_CHARS] + f"\n...[truncated {cut} chars of context.md]..."


# ---------------------------------------------------------------- (a) triage

def _load_all_findings(run, plan):
    """[(role, finding_dict), ...] across every recorded panel report, role-then-order,
    so component/duplicate grouping is deterministic."""
    out = []
    for role in sorted(plan.get("roles", {})):
        p = run / "panel" / f"{role}.json"
        if not p.exists():
            continue
        report = read_json(p)
        for f in report.get("findings", []):
            out.append((role, f))
    return out


def _triage_one(model, base, timeout, context_summary, diff_text, role, finding, prior_ids):
    fid = finding.get("id", "")
    hunk = extract_cited_hunk(diff_text, finding.get("file", ""), finding.get("line") or 0)
    state = _budget_state({
        "finding": {k: finding.get(k) for k in
                    ("id", "title", "severity", "confidence", "file", "line",
                     "evidence", "scenario")},
        "diff_excerpt": hunk,
        "context_summary": context_summary,
    })
    criteria = {pid: f"the same underlying issue as earlier finding {pid} in this file"
                for pid in prior_ids}
    criteria["none"] = "not a duplicate of any earlier finding in this file"
    questions = {
        "is_real": {"type": "noul", "instructions":
                    "This finding describes a genuine defect, not a false positive or a "
                    "style nit"},
        "severity": {"type": "score", "instructions":
                     "How severe this finding is if real", "criteria": SEVERITY_CRITERIA},
        "duplicate_of": {"type": "choice", "instructions":
                          "This finding is the same underlying issue as", "criteria": criteria},
        "needs_human": {"type": "noul", "instructions":
                         "Resolving this requires product or business judgment a reviewer "
                         "cannot make"},
        "fix_is_obvious": {"type": "noul", "instructions":
                            "The fix is small and mechanical with no design choice involved"},
    }
    result, err = call_jev(state, questions, model=model, base=base, timeout=timeout)
    if err:
        jev = {"model": model, "called_at": now_iso(), "error": err, "cost": None,
               "is_real": 1.0, "severity": None,
               "duplicate_of": {"choice": "none", "confidence": None, "probabilities": None},
               "needs_human": 1.0, "fix_is_obvious": 0.0}
    else:
        answers = result["answers"]
        is_real, ok1 = _noul(answers, "is_real", 1.0)
        severity, _ = _score(answers, "severity", SEVERITY_CRITERIA)
        dup, ok3 = _choice(answers, "duplicate_of")
        needs_human, ok4 = _noul(answers, "needs_human", 1.0)
        fix_obvious, ok5 = _noul(answers, "fix_is_obvious", 0.0)
        shape_err = None if (ok1 and ok3 and ok4 and ok5) else \
            "malformed answer shape for one or more questions -- fail-closed defaults applied"
        jev = {"model": model, "called_at": now_iso(), "error": shape_err,
               "cost": result.get("cost"), "is_real": is_real, "severity": severity,
               "duplicate_of": dup or {"choice": "none", "confidence": None,
                                       "probabilities": None},
               "needs_human": needs_human, "fix_is_obvious": fix_obvious}
    return {"finding_id": fid, "role": role, "component": finding.get("file", ""),
            "reviewer_severity": finding.get("severity"), "title": finding.get("title"),
            "release_blocking": bool(finding.get("release_blocking", False)), "jev": jev}


def _print_triage_worklist(records):
    high = [r for r in records
            if r["reviewer_severity"] in HIGH and r["jev"]["is_real"] >= 0.6]
    high.sort(key=lambda r: -r["jev"]["is_real"])
    dup_clusters = {}
    for r in records:
        d = r["jev"]["duplicate_of"].get("choice")
        if d and d != "none":
            dup_clusters.setdefault(d, []).append(r["finding_id"])
    candidate_fp = [r for r in records
                    if r["reviewer_severity"] not in HIGH and r["jev"]["is_real"] < 0.25]
    errors = [r for r in records if r["jev"]["error"]]

    print(f"\njev triage worklist ({len(records)} finding(s)):")
    print(f"\n  high/critical, likely real ({len(high)}) -- validate these first:")
    for r in high:
        print(f"    [{r['reviewer_severity']:>8}] {r['finding_id']:<16} "
              f"is_real={r['jev']['is_real']:.2f}  needs_human={r['jev']['needs_human']:.2f}  "
              f"{r['title']}")
    if dup_clusters:
        print(f"\n  possible duplicate clusters ({len(dup_clusters)}):")
        for lead, members in dup_clusters.items():
            print(f"    {lead}  <-  {', '.join(members)}")
    print(f"\n  candidate false positives ({len(candidate_fp)}) -- still need a validation "
          f"record; never auto-dismissed:")
    for r in candidate_fp:
        print(f"    [{r['reviewer_severity']:>8}] {r['finding_id']:<16} "
              f"is_real={r['jev']['is_real']:.2f}  {r['title']}")
    if errors:
        print(f"\n  {len(errors)} finding(s) hit a Jev error and were treated as real / "
              f"needs-human (fail-closed) -- see triage/<id>.json")


def cmd_triage(args):
    run = resolve_run(args.run)
    plan_path = run / "panel" / "plan.json"
    if not plan_path.exists():
        die("panel plan missing -- run `panel.py assign` and `panel.py run` first", 2)
    plan = read_json(plan_path)
    all_findings = _load_all_findings(run, plan)
    if not all_findings:
        write_json(run / "triage" / "_summary.json",
                   {"generated_at": now_iso(), "findings": 0})
        print("jev triage: no findings to triage")
        return

    require_jev_key()
    model, base, timeout = jev_config()
    diff_text = _read_text(args.context_file)
    context_summary = _context_summary(diff_text)

    seen_by_component = {}
    records = []
    jev_cost_total = 0.0
    for role, finding in all_findings:
        component = finding.get("file", "") or "(unknown)"
        prior_ids = seen_by_component.get(component, [])
        record = _triage_one(model, base, timeout, context_summary, diff_text, role,
                             finding, prior_ids)
        seen_by_component.setdefault(component, []).append(record["finding_id"])
        fname = record["finding_id"] or f"{role}-unnamed-{len(records)}"
        write_json(run / "triage" / f"{fname}.json", record)
        records.append(record)
        cost = record["jev"].get("cost")
        if isinstance(cost, (int, float)):
            jev_cost_total += cost

    _print_triage_worklist(records)
    write_json(run / "triage" / "_summary.json", {
        "generated_at": now_iso(), "model": model, "findings": len(records),
        "errors": sum(1 for r in records if r["jev"]["error"]),
        "jev_cost_usd": round(jev_cost_total, 6)})


# ---------------------------------------------------------------- (b) rebuttal-gate

def cmd_rebuttal_gate(args):
    run = resolve_run(args.run)
    plan_path = run / "panel" / "plan.json"
    if not plan_path.exists():
        die("panel plan missing -- run `panel.py assign` and `panel.py run` first", 2)
    plan = read_json(plan_path)
    digest = panel.high_critical_digest(run, plan)  # same digest panel.py rebuttal contests
    if not digest:
        write_json(run / "rebuttal" / "plan.json", {
            "generated_at": now_iso(), "model": None, "decisions": {},
            "required_finding_ids": [], "skipped_finding_ids": []})
        write_json(run / "rebuttal" / "digest.json", [])
        print("jev rebuttal-gate: no high/critical findings -- nothing to gate")
        return

    require_jev_key()
    model, base, timeout = jev_config()
    context_summary = _context_summary(_read_text(args.context_file))

    decisions, required, skipped = {}, [], []
    jev_cost_total = 0.0
    for item in digest:
        state = _budget_state({"finding": item, "context_summary": context_summary})
        questions = {
            "contested": {"type": "noul", "instructions":
                          "Reviewers from other roles would materially disagree with this "
                          "finding"},
            "rebuttal_would_change_outcome": {"type": "noul", "instructions":
                          "A rebuttal round could plausibly change whether this finding is "
                          "confirmed, dismissed, or its severity"},
        }
        result, err = call_jev(state, questions, model=model, base=base, timeout=timeout)
        if err:
            contested, would_change = 1.0, 1.0
        else:
            answers = result["answers"]
            contested, ok1 = _noul(answers, "contested", 1.0)
            would_change, ok2 = _noul(answers, "rebuttal_would_change_outcome", 1.0)
            if not (ok1 and ok2):
                err = "malformed answer shape -- fail-closed defaults applied"
            cost = result.get("cost")
            if isinstance(cost, (int, float)):
                jev_cost_total += cost
        decision = "run" if (err or contested >= 0.5 or would_change >= 0.5) else "skip"
        decisions[item["id"]] = {"contested": contested, "would_change": would_change,
                                 "error": err, "decision": decision}
        (required if decision == "run" else skipped).append(item["id"])

    write_json(run / "rebuttal" / "plan.json", {
        "generated_at": now_iso(), "model": model, "decisions": decisions,
        "required_finding_ids": required, "skipped_finding_ids": skipped,
        "jev_cost_usd": round(jev_cost_total, 6)})
    digest_path = run / "rebuttal" / "digest.json"
    write_json(digest_path, [item for item in digest if item["id"] in required])

    print(f"\njev rebuttal-gate: {len(required)}/{len(digest)} high/critical finding(s) "
          f"need contest, {len(skipped)} skipped.")
    for fid in required:
        d = decisions[fid]
        print(f"    RUN   {fid}  contested={d['contested']:.2f}  "
              f"would_change={d['would_change']:.2f}")
    for fid in skipped:
        d = decisions[fid]
        print(f"    skip  {fid}  contested={d['contested']:.2f}  "
              f"would_change={d['would_change']:.2f}")
    print(f"\nnext: panel.py rebuttal --digest-file {digest_path}"
          + ("" if required else "  (empty digest -> writes the none-required marker)"))


# ---------------------------------------------------------------- (c) patch-check

def _confirmed_validation_records(run):
    vdir = run / "validation"
    out = []
    if not vdir.is_dir():
        return out
    for p in sorted(vdir.glob("*.json")):
        if p.name == "concur-request.json":
            continue
        try:
            rec = read_json(p)
        except (OSError, ValueError):
            continue
        if isinstance(rec, dict) and rec.get("classification") == "confirmed":
            out.append((p.stem, rec))
    return out


def _next_patch_check_round(run):
    d = run / "patch_check"
    if not d.is_dir():
        return 1
    nums = []
    for p in d.glob("round-*.json"):
        m = re.match(r"round-(\d+)\.json$", p.name)
        if m:
            nums.append(int(m.group(1)))
    return (max(nums) + 1) if nums else 1


def cmd_patch_check(args):
    run = resolve_run(args.run)
    patch_path = Path(args.patch)
    if not patch_path.is_file():
        die(f"patch file not found: {patch_path}", 2)
    patch_text = _read_text(patch_path)

    confirmed = _confirmed_validation_records(run)
    if not confirmed:
        print("jev patch-check: no confirmed findings on record -- nothing to check")
        round_n = _next_patch_check_round(run)
        write_json(run / "patch_check" / f"round-{round_n}.json", {
            "generated_at": now_iso(), "round": round_n,
            "patch": str(patch_path), "model": None, "jev_cost_usd": 0.0, "items": []})
        return

    require_jev_key()
    model, base, timeout = jev_config()

    results = []
    jev_cost_total = 0.0
    for slug, rec in confirmed:
        finding_ids = rec.get("finding_ids") or [slug]
        state = _budget_state({
            "finding_ids": finding_ids, "evidence": rec.get("evidence", ""),
            "resolution": rec.get("resolution", {}), "patch": patch_text,
        })
        questions = {
            "resolved_by_patch": {"type": "noul", "instructions":
                "This patch fixes the confirmed finding described in evidence/resolution"},
            "patch_introduces_new_risk": {"type": "noul", "instructions":
                "This patch introduces a new defect or risk not present before"},
        }
        result, err = call_jev(state, questions, model=model, base=base, timeout=timeout)
        if err:
            resolved, new_risk = 0.0, 1.0
        else:
            answers = result["answers"]
            resolved, ok1 = _noul(answers, "resolved_by_patch", 0.0)
            new_risk, ok2 = _noul(answers, "patch_introduces_new_risk", 1.0)
            if not (ok1 and ok2):
                err = "malformed answer shape -- fail-closed defaults applied"
            cost = result.get("cost")
            if isinstance(cost, (int, float)):
                jev_cost_total += cost
        if resolved >= 0.8:
            status = "resolved (Claude must confirm)"
        elif resolved < 0.4:
            status = "still open"
        else:
            status = "still open (ambiguous -- verify by hand)"
        results.append({"slug": slug, "finding_ids": finding_ids,
                        "resolved_by_patch": resolved,
                        "patch_introduces_new_risk": new_risk, "status": status,
                        "error": err})

    resolved_items = [r for r in results if r["resolved_by_patch"] >= 0.8]
    open_items = [r for r in results if r["resolved_by_patch"] < 0.8]
    risk_items = [r for r in results if r["patch_introduces_new_risk"] >= 0.5]

    round_n = _next_patch_check_round(run)
    write_json(run / "patch_check" / f"round-{round_n}.json", {
        "generated_at": now_iso(), "round": round_n, "patch": str(patch_path),
        "model": model, "jev_cost_usd": round(jev_cost_total, 6), "items": results})

    print(f"\njev patch-check round {round_n}: {len(results)} confirmed finding(s) checked "
          f"against {patch_path.name}")
    print(f"  resolved, Claude confirms ({len(resolved_items)}):")
    for r in resolved_items:
        print(f"    OK    {r['slug']}  resolved={r['resolved_by_patch']:.2f}")
    print(f"  still open ({len(open_items)}):")
    for r in open_items:
        print(f"    OPEN  {r['slug']}  resolved={r['resolved_by_patch']:.2f}  ({r['status']})")
    print(f"  new risk introduced, back to panel ({len(risk_items)}):")
    for r in risk_items:
        print(f"    RISK  {r['slug']}  new_risk={r['patch_introduces_new_risk']:.2f}")


# ---------------------------------------------------------------- CLI

def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("triage")
    p.add_argument("run", nargs="?", help="run directory (default: newest run under "
                                          "AR_RUN_DIR)")
    p.add_argument("--context-file", default="context.md")
    p.set_defaults(fn=cmd_triage)

    p = sub.add_parser("rebuttal-gate")
    p.add_argument("run", nargs="?")
    p.add_argument("--context-file", default="context.md")
    p.set_defaults(fn=cmd_rebuttal_gate)

    p = sub.add_parser("patch-check")
    p.add_argument("run", nargs="?")
    p.add_argument("patch", help="path to the patch/diff file for the next round")
    p.set_defaults(fn=cmd_patch_check)

    args = ap.parse_args()
    args.fn(args)


if __name__ == "__main__":
    main()
