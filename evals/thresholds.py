#!/usr/bin/env python3
"""Regression thresholds + model-degraded comparison for the reviewer meta-eval (E1-S5).

Two guards, both stdlib-only and 3.9-safe:

  check    run the OFFLINE harness and fail (exit 1) if any metric regresses past a floor in
           ``evals/thresholds.json``. Wired into the CI ``evals`` job. Offline serves SCRIPTED
           reviewer findings, so this guards harness / scorer / dispatch correctness, not model
           quality (which is what a live calibration measures).
  compare  diff two LIVE calibration reports and flag regressions — an overall/per-category detection
           drop past the configured max, or any model whose true-positive contribution fell (the
           "model degraded" alarm). Baseline is the last committed live report; see the runbook in
           ``evals/README.md``.

    python evals/thresholds.py check
    python evals/thresholds.py compare --baseline OLD.json --current NEW.json
"""
import argparse
import json
import math
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
DEFAULT_THRESHOLDS = HERE / "thresholds.json"


def load_thresholds(path=None):
    return json.loads(Path(path or DEFAULT_THRESHOLDS).read_text(encoding="utf-8"))


def _result(obj):
    """Accept either a bare scored ``result`` or the ``{schema, mode, result}`` report wrapper."""
    return obj["result"] if isinstance(obj, dict) and "result" in obj and "aggregate" not in obj else obj


def _finite_rate(x):
    """True if x is a real (non-bool) number and a finite fraction in [0, 1]."""
    return isinstance(x, (int, float)) and not isinstance(x, bool) and math.isfinite(x) and 0 <= x <= 1


def _is_count(x):
    """True if x is a real (non-bool), finite number usable as a true-positive count."""
    return isinstance(x, (int, float)) and not isinstance(x, bool) and math.isfinite(x)


def check_offline(result, thresholds):
    """Return a list of human-readable breach strings (empty list = pass). Pure."""
    result = _result(result)
    breaches = []
    off = thresholds.get("offline", {})
    agg = result.get("aggregate", {}) or {}
    ov = agg.get("overall", {}) or {}
    o = off.get("overall", {})
    dr = ov.get("detection_rate")
    if "min_detection_rate" in o and (dr is None or dr < o["min_detection_rate"]):
        breaches.append("overall detection_rate %s < floor %s" % (dr, o["min_detection_rate"]))
    ofp = ov.get("fp")
    if "max_fp" in o and (not isinstance(ofp, (int, float)) or ofp > o["max_fp"]):
        breaches.append("overall fp %s > ceiling %d" % (ofp, o["max_fp"]))
    for cat, cthr in (off.get("by_category") or {}).items():
        c = (agg.get("by_category") or {}).get(cat)
        if c is None:
            breaches.append("category %r expected by thresholds is absent from the result" % cat)
            continue
        cdr = c.get("detection_rate")
        if "min_detection_rate" in cthr and (cdr is None or cdr < cthr["min_detection_rate"]):
            breaches.append("category %s detection_rate %s < floor %s"
                            % (cat, cdr, cthr["min_detection_rate"]))
        cfp = c.get("fp")
        if "max_fp" in cthr and (not isinstance(cfp, (int, float)) or cfp > cthr["max_fp"]):
            breaches.append("category %s fp %s > ceiling %d" % (cat, cfp, cthr["max_fp"]))
    return breaches


def compare_live(baseline, current, max_drop):
    """Flag regressions between two live calibration reports. Hard signal: overall / per-category
    detection_rate dropping by more than ``max_drop`` (a fraction, e.g. 0.2). Candidate signal: any
    model whose true-positive contribution fell (assignment varies run to run, so it is a candidate
    for pin review, not proof). Returns a list of strings (empty = no regression). Pure."""
    b, c = _result(baseline), _result(current)

    def det(rep, path):
        agg = rep.get("aggregate", {}) or {}
        node = agg.get("overall", {}) if path == "overall" else (agg.get("by_category") or {}).get(path, {})
        return node.get("detection_rate")

    out = []

    def drop(label, bv, cv):
        if bv is None:
            return
        if cv is None:
            out.append("%s detection_rate is absent from the current report" % label)
            return
        if not _finite_rate(bv) or not _finite_rate(cv):
            out.append("%s detection_rate is invalid (baseline=%r, current=%r); expected a finite fraction in [0, 1]"
                       % (label, bv, cv))
            return
        if (bv - cv) > max_drop:
            out.append("%s detection dropped %.0f%% -> %.0f%% (max allowed drop %.0f%%)"
                       % (label, bv * 100, cv * 100, max_drop * 100))

    if c.get("complete") is False:
        out.append("current report is incomplete (stopped early: %s) -- comparison may mask regressions"
                   % (c.get("stop_reason") or "unknown"))
    drop("overall", det(b, "overall"), det(c, "overall"))
    bcat = (b.get("aggregate", {}) or {}).get("by_category", {}) or {}
    ccat = (c.get("aggregate", {}) or {}).get("by_category", {}) or {}
    for cat in sorted(bcat):
        if cat not in ccat:
            out.append("category %s present in baseline is absent from the current report" % cat)
            continue
        drop("category %s" % cat, bcat[cat].get("detection_rate"), ccat[cat].get("detection_rate"))
    bm = (b.get("aggregate", {}) or {}).get("by_model", {}) or {}
    cm = (c.get("aggregate", {}) or {}).get("by_model", {}) or {}
    for m in sorted(bm):
        btp = bm[m].get("tp")
        if not _is_count(btp):
            continue  # no reliable baseline signal for this model
        cmi = cm.get(m, {})
        if "tp" in cmi and not _is_count(cmi["tp"]):
            out.append("model %s true-positive count is invalid in the current report (%r) -- not comparable"
                       % (m, cmi["tp"]))
            continue
        ctp = cmi.get("tp", 0)  # absent -> 0 (real no-contribution signal, unlike malformed data)
        if btp > 0 and ctp < btp:
            out.append("model %s true positives fell %d -> %d (candidate for pin removal / substitution)"
                       % (m, btp, ctp))
    return out


def _run_offline():
    r = subprocess.run([sys.executable, str(HERE / "run.py"), "--mode", "offline",
                        "--no-write", "--print-result", "--quiet"], capture_output=True, text=True)
    if r.returncode != 0:
        sys.stderr.write(r.stderr)
        raise SystemExit("offline harness failed (exit %d)" % r.returncode)
    lines = r.stdout.strip().splitlines()
    if not lines:
        raise SystemExit("offline harness produced no result on stdout")
    return json.loads(lines[-1])


def main(argv=None):
    ap = argparse.ArgumentParser(description="Reviewer meta-eval regression thresholds (E1-S5).")
    sub = ap.add_subparsers(dest="cmd", required=True)
    pc = sub.add_parser("check", help="run the offline harness and fail (exit 1) on any threshold breach")
    pc.add_argument("--thresholds", default=str(DEFAULT_THRESHOLDS))
    pc.add_argument("--result", help="check a pre-computed result JSON instead of running the harness")
    pk = sub.add_parser("compare", help="flag model degradation between two live reports")
    pk.add_argument("--baseline", required=True)
    pk.add_argument("--current", required=True)
    pk.add_argument("--max-drop", type=float, default=None)
    pk.add_argument("--thresholds", default=str(DEFAULT_THRESHOLDS))
    args = ap.parse_args(argv)
    thr = load_thresholds(args.thresholds)

    if args.cmd == "check":
        result = json.loads(Path(args.result).read_text(encoding="utf-8")) if args.result else _run_offline()
        breaches = check_offline(result, thr)
        if breaches:
            print("THRESHOLD BREACH (offline harness regressed past evals/thresholds.json):", file=sys.stderr)
            for b in breaches:
                print("  - " + b, file=sys.stderr)
            return 1
        print("offline thresholds OK", file=sys.stderr)
        return 0

    md = args.max_drop if args.max_drop is not None else (thr.get("live") or {}).get("max_detection_drop", 0.2)
    if not (isinstance(md, (int, float)) and math.isfinite(md) and 0 <= md <= 1):
        print("invalid max drop %r: must be a finite fraction in [0, 1]" % (md,), file=sys.stderr)
        return 2
    base = json.loads(Path(args.baseline).read_text(encoding="utf-8"))
    cur = json.loads(Path(args.current).read_text(encoding="utf-8"))
    regs = compare_live(base, cur, md)
    if regs:
        print("LIVE MODEL DEGRADATION vs baseline:", file=sys.stderr)
        for r in regs:
            print("  - " + r, file=sys.stderr)
        return 1
    print("no live regression vs baseline", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
