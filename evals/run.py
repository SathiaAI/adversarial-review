#!/usr/bin/env python3
"""Offline meta-evaluation harness runner (E1-S3).

Drives the **real** panel pipeline — `panel.py init` / `assign` / `run`, then the same
ingest+validate path production uses — over the corpus (E1-S1) against the in-process mock
router (`tests/mock_router.py`). Each case's *scripted* reviewer findings
(`expected.json.scripts.offline`, E1-S3) are served through the E0-S1 `response_provider`, the
ingested findings are read back from the run dir, and `evals/score.py` (E1-S2) grades them against
ground truth.

Because the reviewer outputs are scripted, offline mode measures **harness correctness** — panel
assembly, finding ingest/validation, scoring, and aggregation — not model quality, and does so
**deterministically with no network and no API keys**. (Live model quality is E1-S4.) A case scripts
a deliberate miss by omitting the detecting role and a false positive by adding an unmatched finding,
so every scoring outcome (TP / partial / FN / FP / noise) is exercised end-to-end.

    python evals/run.py --mode offline [--corpus DIR] [--out DIR] [--only CASE ...] [--line-tol N]

The scored payload (`result`) is deterministic: same corpus + same scripts -> byte-identical
`result`, with wall-clock stamped only *outside* it (`generated_at`, and the report filename). Stdlib
only, Python 3.9+ — as portable as the pipeline it measures.
"""
import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
for _p in (ROOT / "tests", ROOT / "scripts", HERE):  # mock_router, panel, score/corpus_schema
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

import mock_router  # noqa: E402  (path set above)
import score  # noqa: E402
from corpus_schema import default_corpus_dir, validate_case  # noqa: E402

REPORT_SCHEMA_ID = "adversarial-review/eval-report/1"


def _build_finding(role, i, s):
    """Fill a terse script finding (`SCRIPT_FINDING_SCHEMA`) into a complete panel FINDING so the
    mock router serves a `REPORT_SCHEMA`-valid report and the real ingest/validation path still runs.
    Only the scoring-relevant fields come from the script; the structural rest are defaulted."""
    sev = s["severity"]
    return {
        "id": s.get("id") or "%s-%d" % (role, i + 1),
        "title": s["title"], "severity": sev,
        "confidence": 0.7, "file": s["file"], "line": s["line"],
        "evidence": s.get("evidence", ""), "scenario": s.get("scenario", ""),
        "reproduction": [], "fix": s.get("fix", ""), "regression_test": "",
        "release_blocking": bool(s.get("release_blocking", sev in ("critical", "high"))),
    }


def _make_provider(offline):
    """A `response_provider` (E0-S1) that serves this case's scripted findings per role. A role absent
    from `offline` reviews and finds nothing. Non-`report` kinds fall back to the router default."""
    def provider(meta):
        if meta.get("kind") != "report":
            return None
        role = meta["role"]
        report = mock_router._report(role, meta["model"])  # valid skeleton; override its findings
        report["findings"] = [_build_finding(role, i, s) for i, s in enumerate(offline.get(role, []))]
        return report
    return provider


def _panel_env(base_url):
    """Subprocess env for the panel run. Pointing `AR_BASE_URL` at the local mock router is what keeps
    a synthetic corpus offline — every reviewer call resolves there. Real credential env vars are also
    dropped (defence-in-depth): if `AR_BASE_URL` were somehow ignored, there is still no key in the
    child env to authenticate a live call. The credential list is a denylist of the keys this pipeline
    reads, not an exhaustive secret scrub — the offline guarantee rests on the base-URL binding."""
    env = {k: v for k, v in os.environ.items()
           if k not in ("OPENROUTER_API_KEY", "OPENAI_API_KEY", "AR_KEY_FILE", "AR_MAX_COST_USD",
                        "AR_PINS")}
    env.update({"AR_BASE_URL": base_url, "AR_API_KEY": "offline-mock-key",
                "AR_TIMEOUT_S": "20", "AR_MAX_TOKENS": "2000"})
    return env


def _run_panel(case_dir, tier, base_url):
    """init/assign/run in a throwaway repo; return (repo, run_dir). Findings land under the run dir."""
    repo = Path(tempfile.mkdtemp(prefix="ar-eval-"))
    shutil.copyfile(case_dir / "context.md", repo / "context.md")
    env = _panel_env(base_url)
    panel = str(ROOT / "scripts" / "panel.py")

    def run(args):
        r = subprocess.run([sys.executable, panel] + args, cwd=str(repo), env=env,
                           capture_output=True, text=True)
        if r.returncode != 0:
            raise RuntimeError("panel %s failed (exit %d)\n%s" % (" ".join(args), r.returncode, r.stderr))
        return r

    run(["init", "--risk", tier, "--dev-providers", "anthropic"])
    run(["assign"])
    run(["run", "--context-file", "context.md"])
    runs = sorted((repo / ".adversarial-review").glob("run-*"))
    if not runs:
        raise RuntimeError("panel produced no run dir under %s" % repo)
    return repo, runs[-1]


def _collect_findings(run_dir):
    """Read the ingested per-role reports back from the run dir, in a stable role order."""
    plan = json.loads((run_dir / "panel" / "plan.json").read_text(encoding="utf-8"))
    per_role = {}
    for role in sorted(plan["roles"]):
        p = run_dir / "panel" / ("%s.json" % role)
        if p.exists():
            per_role[role] = json.loads(p.read_text(encoding="utf-8")).get("findings", [])
    return per_role


def _attribute_roles(flat, case_score):
    """Per-role attribution from the case's flat score: findings emitted, and how many landed as a
    true positive / partial / unmatched (FP candidate or noise). `flat` items carry a `_role` tag."""
    roles = {}

    def acc(r):
        return roles.setdefault(r, {"emitted": 0, "tp": 0, "partial": 0, "unmatched": 0})

    for f in flat:
        acc(f.get("_role", "?"))["emitted"] += 1
    for o in case_score["defect_outcomes"]:
        if o["outcome"] in ("tp", "partial"):
            for idx in o["matched_finding_indices"]:
                acc(flat[idx].get("_role", "?"))[o["outcome"]] += 1
    for idx in case_score["unmatched_finding_indices"]:
        acc(flat[idx].get("_role", "?"))["unmatched"] += 1
    return roles


def _score_one(case_id, meta, expected, per_role, line_tol):
    """Score one case: the flat cross-reviewer result plus per-role attribution."""
    flat = []
    for role in sorted(per_role):
        for f in per_role[role]:
            item = dict(f)
            item["_role"] = role
            flat.append(item)
    cs = score.score_case(expected, flat, line_tol)
    return {
        "case_id": case_id, "category": meta.get("category"), "tier": meta.get("tier"),
        "tp": cs["tp"], "partial": cs["partial"], "fn": cs["fn"], "fp": cs["fp"],
        "noise": cs["noise"], "fp_budget": cs["fp_budget"],
        "fp_candidates": cs["fp_candidates"], "must_detect_total": cs["must_detect_total"],
        "defect_outcomes": cs["defect_outcomes"],
        "roles": _attribute_roles(flat, cs),
    }, (meta, cs)


def _roll_roles(cases):
    """Aggregate per-role attribution across cases."""
    out = {}
    for c in cases:
        for role, r in c["roles"].items():
            acc = out.setdefault(role, {"emitted": 0, "tp": 0, "partial": 0, "unmatched": 0})
            for k in ("emitted", "tp", "partial", "unmatched"):
                acc[k] += r[k]
    return out


def run_offline(corpus_dir, only=None, line_tol=score.DEFAULT_LINE_TOL, quiet=False):
    """Drive the whole corpus offline and return the deterministic `result` payload. Raises on a
    *malformed* case or a panel failure — offline mode is a self-test, so a broken case fails the run
    rather than being silently dropped. A case with no `scripts.offline` is not broken, only not
    offline-runnable: it is skipped and listed in `result['skipped']` (surfaced, never silent)."""
    corpus_dir = Path(corpus_dir)
    names = sorted(d.name for d in corpus_dir.iterdir()
                   if d.is_dir() and not d.name.startswith("."))
    if only:
        want = set(only)
        missing = want - set(names)
        if missing:
            raise SystemExit("unknown case(s): %s" % ", ".join(sorted(missing)))
        names = [n for n in names if n in want]
    if not names:
        raise SystemExit("no cases to run in %s" % corpus_dir)

    srv = mock_router.start(0)  # ephemeral port: never collides with a suite already on 8811
    base_url = "http://127.0.0.1:%d/v1" % srv.server_address[1]
    skipped = []
    try:
        case_reports, score_pairs = [], []
        for name in names:
            cdir = corpus_dir / name
            problems = validate_case(str(cdir))
            if problems:  # a malformed case is broken, never silently skipped
                raise SystemExit("case %s is invalid:\n  - %s" % (name, "\n  - ".join(problems)))
            meta = json.loads((cdir / "meta.json").read_text(encoding="utf-8"))
            expected = json.loads((cdir / "expected.json").read_text(encoding="utf-8"))
            offline = (expected.get("scripts") or {}).get("offline")
            if offline is None:
                # `scripts.offline` is optional (E1-S1): a case without it is valid but not
                # offline-runnable (e.g. a live-only historical case). Skip it, but surface the
                # skip — silent truncation would read as "scored everything" when it didn't.
                skipped.append(name)
                if not quiet:
                    print("  %-28s SKIP (no scripts.offline)" % name)
                continue

            mock_router.reset()
            mock_router.STATE["response_provider"] = _make_provider(offline)
            repo, run_dir = _run_panel(cdir, meta.get("tier", "NORMAL"), base_url)
            try:
                per_role = _collect_findings(run_dir)
            finally:
                shutil.rmtree(repo, ignore_errors=True)

            report, pair = _score_one(name, meta, expected, per_role, line_tol)
            case_reports.append(report)
            score_pairs.append(pair)
            if not quiet:
                print("  %-28s tp=%d partial=%d fn=%d fp=%d noise=%d"
                      % (name, report["tp"], report["partial"], report["fn"],
                         report["fp"], report["noise"]))
    finally:
        mock_router.reset()
        srv.shutdown()

    agg = score.aggregate(score_pairs)
    agg["by_role"] = _roll_roles(case_reports)
    return {"corpus": corpus_dir.name, "line_tol": line_tol,
            "cases": case_reports, "skipped": sorted(skipped), "aggregate": agg}


def _summary_md(result, generated_at):
    """Human-readable rollup. The audience may not have run the harness — plain language, and the
    scored numbers come straight from `result` (this file is a view, never a second source of truth)."""
    ov = result["aggregate"]["overall"]
    lines = ["# Reviewer meta-eval — offline harness report", ""]
    lines.append("Generated: %s · corpus: `%s` · line tolerance: ±%d"
                 % (generated_at, result["corpus"], result["line_tol"]))
    lines.append("")
    lines.append("Offline mode serves **scripted** reviewer findings, so these numbers measure the "
                 "harness (assembly + scoring), not model quality. Live-model calibration is E1-S4.")
    lines.append("")
    dr = "n/a" if ov["detection_rate"] is None else "%.0f%%" % (ov["detection_rate"] * 100)
    lines.append("## Overall")
    lines.append("")
    lines.append("- Cases: **%d** · must-detect defects: **%d**" % (ov["cases"], ov["must_detect_total"]))
    lines.append("- Detection rate (true positives): **%s** — %d TP, %d partial, %d FN"
                 % (dr, ov["tp"], ov["partial"], ov["fn"]))
    lines.append("- False positives: **%d** · noise (unmatched low/med on defect cases): %d"
                 % (ov["fp"], ov["noise"]))
    if result.get("skipped"):
        lines.append("- Skipped (no `scripts.offline`, not offline-runnable): %s"
                     % ", ".join("`%s`" % s for s in result["skipped"]))
    lines.append("")

    def table(title, by):
        rows = ["## %s" % title, "",
                "| %s | cases | TP | partial | FN | FP | detection |" % title.split()[-1].lower(),
                "|---|---:|---:|---:|---:|---:|---:|"]
        for key in sorted(by):
            a = by[key]
            d = "n/a" if a["detection_rate"] is None else "%.0f%%" % (a["detection_rate"] * 100)
            rows.append("| %s | %d | %d | %d | %d | %d | %s |"
                        % (key, a["cases"], a["tp"], a["partial"], a["fn"], a["fp"], d))
        rows.append("")
        return rows

    lines += table("By category", result["aggregate"]["by_category"])
    lines += table("By tier", result["aggregate"]["by_tier"])

    lines += ["## By reviewer role", "",
              "| role | emitted | TP | partial | unmatched |", "|---|---:|---:|---:|---:|"]
    for role in sorted(result["aggregate"]["by_role"]):
        r = result["aggregate"]["by_role"][role]
        lines.append("| %s | %d | %d | %d | %d |"
                     % (role, r["emitted"], r["tp"], r["partial"], r["unmatched"]))
    lines.append("")

    lines += ["## Per case", "", "| case | category | tier | outcome |", "|---|---|---|---|"]
    for c in result["cases"]:
        bits = []
        for k in ("tp", "partial", "fn", "fp", "noise"):
            if c[k]:
                bits.append("%d %s" % (c[k], k))
        lines.append("| %s | %s | %s | %s |"
                     % (c["case_id"], c["category"], c["tier"], ", ".join(bits) or "clean"))
    lines.append("")
    return "\n".join(lines)


def main(argv=None):
    ap = argparse.ArgumentParser(description="Reviewer meta-evaluation harness (offline mode).")
    ap.add_argument("--mode", choices=["offline"], default="offline",
                    help="offline drives scripted reviewers via the mock router (live is E1-S4).")
    ap.add_argument("--corpus", default=default_corpus_dir(), help="corpus directory")
    ap.add_argument("--out", default=str(HERE / "report"), help="where to write the report + summary")
    ap.add_argument("--only", nargs="+", metavar="CASE", help="run only these case ids")
    ap.add_argument("--line-tol", type=int, default=score.DEFAULT_LINE_TOL,
                    help="line-match tolerance passed to the scorer")
    ap.add_argument("--print-result", action="store_true",
                    help="print the canonical (deterministic) result JSON to stdout")
    ap.add_argument("--no-write", action="store_true", help="do not write report files")
    ap.add_argument("--quiet", action="store_true", help="suppress per-case progress")
    args = ap.parse_args(argv)

    result = run_offline(args.corpus, only=args.only, line_tol=args.line_tol, quiet=args.quiet)
    canonical = json.dumps(result, sort_keys=True, separators=(",", ":"))

    if not args.no_write:
        generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        out = Path(args.out)
        out.mkdir(parents=True, exist_ok=True)
        report = {"schema": REPORT_SCHEMA_ID, "mode": "offline", "generated_at": generated_at,
                  "python": "%d.%d" % sys.version_info[:2], "result": result}
        (out / ("offline-%s.json" % stamp)).write_text(
            json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        (out / ("offline-%s.summary.md" % stamp)).write_text(
            _summary_md(result, generated_at), encoding="utf-8")
        if not args.quiet:
            ov = result["aggregate"]["overall"]
            print("report: %s" % (out / ("offline-%s.json" % stamp)))
            print("detection=%s fp=%d over %d case(s)"
                  % ("n/a" if ov["detection_rate"] is None else "%.0f%%" % (ov["detection_rate"] * 100),
                     ov["fp"], ov["cases"]))

    if args.print_result:
        print(canonical)
    return 0


if __name__ == "__main__":
    sys.exit(main())
