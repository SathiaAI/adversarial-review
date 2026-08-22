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
from _common import meta_cost  # noqa: E402

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
    reads, not an exhaustive secret scrub — the offline guarantee rests on the base-URL binding.
    `AR_RUN_DIR` is also dropped: an inherited run-root override would send the child's artifacts
    outside the throwaway repo, so `_run_panel` would then find no run dir."""
    env = {k: v for k, v in os.environ.items()
           if k not in ("OPENROUTER_API_KEY", "OPENAI_API_KEY", "AR_KEY_FILE", "AR_MAX_COST_USD",
                        "AR_PINS", "AR_RUN_DIR")}
    env.update({"AR_BASE_URL": base_url, "AR_API_KEY": "offline-mock-key",
                "AR_TIMEOUT_S": "20", "AR_MAX_TOKENS": "2000"})
    return env


def _run_panel(case_dir, tier, base_url, env=None, keep_on_error=False):
    """init/assign/run in a throwaway repo; return (repo, run_dir). Findings land under the run dir.
    The caller owns `repo` on success and removes it; if anything here raises, the repo is removed
    before re-raising so a failed case never leaks an ``ar-eval-*`` directory (Codex, PR #45) — unless
    keep_on_error is set (live mode), where a failed panel may already have billed reviewers, so the
    paid artifacts are preserved for audit and their path logged instead (Codex, PR #46)."""
    repo = Path(tempfile.mkdtemp(prefix="ar-eval-"))
    try:
        shutil.copyfile(case_dir / "context.md", repo / "context.md")
        if env is None:  # offline default; live mode passes the real ambient env
            env = _panel_env(base_url)
        panel = str(ROOT / "scripts" / "panel.py")

        def run(args):
            r = subprocess.run([sys.executable, panel] + args, cwd=str(repo), env=env,
                               capture_output=True, text=True)
            if r.returncode != 0:
                raise RuntimeError("panel %s failed (exit %d)\n%s"
                                   % (" ".join(args), r.returncode, r.stderr))
            return r

        run(["init", "--risk", tier, "--dev-providers", "anthropic"])
        run(["assign"])
        run(["run", "--context-file", "context.md"])
        runs = sorted((repo / ".adversarial-review").glob("run-*"))
        if not runs:
            raise RuntimeError("panel produced no run dir under %s" % repo)
        return repo, runs[-1]
    except BaseException:
        if keep_on_error:
            print("  live panel failed; paid artifacts preserved at %s" % repo, file=sys.stderr)
        else:
            shutil.rmtree(repo, ignore_errors=True)
        raise


def _collect_findings(run_dir):
    """Read the ingested per-role reports back from the run dir, in a stable role order."""
    plan = json.loads((run_dir / "panel" / "plan.json").read_text(encoding="utf-8"))
    per_role = {}
    for role in sorted(plan["roles"]):
        p = run_dir / "panel" / ("%s.json" % role)
        if p.exists():
            per_role[role] = json.loads(p.read_text(encoding="utf-8")).get("findings", [])
    return per_role


def _attribute_roles(flat, case_score, roles_ran=()):
    """Per-role attribution from the case's flat score: findings emitted, and how many landed as a
    true positive / partial / unmatched (FP candidate or noise). `flat` items carry a `_role` tag.
    Every role in `roles_ran` gets an entry even if it emitted nothing — a reviewer that reviewed
    and stayed silent must stay visible (`emitted: 0`), not vanish from the rollup (Codex, PR #45).
    Per-role FN/FP are deliberately not attributed: which defect a given role *should* have caught is
    not encoded (any role may catch any defect), so those live at the case/category/tier level."""
    roles = {}

    def acc(r):
        return roles.setdefault(r, {"emitted": 0, "tp": 0, "partial": 0, "unmatched": 0})

    for r in roles_ran:
        acc(r)
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
        "roles": _attribute_roles(flat, cs, roles_ran=sorted(per_role)),
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
                    print("  %-28s SKIP (no scripts.offline)" % name, file=sys.stderr)
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
                         report["fp"], report["noise"]), file=sys.stderr)
    finally:
        mock_router.reset()
        srv.shutdown()

    agg = score.aggregate(score_pairs)
    agg["by_role"] = _roll_roles(case_reports)
    return {"corpus": corpus_dir.name, "line_tol": line_tol,
            "cases": case_reports, "skipped": sorted(skipped), "aggregate": agg}


def _panel_env_live():
    """Env for a LIVE panel: the ambient environment is passed through unchanged, so reviewers reach
    the configured provider with the operator's real credentials and transport (`AR_BASE_URL`,
    `OPENROUTER_API_KEY`, a key file, or a proxy — whatever config.md resolves). Nothing is stripped,
    unlike the offline env, except AR_RUN_DIR: a child must write its run dir inside its own throwaway
    repo, so an inherited run-root override (which would send artifacts elsewhere and make _run_panel
    find no run dir) is dropped, mirroring the offline env (CodeRabbit + Codex, PR #46)."""
    env = dict(os.environ)
    env.pop("AR_RUN_DIR", None)
    return env


def _live_credentialed(env=None):
    """True only when the panel's OWN resolver (`panel.api_config`) would find a usable key: an
    `AR_API_KEY`, an `OPENROUTER_API_KEY`, or an `AR_KEY_FILE` that actually exists. Mirrors the panel
    exactly (a key is required even behind an `AR_BASE_URL` proxy), so `--mode live` fails fast with the
    same criteria the reviewer calls use instead of passing here — e.g. on `OPENAI_API_KEY`, or a
    non-existent key-file path — only to die later mid-assignment (Codex, PR #46)."""
    e = env if env is not None else os.environ
    key = e.get("AR_API_KEY") or e.get("OPENROUTER_API_KEY")
    kf = e.get("AR_KEY_FILE")
    if not key and kf and Path(kf).expanduser().is_file():
        key = "keyfile"
    return bool(key)


def _case_costs_and_models(run_dir):
    """Per-reviewer model + recorded USD cost from the run dir. Cost is read from the same per-reviewer
    meta the panel's own cost cap sums, via `meta_cost` (a missing / non-finite / negative cost counts
    as 0). Returns `{role: {"model": slug|None, "cost": float}}`."""
    info = {}
    plan = json.loads((run_dir / "panel" / "plan.json").read_text(encoding="utf-8"))
    roles = plan.get("roles", {})
    for role in sorted(roles):
        entry = roles[role] if isinstance(roles[role], dict) else {}
        model, cost = entry.get("model"), 0.0
        mp = run_dir / "panel" / "meta" / ("%s.json" % role)
        if mp.exists():
            m = json.loads(mp.read_text(encoding="utf-8"))
            model = m.get("model", model)
            cost = meta_cost(m)
        info[role] = {"model": model, "cost": cost}
    return info


def _roll_models(units):
    """Per-model attribution + cost, aggregated across every scored (case, rep) unit. A model is
    credited via the role->model map the run recorded. Per-model FN/FP are not attributed, for the same
    reason as per-role: which model *should* have caught a defect is not encoded. Every reviewer's cost
    is summed (even a silent one), so the per-model cost column always reconciles to the run total."""
    out = {}

    def acc(model):
        return out.setdefault(model, {"emitted": 0, "tp": 0, "partial": 0,
                                      "unmatched": 0, "cost_usd": 0.0})

    for u in units:
        for role, r in u["roles"].items():
            a = acc(u["models"].get(role) or "?")
            for k in ("emitted", "tp", "partial", "unmatched"):
                a[k] += r[k]
        for role, cost in u["_role_cost"].items():
            acc(u["models"].get(role) or "?")["cost_usd"] += cost
    return out


def _case_rollup(case_id, meta, units):
    """Collapse a case's per-rep units into one report row: per-rep detail (so single-run noise stays
    visible) plus the case's summed cost and mean detection across reps."""
    md = sum(u["must_detect_total"] for u in units)
    tp = sum(u["tp"] for u in units)
    return {
        "case_id": case_id, "category": meta.get("category"), "tier": meta.get("tier"),
        "reps": len(units),
        "detection_rate": (tp / md) if md else None,
        "tp": tp, "partial": sum(u["partial"] for u in units),
        "fn": sum(u["fn"] for u in units), "fp": sum(u["fp"] for u in units),
        "noise": sum(u["noise"] for u in units),
        "cost_usd": round(sum(u["cost_usd"] for u in units), 6),
        "per_rep": [{"rep": u["rep"], "tp": u["tp"], "partial": u["partial"], "fn": u["fn"],
                     "fp": u["fp"], "noise": u["noise"], "cost_usd": round(u["cost_usd"], 6)}
                    for u in units],
    }


def run_live(corpus_dir, only=None, reps=1, line_tol=score.DEFAULT_LINE_TOL,
             budget_usd=None, quiet=False):
    """Drive the corpus through REAL model panels (`reps` per case) over the configured transport, and
    score each panel's ingested findings with `evals/score.py`. Unlike offline mode it serves no scripts
    and starts no mock router — reviewers answer for real — so it measures model + panel quality, not
    just harness assembly. A cumulative USD budget caps the whole run: before each panel, if spend has
    already reached `budget_usd`, the remaining (case, rep) units are recorded in `not_run` and the run
    stops rather than overspending or silently truncating. Non-deterministic by nature (real models);
    the report keeps enough per-rep raw detail to be audited."""
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
    if reps < 1:
        raise SystemExit("reps must be >= 1")

    # Preflight: validate + load EVERY selected case before any paid call (Codex, PR #46). A malformed
    # case late in the corpus must fail the run before earlier cases spend real money, never after.
    loaded = []
    for name in names:
        cdir = corpus_dir / name
        problems = validate_case(str(cdir))
        if problems:  # a malformed case is broken, never silently skipped
            raise SystemExit("case %s is invalid:\n  - %s" % (name, "\n  - ".join(problems)))
        loaded.append((name, cdir,
                       json.loads((cdir / "meta.json").read_text(encoding="utf-8")),
                       json.loads((cdir / "expected.json").read_text(encoding="utf-8"))))

    env = _panel_env_live()
    units, score_pairs, cases_out, not_run = [], [], [], []
    spent, stopped, stop_reason = 0.0, False, None
    for name, cdir, meta, expected in loaded:
        tier = meta.get("tier", "NORMAL")
        case_units = []
        for k in range(1, reps + 1):
            if stopped or (budget_usd is not None and spent >= budget_usd):
                if not stopped:
                    stopped = True
                    stop_reason = "budget reached ($%.4f of $%.2f)" % (spent, budget_usd)
                not_run.append({"case": name, "rep": k})
                continue
            try:
                repo, run_dir = _run_panel(cdir, tier, None, env=env, keep_on_error=True)
            except BaseException as exc:
                # A live panel can fail after billing earlier reviewers; keep_on_error preserves that
                # paid throwaway repo for audit, and we stop with a report rather than aborting the whole
                # run with a traceback (Codex, PR #46).
                stopped = True
                stop_reason = "live panel failed at %s rep %d: %s" % (name, k, str(exc)[:160])
                not_run.append({"case": name, "rep": k, "error": str(exc)[:200]})
                break
            try:
                per_role = _collect_findings(run_dir)
                role_info = _case_costs_and_models(run_dir)
            finally:
                shutil.rmtree(repo, ignore_errors=True)
            report, pair = _score_one(name, meta, expected, per_role, line_tol)
            rep_cost = sum(ci["cost"] for ci in role_info.values())
            spent += rep_cost
            unit = {
                "case_id": name, "category": meta.get("category"), "tier": tier, "rep": k,
                "tp": report["tp"], "partial": report["partial"], "fn": report["fn"],
                "fp": report["fp"], "noise": report["noise"],
                "must_detect_total": report["must_detect_total"], "cost_usd": rep_cost,
                "roles": report["roles"],
                "models": {r: role_info[r]["model"] for r in role_info},
                "_role_cost": {r: role_info[r]["cost"] for r in role_info},
            }
            units.append(unit)
            score_pairs.append(pair)
            case_units.append(unit)
            if not quiet:
                print("  %-28s rep %d/%d tp=%d partial=%d fn=%d fp=%d cost=$%.4f"
                      % (name, k, reps, unit["tp"], unit["partial"], unit["fn"],
                         unit["fp"], rep_cost), file=sys.stderr)
            if budget_usd is not None and rep_cost <= 0:
                # Fail closed: a completed panel reported no usable cost telemetry, so a dollar budget
                # can't be enforced by summing costs. Stop rather than risk unbounded spend, and say
                # why -- never silently keep spending under a cap that isn't actually binding (PR #46).
                stopped = True
                stop_reason = ("cost telemetry unavailable -- a completed panel reported $0, so "
                               "--budget-usd cannot be enforced")
        if case_units:
            cases_out.append(_case_rollup(name, meta, case_units))

    if score_pairs:
        agg = score.aggregate(score_pairs)
    else:  # budget too small to run even one panel; still emit an honest, empty rollup
        agg = {"overall": {"cases": 0, "must_detect_total": 0, "detection_rate": None,
                           "tp": 0, "partial": 0, "fn": 0, "fp": 0, "noise": 0},
               "by_category": {}, "by_tier": {}}
    agg["by_role"] = _roll_roles(units)
    agg["by_model"] = _roll_models(units)
    clean = [u for u in units if u["category"] == "clean"]
    return {
        "corpus": corpus_dir.name, "line_tol": line_tol, "reps": reps,
        "budget_usd": budget_usd, "spent_usd": round(spent, 6),
        "complete": not stopped, "stop_reason": stop_reason, "not_run": not_run,
        "clean_fp": sum(u["fp"] for u in clean), "clean_units": len(clean),
        "clean_fp_rate": (sum(u["fp"] for u in clean) / len(clean)) if clean else None,
        "cases": cases_out, "aggregate": agg,
    }


def _md_cell(value):
    """Escape a repository-controlled identifier (a case id, category, tier, role, corpus path, or
    skipped id) before it goes into Markdown: a stray ``|``, backtick, or newline in an external
    corpus's id would otherwise forge extra cells/rows or break out of a code span (Codex +
    CodeRabbit, PR #45). Pipes and backticks are escaped; control chars collapse to a space. Callers
    render the result unwrapped — never inside raw backticks, which an embedded backtick could close."""
    s = str(value)
    s = "".join(" " if c in "\r\n\t" else c for c in s)
    return s.replace("\\", "\\\\").replace("|", "\\|").replace("`", "\\`")


def _summary_md(result, generated_at):
    """Human-readable rollup. The audience may not have run the harness — plain language, and the
    scored numbers come straight from `result` (this file is a view, never a second source of truth)."""
    ov = result["aggregate"]["overall"]
    lines = ["# Reviewer meta-eval — offline harness report", ""]
    lines.append("Generated: %s · corpus: %s · line tolerance: ±%d"
                 % (generated_at, _md_cell(result["corpus"]), result["line_tol"]))
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
                     % ", ".join(_md_cell(s) for s in result["skipped"]))
    lines.append("")

    def table(title, by):
        rows = ["## %s" % title, "",
                "| %s | cases | TP | partial | FN | FP | detection |" % title.split()[-1].lower(),
                "|---|---:|---:|---:|---:|---:|---:|"]
        for key in sorted(by):
            a = by[key]
            d = "n/a" if a["detection_rate"] is None else "%.0f%%" % (a["detection_rate"] * 100)
            rows.append("| %s | %d | %d | %d | %d | %d | %s |"
                        % (_md_cell(key), a["cases"], a["tp"], a["partial"], a["fn"], a["fp"], d))
        rows.append("")
        return rows

    lines += table("By category", result["aggregate"]["by_category"])
    lines += table("By tier", result["aggregate"]["by_tier"])

    lines += ["## By reviewer role", "",
              "| role | emitted | TP | partial | unmatched |", "|---|---:|---:|---:|---:|"]
    for role in sorted(result["aggregate"]["by_role"]):
        r = result["aggregate"]["by_role"][role]
        lines.append("| %s | %d | %d | %d | %d |"
                     % (_md_cell(role), r["emitted"], r["tp"], r["partial"], r["unmatched"]))
    lines.append("")

    lines += ["## Per case", "", "| case | category | tier | outcome |", "|---|---|---|---|"]
    for c in result["cases"]:
        bits = []
        for k in ("tp", "partial", "fn", "fp", "noise"):
            if c[k]:
                bits.append("%d %s" % (c[k], k))
        lines.append("| %s | %s | %s | %s |"
                     % (_md_cell(c["case_id"]), _md_cell(c["category"]),
                        _md_cell(c["tier"]), ", ".join(bits) or "clean"))
    lines.append("")
    return "\n".join(lines)


def _live_summary_md(result, generated_at):
    """Human-readable live calibration rollup. Numbers come straight from `result` (this file is a view,
    never a second source of truth). Corpus-controlled ids go through `_md_cell` (Codex + CodeRabbit,
    PR #45)."""
    ov = result["aggregate"]["overall"]
    lines = ["# Reviewer meta-eval \u2014 live calibration report", ""]
    lines.append("Generated: %s \u00b7 corpus: %s \u00b7 reps/case: %d \u00b7 line tolerance: \u00b1%d"
                 % (generated_at, _md_cell(result["corpus"]), result["reps"], result["line_tol"]))
    lines.append("")
    ran = ("Each case ran %d rep(s)" % result["reps"] if result["complete"]
           else "Up to %d rep(s) per case were requested; the run stopped early, so later repetitions "
                "or cases were skipped -- see the per-case table and not_run" % result["reps"])
    lines.append("Live mode runs **real** model panels, so these numbers reflect model + panel quality, "
                 "not just harness assembly. %s; per-rep detail is in the JSON so single-run noise "
                 "stays visible." % ran)
    lines.append("")
    cap = "none" if result["budget_usd"] is None else "$%.2f" % result["budget_usd"]
    tail = "" if result["complete"] else " \u00b7 **stopped early: %s**" % (result.get("stop_reason") or "budget reached")
    lines.append("Budget: %s \u00b7 spent: **$%.4f**%s" % (cap, result["spent_usd"], tail))
    if result["not_run"]:
        skipped = ", ".join("%s#%d" % (_md_cell(u["case"]), u["rep"]) for u in result["not_run"])
        lines.append("")
        lines.append("- Not run (early stop): %s" % skipped)
    lines.append("")
    dr = "n/a" if ov["detection_rate"] is None else "%.0f%%" % (ov["detection_rate"] * 100)
    lines.append("## Overall")
    lines.append("")
    lines.append("- Scored panels (case\u00d7rep): **%d** \u00b7 must-detect (summed over reps): **%d**"
                 % (ov["cases"], ov["must_detect_total"]))
    lines.append("- Detection rate: **%s** \u2014 %d TP, %d partial, %d FN"
                 % (dr, ov["tp"], ov["partial"], ov["fn"]))
    lines.append("- False positives: **%d** \u00b7 clean-case FPs: %d over %d clean panel(s)"
                 % (ov["fp"], result["clean_fp"], result["clean_units"]))
    lines.append("")

    def dtable(title, by):
        rows = ["## %s" % title, "",
                "| %s | panels | TP | partial | FN | FP | detection |" % title.split()[-1].lower(),
                "|---|---:|---:|---:|---:|---:|---:|"]
        for key in sorted(by):
            a = by[key]
            d = "n/a" if a["detection_rate"] is None else "%.0f%%" % (a["detection_rate"] * 100)
            rows.append("| %s | %d | %d | %d | %d | %d | %s |"
                        % (_md_cell(key), a["cases"], a["tp"], a["partial"], a["fn"], a["fp"], d))
        rows.append("")
        return rows

    lines += dtable("By category", result["aggregate"]["by_category"])
    lines += dtable("By tier", result["aggregate"]["by_tier"])

    lines += ["## By reviewer role", "",
              "| role | emitted | TP | partial | unmatched |", "|---|---:|---:|---:|---:|"]
    for role in sorted(result["aggregate"]["by_role"]):
        r = result["aggregate"]["by_role"][role]
        lines.append("| %s | %d | %d | %d | %d |"
                     % (_md_cell(role), r["emitted"], r["tp"], r["partial"], r["unmatched"]))
    lines.append("")

    lines += ["## By model", "",
              "| model | emitted | TP | partial | unmatched | cost |",
              "|---|---:|---:|---:|---:|---:|"]
    for model in sorted(result["aggregate"]["by_model"]):
        m = result["aggregate"]["by_model"][model]
        lines.append("| %s | %d | %d | %d | %d | $%.4f |"
                     % (_md_cell(model), m["emitted"], m["tp"], m["partial"], m["unmatched"],
                        m["cost_usd"]))
    lines.append("")

    lines += ["## Per case", "",
              "| case | category | tier | reps | detection | cost |", "|---|---|---|---:|---:|---:|"]
    for c in result["cases"]:
        d = "n/a" if c["detection_rate"] is None else "%.0f%%" % (c["detection_rate"] * 100)
        lines.append("| %s | %s | %s | %d | %s | $%.4f |"
                     % (_md_cell(c["case_id"]), _md_cell(c["category"]), _md_cell(c["tier"]),
                        c["reps"], d, c["cost_usd"]))
    lines.append("")
    return "\n".join(lines)


def main(argv=None):
    ap = argparse.ArgumentParser(description="Reviewer meta-evaluation harness (offline mode).")
    ap.add_argument("--mode", choices=["offline", "live"], default="offline",
                    help="offline serves scripted reviewers via the mock router (deterministic, free); "
                         "live runs real model panels for calibration (opt-in, spends money).")
    ap.add_argument("--reps", type=int, default=1,
                    help="live mode: panels per case, to quantify reviewer variance (default 1)")
    ap.add_argument("--budget-usd", type=float, default=20.0,
                    help="live mode: hard USD ceiling for the whole run; 0 disables (default 20)")
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
    if args.line_tol < 0:
        # A negative tolerance reaches score.line_in_range(), which then fails every location match
        # and silently reports real detections as false negatives. Reject it up front.
        ap.error("--line-tol must be >= 0 (a negative tolerance makes every location match fail)")

    if args.reps < 1:
        ap.error("--reps must be >= 1")
    if args.mode == "live":
        if not _live_credentialed():
            ap.error("--mode live needs a provider key: set OPENROUTER_API_KEY / AR_API_KEY, or "
                     "AR_KEY_FILE (a key is required even behind an AR_BASE_URL proxy). Offline mode "
                     "needs neither.")
        b = args.budget_usd
        if b is not None and (b != b or b < 0 or b == float("inf")):
            ap.error("--budget-usd must be finite and >= 0 (0 disables the cap; omit for the $20 default)")
        budget = b if (b and b > 0) else None
        result = run_live(args.corpus, only=args.only, reps=args.reps, line_tol=args.line_tol,
                          budget_usd=budget, quiet=args.quiet)
        summarize = _live_summary_md
    else:
        result = run_offline(args.corpus, only=args.only, line_tol=args.line_tol, quiet=args.quiet)
        summarize = _summary_md
    canonical = json.dumps(result, sort_keys=True, separators=(",", ":"))

    if not args.no_write:
        now = datetime.now(timezone.utc)
        generated_at = now.strftime("%Y-%m-%dT%H:%M:%SZ")
        # Filename carries the pid so two harness processes sharing one --out dir in the same second
        # don't overwrite each other's report (Codex, PR #45); it is outside the scored payload.
        stamp = "%s-%d" % (now.strftime("%Y%m%d-%H%M%S"), os.getpid())
        out = Path(args.out)
        out.mkdir(parents=True, exist_ok=True)
        report = {"schema": REPORT_SCHEMA_ID, "mode": args.mode, "generated_at": generated_at,
                  "python": "%d.%d" % sys.version_info[:2], "result": result}
        base = "%s-%s" % (args.mode, stamp)
        (out / (base + ".json")).write_text(
            json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        (out / (base + ".summary.md")).write_text(
            summarize(result, generated_at), encoding="utf-8")
        if not args.quiet:  # diagnostics on stderr so --print-result keeps stdout pure JSON
            ov = result["aggregate"]["overall"]
            print("report: %s" % (out / (base + ".json")), file=sys.stderr)
            noun = "panel(s)" if args.mode == "live" else "case(s)"
            print("detection=%s fp=%d over %d %s"
                  % ("n/a" if ov["detection_rate"] is None else "%.0f%%" % (ov["detection_rate"] * 100),
                     ov["fp"], ov["cases"], noun), file=sys.stderr)

    if args.print_result:
        print(canonical)
    return 0


if __name__ == "__main__":
    sys.exit(main())
