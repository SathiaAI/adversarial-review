#!/usr/bin/env python3
"""Cross-run trends dashboard for adversarial-review (E5-S2).

Reads a directory of **immutable** run artifacts — each a run dir written by
``aggregate.py`` and carrying a ``verdict.json`` — and emits two files:

  trends.json   a deterministic rollup: every run's extracted metrics (sorted) + a summary.
  trends.html   one self-contained dashboard — inline CSS, inline SVG charts, no JavaScript
                dependencies, and **no external network calls** — so it opens anywhere, offline.

This tool is strictly **read-only** over the run dirs (audit integrity: it never writes into,
renames, or deletes a run artifact). It **tolerates** partial, old, or malformed runs: a run dir
without a readable ``verdict.json`` is skipped and named in the rollup's ``skipped`` list rather
than crashing the report. Runs predating cost accounting (E4) simply have ``cost_usd == null``.

This is *tooling*, not pipeline runtime — it lives in ``integrations/`` and is never imported by
``scripts/*.py``. It is nonetheless kept stdlib-only and Python 3.9-safe for portability.

Usage:
    python integrations/trends.py [RUN_ROOT] [--out-dir DIR]

``RUN_ROOT`` defaults to ``$AR_RUN_DIR`` or ``.adversarial-review``. A run dir is any immediate
subdirectory containing ``verdict.json`` (and ``RUN_ROOT`` itself is accepted if it holds one).
"""
import argparse
import html
import json
import os
import sys

VERDICTS = ("PASS", "FAIL", "BLOCKED")
_VERDICT_CLASS = {"PASS": "pass", "FAIL": "fail", "BLOCKED": "blocked"}


def _read_json(path):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def _int(value):
    """A non-negative int or 0 — never a bool, never a string. Old/partial artifacts vary."""
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else 0


def _extract(run_id, v):
    """Pull the trend metrics out of one ``verdict.json`` mapping.

    Missing or malformed fields degrade to ``None``/``0`` so a mixed corpus of old and new runs
    still charts. ``cost_usd`` is ``None`` when absent (predates E4) and a real float otherwise —
    the two are distinct on the dashboard (unknown vs. measured-zero).
    """
    coverage = v.get("coverage") if isinstance(v.get("coverage"), dict) else {}
    counts = v.get("counts") if isinstance(v.get("counts"), dict) else {}
    findings = coverage.get("findings") if isinstance(coverage.get("findings"), dict) else {}
    gates = coverage.get("gates") if isinstance(coverage.get("gates"), dict) else {}
    panel = coverage.get("panel") if isinstance(coverage.get("panel"), dict) else {}

    verdict = v.get("verdict")
    if verdict not in VERDICTS:
        verdict = "BLOCKED"  # an unrecognized verdict is treated as not-a-pass, never as PASS

    cost = coverage.get("cost_usd")
    cost = float(cost) if isinstance(cost, (int, float)) and not isinstance(cost, bool) else None

    def _len(seq):
        return len(seq) if isinstance(seq, list) else 0

    return {
        "run_id": str(v.get("run_id") or run_id),
        "computed_at": str(v.get("computed_at") or ""),
        "verdict": verdict,
        "risk": str(v.get("risk") or coverage.get("risk") or ""),
        "findings_high_critical": _int(counts.get("findings_high_critical")),
        "findings_medium_low": _int(counts.get("findings_medium_low")),
        "confirmed": _int(counts.get("confirmed")),
        "unresolved": _int(counts.get("unresolved")),
        "findings_raised": _int(findings.get("raised")),
        "findings_triaged": _int(findings.get("triaged")),
        "gates_passed": _len(gates.get("passed")),
        "gates_required": _len(gates.get("required")),
        "roles_filled": _len(panel.get("roles_filled")),
        "roles_required": _len(panel.get("roles_required")),
        "cost_usd": cost,
    }


def collect_runs(root):
    """Walk ``root`` for run dirs and return ``(records, skipped)``.

    A run dir is ``root`` itself if it holds ``verdict.json``, otherwise every immediate
    subdirectory that does. Read-only: nothing under ``root`` is modified. ``records`` is sorted
    deterministically by ``(computed_at, run_id)`` so the report is reproducible; ``skipped`` names
    each candidate dir that had no readable/parseable ``verdict.json`` and why.
    """
    records, skipped = [], []
    if not os.path.isdir(root):
        return records, [f"{root}: not a directory"]

    candidates = []
    if os.path.isfile(os.path.join(root, "verdict.json")):
        candidates.append(root)
    else:
        for name in sorted(os.listdir(root)):
            d = os.path.join(root, name)
            if os.path.isdir(d) and not name.startswith("."):
                candidates.append(d)

    for d in candidates:
        vpath = os.path.join(d, "verdict.json")
        run_id = os.path.basename(d.rstrip("/"))
        if not os.path.isfile(vpath):
            skipped.append(f"{run_id}: no verdict.json")
            continue
        try:
            v = _read_json(vpath)
        except (ValueError, OSError) as exc:
            skipped.append(f"{run_id}: verdict.json unreadable ({exc})")
            continue
        if not isinstance(v, dict):
            skipped.append(f"{run_id}: verdict.json is not an object")
            continue
        records.append(_extract(run_id, v))

    records.sort(key=lambda r: (r["computed_at"], r["run_id"]))
    return records, skipped


def summarize(records):
    """Deterministic aggregate over the extracted records (no wall-clock, no ordering surprises)."""
    by_verdict = {k: 0 for k in VERDICTS}
    for r in records:
        by_verdict[r["verdict"]] += 1
    costs = [r["cost_usd"] for r in records if r["cost_usd"] is not None]
    total = len(records)
    return {
        "total_runs": total,
        "by_verdict": by_verdict,
        "pass_rate": round(by_verdict["PASS"] / total, 4) if total else None,
        "total_cost_usd": round(sum(costs), 6) if costs else None,
        "runs_with_cost": len(costs),
        "total_findings_high_critical": sum(r["findings_high_critical"] for r in records),
        "total_unresolved": sum(r["unresolved"] for r in records),
    }


# --- rendering (inline SVG, no JS deps, no external calls) --------------------------------------

def _esc(text):
    return html.escape(str(text), quote=True)


def _svg_line(records, key, label, stroke):
    """A minimal inline-SVG line chart over the run sequence (index x-axis, so it is 3.9-safe and
    needs no datetime parsing). Returns '' when there is nothing numeric to plot."""
    pts = [(i, r[key]) for i, r in enumerate(records) if isinstance(r.get(key), (int, float))]
    if len(pts) < 1:
        return ""
    W, H, pad = 640, 140, 24
    xs = [p[0] for p in pts]
    ys = [p[1] for p in pts]
    xmin, xmax = min(xs), max(xs)
    ymax = max(ys) or 1
    span = (xmax - xmin) or 1

    def sx(x):
        return pad + (x - xmin) / span * (W - 2 * pad)

    def sy(y):
        return H - pad - (y / ymax) * (H - 2 * pad)

    if len(pts) == 1:
        body = '<circle cx="%.1f" cy="%.1f" r="3" fill="%s"/>' % (sx(xs[0]), sy(ys[0]), stroke)
    else:
        d = " ".join(("M" if i == 0 else "L") + "%.1f %.1f" % (sx(x), sy(y))
                     for i, (x, y) in enumerate(pts))
        dots = "".join('<circle cx="%.1f" cy="%.1f" r="2.5" fill="%s"/>' % (sx(x), sy(y), stroke)
                       for x, y in pts)
        body = '<path d="%s" fill="none" stroke="%s" stroke-width="2"/>%s' % (d, stroke, dots)
    return (
        '<figure class="chart"><figcaption>%s <span class="peak">peak %s</span></figcaption>'
        '<svg viewBox="0 0 %d %d" role="img" aria-label="%s over %d runs">'
        '<line x1="%d" y1="%d" x2="%d" y2="%d" class="axis"/>'
        '<line x1="%d" y1="%d" x2="%d" y2="%d" class="axis"/>%s</svg></figure>'
        % (_esc(label), _esc(ymax), W, H, _esc(label), len(pts),
           pad, H - pad, W - pad, H - pad, pad, pad, pad, H - pad, body))


def _verdict_bar(summary):
    """A stacked verdict-distribution bar — pure inline SVG, proportional widths."""
    total = summary["total_runs"] or 1
    W, H = 640, 34
    x = 0
    segs = []
    for verdict in VERDICTS:
        n = summary["by_verdict"][verdict]
        if not n:
            continue
        w = n / total * W
        segs.append(
            '<rect x="%.1f" y="0" width="%.1f" height="%d" class="seg %s"/>'
            '<text x="%.1f" y="22" class="segtext">%s %d</text>'
            % (x, w, H, _VERDICT_CLASS[verdict], x + 6, verdict[0], n))
        x += w
    return ('<svg viewBox="0 0 %d %d" class="vbar" role="img" aria-label="verdict distribution">'
            '%s</svg>' % (W, H, "".join(segs)))


def _rows(records):
    out = []
    for r in reversed(records):  # newest first in the table
        cost = "—" if r["cost_usd"] is None else "$%.4f" % r["cost_usd"]
        out.append(
            "<tr><td>%s</td><td>%s</td><td><span class='pill %s'>%s</span></td><td>%s</td>"
            "<td class='num'>%d</td><td class='num'>%d</td><td class='num'>%d/%d</td>"
            "<td class='num'>%s</td></tr>"
            % (_esc(r["run_id"]), _esc(r["computed_at"] or "—"),
               _VERDICT_CLASS[r["verdict"]], _esc(r["verdict"]), _esc(r["risk"] or "—"),
               r["findings_high_critical"], r["unresolved"],
               r["gates_passed"], r["gates_required"], cost))
    return "".join(out)


def render_html(records, summary, skipped, generated_at=""):
    """One self-contained HTML document. ``generated_at`` is stamped only in the header (kept out
    of the machine rollup) so the JSON stays byte-identical across regenerations of the same runs."""
    tiles = [
        ("Runs", summary["total_runs"]),
        ("Pass rate", "—" if summary["pass_rate"] is None else "%d%%" % round(summary["pass_rate"] * 100)),
        ("High/critical", summary["total_findings_high_critical"]),
        ("Unresolved", summary["total_unresolved"]),
        ("Total cost", "—" if summary["total_cost_usd"] is None else "$%.2f" % summary["total_cost_usd"]),
    ]
    tile_html = "".join('<div class="tile"><span class="v">%s</span><span class="k">%s</span></div>'
                        % (_esc(val), _esc(key)) for key, val in tiles)
    charts = (
        _svg_line(records, "findings_high_critical", "High/critical findings", "#c0392b")
        + _svg_line(records, "unresolved", "Unresolved findings", "#b9770e")
        + (_svg_line(records, "cost_usd", "Cost per run (USD)", "#1f6f5c")
           if summary["runs_with_cost"] else ""))
    skip_html = ""
    if skipped:
        skip_html = ('<details class="skips"><summary>%d run(s) skipped</summary><ul>%s</ul></details>'
                     % (len(skipped), "".join("<li>%s</li>" % _esc(s) for s in skipped)))
    empty = "" if records else '<p class="empty">No runs with a readable verdict.json were found.</p>'
    gen = ('<span class="gen">generated %s</span>' % _esc(generated_at)) if generated_at else ""
    # str.replace (not %/.format) because the inline CSS is full of literal % and {} that would
    # otherwise be read as format directives.
    subs = {
        "@@TILES@@": tile_html, "@@VBAR@@": _verdict_bar(summary), "@@CHARTS@@": charts,
        "@@ROWS@@": _rows(records), "@@SKIPS@@": skip_html, "@@EMPTY@@": empty, "@@GEN@@": gen,
    }
    out = _TEMPLATE
    for token, value in subs.items():
        out = out.replace(token, value)
    return out


_TEMPLATE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>adversarial-review — run trends</title>
<style>
:root{color-scheme:light dark}
*{box-sizing:border-box}
body{margin:0;font:15px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif;
  background:#f6f7f9;color:#1a1c1f}
@media(prefers-color-scheme:dark){body{background:#14161a;color:#e8eaed}
  .tile,.panel{background:#1e2126;border-color:#2c3038}
  th{background:#1e2126}}
.wrap{max-width:860px;margin:0 auto;padding:28px 20px 56px}
h1{font-size:20px;margin:0 0 2px}.gen{color:#8a9099;font-size:12px}
.tiles{display:flex;flex-wrap:wrap;gap:12px;margin:18px 0}
.tile{flex:1 1 120px;background:#fff;border:1px solid #e3e6ea;border-radius:10px;padding:12px 14px}
.tile .v{display:block;font-size:24px;font-weight:650}
.tile .k{color:#6b7280;font-size:12px;text-transform:uppercase;letter-spacing:.03em}
.panel{background:#fff;border:1px solid #e3e6ea;border-radius:10px;padding:16px 18px;margin:16px 0}
.vbar{width:100%;height:34px}.seg{opacity:.9}.segtext{fill:#fff;font-size:12px;font-weight:600}
.seg.pass{fill:#2e8b57}.seg.fail{fill:#c0392b}.seg.blocked{fill:#b9770e}
.chart{margin:10px 0 4px}.chart figcaption{font-size:13px;color:#6b7280;margin-bottom:2px}
.chart .peak{color:#9aa0a8}.chart svg{width:100%;height:auto}.axis{stroke:#c7ccd2;stroke-width:1}
table{width:100%;border-collapse:collapse;font-size:13px}
th,td{text-align:left;padding:7px 8px;border-bottom:1px solid #e6e9ed}
th{background:#f0f2f5;font-weight:600}.num{text-align:right;font-variant-numeric:tabular-nums}
.pill{padding:1px 8px;border-radius:20px;color:#fff;font-size:12px;font-weight:600}
.pill.pass{background:#2e8b57}.pill.fail{background:#c0392b}.pill.blocked{background:#b9770e}
.skips{margin-top:14px;font-size:13px;color:#6b7280}.empty{color:#6b7280}
h2{font-size:15px;margin:0 0 8px}
</style></head>
<body><div class="wrap">
<h1>adversarial-review — run trends @@GEN@@</h1>
<div class="tiles">@@TILES@@</div>
<div class="panel"><h2>Verdict distribution</h2>@@VBAR@@</div>
<div class="panel"><h2>Trends</h2>@@CHARTS@@@@EMPTY@@</div>
<div class="panel"><h2>Runs</h2>
<table><thead><tr><th>Run</th><th>Computed</th><th>Verdict</th><th>Risk</th>
<th class="num">Hi/Crit</th><th class="num">Unresolved</th><th class="num">Gates</th>
<th class="num">Cost</th></tr></thead><tbody>@@ROWS@@</tbody></table>
@@SKIPS@@</div>
</div></body></html>
"""


def build(root, out_dir, generated_at=""):
    """Collect, summarize, and write ``trends.json`` + ``trends.html`` into ``out_dir`` (created if
    needed, and never inside a run dir). Returns ``(records, summary, skipped)``."""
    records, skipped = collect_runs(root)
    summary = summarize(records)
    os.makedirs(out_dir, exist_ok=True)
    rollup = {"summary": summary, "runs": records, "skipped": skipped}
    with open(os.path.join(out_dir, "trends.json"), "w", encoding="utf-8") as fh:
        json.dump(rollup, fh, indent=2, sort_keys=True)
        fh.write("\n")
    with open(os.path.join(out_dir, "trends.html"), "w", encoding="utf-8") as fh:
        fh.write(render_html(records, summary, skipped, generated_at))
    return records, summary, skipped


def main(argv=None):
    ap = argparse.ArgumentParser(description="Cross-run trends dashboard (read-only over run dirs).")
    ap.add_argument("root", nargs="?",
                    default=os.environ.get("AR_RUN_DIR", ".adversarial-review"),
                    help="directory holding run dirs (default: $AR_RUN_DIR or .adversarial-review)")
    ap.add_argument("--out-dir", default=".",
                    help="where to write trends.json + trends.html (default: current directory)")
    ap.add_argument("--stamp", default="",
                    help="optional generation label shown in the HTML header (kept out of the JSON)")
    args = ap.parse_args(argv)
    records, summary, skipped = build(args.root, args.out_dir, args.stamp)
    print("trends: %d run(s), %d skipped -> %s"
          % (len(records), len(skipped), os.path.join(args.out_dir, "trends.html")))
    if not records and skipped:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
