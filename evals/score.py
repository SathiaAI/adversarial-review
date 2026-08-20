"""Ground-truth matching + TP/FN/FP scoring for the reviewer meta-evaluation harness (E1-S2).

Consumes the corpus `expected.json` format defined in `evals/corpus_schema.py` (E1-S1) and a list
of reviewer findings (the `findings` array of a `panel.py` report — see `REPORT_SCHEMA`), and answers
one question without hand-waving: **did the panel find defect X?** From that, per-case and aggregate
true-positive / partial / false-negative / false-positive counts fall out.

This module is TOOLING, not pipeline runtime — but it is deliberately kept **stdlib-only and 3.9-safe**
so the harness (E1-S3) is as portable as the thing it measures. It has no side effects: every function
here is pure, so the offline suite can drive every branch deterministically (E1-S2 DoD: 100% branch
coverage of the match/score logic).

## Why the match rule is `file overlap AND (line-near OR root-cause-named)`

A reviewer finding is matched to a known defect when the finding lands in the same file **and** either
its cited line is within the defect's line range (±`line_tol`) **or** the finding's text names the
defect's root cause. Both halves of the OR are necessary because either alone is wrong:

- **Line-only is too strict.** Reviewers cite a line *near* the defect, not always the exact one —
  they may anchor on the call site rather than the definition, cite the fix location, or count lines
  differently than the diff does. An exact-line match would score real detections as misses. Hence a
  tolerance, and hence a second path for when the anchor drifts past it.
- **Tag-only is too loose.** A reviewer's prose might mention "authorization" while discussing an
  unrelated part of the file; counting that as a hit would inflate detection. So the root-cause path
  still requires the finding to be in the *right file*.

The two together credit a detection when the reviewer either pointed at the right place or, having the
right file, named the right root cause — mirroring how Step-4 dedup treats "same component + same root
cause" as the same issue, not "same line".

## Severity awareness

A `must_detect` defect matched by a finding **at or above** its `severity_floor` is a true positive. A
match **below** the floor (a `low` finding on a `high` defect — the panel noticed something but
under-rated it) is a **partial**: recorded separately, and NOT counted as a detection. An unmatched
`must_detect` defect is a false negative.

A false positive is a finding that matches no known defect: on a clean case (no defects) any such
finding beyond `fp_budget` counts; on a defect case only an unmatched **high/critical** finding beyond
budget counts (an extra low/medium finding on a real-defect diff is noise, recorded but not an FP).
"""
import re

# Sensible default line tolerance. Reviewers routinely cite within a few lines of a defect (call site
# vs definition, diff vs file numbering); ±3 credits those without letting an anchor wander into an
# unrelated block. Tunable per call (and per corpus) — the harness (E1-S3) may sweep it.
DEFAULT_LINE_TOL = 3

_SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}
_HIGH = _SEV_RANK["high"]


def sev_rank(severity):
    """Ordinal severity (higher = more severe); an unknown/absent severity floors to the weakest so it
    can never spuriously satisfy a floor."""
    return _SEV_RANK.get(severity, 0)


def _severity_of(finding):
    """Ordinal severity of a finding, tolerating a non-dict finding the same way
    ``match_finding_to_defect`` does — a stray non-dict entry floors to 0 rather than raising, so the
    false-positive tally never crashes on malformed input it already refuses to match."""
    return sev_rank(finding.get("severity") if isinstance(finding, dict) else None)


def _norm_path(path):
    """Normalize a file path for comparison: strip, drop a leading ``./``, ``a/`` or ``b/`` (diff
    prefixes), and collapse backslashes so a Windows-style path compares equal."""
    p = str(path or "").strip().replace("\\", "/")
    for pre in ("./", "a/", "b/"):
        if p.startswith(pre):
            p = p[len(pre):]
            break
    return p


def file_overlaps(finding_file, defect_file):
    """True when a finding's file refers to the same file as a defect locator. Exact match after
    normalization, or a basename match as a fallback for path-prefix differences (a reviewer citing
    ``invoices.py`` vs the locator's ``api/invoices.py``). Basename fallback can over-match two
    same-named files in different dirs, but a single case's diff is small enough that this is a safe,
    documented trade for tolerating prefix drift."""
    a, b = _norm_path(finding_file), _norm_path(defect_file)
    if not a or not b:
        return False
    if a == b:
        return True
    return a.rsplit("/", 1)[-1] == b.rsplit("/", 1)[-1]


def line_in_range(finding_line, line_range, line_tol=DEFAULT_LINE_TOL):
    """True when ``finding_line`` falls within ``[start-tol, end+tol]``. A missing/non-int line (a
    finding with no anchor) never satisfies the line path — it must qualify via the tag path instead."""
    if not isinstance(finding_line, int) or isinstance(finding_line, bool):
        return False
    if not isinstance(line_range, (list, tuple)) or len(line_range) < 2:
        return False
    start, end = line_range[0], line_range[1]
    if start > end:  # tolerate a reversed range in the label
        start, end = end, start
    return (start - line_tol) <= finding_line <= (end + line_tol)


def _finding_text(finding):
    return " ".join(str(finding.get(k) or "") for k in ("title", "evidence", "scenario", "fix"))


def _tokens(text):
    return set(t for t in re.split(r"[^a-z0-9]+", str(text).lower()) if t)


def tag_intersects(root_cause_tags, finding):
    """True when the finding's text names one of the defect's root-cause tags. A tag matches when
    **every** word of the (usually short, hyphenated) tag appears as a token in the finding's
    title/evidence/scenario/fix — e.g. ``missing-ownership-check`` matches text containing "missing",
    "ownership" and "check"; ``idor`` matches text containing "idor". Returns ``(bool, matched_tag)``."""
    toks = _tokens(_finding_text(finding))
    for tag in root_cause_tags or ():
        words = _tokens(tag)
        if words and words <= toks:
            return True, tag
    return False, None


def match_finding_to_defect(finding, defect, line_tol=DEFAULT_LINE_TOL):
    """Whether a reviewer ``finding`` identifies ``defect``. Returns ``(matched, reason)`` where reason
    is ``"location"`` (right file + line near a locator), ``"root_cause"`` (right file + tag named), or
    ``None``."""
    if not isinstance(finding, dict) or not isinstance(defect, dict):
        return False, None
    ffile = finding.get("file")
    fline = finding.get("line")
    locators = defect.get("locators") or []
    file_here = False
    for loc in locators:
        if file_overlaps(ffile, loc.get("file")):
            file_here = True
            if line_in_range(fline, loc.get("line_range"), line_tol):
                return True, "location"
    if file_here and tag_intersects(defect.get("root_cause_tags"), finding)[0]:
        return True, "root_cause"
    return False, None


def score_case(expected, findings, line_tol=DEFAULT_LINE_TOL):
    """Score one case's reviewer findings against its ground truth. ``findings`` is a flat list across
    all reviewers (each an item of a report's ``findings``); pass role-tagged subsets to attribute per
    role. Returns a dict with per-defect outcomes and the case's tp/partial/fn/fp/noise counts."""
    defects = expected.get("defects") or []
    fp_budget = expected.get("fp_budget", 0)
    if not isinstance(fp_budget, int) or isinstance(fp_budget, bool) or fp_budget < 0:
        fp_budget = 0
    findings = list(findings or [])

    matched_idx = set()
    outcomes = []
    tp = partial = fn = 0
    for d in defects:
        floor = sev_rank(d.get("severity_floor"))
        hits = []
        for i, f in enumerate(findings):
            ok, reason = match_finding_to_defect(f, d, line_tol)
            if ok:
                hits.append((i, reason))
        matched_idx.update(i for i, _ in hits)
        if not d.get("must_detect", False):
            outcome = "informational"  # known but optional: matching is a bonus, missing is not an FN
        elif not hits:
            outcome = "fn"
            fn += 1
        else:
            best = max(_severity_of(findings[i]) for i, _ in hits)
            if best >= floor:
                outcome = "tp"
                tp += 1
            else:
                outcome = "partial"
                partial += 1
        outcomes.append({"defect_id": d.get("defect_id"), "must_detect": bool(d.get("must_detect", False)),
                         "outcome": outcome, "matched_finding_indices": [i for i, _ in hits],
                         "match_reasons": [r for _, r in hits]})

    unmatched = [i for i in range(len(findings)) if i not in matched_idx]
    if not defects:  # clean case: every finding is a candidate false positive
        candidate_fp = list(unmatched)
    else:  # defect case: only unmatched high/critical findings are false-alarm candidates
        candidate_fp = [i for i in unmatched if _severity_of(findings[i]) >= _HIGH]
    fp = max(0, len(candidate_fp) - fp_budget)
    noise = len(unmatched) - len(candidate_fp)  # unmatched low/medium on a defect case

    return {
        "tp": tp, "partial": partial, "fn": fn, "fp": fp,
        "fp_budget": fp_budget, "fp_candidates": len(candidate_fp), "noise": noise,
        "must_detect_total": tp + partial + fn,
        "defect_outcomes": outcomes,
        "unmatched_finding_indices": unmatched,
    }


def aggregate(case_results):
    """Roll a list of ``(meta, score)`` pairs up into overall + per-category + per-tier metrics.
    ``meta`` is the case's ``meta.json`` (for ``category``/``tier``); ``score`` is a ``score_case``
    result. ``detection_rate`` counts only true positives (partials are surfaced separately)."""
    def _blank():
        return {"cases": 0, "tp": 0, "partial": 0, "fn": 0, "fp": 0, "noise": 0, "must_detect_total": 0}

    def _add(acc, s):
        acc["cases"] += 1
        for k in ("tp", "partial", "fn", "fp", "noise", "must_detect_total"):
            acc[k] += s.get(k, 0)

    overall, by_cat, by_tier = _blank(), {}, {}
    for meta, s in case_results:
        _add(overall, s)
        cat = (meta or {}).get("category", "?")
        tier = (meta or {}).get("tier", "?")
        _add(by_cat.setdefault(cat, _blank()), s)
        _add(by_tier.setdefault(tier, _blank()), s)

    def _rates(acc):
        md = acc["must_detect_total"]
        acc["detection_rate"] = round(acc["tp"] / md, 4) if md else None
        acc["partial_rate"] = round(acc["partial"] / md, 4) if md else None
        return acc

    _rates(overall)
    for acc in list(by_cat.values()) + list(by_tier.values()):
        _rates(acc)
    return {"overall": overall, "by_category": by_cat, "by_tier": by_tier}
