"""Corpus case format + validator for the reviewer meta-evaluation harness (E1-S1).

A case lives in ``evals/corpus/<case-id>/`` and is three files:

  meta.json      case identity/classification            (schema: META_SCHEMA)
  context.md     the diff + surrounding code, exactly as a reviewer receives it
  expected.json  ground-truth labels the scorer grades reviewer output against
                 (schema: EXPECTED_SCHEMA)

Cases are DATA, not code — a new case is added by dropping in a directory, no harness
change. The matching/scoring semantics that consume ``expected.json`` (TP/FN/FP) land in
E1-S2 (``evals/score.py``); this module owns only the *format* and its validation.

The validator reuses ``scripts/panel.py:validate_obj`` — the same stdlib JSON-schema subset
the panel uses for reviewer reports — so the corpus is held to the pipeline's strictness with
zero new dependencies. Malformed cases fail loudly (a typo'd key or bad enum is an error, never
silently ignored), mirroring the strict policy-file parsing in ``_common.py``. Python 3.9+, stdlib
only.
"""
import json
import os
import sys

# Reuse the pipeline's stdlib schema validator instead of reimplementing one.
_SCRIPTS = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts")
if _SCRIPTS not in sys.path:
    sys.path.insert(0, _SCRIPTS)
from panel import validate_obj  # noqa: E402  (path set above)

# Mirrors scripts/panel.py:ROLES (all six reviewer lenses) plus "clean" for no-defect cases,
# so the corpus can classify coverage for every role the panel runs — including the
# SENSITIVE/CRITICAL-only data_privacy and reliability reviewers.
CATEGORIES = ["security", "correctness", "data_privacy", "test_quality", "reliability",
              "output_fidelity", "clean"]
TIERS = ["NORMAL", "SENSITIVE", "CRITICAL"]
SEVERITIES = ["critical", "high", "medium", "low"]
SOURCES = ["seeded", "historical", "cve"]

META_SCHEMA = {
    "type": "object", "additionalProperties": False,
    "properties": {
        "id": {"type": "string"},
        "title": {"type": "string"},
        "tier": {"type": "string", "enum": TIERS},
        "category": {"type": "string", "enum": CATEGORIES},
        "language": {"type": "string"},
        "source": {"type": "string", "enum": SOURCES},
        "cwe": {"type": "string"},  # optional (present for security/known-taxonomy cases)
    },
    "required": ["id", "title", "tier", "category", "language", "source"],
}

LOCATOR_SCHEMA = {
    "type": "object", "additionalProperties": False,
    "properties": {
        "file": {"type": "string"},
        # [start, end] 1-indexed lines in the file as it appears in context.md's diff.
        "line_range": {"type": "array", "items": {"type": "integer"}, "minItems": 2},
    },
    "required": ["file", "line_range"],
}

DEFECT_SCHEMA = {
    "type": "object", "additionalProperties": False,
    "properties": {
        "defect_id": {"type": "string"},
        "must_detect": {"type": "boolean"},
        "locators": {"type": "array", "items": LOCATOR_SCHEMA, "minItems": 1},
        "root_cause_tags": {"type": "array", "items": {"type": "string"}, "minItems": 1},
        "severity_floor": {"type": "string", "enum": SEVERITIES},
    },
    "required": ["defect_id", "must_detect", "locators", "root_cause_tags", "severity_floor"],
}

# The nested defect/locator objects are STRICT (additionalProperties: False) so a typo'd label
# is caught. The top level is STRICT too (additionalProperties: False) so a typo'd or stray
# expected-result field fails loudly. When E1-S3 adds its optional `scripts` block (scripted
# reviewer outputs for offline harness mode), it adds that to `properties` here in the same change.
EXPECTED_SCHEMA = {
    "type": "object", "additionalProperties": False,
    "properties": {
        "defects": {"type": "array", "items": DEFECT_SCHEMA},
        # Max tolerated findings before an extra one scores as a false positive. Clean cases
        # (defects == []) bound total findings; defect cases bound findings beyond the known set.
        "fp_budget": {"type": "integer"},
    },
    "required": ["defects", "fp_budget"],
}

CASE_FILES = ("meta.json", "context.md", "expected.json")


def _read_json(path):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def validate_case(case_dir):
    """Return a list of human-readable problems with the case ([] means valid)."""
    errs = []
    case_id = os.path.basename(case_dir.rstrip("/"))
    paths = {name: os.path.join(case_dir, name) for name in CASE_FILES}

    missing = [name for name in CASE_FILES if not os.path.isfile(paths[name])]
    if missing:
        return [f"{case_id}: missing {name}" for name in missing]

    try:  # context.md must be readable UTF-8 with substantive (non-whitespace) content
        ctx_text = open(paths["context.md"], encoding="utf-8").read()
        if not ctx_text.strip():
            errs.append(f"{case_id}: context.md is blank (a reviewer needs something to review)")
    except (UnicodeDecodeError, OSError) as exc:
        errs.append(f"{case_id}: context.md is not readable UTF-8 text: {exc}")

    meta, meta_ok = None, False
    try:
        meta = _read_json(paths["meta.json"])
        meta_ok = True
    except (ValueError, OSError) as exc:
        errs.append(f"{case_id}: meta.json is not valid JSON: {exc}")
    if meta_ok:  # validate even a non-object root — a JSON array/scalar is malformed, not skipped
        errs += ["%s/meta.json %s" % (case_id, e) for e in validate_obj(meta, META_SCHEMA)]
        if isinstance(meta, dict) and meta.get("id") != case_id:
            errs.append(f"{case_id}: meta.json id {meta.get('id')!r} != directory name {case_id!r}")

    exp, exp_ok = None, False
    try:
        exp = _read_json(paths["expected.json"])
        exp_ok = True
    except (ValueError, OSError) as exc:
        errs.append(f"{case_id}: expected.json is not valid JSON: {exc}")
    if exp_ok:
        errs += ["%s/expected.json %s" % (case_id, e) for e in validate_obj(exp, EXPECTED_SCHEMA)]
        if isinstance(exp, dict):
            errs += _expected_semantics(case_id, meta, exp)
    return errs


def _expected_semantics(case_id, meta, exp):
    """Checks the schema subset can't express (ordering, budgets, category coherence)."""
    errs = []
    budget = exp.get("fp_budget")
    if isinstance(budget, int) and not isinstance(budget, bool) and budget < 0:
        errs.append(f"{case_id}: expected.json fp_budget must be >= 0")

    defects = exp.get("defects") if isinstance(exp.get("defects"), list) else []
    for i, defect in enumerate(defects):
        if not isinstance(defect, dict):
            continue
        locs = defect.get("locators") if isinstance(defect.get("locators"), list) else []
        for j, loc in enumerate(locs):
            if not (isinstance(loc, dict) and isinstance(loc.get("line_range"), list)):
                continue
            lr = loc["line_range"]
            if len(lr) != 2:
                errs.append(f"{case_id}: defects[{i}].locators[{j}].line_range must be [start, end]")
            elif all(isinstance(x, int) and not isinstance(x, bool) for x in lr):
                if lr[0] < 1 or lr[1] < 1:
                    errs.append(
                        f"{case_id}: defects[{i}].locators[{j}].line_range lines are 1-indexed (>= 1)")
                elif lr[0] > lr[1]:
                    errs.append(f"{case_id}: defects[{i}].locators[{j}].line_range start > end")

    # Category/label coherence: a 'clean' case asserts no defect to find; any other category
    # must carry at least one must_detect defect, else the case can never score a true positive.
    if isinstance(meta, dict):
        has_must = any(isinstance(d, dict) and d.get("must_detect") for d in defects)
        if meta.get("category") == "clean" and defects:
            errs.append(f"{case_id}: 'clean' category must have an empty defects list")
        if meta.get("category") not in (None, "clean") and not has_must:
            errs.append(
                f"{case_id}: category {meta.get('category')!r} needs >= 1 must_detect defect")
    return errs


def validate_corpus(corpus_dir):
    """Validate every case directory under corpus_dir. Returns (n_cases, errors)."""
    if not os.path.isdir(corpus_dir):
        return 0, [f"corpus directory not found: {corpus_dir}"]
    case_dirs = sorted(
        os.path.join(corpus_dir, name) for name in os.listdir(corpus_dir)
        if os.path.isdir(os.path.join(corpus_dir, name)) and not name.startswith("."))
    errs = []
    for cd in case_dirs:
        errs += validate_case(cd)
    return len(case_dirs), errs


def default_corpus_dir():
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "corpus")


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else default_corpus_dir()
    n_cases, problems = validate_corpus(target)
    if problems:
        print(f"corpus INVALID — {len(problems)} problem(s) across {n_cases} case(s):")
        for p in problems:
            print("  -", p)
        sys.exit(1)
    print(f"corpus OK — {n_cases} case(s) valid")
