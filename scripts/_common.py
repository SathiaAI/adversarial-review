"""Shared helpers for adversarial-review scripts. Stdlib only, by design."""
import hashlib
import json
import math
import os
import re
import sys
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

RUN_ROOT = Path(os.environ.get("AR_RUN_DIR", ".adversarial-review"))


def now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def resolve_run(run_arg=None):
    """Return the run directory: explicit arg, else newest run-* under the root."""
    if run_arg:
        p = Path(run_arg) if os.sep in str(run_arg) else RUN_ROOT / run_arg
        if not p.is_dir():
            die(f"run directory not found: {p}")
        return p
    if not RUN_ROOT.is_dir():
        die(f"no {RUN_ROOT}/ directory — run `panel.py init` first")
    runs = sorted(d for d in RUN_ROOT.iterdir() if d.is_dir() and d.name.startswith("run-"))
    if not runs:
        die(f"no runs under {RUN_ROOT}/ — run `panel.py init` first")
    return runs[-1]


def read_json(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def write_json(path, obj):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, ensure_ascii=False)
        f.write("\n")


def die(msg, code=1):
    print(f"ERROR: {msg}", file=sys.stderr)
    sys.exit(code)


# Provider-family normalization. Family = the model AUTHOR's organization — the unit of
# independence. Slug prefixes vary across routers; map known variants to one family key.
FAMILY_ALIASES = {
    "anthropic": "anthropic",
    "openai": "openai",
    "google": "google",
    "x-ai": "xai", "xai": "xai",
    "qwen": "qwen", "alibaba": "qwen",
    "mistralai": "mistral", "mistral": "mistral",
    "deepseek": "deepseek",
    "meta-llama": "meta", "meta": "meta",
    "moonshotai": "moonshot", "moonshot": "moonshot",
    "z-ai": "zai", "zai": "zai", "zhipu": "zai",
    "cohere": "cohere",
    "amazon": "amazon",
    "microsoft": "microsoft",
    "nvidia": "nvidia",
    "ai21": "ai21",
}


def family_of(slug):
    prefix = slug.split("/", 1)[0].lower()
    return FAMILY_ALIASES.get(prefix, prefix)


# ------------------------------------------------------------------- policy as code
# Repo-versioned defaults (issue #6): `.adversarial-review.yml` (strict minimal YAML
# subset) or `.adversarial-review.json` at the reviewed repo's root. Precedence
# everywhere: CLI flag > env var > policy file > built-in default. A malformed policy
# is a loud error — never a silent fallback — even when CLI flags would have sufficed.

POLICY_BASENAMES = (".adversarial-review.yml", ".adversarial-review.json")
POLICY_KEYS = ("risk", "dev_providers", "rebuttal_policy", "required_gates", "pins",
               "mutation", "max_cost_usd", "high_samples",
               "allow_critical_waivers", "max_waiver_days")
VALID_RISKS = ("NORMAL", "SENSITIVE", "CRITICAL")
VALID_REBUTTAL = ("critical", "contention", "any")
MAX_HIGH_SAMPLES = 25  # practical upper bound on corroboration samples (E4-S3): bounds the
                       # cost blast radius and the not_run list built on a cost-abort.
# Scoped/bounded mutation budget — a repo-tunable cost cap so mutation testing survives
# large or resource-constrained repos. A flat mapping (the strict YAML subset allows one
# nested level); every field is optional. The configured budget is snapshotted into the
# run's policy record, so a bounded run's coverage reduction is on the record, never
# silent. See references/gates.md.
MUTATION_KEYS = ("scope", "threshold", "max_mutants", "sample_pct",
                 "concurrency", "timeout_s", "exclude_files", "exclude_tests")


def _strip_comment(line):
    """Drop a trailing comment: '#' at start-of-line or preceded by whitespace,
    outside single/double quotes."""
    quote = None
    for j, ch in enumerate(line):
        if quote:
            if ch == quote:
                quote = None
        elif ch in "'\"":
            quote = ch
        elif ch == "#" and (j == 0 or line[j - 1] in " \t"):
            return line[:j]
    return line


def _parse_policy_yaml(text, name):
    """Parse the documented strict YAML subset: 'key: value' scalars, inline
    [a, b] lists, '{}' empty maps, 'key:' followed by '- item' block lists or ONE
    nested mapping level, comments. No coercion — every scalar stays a string.
    Anything outside the subset dies loudly; .adversarial-review.json is the
    escape hatch for richer needs."""
    def perr(ln, msg):
        die(f"{name}:{ln}: {msg}\n  supported subset: 'key: value', 'key:' + "
            "'- item' lists, one nested mapping level, inline [a, b] lists, '{}' "
            "for an empty map, '#' comments. For anything richer use "
            ".adversarial-review.json")

    def scalar(tok, ln):
        tok = tok.strip()
        if not tok:
            perr(ln, "missing value")
        if tok[0] in "&*!|>" or tok.startswith("---"):
            perr(ln, f"unsupported YAML construct {tok!r}")
        if len(tok) >= 2 and tok[0] == tok[-1] and tok[0] in "'\"":
            tok = tok[1:-1].strip()
            if not tok:
                perr(ln, "empty quoted value")
        if any(c in tok for c in "{}[],"):
            perr(ln, f"unexpected flow character in scalar {tok!r}")
        return tok

    def value_of(tok, ln):
        tok = tok.strip()
        if tok == "{}":
            return {}
        if tok == "[]":
            return []
        if tok.startswith("["):
            if not tok.endswith("]"):
                perr(ln, f"unterminated flow list {tok!r}")
            inner = tok[1:-1].strip()
            return [scalar(p, ln) for p in inner.split(",")] if inner else []
        if tok.startswith("{"):
            perr(ln, "non-empty {…} flow mappings are not supported")
        return scalar(tok, ln)

    items = []
    for ln, raw in enumerate(text.splitlines(), 1):
        s = _strip_comment(raw).rstrip()
        if not s.strip():
            continue
        stripped = s.lstrip(" ")
        if stripped.startswith("\t"):
            perr(ln, "tab characters are not allowed in indentation")
        items.append((ln, len(s) - len(stripped), stripped))
    if not items:
        die(f"{name}: policy file exists but is empty — delete it or add settings")

    idx = 0

    def parse_list(parent_indent):
        nonlocal idx
        base = items[idx][1]
        out = []
        while idx < len(items) and items[idx][1] >= base and items[idx][2].startswith("-"):
            ln, ind, s = items[idx]
            if ind != base:
                perr(ln, f"inconsistent indentation (expected column {base})")
            if not s.startswith("- "):
                perr(ln, f"list items must be '- value', got {s!r}")
            out.append(scalar(s[2:], ln))
            idx += 1
        if idx < len(items) and items[idx][1] > parent_indent \
                and not items[idx][2].startswith("-"):
            perr(items[idx][0], "unexpected line after list items")
        return out

    def parse_map(depth):
        nonlocal idx
        base = items[idx][1]
        if depth == 0 and base != 0:
            perr(items[idx][0], "top-level keys must start at column 0")
        out = {}
        while idx < len(items) and items[idx][1] >= base:
            ln, ind, s = items[idx]
            if ind != base:
                perr(ln, f"inconsistent indentation (expected column {base})")
            if s.startswith("-"):
                perr(ln, "list item found where a key was expected")
            if ":" not in s:
                perr(ln, f"expected 'key:' or 'key: value', got {s!r}")
            key, _, rest = s.partition(":")
            key = scalar(key, ln)
            if key in out:
                perr(ln, f"duplicate key {key!r}")
            rest = rest.strip()
            idx += 1
            if rest:
                out[key] = value_of(rest, ln)
                continue
            if idx >= len(items) or items[idx][1] <= base:
                perr(ln, f"key {key!r} has no value (use '{{}}' or '[]' for empty)")
            if items[idx][2].startswith("-"):
                out[key] = parse_list(base)
            elif depth >= 1:
                perr(items[idx][0],
                     "nesting beyond one mapping level is not supported")
            else:
                out[key] = parse_map(depth + 1)
        return out

    data = parse_map(0)
    return data


def _policy_number(v):
    """A policy scalar is a string under the YAML subset but a real number under JSON.
    Return it as a finite float, or None when it is not a usable finite number: a bool is
    not a number here, and inf/nan/over-large magnitudes are rejected so downstream range
    and integer checks never crash on them (int(inf)/int(nan) would raise)."""
    if isinstance(v, bool):
        return None
    if isinstance(v, (int, float)):
        try:
            n = float(v)
        except OverflowError:
            return None
    elif isinstance(v, str):
        try:
            n = float(v.strip())
        except ValueError:
            return None
    else:
        return None
    return n if math.isfinite(n) else None


def meta_cost(meta):
    """Billed USD from one reviewer-meta mapping as a finite float (0.0 if absent/malformed).
    Prefers the top-level ``cost``; falls back to nested ``usage.cost`` — the MCP ingest path
    records cost only under ``usage``. A missing, non-finite, or negative cost counts as 0: a
    provider that omits or corrupts cost can neither be charged against the cap nor drive the
    running total down, and cannot poison the sum or the coverage JSON."""
    if not isinstance(meta, dict):
        return 0.0
    c = _policy_number(meta.get("cost"))
    if c is None and isinstance(meta.get("usage"), dict):
        c = _policy_number(meta["usage"].get("cost"))
    return c if c is not None and c >= 0 else 0.0


def merge_usage(prior, current):
    """Sum the billed numeric fields of two usage objects so a malformed-JSON retry — a second
    paid call — is fully counted, not just the final attempt. Only finite numbers accumulate;
    non-numeric metadata from the latest response is preserved. ``prior`` None means first call."""
    current = current if isinstance(current, dict) else {}
    if not prior:
        return dict(current)
    out = dict(prior)
    for k, v in current.items():
        cv = _policy_number(v)
        if cv is not None:
            pv = _policy_number(out.get(k))
            out[k] = (pv or 0.0) + cv
        elif k not in out:
            out[k] = v
    return out


def _validate_mutation(v, name):
    if not isinstance(v, dict):
        die(f"{name}: mutation must be a mapping of budget settings "
            f"(allowed: {', '.join(MUTATION_KEYS)})")
    unknown = sorted(set(v) - set(MUTATION_KEYS))
    if unknown:
        die(f"{name}: mutation has unknown key(s): {', '.join(unknown)} "
            f"(allowed: {', '.join(MUTATION_KEYS)})")
    if "scope" in v and v["scope"] not in ("changed", "all"):
        die(f"{name}: mutation.scope must be 'changed' or 'all', got {v['scope']!r}")
    for k in ("max_mutants", "concurrency", "timeout_s"):
        if k in v:
            n = _policy_number(v[k])
            # 2**53 is float64's exact-integer ceiling: at or above it a fractional
            # value (e.g. 9007199254740992.5) rounds to a whole float and would slip
            # the `n != int(n)` check, and such a budget is absurd anyway.
            if n is None or n < 1 or n >= 2 ** 53 or n != int(n):
                die(f"{name}: mutation.{k} must be a positive integer, got {v[k]!r}")
    for k in ("sample_pct", "threshold"):
        if k in v:
            n = _policy_number(v[k])
            if n is None or not 0 <= n <= 100:
                die(f"{name}: mutation.{k} must be a number in [0, 100], got {v[k]!r}")
    for k in ("exclude_files", "exclude_tests"):
        if k in v:
            lst = v[k]
            if not isinstance(lst, list) or not all(
                    isinstance(x, str) and x.strip() for x in lst):
                die(f"{name}: mutation.{k} must be a list of non-empty path/glob strings")


def _policy_bool(v):
    """A policy boolean: a real bool (JSON), or the literal string 'true'/'false' (the YAML
    subset never coerces scalars). Anything else is not a usable boolean here."""
    if isinstance(v, bool):
        return v
    if isinstance(v, str) and v.strip().lower() in ("true", "false"):
        return v.strip().lower() == "true"
    return None


# --------------------------------------------------------------- gate waivers (M1)
# A waiver is a time-boxed, accountable exception, never a permanent hole: it must name an
# authorizer, give a real reason, and expire — and it is independently re-validated from the
# gates/<name>.json record itself at aggregate time, never trusted just because gate.py wrote
# it (a hand-edited/tampered record is caught exactly like a fresh one). See references/gates.md.
WAIVER_REASON_PLACEHOLDERS = {"tbd", "n/a", "na", "temp", "fixme", "todo", "none", ""}
WAIVER_REASON_MIN_LEN = 16
DEFAULT_MAX_WAIVER_DAYS = 14
# Hard ceiling on any configured waiver lifetime. Bounds max_waiver_days at policy-load
# time so an absurd value (a typo, or a deliberate 10**12) can neither pass validation nor
# reach timedelta(days=...) and raise OverflowError, which would leave a run with no verdict.
MAX_WAIVER_DAYS_CAP = 365

# A gate identifier becomes a filename: gates/<name>.json. It must therefore be a strict,
# path-safe slug with NO leading underscore — gates/_required.json is the run manifest, and
# waiving or requiring a name like '_required' (or '../x', 'a/b', 'x.json') would overwrite
# the manifest or escape the gates dir, blanking the required set into a silent all-pass.
GATE_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")


def validate_gate_name(name):
    """Return an error string, or None when `name` is a safe gate identifier. Rejects
    leading-underscore/reserved names (gates/_required.json is the manifest), path
    separators, dots, and anything outside a strict lowercase slug — so gates/<name>.json
    can never escape the gates dir or overwrite the manifest."""
    if not isinstance(name, str):
        return "gate name must be a string"
    n = name.strip()
    if not n:
        return "gate name is required"
    if not GATE_NAME_RE.match(n):
        return (f"gate name {n!r} is invalid — must match [a-z0-9][a-z0-9_-]{{0,63}} "
                "(lowercase alphanumerics, '-' or '_', no leading underscore, no path "
                "separators or dots); leading-underscore names such as '_required' are reserved")
    return None


def validate_waiver_reason(reason):
    """Return an error string, or None when `reason` is an acceptable justification: a
    non-empty string, long enough to be a real explanation, and not a placeholder."""
    if not isinstance(reason, str):
        return "reason must be a string"
    r = reason.strip()
    if not r:
        return "reason is required"
    if r.lower() in WAIVER_REASON_PLACEHOLDERS:
        return f"reason {r!r} is a placeholder, not a real justification"
    if len(r) < WAIVER_REASON_MIN_LEN:
        return f"reason must be at least {WAIVER_REASON_MIN_LEN} characters, got {len(r)}"
    return None


def parse_waiver_expiry(expires):
    """Strict YYYY-MM-DD only (no datetimes, no other separators) — returns a `date`, or
    None when `expires` is missing, malformed, or not that exact shape."""
    if not isinstance(expires, str):
        return None
    s = expires.strip()
    if len(s) != 10 or s[4] != "-" or s[7] != "-":
        return None
    y, m, d = s[0:4], s[5:7], s[8:10]
    if not (y.isdigit() and m.isdigit() and d.isdigit()):
        return None
    try:
        return date(int(y), int(m), int(d))
    except ValueError:
        return None


def _date_from_iso(value):
    """The date part of an ISO-8601 datetime (or bare date) string, or None if `value`
    is not a string or is not parseable."""
    if not isinstance(value, str) or not value.strip():
        return None
    s = value.strip()
    if s[-1:] in ("Z", "z"):
        s = s[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(s).date()
    except ValueError:
        return None


def resolve_waiver_clock():
    """The 'now' date waiver expiries are compared against: the LATER of today in UTC and the
    date part of GITHUB_RUN_STARTED_AT (when that env var is set). Returns (clock_date, error).
    When the env var is set but cannot be parsed, returns (None, <message>) — fail closed:
    callers must BLOCK rather than fall back to today, since silently guessing the clock would
    defeat the whole expiry check. Taking the later of the two means a run clock rolled BACKWARD
    (a stale/forged GITHUB_RUN_STARTED_AT) cannot un-expire a waiver — real UTC still applies —
    while a forward run clock is still honored."""
    today = datetime.now(timezone.utc).date()
    raw = os.environ.get("GITHUB_RUN_STARTED_AT", "")
    if not raw.strip():
        return today, None
    d = _date_from_iso(raw)
    if d is None:
        return None, (f"GITHUB_RUN_STARTED_AT={raw!r} could not be parsed as a date/time — "
                       "the run is BLOCKED rather than guessing the current date")
    return max(d, today), None


def _validate_gate_exception_common(kind, gate_name, tier, authorized_by, reason, pol_data,
                                    strict_reason=True):
    """Checks shared by a WAIVED and a NOT_APPLICABLE gate record: the CRITICAL-tier
    restrictions, a named authorizer, and a justification. `kind` is 'WAIVED' or
    'NOT_APPLICABLE', used only for messages. `strict_reason` selects the justification
    contract: True (WAIVED) applies the full waiver-reason rule (>=16 chars, not a
    placeholder); False (NOT_APPLICABLE) only requires a non-empty summary — its original
    contract, which the shared 16-char rule had inadvertently tightened. Returns an error
    string, or None."""
    # Mutation on CRITICAL can NEVER be waived or marked not-applicable, regardless of policy:
    # CRITICAL mutation coverage stays BLOCKED by design until the mutation-runner milestone
    # (M4) implements it for real — a green verdict must never be reachable by waiving/N-A'ing
    # the one gate meant to catch that gap.
    if tier == "CRITICAL" and gate_name == "mutation":
        return ("mutation cannot be waived or marked NOT_APPLICABLE on CRITICAL tier — "
                "CRITICAL mutation coverage stays BLOCKED by design until the mutation-runner "
                "milestone (M4); run and record the real gate instead")
    if tier == "CRITICAL" and not (_policy_bool(pol_data.get("allow_critical_waivers")) or False):
        return (f"{kind} of a CRITICAL-tier gate requires policy allow_critical_waivers: true "
                "(default false) — CRITICAL waivers/NOT_APPLICABLE are disabled by default")
    who = authorized_by.strip() if isinstance(authorized_by, str) else ""
    if not who:
        return f"{kind} without a named authorizer"
    if strict_reason:
        err = validate_waiver_reason(reason)
        if err:
            return f"{kind} with an invalid reason: {err}"
    elif not (isinstance(reason, str) and reason.strip()):
        return f"{kind} requires a non-empty summary"
    return None


def validate_waived_gate(gate_name, tier, rec, pol_data, clock_date, manifest_planned_at=None):
    """Independently re-validate a gates/<name>.json record with status WAIVED (never
    trusting that gate.py's own plan-time checks ran, or ran correctly): named authorizer,
    real reason, CRITICAL restrictions, a strict future YYYY-MM-DD expiry, and the
    max_waiver_days cap measured from the RUN's planning time. `tier` is the run's ACTUAL
    current tier (never the record's own claim); `clock_date` is the resolved 'now' from
    resolve_waiver_clock (the caller must already have handled its error case);
    `manifest_planned_at` is the authoritative planning timestamp from the run's
    gates/_required.json manifest — the cap is anchored to it, not to the record's own
    planned_at, so editing only the record's planned_at cannot slide the whole window
    forward. Returns an error string, or None when the waiver is valid."""
    err = _validate_gate_exception_common("WAIVED", gate_name, tier,
                                          rec.get("authorized_by"), rec.get("reason"), pol_data)
    if err:
        return err
    expires = parse_waiver_expiry(rec.get("expires"))
    if expires is None:
        return f"expires {rec.get('expires')!r} is missing or not a valid YYYY-MM-DD date"
    if not (expires > clock_date):
        return f"waiver expired {expires.isoformat()} (as of {clock_date.isoformat()})"
    rec_planned = _date_from_iso(rec.get("planned_at"))
    if rec_planned is None:
        return "waiver record is missing a valid planned_at date — cannot verify the waiver-lifetime cap"
    # Anchor the lifetime cap on the RUN's planning time (the _required.json manifest), never
    # the record's own planned_at: editing just the record's planned_at must not move the
    # window. Cross-check the record's planned_at against that anchor and the clock, and
    # reject a tampered/implausible value (a small 1-day skew absorbs timezone/rounding).
    anchor = _date_from_iso(manifest_planned_at) if manifest_planned_at is not None else rec_planned
    if anchor is None:
        return "run plan is missing a valid planned_at date — cannot anchor the waiver-lifetime cap"
    if rec_planned > clock_date + timedelta(days=1):
        return (f"waiver planned_at {rec_planned.isoformat()} is in the future "
                f"(clock {clock_date.isoformat()}) — record tampered")
    if rec_planned < anchor - timedelta(days=1):
        return (f"waiver planned_at {rec_planned.isoformat()} predates the run's planning date "
                f"{anchor.isoformat()} — record tampered")
    n = _policy_number(pol_data.get("max_waiver_days"))
    max_days = (int(n) if n is not None and 1 <= n <= MAX_WAIVER_DAYS_CAP
                else DEFAULT_MAX_WAIVER_DAYS)
    try:
        deadline = anchor + timedelta(days=max_days)
    except (OverflowError, ValueError):
        return "waiver-lifetime cap is too large to evaluate — run BLOCKED"
    if expires > deadline:
        return (f"waiver expires {expires.isoformat()}, more than {max_days} days after the "
                f"run was planned ({anchor.isoformat()}) — waivers are capped at {max_days} days")
    return None


def validate_not_applicable_gate(gate_name, tier, rec, pol_data):
    """Independently re-validate a gates/<name>.json record with status NOT_APPLICABLE:
    named authorizer, a non-empty summary, and the CRITICAL restrictions. N/A keeps its
    original non-empty-summary contract (it is not a time-boxed waiver, so the >=16-char /
    no-placeholder waiver-reason rule does not apply). Returns an error string, or None."""
    return _validate_gate_exception_common("NOT_APPLICABLE", gate_name, tier,
                                           rec.get("authorized_by"), rec.get("summary"), pol_data,
                                           strict_reason=False)


def _validate_policy(data, name):
    if not isinstance(data, dict):
        die(f"{name}: top level must be a mapping of settings")
    unknown = sorted(set(data) - set(POLICY_KEYS))
    if unknown:
        die(f"{name}: unknown key(s): {', '.join(unknown)} "
            f"(allowed: {', '.join(POLICY_KEYS)})")
    if "risk" in data and data["risk"] not in VALID_RISKS:
        die(f"{name}: invalid risk {data['risk']!r} ({'|'.join(VALID_RISKS)})")
    if "rebuttal_policy" in data and data["rebuttal_policy"] not in VALID_REBUTTAL:
        die(f"{name}: invalid rebuttal_policy {data['rebuttal_policy']!r} "
            f"({'|'.join(VALID_REBUTTAL)})")
    if "dev_providers" in data:
        v = data["dev_providers"]
        if not isinstance(v, list) or not v \
                or not all(isinstance(x, str) and x.strip() for x in v):
            die(f"{name}: dev_providers must be a non-empty list of provider families")
    if "required_gates" in data:
        v = data["required_gates"]
        if not isinstance(v, dict):
            die(f"{name}: required_gates must be a mapping of tier -> gate list")
        bad = sorted(set(v) - set(VALID_RISKS))
        if bad:
            die(f"{name}: required_gates has unknown tier(s): {', '.join(bad)}")
        for tier, gates in v.items():
            if not isinstance(gates, list) \
                    or not all(isinstance(g, str) and g.strip() for g in gates):
                die(f"{name}: required_gates.{tier} must be a list of gate names")
    if "pins" in data:
        v = data["pins"]
        if not isinstance(v, dict):
            die(f"{name}: pins must be a mapping of role -> provider/model-slug")
        for role, slug in v.items():
            if not isinstance(slug, str) or "/" not in slug:
                die(f"{name}: pins.{role} must be a provider/model-slug, "
                    f"got {slug!r}")
    if "mutation" in data:
        _validate_mutation(data["mutation"], name)
    if "allow_critical_waivers" in data:
        if _policy_bool(data["allow_critical_waivers"]) is None:
            die(f"{name}: allow_critical_waivers must be true or false, got "
                f"{data['allow_critical_waivers']!r}")
    if "max_waiver_days" in data:
        v = data["max_waiver_days"]
        n = _policy_number(v)
        if n is None or n < 1 or n > MAX_WAIVER_DAYS_CAP or n != int(n):
            die(f"{name}: max_waiver_days must be an integer from 1 to "
                f"{MAX_WAIVER_DAYS_CAP}, got {v!r}")
    if "max_cost_usd" in data:
        v = data["max_cost_usd"]
        # A documented disable token, or a finite non-negative number. Reject at load so a bare
        # NaN/inf/negative can't pass validation and silently disable the cap at resolution time.
        tok = v.strip().lower() if isinstance(v, str) else None
        if tok not in ("", "none", "off", "unlimited"):
            n = _policy_number(v)
            if n is None or n < 0:
                die(f"{name}: max_cost_usd must be a finite non-negative number or "
                    f"'none'/'off'/'unlimited', got {v!r}")
    if "high_samples" in data:
        # Multi-sample corroboration count (E4-S3), informational-only: an integer in
        # [1, MAX_HIGH_SAMPLES]; 1 (the default) disables resampling. Validate EXACTLY as
        # panel.high_samples() resolves it — int(str(value)) — so an integral-looking float ("3.0",
        # 1e1) or any non-integer that `init` would accept here cannot be rejected later at `run`
        # time; the two must agree (panel/Codex E4-S3).
        hv = data["high_samples"]
        try:
            n = int(str(hv).strip())
        except (TypeError, ValueError):
            n = None
        if n is None or n < 1 or n > MAX_HIGH_SAMPLES:
            die(f"{name}: high_samples must be an integer in [1, {MAX_HIGH_SAMPLES}], "
                f"got {hv!r}")


def load_policy(root=None):
    """Load and validate the repo policy file. Returns None when absent, else
    {'data': dict, 'path': Path, 'sha256': hex, 'text': str}. Malformed input
    dies loudly (exit 1) — a policy is never silently ignored."""
    root = Path(root) if root else Path.cwd()
    found = [root / n for n in POLICY_BASENAMES if (root / n).is_file()]
    if not found:
        return None
    if len(found) > 1:
        die(f"both {' and '.join(POLICY_BASENAMES)} exist — keep exactly one")
    path = found[0]
    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError as e:
        die(f"{path.name}: not valid UTF-8: {e}")
    if path.suffix == ".json":
        try:
            data = json.loads(text)
        except ValueError as e:
            die(f"{path.name}: invalid JSON: {e}")
    else:
        data = _parse_policy_yaml(text, path.name)
    _validate_policy(data, path.name)
    return {"data": data, "path": path,
            "sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
            "text": text}


def load_attested_policy(run):
    """Return (pol_data, error) from the run's attested policy.snapshot.json — the exact
    policy text captured at init — NEVER the mutable working-tree policy, so a post-init edit
    cannot widen a waiver that is absent from the audit record (#3).

      ({}, None)     no policy at init (no snapshot) → strict built-in defaults apply.
      (data, None)   snapshot present, its text matches its recorded sha256, and it parses
                     and validates against the current schema.
      (None, msg)    snapshot present but unreadable, sha-mismatched (tampered), or no longer
                     valid — the caller must BLOCK (fail closed), never fall back to the
                     working tree."""
    snap_path = Path(run) / "policy.snapshot.json"
    if not snap_path.is_file():
        return {}, None
    try:
        snap = read_json(snap_path)
    except (ValueError, OSError) as e:
        return None, f"policy.snapshot.json is unreadable/corrupt: {e}"
    if not isinstance(snap, dict):
        return None, "policy.snapshot.json is not a JSON object"
    text = snap.get("text")
    sha = snap.get("sha256", "")
    fname = snap.get("file", "") or ""
    if not isinstance(text, str):
        return None, "policy.snapshot.json has no captured policy text"
    if hashlib.sha256(text.encode("utf-8")).hexdigest() != sha:
        return None, "policy.snapshot.json text does not match its recorded sha256 — tampered"
    try:
        data = json.loads(text) if fname.endswith(".json") else _parse_policy_yaml(
            text, "policy.snapshot.json")
        _validate_policy(data, "policy.snapshot.json")
    except (ValueError, SystemExit):
        return None, "policy.snapshot.json failed to parse/validate against the current schema"
    if not isinstance(data, dict):
        return None, "policy.snapshot.json did not parse to a mapping"
    return data, None


def resolve_setting(cli_value, env_var, pol, key, default=None):
    """One value through the precedence chain: CLI flag > env var > policy file >
    built-in default. Returns (value, source); (None, 'unset') when nothing
    provides one — callers decide whether that is fatal. An empty env var
    counts as unset."""
    if cli_value not in (None, ""):
        return cli_value, "cli"
    env_val = os.environ.get(env_var, "")
    if env_val != "":
        return env_val, "env"
    if pol is not None and key in pol["data"]:
        return pol["data"][key], "policy"
    if default is not None:
        return default, "default"
    return None, "unset"


# --- Model capability profiles (E0-S2) ---------------------------------------------
# A per-model profile governs how a request is shaped. Catalog-derived defaults (from
# `supported_parameters`) merge with an optional repo file
# `.adversarial-review.capabilities.yml`/`.json` and an `AR_CAP_OVERRIDES` env path, so
# quirks the catalog can't express (temperature-forbidden, mandatory reasoning, a
# min-token floor) are declared once and recorded. Precedence: catalog < file < env.
# NOTE: this only resolves the profile; wiring it into request-building is a later story.
CAP_BASENAMES = (".adversarial-review.capabilities.yml", ".adversarial-review.capabilities.json")
CAP_KEYS = ("temperature", "structured_outputs", "reasoning", "max_tokens_floor",
            "latency_class", "notes")
CAP_ENUMS = {"temperature": ("supported", "forbidden", "default"),
             "reasoning": ("none", "optional", "mandatory"),
             "latency_class": ("fast", "slow")}


def capability_defaults(catalog_entry):
    """Per-model capability profile derived from the live catalog entry alone."""
    sp = (catalog_entry or {}).get("supported_parameters") or []
    return {"temperature": "supported" if "temperature" in sp else "default",
            "structured_outputs": "structured_outputs" in sp,
            "reasoning": "none", "max_tokens_floor": None,
            "latency_class": None, "notes": ""}


def _cap_bool(v):
    if isinstance(v, bool):
        return v
    if isinstance(v, str) and v.strip().lower() in ("true", "false"):
        return v.strip().lower() == "true"
    return None


def _cap_pos_int(v):
    if isinstance(v, bool):
        return None
    if isinstance(v, int):
        return v if v > 0 else None
    if isinstance(v, str) and v.strip().isdigit():
        n = int(v.strip())
        return n if n > 0 else None
    return None


def _validate_cap_block(slug, block, name):
    if not isinstance(block, dict):
        die(f"{name}: capabilities['{slug}'] must be a mapping of capability settings")
    unknown = sorted(set(block) - set(CAP_KEYS))
    if unknown:
        die(f"{name}: capabilities['{slug}'] has unknown keys {unknown} "
            f"(allowed: {', '.join(CAP_KEYS)})")
    out = {}
    for k, allowed in CAP_ENUMS.items():
        if k in block:
            v = block[k]
            # latency_class is nullable (its catalog default is None); an explicit
            # null resets it rather than tripping the enum check below.
            if k == "latency_class" and v in (None, "", "null"):
                out[k] = None
                continue
            if v not in allowed:
                die(f"{name}: capabilities['{slug}'].{k}={v!r} not in {list(allowed)}")
            out[k] = v
    if "structured_outputs" in block:
        b = _cap_bool(block["structured_outputs"])
        if b is None:
            die(f"{name}: capabilities['{slug}'].structured_outputs must be true/false")
        out["structured_outputs"] = b
    if "max_tokens_floor" in block:
        # An explicit null resets the floor (its catalog default is None); any other
        # value must be a positive integer.
        if block["max_tokens_floor"] in (None, "", "null"):
            out["max_tokens_floor"] = None
        else:
            n = _cap_pos_int(block["max_tokens_floor"])
            if n is None:
                die(f"{name}: capabilities['{slug}'].max_tokens_floor must be a positive integer")
            out["max_tokens_floor"] = n
    if "notes" in block:
        out["notes"] = str(block["notes"])
    return out


def _load_cap_file(path):
    p = Path(path)
    text = p.read_text(encoding="utf-8")
    if p.suffix == ".json":
        try:
            data = json.loads(text)
        except ValueError as e:
            die(f"{p.name}: invalid JSON: {e}")
    else:
        data = _parse_policy_yaml(text, p.name)
    if not isinstance(data, dict):
        die(f"{p.name}: top level must be a mapping of model-slug -> capability settings")
    out = {}
    for slug, block in data.items():
        if not isinstance(slug, str) or "/" not in slug:
            die(f"{p.name}: capability key must be a provider/model-slug, got {slug!r}")
        out[slug] = _validate_cap_block(slug, block, p.name)
    return out


def load_capabilities(root=None):
    """Merged capability overrides {model_slug: {...}} from the repo file and the
    AR_CAP_OVERRIDES env path (env wins per key). Empty dict when neither is present.
    Malformed input dies loudly, exactly like the policy loader."""
    root = Path(root) if root else Path.cwd()
    found = [root / n for n in CAP_BASENAMES if (root / n).is_file()]
    if len(found) > 1:
        die(f"both {' and '.join(CAP_BASENAMES)} exist — keep exactly one")
    overrides = _load_cap_file(found[0]) if found else {}
    env_path = os.environ.get("AR_CAP_OVERRIDES", "")
    if env_path:
        if not Path(env_path).is_file():
            die(f"AR_CAP_OVERRIDES points to a missing file: {env_path}")
        for slug, block in _load_cap_file(env_path).items():
            overrides.setdefault(slug, {}).update(block)  # env wins per key
    return overrides


def capability_of(model_slug, catalog_entry, overrides=None):
    """Effective profile for a model: catalog defaults with file/env overrides applied.
    Returns (profile, source) where source is 'catalog' (no override) or 'override'."""
    prof = capability_defaults(catalog_entry)
    ov = (overrides or {}).get(model_slug)
    if not ov:
        return prof, "catalog"
    prof.update(ov)
    return prof, "override"
