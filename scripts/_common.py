"""Shared helpers for adversarial-review scripts. Stdlib only, by design."""
import hashlib
import json
import math
import os
import sys
from datetime import datetime, timezone
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
               "mutation", "max_cost_usd")
VALID_RISKS = ("NORMAL", "SENSITIVE", "CRITICAL")
VALID_REBUTTAL = ("critical", "contention", "any")
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
