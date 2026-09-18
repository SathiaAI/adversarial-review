#!/usr/bin/env python3
"""Deterministic gate recorder for adversarial-review.

  gate.py plan   --tier SENSITIVE --require build,lint,typecheck,unit,secrets,deps,sast
  gate.py run    --name unit -- npm test
  gate.py record --name deps --exit-code 0 --summary "osv-scanner in CI: <link>"

Every gate becomes a JSON artifact the aggregator can see. An unrecorded gate does not
exist; a dishonestly recorded gate defeats the pipeline you are relying on.
Exit codes: `run` exits with the wrapped command's code; `plan`/`record` exit 0/1.
"""
import argparse
import os
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _common import die, load_policy, now_iso, read_json, resolve_run, write_json

# Floors per tier: these cannot be silently omitted, only waived on the record with a
# named authorizer (surfaced in the verdict reasons and the report). A waived floor gate
# stays in the required set — its gates/<name>.json record (status WAIVED) is what
# aggregate.py independently re-validates (expiry, cap, authorizer, reason, CRITICAL
# rules); waiving it here never removes it from `required`. NOTE: CRITICAL's `mutation`
# can never be waived or marked NOT_APPLICABLE (see aggregate.py/_common.py) — real
# CRITICAL mutation coverage is a later milestone (M4), so until then a CRITICAL run
# with no genuine mutation gate result stays BLOCKED, by design.
MINIMUM_GATES = {
    "NORMAL": ["build", "unit", "secrets", "deps", "sast"],
    "SENSITIVE": ["build", "unit", "secrets", "deps", "sast", "mutation"],
    "CRITICAL": ["build", "unit", "secrets", "deps", "sast", "mutation"],
}


def cmd_plan(args):
    run = resolve_run(args.run)
    tier = read_json(run / "run.json")["risk"]
    # Requested-gate precedence: CLI flag > AR_REQUIRE env > policy file. The
    # policy's required_gates is a per-tier map; a missing tier entry is simply
    # "not provided" (tier keys themselves are validated at policy load).
    pol = load_policy()  # malformed policy dies here — never silently ignored
    if args.require:
        requested, req_src = args.require.split(","), "cli"
    elif os.environ.get("AR_REQUIRE", ""):
        requested, req_src = os.environ["AR_REQUIRE"].split(","), "env"
    elif pol is not None and tier in pol["data"].get("required_gates", {}):
        requested, req_src = list(pol["data"]["required_gates"][tier]), "policy"
    else:
        die(f"required gates unresolved for tier {tier}: pass --require, set "
            f"AR_REQUIRE, or add required_gates.{tier} to .adversarial-review.yml")
    requested = [g.strip() for g in requested if g.strip()]
    # The gates that are required BEFORE any waiver is applied: this is the set a --waive
    # is allowed to name. Waiving a name outside it is rejected (gate-name smuggling) —
    # otherwise a typo'd or invented gate name could be "waived" while the real required
    # gate it was meant to stand in for goes completely unaddressed, with nothing to show
    # for it but a plausible-looking (but meaningless) waiver in the audit trail.
    base_required = set(requested) | set(MINIMUM_GATES[tier])
    waived = []
    for w in args.waive or []:
        if w not in base_required:
            die(f"cannot waive '{w}': not among this tier's requested/floor gates "
                f"({', '.join(sorted(base_required))}) — waiving a gate name that was "
                "never required does nothing and is rejected (gate-name smuggling)")
        if not args.authorized_by:
            die(f"waiving gate '{w}' requires --authorized-by '<user>'")
        if not args.waive_reason.strip():
            die(f"waiving gate '{w}' requires --waive-reason '<a real justification, "
                "at least 16 characters, not a placeholder>'")
        if not args.waive_expires.strip():
            die(f"waiving gate '{w}' requires --waive-expires 'YYYY-MM-DD' — a waiver is "
                "time-boxed, never permanent")
        waived.append({"name": w, "authorized_by": args.authorized_by,
                       "reason": args.waive_reason, "expires": args.waive_expires})
    # A waived gate stays in `required` — it no longer disappears from the set aggregate.py
    # checks. Its own gates/<name>.json record (status WAIVED, written below) is what
    # aggregate.py independently re-validates; this manifest's `waived` list is kept only
    # for at-a-glance visibility.
    required = sorted(base_required)
    planned_at = now_iso()
    write_json(run / "gates" / "_required.json",
               {"tier": tier, "required": required, "requested": requested,
                "requested_source": req_src, "waived": waived,
                "planned_at": planned_at})
    for w in waived:
        write_json(run / "gates" / f"{w['name']}.json", {
            "gate": w["name"], "status": "WAIVED",
            "authorized_by": w["authorized_by"], "reason": w["reason"],
            "expires": w["expires"], "tier": tier, "planned_at": planned_at,
            "source": "plan"})
    print(f"required gates ({tier}): {', '.join(required)}  "
          f"[requested via {req_src}]")
    for w in waived:
        print(f"  WAIVED: {w['name']} (authorized by {w['authorized_by']}, "
              f"expires {w['expires']})")


def _parse_exit_map(spec):
    """Opt-in exit-code -> status map for `run`. `spec` is a comma list of CODE=STATUS
    (CODE an integer, or '*' as the catch-all for any unmapped nonzero exit); STATUS is
    PASS|FAIL|BLOCKED. Returns (dict, star_status_or_None). This is how a wrapper that
    emits a tri-state exit (e.g. ai-defects: 0/1/2) records BLOCKED, with no aggregator
    change and no effect on gates that don't pass the flag."""
    mapping, star = {}, None
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "=" not in part:
            die(f"--exit-map entry {part!r} must be CODE=STATUS")
        code_s, status = (x.strip() for x in part.split("=", 1))
        if status not in ("PASS", "FAIL", "BLOCKED"):
            die(f"--exit-map status must be PASS|FAIL|BLOCKED, got {status!r}")
        if status == "PASS" and code_s != "0":
            die(f"--exit-map may not map a nonzero exit to PASS (got {part!r}); PASS is "
                f"reserved for exit 0 so a failing check can never be weakened to a pass")
        if code_s == "*":
            star = status
        else:
            try:
                mapping[int(code_s)] = status
            except ValueError:
                die(f"--exit-map code must be an integer or '*', got {code_s!r}")
    return mapping, star


def cmd_run(args):
    run = resolve_run(args.run)
    cmd = args.command
    if not cmd:
        die("no command given after --")
    # Validate any --exit-map BEFORE running, so a malformed map fails fast.
    emap, estar = _parse_exit_map(args.exit_map) if args.exit_map else ({}, None)
    proc = subprocess.run(cmd, capture_output=True, text=True)
    tail = ((proc.stdout or "") + ("\n" + proc.stderr if proc.stderr else ""))[-4000:]
    rc = proc.returncode
    if args.exit_map:
        # Explicit CODE wins; exit 0 is PASS unless explicitly remapped; an unmapped
        # nonzero uses '*' if given, else FAIL (the built-in, backward-compatible default).
        if rc in emap:
            status = emap[rc]
        elif rc == 0:
            status = "PASS"
        else:
            status = estar if estar is not None else "FAIL"
    else:
        status = "PASS" if rc == 0 else "FAIL"
    default_summary = {"PASS": "pass", "FAIL": "fail",
                       "BLOCKED": f"blocked (command exited {rc})"}[status]
    write_json(run / "gates" / f"{args.name}.json", {
        "gate": args.name, "command": " ".join(cmd), "exit_code": rc,
        "status": status,
        "summary": args.summary or default_summary,
        "output_tail": tail, "recorded_at": now_iso(), "source": "run"})
    print(f"gate {args.name}: {status}" + (f" (exit {rc})" if rc else ""))
    sys.exit(rc)


def cmd_record(args):
    run = resolve_run(args.run)
    # Status states, none of which may be inferred silently:
    #   PASS/FAIL    derive from the exit code by default.
    #   BLOCKED      required coverage that could not be run or verified (unknown).
    #   NOT_APPLICABLE  the gate genuinely does not apply to this stack (e.g. a
    #                config-only repo has no build/unit gate). Unlike BLOCKED it does
    #                not restrict the verdict — but it is an accountable, on-record
    #                determination, so it REQUIRES a named authorizer and a reason and
    #                is surfaced distinctly in the verdict. Nothing ran, so no exit code.
    no_exit_ok = args.status in ("BLOCKED", "NOT_APPLICABLE")
    if not no_exit_ok and args.exit_code is None:
        die("--exit-code is required unless --status BLOCKED or NOT_APPLICABLE "
            "(nothing ran to produce one)")
    status = args.status or ("PASS" if args.exit_code == 0 else "FAIL")
    if status == "BLOCKED" and not args.summary.strip():
        die("a BLOCKED gate needs --summary naming exactly what could not be verified")
    if status == "NOT_APPLICABLE":
        if not args.authorized_by.strip():
            die("NOT_APPLICABLE requires --authorized-by '<user>' — marking a required "
                "gate inapplicable is an accountable decision, never anonymous")
        if not args.summary.strip():
            die("NOT_APPLICABLE requires --summary explaining why the gate does not "
                "apply to this stack")
    rec = {"gate": args.name, "command": args.command or "(external)",
           "exit_code": args.exit_code, "status": status, "summary": args.summary,
           "output_tail": "", "recorded_at": now_iso(), "source": "record"}
    if status == "NOT_APPLICABLE":
        rec["authorized_by"] = args.authorized_by
    write_json(run / "gates" / f"{args.name}.json", rec)
    tail = f" (authorized by {args.authorized_by})" if status == "NOT_APPLICABLE" else \
           f" (exit {args.exit_code})"
    print(f"gate {args.name}: recorded {status}{tail}")


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("plan")
    p.add_argument("--run")
    p.add_argument("--require",
                   help="comma list of gates (required unless AR_REQUIRE or the "
                        "repo policy file's required_gates provides this tier)")
    p.add_argument("--waive", action="append")
    p.add_argument("--waive-reason", default="",
                   help="required when waiving a gate: a real justification (>=16 chars, "
                        "not a placeholder like 'tbd'); independently re-validated at "
                        "aggregate time")
    p.add_argument("--waive-expires", default="",
                   help="required when waiving a gate: 'YYYY-MM-DD', strictly after the "
                        "aggregate run's clock date and within policy max_waiver_days "
                        "(default 14) of when it was planned")
    p.add_argument("--authorized-by", default="")
    p.set_defaults(fn=cmd_plan)

    p = sub.add_parser("run")
    p.add_argument("--run"); p.add_argument("--name", required=True)
    p.add_argument("--summary", default="")
    p.add_argument("--exit-map", default="",
                   help="opt-in exit-code to status map, e.g. '1=FAIL,2=BLOCKED,*=BLOCKED' "
                        "('*' = catch-all for unmapped nonzero). Absent: exit 0=PASS, "
                        "nonzero=FAIL (unchanged). Lets a tri-state wrapper (e.g. ai-defects) "
                        "record BLOCKED without any aggregator change.")
    p.add_argument("command", nargs=argparse.REMAINDER,
                   help="command after -- to execute")
    p.set_defaults(fn=cmd_run)

    p = sub.add_parser("record")
    p.add_argument("--run"); p.add_argument("--name", required=True)
    p.add_argument("--exit-code", type=int, default=None)
    p.add_argument("--status", choices=["PASS", "FAIL", "BLOCKED", "NOT_APPLICABLE"],
                   help="override derived status; BLOCKED = could not verify/run; "
                        "NOT_APPLICABLE = gate does not apply to this stack "
                        "(requires --authorized-by, does not restrict the verdict)")
    p.add_argument("--summary", required=True)
    p.add_argument("--authorized-by", default="",
                   help="named authorizer, required for --status NOT_APPLICABLE")
    p.add_argument("--command", default="")
    p.set_defaults(fn=cmd_record)

    args = ap.parse_args()
    if getattr(args, "command", None) and args.command and args.command[0] == "--":
        args.command = args.command[1:]
    args.fn(args)


if __name__ == "__main__":
    main()
