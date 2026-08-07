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
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _common import die, now_iso, read_json, resolve_run, write_json

# Floors per tier: these cannot be silently omitted, only waived on the record with a
# named authorizer (surfaced in the verdict reasons and the report).
MINIMUM_GATES = {
    "NORMAL": ["build", "unit", "secrets", "deps", "sast"],
    "SENSITIVE": ["build", "unit", "secrets", "deps", "sast", "mutation"],
    "CRITICAL": ["build", "unit", "secrets", "deps", "sast", "mutation"],
}


def cmd_plan(args):
    run = resolve_run(args.run)
    tier = read_json(run / "run.json")["risk"]
    requested = [g.strip() for g in args.require.split(",") if g.strip()]
    waived = []
    for w in args.waive or []:
        if not args.authorized_by:
            die(f"waiving gate '{w}' requires --authorized-by '<user>'")
        waived.append({"name": w, "authorized_by": args.authorized_by})
    waived_names = {w["name"] for w in waived}
    required = sorted(set(requested) | {g for g in MINIMUM_GATES[tier]
                                        if g not in waived_names})
    write_json(run / "gates" / "_required.json",
               {"tier": tier, "required": required, "waived": waived,
                "planned_at": now_iso()})
    print(f"required gates ({tier}): {', '.join(required)}")
    for w in waived:
        print(f"  WAIVED: {w['name']} (authorized by {w['authorized_by']})")


def cmd_run(args):
    run = resolve_run(args.run)
    cmd = args.command
    if not cmd:
        die("no command given after --")
    proc = subprocess.run(cmd, capture_output=True, text=True)
    tail = ((proc.stdout or "") + ("\n" + proc.stderr if proc.stderr else ""))[-4000:]
    status = "PASS" if proc.returncode == 0 else "FAIL"
    write_json(run / "gates" / f"{args.name}.json", {
        "gate": args.name, "command": " ".join(cmd), "exit_code": proc.returncode,
        "status": status,
        "summary": args.summary or ("pass" if proc.returncode == 0 else "fail"),
        "output_tail": tail, "recorded_at": now_iso(), "source": "run"})
    print(f"gate {args.name}: {status}"
          + (f" (exit {proc.returncode})" if proc.returncode else ""))
    sys.exit(proc.returncode)


def cmd_record(args):
    run = resolve_run(args.run)
    # Tri-state status: PASS/FAIL derive from the exit code by default; BLOCKED is for
    # required coverage that could not be verified or run at all (unsupported stack,
    # missing access) — that is "unknown", which must never be recorded as pass/fail.
    if args.status != "BLOCKED" and args.exit_code is None:
        die("--exit-code is required unless --status BLOCKED (nothing ran to produce one)")
    status = args.status or ("PASS" if args.exit_code == 0 else "FAIL")
    if status == "BLOCKED" and not args.summary.strip():
        die("a BLOCKED gate needs --summary naming exactly what could not be verified")
    write_json(run / "gates" / f"{args.name}.json", {
        "gate": args.name, "command": args.command or "(external)",
        "exit_code": args.exit_code, "status": status, "summary": args.summary,
        "output_tail": "", "recorded_at": now_iso(), "source": "record"})
    print(f"gate {args.name}: recorded {status} (exit {args.exit_code})")


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("plan")
    p.add_argument("--run"); p.add_argument("--require", required=True)
    p.add_argument("--waive", action="append")
    p.add_argument("--authorized-by", default="")
    p.set_defaults(fn=cmd_plan)

    p = sub.add_parser("run")
    p.add_argument("--run"); p.add_argument("--name", required=True)
    p.add_argument("--summary", default="")
    p.add_argument("command", nargs=argparse.REMAINDER,
                   help="command after -- to execute")
    p.set_defaults(fn=cmd_run)

    p = sub.add_parser("record")
    p.add_argument("--run"); p.add_argument("--name", required=True)
    p.add_argument("--exit-code", type=int, default=None)
    p.add_argument("--status", choices=["PASS", "FAIL", "BLOCKED"],
                   help="override derived status; BLOCKED = could not verify/run")
    p.add_argument("--summary", required=True)
    p.add_argument("--command", default="")
    p.set_defaults(fn=cmd_record)

    args = ap.parse_args()
    if getattr(args, "command", None) and args.command and args.command[0] == "--":
        args.command = args.command[1:]
    args.fn(args)


if __name__ == "__main__":
    main()
