#!/usr/bin/env python3
"""End-to-end tests for the adversarial-review skill scripts against a mock router."""
import hashlib
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
from pathlib import Path

HERE = Path(__file__).resolve().parent
SKILL = Path(os.environ.get("SKILL_DIR", HERE.parent))  # repo root = skill root
sys.path.insert(0, str(HERE))
import mock_router  # noqa: E402
sys.path.insert(0, str(SKILL / "scripts"))
import mcp_server as mcpsrv  # noqa: E402

PORT = 8811
ENV = {**os.environ, "AR_BASE_URL": f"http://127.0.0.1:{PORT}/v1",
       "AR_API_KEY": "test-key", "AR_TIMEOUT_S": "15", "AR_MAX_TOKENS": "2000"}

PASSED, FAILED = [], []


def sh(args, cwd, expect=0, env=ENV):
    r = subprocess.run([sys.executable, str(SKILL / "scripts" / args[0])] + args[1:],
                       cwd=cwd, env=env, capture_output=True, text=True)
    if expect is not None and r.returncode != expect:
        raise AssertionError(
            f"{' '.join(args)} -> exit {r.returncode}, expected {expect}\n"
            f"stdout: {r.stdout}\nstderr: {r.stderr}")
    return r


def check(name, fn):
    try:
        fn()
        PASSED.append(name)
        print(f"  PASS  {name}")
    except Exception as e:  # noqa: BLE001
        FAILED.append((name, e))
        print(f"  FAIL  {name}: {e}")


def fresh_repo():
    d = Path(tempfile.mkdtemp(prefix="ar-test-"))
    (d / "context.md").write_text("diff --git a/x b/x\n+code under review\n")
    return d


def latest_run(repo):
    return sorted((repo / ".adversarial-review").glob("run-*"))[-1]


def read(p):
    return json.loads(Path(p).read_text())


def write(p, obj):
    Path(p).parent.mkdir(parents=True, exist_ok=True)
    Path(p).write_text(json.dumps(obj, indent=2))


# ---------------------------------------------------------------- scenarios

def t_assign_normal_excludes_dev():
    repo = fresh_repo()
    sh(["panel.py", "init", "--risk", "NORMAL", "--dev-providers", "anthropic",
        "--diff-ref", "main...HEAD"], repo)
    sh(["panel.py", "assign"], repo)
    plan = read(latest_run(repo) / "panel" / "plan.json")
    fams = [v["family"] for v in plan["roles"].values()]
    assert len(plan["roles"]) == 4, f"expected 4 roles, got {len(plan['roles'])}"
    assert len(set(fams)) == 4, f"family collision: {fams}"
    assert "output_fidelity" in plan["roles"], "output_fidelity role missing at NORMAL"
    assert "anthropic" not in fams, "dev family leaked into panel"
    slugs = [v["model"] for v in plan["roles"].values()]
    for s in slugs:
        assert ":free" not in s and "latest" not in s and "preview" not in s, s


def t_assign_collision_free_under_multi_dev():
    # Dev = anthropic + openai. Security priority now hits xai; correctness would
    # historically collide on google with data_privacy — greedy skip must prevent that.
    repo = fresh_repo()
    sh(["panel.py", "init", "--risk", "SENSITIVE", "--dev-providers",
        "anthropic,openai"], repo)
    sh(["panel.py", "assign"], repo)
    plan = read(latest_run(repo) / "panel" / "plan.json")
    fams = [v["family"] for v in plan["roles"].values()]
    assert len(plan["roles"]) == 6 and len(set(fams)) == 6, f"collision: {fams}"
    assert not {"anthropic", "openai"} & set(fams)


def t_output_fidelity_role_and_forced_attestation():
    # The output-semantics lens (the class of bug an LLM panel misses but a line-by-line
    # reviewer catches — e.g. a FAIL branch that asserts the success condition) is installed
    # two ways: a dedicated output_fidelity reviewer at EVERY tier, and a forced schema
    # attestation every reviewer must fill. Neither may silently regress.
    import panel
    assert "output_fidelity" in panel.ROLES
    for tier in ("NORMAL", "SENSITIVE", "CRITICAL"):
        assert "output_fidelity" in panel.TIER_ROLES[tier], tier
    assert "output_fidelity" in panel.RUBRICS and "output_fidelity" in panel.ROLE_FAMILY_PRIORITY
    assert "HUMAN-FACING OUTPUT" in panel.RUBRICS["output_fidelity"]

    # Forced attestation: it is required, with required sub-fields, so an omission or a
    # malformed entry is rejected at ingest exactly like any other schema violation.
    base = {"role": "correctness", "model_id": "m", "summary": "s", "findings": [],
            "assumptions": [], "additional_tests": [], "areas_reviewed": ["d"],
            "areas_not_reviewed": [], "top_residual_risks": ["r"], "injection_suspected": False}
    assert "output_statements_checked" in panel.REPORT_SCHEMA["required"]
    assert any("output_statements_checked" in e
               for e in panel.validate_obj(base, panel.REPORT_SCHEMA))          # omitted -> reject
    bad = dict(base, output_statements_checked=[{"rendered": "x", "note": "y"}])  # no states_truth
    assert any("states_truth" in e for e in panel.validate_obj(bad, panel.REPORT_SCHEMA))
    good = dict(base, output_statements_checked=[
        {"rendered": "The 'unit' check failed. Run the test suite locally to see which test.",
         "states_truth": True, "note": "true: states the failure and a valid next action",
         "finding_id": ""},
        {"rendered": "The 'unit' check failed. Passing it proves your automated tests pass.",
         "states_truth": False, "note": "a FAIL branch that asserts the success condition is false output",
         "finding_id": "correctness-1"}])
    assert panel.validate_obj(good, panel.REPORT_SCHEMA) == []                    # well-formed -> ok
    # finding_id is a REQUIRED key on every attestation item (empty "" for a true statement):
    # strict structured-output providers (e.g. OpenAI) reject an item whose `required` omits a
    # property, so the local schema must match — omitting finding_id is rejected here too.
    assert "finding_id" in panel.REPORT_SCHEMA["properties"]["output_statements_checked"]["items"]["required"]
    assert any("finding_id" in e for e in panel.validate_obj(
        dict(base, output_statements_checked=[{"rendered": "x", "states_truth": True, "note": "n"}]),
        panel.REPORT_SCHEMA))                                                     # omitting finding_id -> reject

    # Every reviewer scans the diff for output truth (P1), but only output_fidelity enumerates
    # exhaustively; the others report by exception so a large text diff cannot blow the
    # completion cap across the panel (P2).
    for role in panel.TIER_ROLES["NORMAL"]:
        sysmsg = panel.reviewer_messages(role, {"risk": "NORMAL"}, "ctx", "BND")[0]["content"]
        assert "OUTPUT FIDELITY" in sysmsg and "output_statements_checked" in sysmsg, role
        assert "finding_id" in sysmsg, role      # a false statement must be linked to a finding
        assert ("enumerate EVERY" in sysmsg) == (role == "output_fidelity"), role
        assert ("Report by exception" in sysmsg) == (role != "output_fidelity"), role


def t_assign_blocked_when_insufficient():
    repo = fresh_repo()
    sh(["panel.py", "init", "--risk", "SENSITIVE", "--dev-providers",
        "anthropic,openai,google,xai,qwen,mistral,deepseek"], repo)
    r = sh(["panel.py", "assign"], repo, expect=2)
    assert "BLOCKED" in r.stderr


def t_assign_degraded_requires_authorization():
    repo = fresh_repo()
    dev = "anthropic,openai,google,xai,qwen,mistral,deepseek"
    sh(["panel.py", "init", "--risk", "SENSITIVE", "--dev-providers", dev], repo)
    sh(["panel.py", "assign", "--allow-degraded"], repo, expect=2)  # no authorizer
    sh(["panel.py", "assign", "--allow-degraded", "--authorized-by", "Paul"], repo)
    plan = read(latest_run(repo) / "panel" / "plan.json")
    assert plan["degraded"]["authorized_by"] == "Paul"
    assert len(plan["roles"]) >= 3


def t_pin_rejects_dev_family():
    repo = fresh_repo()
    sh(["panel.py", "init", "--risk", "NORMAL", "--dev-providers", "anthropic"], repo)
    r = sh(["panel.py", "assign", "--pin", "security=anthropic/claude-opus-5"],
           repo, expect=2)
    assert "development family" in r.stderr


def t_run_panel_and_malformed_retry():
    mock_router.STATE["malformed_once"].add("google/gemini-3.6-flash")
    mock_router.STATE["calls"].clear()
    repo = fresh_repo()
    sh(["panel.py", "init", "--risk", "SENSITIVE", "--dev-providers", "anthropic"], repo)
    sh(["panel.py", "assign"], repo)
    sh(["panel.py", "run", "--context-file", "context.md"], repo)
    run = latest_run(repo)
    plan = read(run / "panel" / "plan.json")
    for role in plan["roles"]:
        rep = read(run / "panel" / f"{role}.json")
        assert rep["role"] == role and rep["top_residual_risks"]
    sec = read(run / "panel" / "security.json")
    assert sec["findings"] and sec["findings"][0]["severity"] == "high"
    assert mock_router.STATE["calls"].get("google/gemini-3.6-flash", 0) >= 2, \
        "malformed-once model should have been retried"
    mock_router.STATE["malformed_once"].clear()
    return repo


def t_substitution_on_dead_provider():
    mock_router.STATE["fail_models"].add("openai/gpt-5.6-luna-pro")
    repo = fresh_repo()
    sh(["panel.py", "init", "--risk", "NORMAL", "--dev-providers", "anthropic"], repo)
    sh(["panel.py", "assign"], repo)
    sh(["panel.py", "run", "--context-file", "context.md"], repo)
    run = latest_run(repo)
    plan = read(run / "panel" / "plan.json")
    assert plan["substitutions"], "expected a recorded substitution"
    fams = [v["family"] for v in plan["roles"].values()]
    assert len(set(fams)) == len(fams), f"post-substitution collision: {fams}"
    for role in plan["roles"]:
        assert (run / "panel" / f"{role}.json").exists()
    mock_router.STATE["fail_models"].clear()


def _complete_sensitive_repo():
    """Panel + rebuttal done, all required gates green. security-1 finding still open."""
    repo = fresh_repo()
    sh(["panel.py", "init", "--risk", "SENSITIVE", "--dev-providers", "anthropic"], repo)
    sh(["panel.py", "assign"], repo)
    sh(["panel.py", "run", "--context-file", "context.md"], repo)
    sh(["panel.py", "rebuttal"], repo)  # contention policy: required once findings exist
    sh(["gate.py", "plan", "--require", "build,unit,secrets,deps,sast",
        "--waive", "mutation", "--authorized-by", "Paul"], repo)
    for g in ["build", "unit", "secrets", "deps", "sast"]:
        sh(["gate.py", "record", "--name", g, "--exit-code", "0",
            "--summary", "ok"], repo)
    return repo


def t_aggregate_blocked_without_gates():
    repo = fresh_repo()
    sh(["panel.py", "init", "--risk", "NORMAL", "--dev-providers", "anthropic"], repo)
    sh(["panel.py", "assign"], repo)
    sh(["panel.py", "run", "--context-file", "context.md"], repo)
    r = sh(["aggregate.py"], repo, expect=2)
    assert "gate plan missing" in r.stdout


def t_aggregate_blocked_unvalidated_finding():
    repo = _complete_sensitive_repo()
    r = sh(["aggregate.py"], repo, expect=2)
    assert "no validation record" in r.stdout


def t_aggregate_fail_on_failing_gate():
    repo = _complete_sensitive_repo()
    sh(["gate.py", "record", "--name", "unit", "--exit-code", "1",
        "--summary", "2 tests failed"], repo)
    r = sh(["aggregate.py"], repo, expect=1)
    assert "gate 'unit' failed" in r.stdout


def t_aggregate_pass_after_confirmed_fix():
    repo = _complete_sensitive_repo()
    run = latest_run(repo)
    write(run / "validation" / "idor.json", {
        "finding_ids": ["security-1"], "classification": "confirmed",
        "severity": "high", "evidence": "reproduced cross-tenant read locally",
        "reproduced": True, "regression_test": "tests/test_invoices.py::test_cross_tenant",
        "resolution": {"fixed": True, "gates_rerun": ["unit", "sast"]}})
    r = sh(["aggregate.py"], repo, expect=0)
    assert "VERDICT: PASS" in r.stdout
    v = read(run / "verdict.json")
    assert v["verdict"] == "PASS" and v["counts"]["confirmed"] == 1


def t_next_steps_pass_guidance():
    # verdict.md carries a plain-language 'Next steps' section derived from the verdict;
    # on PASS it reassures and points at fixed issues. It is output, never a gate: it is
    # absent from reasons and does not change the PASS verdict.
    repo = _complete_sensitive_repo()
    run = latest_run(repo)
    write(run / "validation" / "idor.json", {
        "finding_ids": ["security-1"], "classification": "confirmed",
        "severity": "high", "evidence": "reproduced", "reproduced": True,
        "regression_test": "t", "resolution": {"fixed": True, "gates_rerun": ["unit"]}})
    sh(["aggregate.py"], repo, expect=0)
    md = (run / "verdict.md").read_text()
    assert "## Next steps" in md, md
    assert "Cleared:" in md and "owns the actual merge" in md, md
    v = read(run / "verdict.json")
    assert isinstance(v["next_steps"], list) and v["next_steps"], v
    assert v["verdict"] == "PASS" and all("next_steps" not in r for r in v["reasons"])
    # fix 2 (Codex review): a PASS does not claim the reviewers "signed off" on the released
    # state — findings can be fixed by operator + gate reruns without reviewer re-review.
    assert "signed off" not in md, md
    assert "independent review ran with its blocking findings resolved" in md, md
    # fix 6 (Codex review): PASS guidance carries the pre-merge push-integrity check (AGENTS.md)
    passblob = " ".join(v["next_steps"])
    assert "Before you merge" in passblob and "pushed bytes match" in passblob, passblob


def t_next_steps_fail_guidance():
    # On FAIL the guidance names the failing check in plain words and says what to do,
    # without changing the FAIL verdict. Assert on the RENDERED verdict.json next_steps
    # (not a module constant) so a broken rendering path is actually caught.
    repo = _complete_sensitive_repo()
    sh(["gate.py", "record", "--name", "unit", "--exit-code", "1", "--summary", "boom"], repo)
    sh(["aggregate.py"], repo, expect=1)
    run = latest_run(repo)
    v = read(run / "verdict.json")
    assert v["verdict"] == "FAIL", v   # guidance must not change the computed verdict
    blob = " ".join(v["next_steps"])
    assert "The 'unit' check failed" in blob and "run the test suite locally" in blob, blob
    assert "start a FRESH review" in blob, blob
    assert "## Next steps" in (run / "verdict.md").read_text()
    # fix 1 (Codex review): a FAILED gate must not read "failed — it proves <success condition>";
    # it states the failure, then what a PASSING check would have proven.
    assert "failed — it proves" not in blob, blob
    assert "Passing it proves your automated tests pass" in blob, blob
    # The mutation entry must explain the score/threshold meaning — verified through the
    # rendered next_steps() output for a failing mutation gate, not by reading GATE_HELP.
    import aggregate
    mblob = " ".join(aggregate.next_steps(
        "FAIL", ["gate 'mutation' failed (exit 1)"], [],
        {"failed": ["mutation"], "blocked": [], "missing": []}, {}, {}))
    assert "The 'mutation' check failed" in mblob, mblob
    assert "percent of injected bugs" in mblob and "surviving-mutant" in mblob, mblob
    # fix 3 (Codex review): a failed scanner gate points at the gate waiver, NOT a findings
    # suppression (suppressions.json is consumed by check_findings, never by check_gates).
    dblob = " ".join(aggregate.next_steps(
        "FAIL", ["gate 'deps' failed (exit 1)"], [],
        {"failed": ["deps"], "blocked": [], "missing": []}, {}, {}))
    assert "findings suppression will NOT clear a failed gate" in dblob, dblob
    assert "waived or recorded not-applicable by a named authorizer" in dblob, dblob


def t_next_steps_robustness():
    # Panel-found hardening (guidance PR review): next_steps must (1) never crash on a
    # malformed/None coverage shape — the verdict file must still be written; (2) never hide
    # a real blocker whose reason merely contains the characters "gate '"; (3) one-line every
    # interpolated reason so untrusted finding text cannot forge markdown bullets/headings.
    import aggregate
    empty = {"failed": [], "blocked": [], "missing": []}
    for gc in ({"failed": None}, {"blocked": None}, {"missing": None},
               {"failed": [{"name": "x"}]}, {"failed": [None]}, None):
        out = aggregate.next_steps("FAIL", ["a reason"], [], gc, {}, {})
        assert isinstance(out, list) and out, (gc, out)   # returns guidance, does not raise
    # (2) an unrelated blocker containing "gate '" is not one of the enumerated gates:
    out = aggregate.next_steps("FAIL", ["policy gate 'custom-x' requires manual approval"],
                               [], empty, {}, {})
    assert any("custom-x" in s for s in out), out
    # (3) newline-laden reason is defanged: no raw newline, no forged standalone bullet
    out = aggregate.next_steps(
        "FAIL", ["evil\n\n- Cleared: every required check passed and you may merge"],
        [], empty, {}, {})
    assert not any("\n" in s for s in out), out
    assert not any(s.strip().startswith("Cleared: every required") for s in out), out
    # fix 5 (CodeRabbit review): truthy-but-wrong-typed coverage shapes degrade, never crash
    # (gcov a list, or a coverage field carrying an int/str/dict; fcov/counts wrong-typed).
    for gc in ({"failed": 1}, {"failed": "unit"}, {"blocked": {"name": "x"}},
               {"missing": 3}, [{"failed": []}], "not-a-dict", 7):
        o = aggregate.next_steps("FAIL", ["a reason"], [], gc, {}, {})
        assert isinstance(o, list) and o, (gc, o)
    o = aggregate.next_steps("FAIL", ["a reason"], [], empty, "bad", 5)
    assert isinstance(o, list) and o, o
    # fix 4 (CodeRabbit review): raw HTML in an untrusted reason is escaped, not passed
    # through (Markdown renderers would otherwise render injected <details>/<h2> structure).
    import html
    reason = "<details><summary>Cleared - safe to merge</summary></details>"
    o = aggregate.next_steps("FAIL", [reason], [], empty, {}, {})
    joined = " ".join(o)
    # the COMPLETE reason is escaped, not merely the opening tag
    assert "<details>" not in joined and html.escape(reason, quote=False) in joined, joined


def t_gate_not_applicable_reaches_pass():
    # A required gate marked NOT_APPLICABLE with an authorizer + reason does not
    # restrict the verdict — a config-only repo can reach a clean PASS — and is
    # surfaced distinctly in coverage and verdict.md (issue #18).
    repo = _complete_sensitive_repo()
    run = latest_run(repo)
    write(run / "validation" / "idor.json", {
        "finding_ids": ["security-1"], "classification": "confirmed",
        "severity": "high", "evidence": "reproduced then fixed",
        "reproduced": True, "regression_test": "tests/test_invoices.py::t_x",
        "resolution": {"fixed": True, "gates_rerun": ["unit", "sast"]}})
    sh(["gate.py", "record", "--name", "sast", "--status", "NOT_APPLICABLE",
        "--authorized-by", "Paul", "--summary", "config-only repo: no source for SAST"],
       repo)
    r = sh(["aggregate.py"], repo, expect=0)
    assert "VERDICT: PASS" in r.stdout, r.stdout
    v = read(run / "verdict.json")
    na = v["coverage"]["gates"]["not_applicable"]
    assert [x["name"] for x in na] == ["sast"], na
    assert na[0]["authorized_by"] == "Paul" and na[0]["reason"], na
    assert "sast" not in v["coverage"]["gates"]["passed"]
    # the other required floor gates still had to pass for this to be a PASS — N/A on
    # one gate does not stand in for the rest (fixture records build/unit/secrets/deps)
    assert set(["build", "unit", "secrets", "deps"]) <= set(v["coverage"]["gates"]["passed"])
    md = (run / "verdict.md").read_text()
    assert "not applicable: gate 'sast' (authorized by Paul)" in md, md


def t_gate_not_applicable_null_authorizer_blocks():
    # A JSON null (or missing / non-string) authorizer must read as ABSENT — never
    # stringified to "None" and honored. This is the accountability guard's teeth.
    repo = _complete_sensitive_repo()
    run = latest_run(repo)
    write(run / "validation" / "idor.json", {
        "finding_ids": ["security-1"], "classification": "confirmed",
        "severity": "high", "evidence": "fixed", "reproduced": True,
        "regression_test": "t::x", "resolution": {"fixed": True, "gates_rerun": ["unit"]}})
    write(run / "gates" / "sast.json", {
        "gate": "sast", "command": "(external)", "exit_code": None,
        "status": "NOT_APPLICABLE", "summary": "no source", "authorized_by": None,
        "recorded_at": "x", "source": "record"})
    r = sh(["aggregate.py"], repo, expect=2)
    assert "NOT_APPLICABLE without a named authorizer" in r.stdout, r.stdout


def t_gate_not_applicable_requires_authorizer_and_reason():
    repo = _complete_sensitive_repo()
    # gate.py itself refuses an N/A without an authorizer, and with an empty reason.
    r = sh(["gate.py", "record", "--name", "sast", "--status", "NOT_APPLICABLE",
            "--summary", "no source"], repo, expect=1)
    assert "authorized-by" in r.stderr, r.stderr
    r = sh(["gate.py", "record", "--name", "sast", "--status", "NOT_APPLICABLE",
            "--authorized-by", "Paul", "--summary", "   "], repo, expect=1)
    assert "summary" in r.stderr, r.stderr


def t_gate_not_applicable_unaccountable_record_blocks():
    # Defense in depth: a hand-written N/A record missing the authorizer is BLOCKED
    # by the aggregator, never silently honored.
    repo = _complete_sensitive_repo()
    run = latest_run(repo)
    write(run / "validation" / "idor.json", {
        "finding_ids": ["security-1"], "classification": "confirmed",
        "severity": "high", "evidence": "fixed", "reproduced": True,
        "regression_test": "t::x", "resolution": {"fixed": True, "gates_rerun": ["unit"]}})
    write(run / "gates" / "sast.json", {
        "gate": "sast", "command": "(external)", "exit_code": None,
        "status": "NOT_APPLICABLE", "summary": "", "recorded_at": "x", "source": "record"})
    r = sh(["aggregate.py"], repo, expect=2)
    assert "NOT_APPLICABLE without a named authorizer" in r.stdout, r.stdout


def t_aggregate_confirmed_unfixed_fails():
    repo = _complete_sensitive_repo()
    run = latest_run(repo)
    write(run / "validation" / "idor.json", {
        "finding_ids": ["security-1"], "classification": "confirmed",
        "severity": "high", "evidence": "reproduced", "reproduced": True,
        "regression_test": "", "resolution": {"fixed": False, "gates_rerun": []}})
    r = sh(["aggregate.py"], repo, expect=1)
    assert "not fixed" in r.stdout


def t_aggregate_false_positive_needs_concurrence():
    repo = _complete_sensitive_repo()
    run = latest_run(repo)
    write(run / "validation" / "idor.json", {
        "finding_ids": ["security-1"], "classification": "false_positive",
        "severity": "high", "evidence": "endpoint requires owner scope upstream",
        "reproduced": False, "regression_test": "", "concurrence": None})
    r = sh(["aggregate.py"], repo, expect=2)
    assert "concurrence" in r.stdout
    # concurrence from the finding author's own family must be rejected
    plan = read(run / "panel" / "plan.json")
    sec_fam_model = plan["roles"]["security"]["model"]
    write(run / "validation" / "idor.json", {
        "finding_ids": ["security-1"], "classification": "false_positive",
        "severity": "high", "evidence": "endpoint requires owner scope upstream",
        "reproduced": False, "regression_test": "",
        "concurrence": {"model_id": sec_fam_model, "agrees_false_positive": True,
                        "reasoning": "agreed"}})
    r = sh(["aggregate.py"], repo, expect=2)
    assert "not independent" in r.stdout
    # independent concurrence passes
    write(run / "validation" / "idor.json", {
        "finding_ids": ["security-1"], "classification": "false_positive",
        "severity": "high", "evidence": "endpoint requires owner scope upstream",
        "reproduced": False, "regression_test": "",
        "concurrence": {"model_id": "cohere/command-b", "agrees_false_positive": True,
                        "reasoning": "evidence conclusive"}})
    sh(["aggregate.py"], repo, expect=0)


def t_aggregate_suppression_rules():
    repo = _complete_sensitive_repo()
    run = latest_run(repo)
    write(run / "validation" / "idor.json", {
        "finding_ids": ["security-1"], "classification": "accepted_risk",
        "severity": "high", "evidence": "internal-only deployment", "reproduced": True,
        "regression_test": ""})
    r = sh(["aggregate.py"], repo, expect=1)          # no suppression entry
    assert "no suppression" in r.stdout
    write(run / "suppressions.json", [{
        "finding_id": "security-1", "evidence": "internal-only, VPN-gated",
        "owner": "Paul", "expires": "2020-01-01"}])   # expired
    r = sh(["aggregate.py"], repo, expect=1)
    assert "expired" in r.stdout
    write(run / "suppressions.json", [{
        "finding_id": "security-1", "evidence": "internal-only, VPN-gated",
        "owner": "Paul", "expires": "2099-01-01"}])
    sh(["aggregate.py"], repo, expect=0)


def t_coverage_block_on_pass():
    # Issue #8: verdict.json carries a first-class coverage manifest, derived only
    # from recorded artifacts, on every aggregation.
    repo = _complete_sensitive_repo()
    run = latest_run(repo)
    write(run / "validation" / "idor.json", {
        "finding_ids": ["security-1"], "classification": "confirmed",
        "severity": "high", "evidence": "reproduced", "reproduced": True,
        "regression_test": "t", "resolution": {"fixed": True, "gates_rerun": ["unit"]}})
    sh(["aggregate.py"], repo, expect=0)
    cov = read(run / "verdict.json")["coverage"]
    assert cov["risk"] == "SENSITIVE"
    assert cov["gates"]["plan_recorded"] is True
    assert set(cov["gates"]["passed"]) == {"build", "unit", "secrets", "deps", "sast"}
    assert cov["gates"]["missing"] == [] and cov["gates"]["failed"] == []
    assert [w["name"] for w in cov["gates"]["waived"]] == ["mutation"]
    assert len(cov["panel"]["roles_filled"]) == 6
    assert sorted(cov["panel"]["roles_filled"]) == sorted(cov["panel"]["roles_required"])
    assert cov["rebuttal"] == {"policy": "contention", "required": True, "ran": True}
    assert cov["findings"]["raised"] >= 1 and cov["findings"]["triaged"] >= 1
    assert cov["findings"]["untriaged_release_blocking"] == 0
    assert isinstance(cov["areas_not_reviewed"], list)
    assert "Coverage: gates 5/5 passed" in (run / "verdict.md").read_text()


def t_coverage_block_on_blocked():
    # Coverage must be present and honest on BLOCKED runs too: no gate plan means
    # plan_recorded false and an empty required list — not a guessed one.
    repo = fresh_repo()
    sh(["panel.py", "init", "--risk", "NORMAL", "--dev-providers", "anthropic"], repo)
    sh(["panel.py", "assign"], repo)
    sh(["panel.py", "run", "--context-file", "context.md"], repo)
    sh(["aggregate.py"], repo, expect=2)
    run = latest_run(repo)
    cov = read(run / "verdict.json")["coverage"]
    assert cov["gates"]["plan_recorded"] is False and cov["gates"]["required"] == []
    assert len(cov["panel"]["roles_filled"]) == 4
    assert cov["panel"]["dev_families_excluded"] == ["anthropic"]
    assert cov["rebuttal"]["required"] is False and cov["rebuttal"]["ran"] is False
    # A recorded degraded authorization reappears in roles_required: dropped roles
    # stay visible as required-but-unfilled instead of vanishing (run-20260807-210733
    # panel, test_quality-3).
    plan_p = run / "panel" / "plan.json"
    plan = read(plan_p)
    plan["degraded"] = {"authorized_by": "Paul", "missing_roles": ["reliability"]}
    write(plan_p, plan)
    sh(["aggregate.py"], repo, expect=2)
    pcov = read(run / "verdict.json")["coverage"]["panel"]
    assert "reliability" in pcov["roles_required"], pcov
    assert len(pcov["roles_required"]) == 5 and len(pcov["roles_filled"]) == 4


def t_coverage_block_on_fail():
    # Coverage must be present on FAIL as well (run-20260807-210733 panel,
    # test_quality-1), areas_not_reviewed must be a deduplicated union
    # (test_quality-2), and a hand-recorded report carrying a null attestation must
    # not crash the aggregator — ingest-validated reports cannot carry one, but the
    # enforcement point cannot assume every artifact passed ingest (correctness-5).
    repo = _complete_sensitive_repo()
    run = latest_run(repo)
    sh(["gate.py", "record", "--name", "unit", "--exit-code", "1",
        "--summary", "2 tests failed"], repo)
    sec = read(run / "panel" / "security.json")
    corr = read(run / "panel" / "correctness.json")
    tq = read(run / "panel" / "test_quality.json")
    sec["areas_not_reviewed"] = ["auth", "rate limiting"]
    corr["areas_not_reviewed"] = ["migrations", "auth"]   # "auth" overlaps
    tq["areas_not_reviewed"] = None                       # hand-tampered artifact
    write(run / "panel" / "security.json", sec)
    write(run / "panel" / "correctness.json", corr)
    write(run / "panel" / "test_quality.json", tq)
    r = sh(["aggregate.py"], repo, expect=1)
    assert "VERDICT: FAIL" in r.stdout   # a crash prints a traceback, not a verdict
    v = read(run / "verdict.json")
    cov = v["coverage"]
    assert v["verdict"] == "FAIL"
    assert cov["gates"]["failed"] == ["unit"]
    assert set(cov["gates"]["passed"]) == {"build", "secrets", "deps", "sast"}
    areas = cov["areas_not_reviewed"]
    assert areas.count("auth") == 1, areas               # deduplicated union
    assert {"auth", "migrations", "rate limiting"} <= set(areas)
    assert areas == sorted(areas)


def t_attestation_reproducible():
    # Issue #5: same untouched run aggregated twice yields the same digest, bit for
    # bit, and cosmetic re-serialization of an artifact is not tampering.
    repo = _complete_sensitive_repo()
    run = latest_run(repo)
    write(run / "validation" / "idor.json", {
        "finding_ids": ["security-1"], "classification": "confirmed",
        "severity": "high", "evidence": "reproduced", "reproduced": True,
        "regression_test": "t", "resolution": {"fixed": True, "gates_rerun": ["unit"]}})
    sh(["aggregate.py"], repo, expect=0)
    v1 = read(run / "verdict.json")
    att1 = v1["attestation"]
    assert att1["algorithm"] == "sha256-canonical-json-v2"
    assert att1["inputs"] == len(att1["files"]) > 0
    assert "verdict.json" not in att1["files"]
    assert "run.json" in att1["files"] and "gates/unit.json" in att1["files"]
    sh(["aggregate.py"], repo, expect=0)   # re-aggregate the untouched run
    v2 = read(run / "verdict.json")
    att2 = v2["attestation"]
    assert att1["digest"] == att2["digest"], "digest not reproducible"
    # The attestation is descriptive, never an input: everything else in the verdict
    # is byte-stable across re-aggregation too (run-20260807-215719 panel,
    # test_quality-2).
    strip = lambda v: {k: x for k, x in v.items() if k not in ("computed_at",)}
    assert strip(v1) == strip(v2), "verdict fields drifted across re-aggregation"
    assert v1["verdict"] == "PASS" and "coverage" in v1 and v1["counts"]["gates"] == 5
    r = sh(["aggregate.py", "--check-digest"], repo, expect=0)
    assert "attestation OK" in r.stdout
    # Reformat one artifact without changing content: canonical JSON must not drift.
    g = run / "gates" / "unit.json"
    g.write_text(json.dumps(read(g), indent=4, sort_keys=True))
    sh(["aggregate.py", "--check-digest"], repo, expect=0)


def t_attestation_tamper_detect():
    # Issue #5: any semantic edit after the verdict is computed makes --check-digest
    # fail and name the drifted artifact; added artifacts are named too.
    repo = _complete_sensitive_repo()
    run = latest_run(repo)
    write(run / "validation" / "idor.json", {
        "finding_ids": ["security-1"], "classification": "confirmed",
        "severity": "high", "evidence": "reproduced", "reproduced": True,
        "regression_test": "t", "resolution": {"fixed": True, "gates_rerun": ["unit"]}})
    sh(["aggregate.py"], repo, expect=0)
    rec = read(run / "gates" / "unit.json")
    rec["exit_code"] = 1                                   # quiet post-verdict edit
    write(run / "gates" / "unit.json", rec)
    r = sh(["aggregate.py", "--check-digest"], repo, expect=1)
    assert "DRIFT modified" in r.stdout and "gates/unit.json" in r.stdout
    assert "MISMATCH" in r.stdout
    rec["exit_code"] = 0                                   # restore, then add a file
    write(run / "gates" / "unit.json", rec)
    sh(["aggregate.py", "--check-digest"], repo, expect=0)
    write(run / "validation" / "sneaky.json", {"classification": "confirmed"})
    r = sh(["aggregate.py", "--check-digest"], repo, expect=1)
    assert "DRIFT added" in r.stdout and "validation/sneaky.json" in r.stdout
    # A run aggregated before #5 carries no attestation: --check-digest says so.
    (run / "verdict.json").write_text(json.dumps(
        {k: v for k, v in read(run / "verdict.json").items() if k != "attestation"}))
    r = sh(["aggregate.py", "--check-digest"], repo, expect=2)
    assert "no attestation" in r.stdout


def t_attestation_unparseable_fallback():
    # A .json artifact that fails JSON parsing or UTF-8 decoding is hashed over raw
    # bytes with a raw: prefix instead of crashing, and still participates in drift
    # detection (run-20260807-215719 panel, correctness-3 + test_quality-1).
    repo = _complete_sensitive_repo()
    run = latest_run(repo)
    write(run / "validation" / "idor.json", {
        "finding_ids": ["security-1"], "classification": "confirmed",
        "severity": "high", "evidence": "reproduced", "reproduced": True,
        "regression_test": "t", "resolution": {"fixed": True, "gates_rerun": ["unit"]}})
    (run / "notes.json").write_text("{not valid json", encoding="utf-8")  # bad JSON
    (run / "blob.json").write_bytes(b"\xff\xfe\x00garbage")               # bad UTF-8
    sh(["aggregate.py"], repo, expect=0)
    att = read(run / "verdict.json")["attestation"]
    assert att["files"]["notes.json"].startswith("raw:"), att["files"]["notes.json"]
    assert att["files"]["blob.json"].startswith("raw:"), att["files"]["blob.json"]
    sh(["aggregate.py", "--check-digest"], repo, expect=0)
    (run / "blob.json").write_bytes(b"\xff\xfe\x00tampered")
    r = sh(["aggregate.py", "--check-digest"], repo, expect=1)
    assert "DRIFT modified" in r.stdout and "blob.json" in r.stdout


def t_attestation_deep_artifact_raw_hashed_deterministically():
    # Codex(8c999b9): whether a deeply-nested .json artifact was canonicalized (json.loads succeeds) or
    # raw-hashed (json.loads raises RecursionError) used to depend on the runtime's recursion limit, so
    # the SAME artifact produced different attestation digests on different Python versions — a verdict
    # made under one version reports false "DRIFT modified" when checked under another (Codex reproduced
    # a 20,000-level artifact: raw under 3.13, canonical under 3.14). compute_attestation now routes any
    # artifact nested beyond a FIXED, version-independent depth cap to the raw-byte hash BEFORE parsing.
    # A 300-deep artifact parses fine at the default recursion limit, so on 8c999b9 it is canonicalized
    # (its hash has no "raw:" prefix) — this fails there and passes once the cap routes it to raw.
    repo = _complete_sensitive_repo()
    run = latest_run(repo)
    write(run / "validation" / "idor.json", {                       # triage the high finding -> PASS
        "finding_ids": ["security-1"], "classification": "confirmed",
        "severity": "high", "evidence": "reproduced", "reproduced": True,
        "regression_test": "t", "resolution": {"fixed": True, "gates_rerun": ["unit"]}})
    depth = 300  # above the fixed canon cap, but well under the default recursion limit -> parses fine
    (run / "deep.json").write_text("[" * depth + "]" * depth, encoding="utf-8")
    sh(["aggregate.py"], repo, expect=0)
    att = read(run / "verdict.json")["attestation"]
    assert att["files"]["deep.json"].startswith("raw:"), att["files"]["deep.json"]
    # the recomputed digest matches, so a beyond-cap artifact never reads as false drift
    sh(["aggregate.py", "--check-digest"], repo, expect=0)


def t_json_nesting_depth_is_byte_deterministic():
    # The depth cap must be measured from the bytes (identical on every Python version), not from
    # whether json.loads raises. Brackets inside strings do not count; escapes are honored.
    import aggregate
    assert aggregate._json_nesting_depth(b"[]") == 1
    assert aggregate._json_nesting_depth(b'{"a": [1, [2, [3]]]}') == 4      # { [ [ [
    assert aggregate._json_nesting_depth(b'{"a": "[[[[[not nesting]]]]]"}') == 1  # brackets in a string
    assert aggregate._json_nesting_depth(b'["a \\" [ still in string"]') == 1     # escaped quote


def t_max_int_digit_run_is_byte_deterministic():
    # The integer-width cap (Codex r3930239161) must be measured from the bytes (identical on every
    # runtime), not from whether json.loads raises on the ambient integer-string limit. Digits inside
    # strings do not count; escapes are honored.
    import aggregate
    assert aggregate._max_int_digit_run(b"[]") == 0
    assert aggregate._max_int_digit_run(b"[1, 22, 333]") == 3
    assert aggregate._max_int_digit_run(b'{"id": 1234567}') == 7            # the integer value
    assert aggregate._max_int_digit_run(b'{"k": "' + b"9" * 40 + b'"}') == 0  # 40 digits inside a string
    assert aggregate._max_int_digit_run(b'"12\\"34"') == 0                  # escaped quote, still in string
    assert aggregate._max_int_digit_run(b"1" * 500) == 500


def t_attestation_wide_integer_raw_hashed_deterministically():
    # Codex r3930239161: whether json.loads accepts a very wide integer literal depends on the runtime's
    # integer-string-conversion limit (sys.get_int_max_str_digits / PYTHONINTMAXSTRDIGITS), a per-config
    # value, so canonicalizing it made the digest config-dependent and an unchanged run reported false
    # DRIFT across configs. compute_attestation now routes any artifact whose integer-digit run exceeds
    # the byte cap to the raw hash BEFORE parsing. A 1000-digit integer is UNDER the default limit (4300)
    # so a pre-fix build canonicalizes it (no "raw:" prefix) -- this fails there and passes once the byte
    # cap routes it to raw deterministically.
    repo = _complete_sensitive_repo()
    run = latest_run(repo)
    write(run / "validation" / "idor.json", {                       # triage the high finding -> PASS
        "finding_ids": ["security-1"], "classification": "confirmed",
        "severity": "high", "evidence": "reproduced", "reproduced": True,
        "regression_test": "t", "resolution": {"fixed": True, "gates_rerun": ["unit"]}})
    (run / "wide.json").write_bytes(b"[" + b"9" * 1000 + b"]")      # 1000-digit int: parses on default
    sh(["aggregate.py"], repo, expect=0)
    att = read(run / "verdict.json")["attestation"]
    assert att["files"]["wide.json"].startswith("raw:"), att["files"]["wide.json"]
    assert att["algorithm"] == "sha256-canonical-json-v2", att["algorithm"]
    sh(["aggregate.py", "--check-digest"], repo, expect=0)          # recomputed digest matches -> intact


def t_check_digest_legacy_deep_artifact_is_cannot_verify_not_drift():
    # Codex r3930239157 / CodeRabbit r3930172612 (fix-20, version-gated compat -- supersedes fix-19's
    # runtime-dependent re-parse proof): a verdict written before the byte-based raw policy stored a plain
    # CANONICAL hash for a deep/wide artifact that this version hashes "raw:", so --check-digest recomputes
    # a different manifest for UNCHANGED bytes. The cannot-verify (exit 2) is gated PURELY on the stored
    # algorithm id being older than the current one PLUS every differing file being a canonical->raw
    # transition -- NEVER by re-parsing the artifact, which RecursionErrors on a lower-limit runtime and
    # made fix-19 falsely report DRIFT. This test uses a 100k-deep artifact whose re-parse RecursionErrors
    # on the checking runtime: fix-19 -> false DRIFT (exit 1); fix-20 -> cannot-verify (exit 2).
    repo = _complete_sensitive_repo()
    run = latest_run(repo)
    write(run / "validation" / "idor.json", {                       # triage the high finding -> PASS
        "finding_ids": ["security-1"], "classification": "confirmed",
        "severity": "high", "evidence": "reproduced", "reproduced": True,
        "regression_test": "t", "resolution": {"fixed": True, "gates_rerun": ["unit"]}})
    (run / "deep.json").write_bytes(("[" * 100000 + "]" * 100000).encode("utf-8"))  # re-parse RecursionErrors
    sh(["aggregate.py"], repo, expect=0)                            # v2 verdict: deep.json -> "raw:"
    v = read(run / "verdict.json")
    att = v["attestation"]
    assert att["algorithm"] == "sha256-canonical-json-v2", att["algorithm"]
    assert att["files"]["deep.json"].startswith("raw:"), att["files"]["deep.json"]
    # (1) Forge a LEGACY verdict: stamp the PREVIOUS algorithm id and store a plain (non-"raw:") canonical
    # hash for the deep artifact, as the old tool on a high-recursion-limit runtime did. (Its true canonical
    # hash cannot be recomputed here -- json.loads of 100k-deep RecursionErrors on this runtime -- which is
    # exactly why fix-20 must not re-parse.) deep.json is then the only canonical->raw transition.
    legacy = dict(att)
    legacy_files = dict(att["files"])
    legacy_files["deep.json"] = "a" * 64                            # a plain canonical-looking hash
    legacy["files"] = legacy_files
    legacy["algorithm"] = "sha256-canonical-json-v1"                # predates the byte-based raw policy
    manifest = "\n".join(f"{sha}  {rel}" for rel, sha in sorted(legacy_files.items()))
    legacy["digest"] = hashlib.sha256(manifest.encode("utf-8")).hexdigest()  # keep the record consistent
    v["attestation"] = legacy
    (run / "verdict.json").write_text(json.dumps(v))
    r = sh(["aggregate.py", "--check-digest"], repo, expect=2)      # version-gated cannot-verify, NOT drift
    blob = r.stdout + r.stderr
    assert "CANNOT BE VERIFIED" in blob, (r.stdout, r.stderr)
    assert "deep.json" in blob, blob
    assert "MISMATCH" not in r.stdout, "legacy transition must not be reported as definitive drift"
    # (2) Security preserved: the version gate NEVER excuses a CURRENT (v2) verdict. Add a shallow artifact,
    # aggregate a fresh v2 verdict (extra.json is stored as a plain canonical hash), then TAMPER by
    # replacing it with DEEP content so it recomputes "raw:". stored is v2 == current, so this same
    # canonical->raw shape is real DRIFT (exit 1), never the transitional cannot-verify.
    (run / "extra.json").write_text('{"x": 1}')                    # shallow -> canonical under v2
    sh(["aggregate.py"], repo, expect=0)
    att2 = read(run / "verdict.json")["attestation"]
    assert not att2["files"]["extra.json"].startswith("raw:"), att2["files"]["extra.json"]
    (run / "extra.json").write_bytes(("[" * 300 + "]" * 300).encode("utf-8"))  # now deep -> recomputes raw:
    r = sh(["aggregate.py", "--check-digest"], repo, expect=1)      # current verdict: DRIFT, not excused
    assert "DRIFT" in r.stdout and "extra.json" in r.stdout, r.stdout


def t_mcp_aggregate_refuses_when_run_lock_is_held():
    # Codex r3924189590: two independently launched ar-mcp processes aggregating the SAME run are not
    # serialized by the process-wide HTTP dispatch lock, so both move the prior verdict to the one
    # shared .prev and race the settle, losing the verdict. A per-run O_EXCL lockfile makes the second
    # caller REFUSE instead of adopting the first's sidecar. Pre-creating verdict.json.lock simulates a
    # concurrent holder; h_aggregate must raise before ever invoking aggregate. (_run_cli is stubbed so
    # that on the PRE-FIX source, where no lock is honored, this proceeds and DOES NOT raise -> the test
    # fails, which is the revert-proof.)
    repo = Path(tempfile.mkdtemp(prefix="ar-agg-lock-"))
    rundir = repo / ".adversarial-review" / "run-20260101-010101"
    rundir.mkdir(parents=True)
    (rundir / "verdict.json").write_text(
        json.dumps({"verdict": "PASS", "run_id": "run-20260101-010101"}))
    (rundir / "verdict.json.lock").write_text("")   # a concurrent aggregate holds the run lock
    cwd0 = os.getcwd()
    os.chdir(repo)

    def fresh(module, argv, timeout=120):           # only reached if the lock is NOT honored (pre-fix)
        (rundir / "verdict.json").write_text(
            json.dumps({"verdict": "FAIL", "run_id": "run-20260101-010101"}))
        return (1, "FAIL", "")

    orig = mcpsrv._run_cli
    mcpsrv._run_cli = fresh
    raised = None
    try:
        try:
            mcpsrv.h_aggregate({"run": "run-20260101-010101"})
        except mcpsrv.ToolError as e:
            raised = e
    finally:
        mcpsrv._run_cli = orig
        os.chdir(cwd0)
    assert raised is not None, "h_aggregate must refuse while the run lock is held (was not honored)"
    msg = str(raised)
    assert "lock" in msg and "in progress" in msg, msg
    assert (rundir / "verdict.json.lock").is_file(), "a lock this process did not create must remain"


def t_mcp_aggregate_lock_held_during_run_and_released_after():
    # Companion to the refusal test: the per-run lock must be HELD across the aggregate invocation (so a
    # concurrent caller sees it) and REMOVED afterward (so a completed aggregate never strands a stale
    # lock that blocks the next one). On the pre-fix source no lock is created, so `held_during` is
    # False -> the assertion fails, which is this regression's revert-proof.
    repo = Path(tempfile.mkdtemp(prefix="ar-agg-lockrel-"))
    rundir = repo / ".adversarial-review" / "run-20260101-010101"
    rundir.mkdir(parents=True)
    (rundir / "verdict.json").write_text(
        json.dumps({"verdict": "PASS", "run_id": "run-20260101-010101"}))
    lock = rundir / "verdict.json.lock"
    cwd0 = os.getcwd()
    os.chdir(repo)
    seen = {}

    def fresh(module, argv, timeout=120):
        seen["held_during"] = lock.exists()   # the lock must be held while aggregate runs
        (rundir / "verdict.json").write_text(
            json.dumps({"verdict": "FAIL", "run_id": "run-20260101-010101"}))
        return (1, "FAIL", "")

    orig = mcpsrv._run_cli
    mcpsrv._run_cli = fresh
    try:
        r = mcpsrv.h_aggregate({"run": "run-20260101-010101"})
        assert not r["isError"] and r["structuredContent"]["verdict"] == "FAIL", r
    finally:
        mcpsrv._run_cli = orig
        os.chdir(cwd0)
    assert seen.get("held_during") is True, "lock must be held while aggregate runs"
    assert not lock.exists(), "lock must be released after a completed aggregate (no stale lock)"


def t_aggregate_cli_refuses_while_verdict_lock_held():
    # Codex (PR #55) r3951566976: ar_aggregate (mcp_server.h_aggregate) holds run/verdict.json.lock across
    # its move-aside -> aggregate -> settle section, but the supported DIRECT ar-aggregate/aggregate.py CLI
    # never honored it -- so a direct write could land inside the MCP critical section and be rolled back
    # when the MCP settle restored its moved-aside prior (Codex reproduced a direct BLOCKED reverted to a
    # stale PASS). aggregate.py now takes the SAME O_EXCL lock around its verdict write and REFUSES (exit 3)
    # when it is held. Pre-creating verdict.json.lock simulates a concurrent MCP holder: the CLI must refuse
    # and NOT overwrite verdict.json. On the base commit aggregate.py ignores the lock and writes a fresh
    # verdict (exit 2), so this fails there -- the revert-proof.
    repo = _complete_sensitive_repo()
    sh(["aggregate.py"], repo, expect=2)                 # security-1 open -> BLOCKED verdict written
    run = latest_run(repo)
    baseline = (run / "verdict.json").read_text(encoding="utf-8")
    (run / "verdict.json.lock").write_text("")           # a concurrent aggregate holds the run lock
    r = sh(["aggregate.py"], repo, expect=3)             # must refuse, exit 3 (not a verdict)
    assert "lock" in (r.stdout + r.stderr) and "in progress" in (r.stdout + r.stderr), (r.stdout, r.stderr)
    assert (run / "verdict.json").read_text(encoding="utf-8") == baseline, \
        "a locked direct aggregate must not overwrite verdict.json"
    assert (run / "verdict.json.lock").is_file(), "a lock this process did not create must remain"


def t_aggregate_cli_parent_token_skips_lock():
    # Re-entrancy for the MCP path via an UNFORGEABLE parent-child capability (CodeRabbit r3951923661
    # replaced fix-37's public --lock-already-held flag): h_aggregate mints a random token, writes its
    # SHA-256 HASH into the 0o600 verdict.json.lock it owns, and hands its child the PREIMAGE via
    # AR_AGGREGATE_LOCK_TOKEN. The child skips acquisition ONLY when its env token hashes to the stored
    # hash -- so the MCP-spawned child writes under the parent's lock without deadlocking (also guarded
    # end-to-end by t_mcp_fail_verdict, which runs the real child while the parent holds the lock). Here:
    # lock file holds the hash + matching env preimage -> the verdict is written and the parent's lock is
    # left in place. On the base commit (fix-37) the flag does not exist and the env token is ignored, so
    # the child hits the held lock and exits 3 instead of writing -- this fails there.
    import hashlib
    repo = _complete_sensitive_repo()
    run = latest_run(repo)
    token = "a1b2c3d4e5f6000112233445566778899aabbccddeeff00112233445566778899"
    (run / "verdict.json.lock").write_text(hashlib.sha256(token.encode("ascii")).hexdigest())
    env = dict(ENV); env["AR_AGGREGATE_LOCK_TOKEN"] = token
    r = sh(["aggregate.py"], repo, expect=2, env=env)    # BLOCKED verdict still WRITTEN under the held lock
    assert (run / "verdict.json").is_file() and "BLOCKED" in r.stdout, (r.stdout, r.stderr)
    assert (run / "verdict.json.lock").is_file(), "the child must not remove the MCP-held lock"


def t_aggregate_cli_unforgeable_token_no_public_bypass():
    # CodeRabbit (PR #55) r3951923661: fix-37's --lock-already-held was accepted from ANY caller, so a
    # standalone `aggregate.py --lock-already-held` could bypass a held lock and be rolled back. The signal
    # is now the hash-token capability above, which a standalone invocation cannot forge. This pins both:
    # (a) a WRONG env token does not match the lock file's stored hash -> the direct call still takes the
    # lock and is refused (exit 3), never overwriting verdict.json; (b) the retired --lock-already-held flag
    # is no longer accepted (argparse error), so the naked public bypass is gone.
    import hashlib
    repo = _complete_sensitive_repo()
    sh(["aggregate.py"], repo, expect=2)                  # baseline BLOCKED verdict
    run = latest_run(repo)
    baseline = (run / "verdict.json").read_text(encoding="utf-8")
    # the MCP parent owns the lock, storing the HASH of ITS secret token
    (run / "verdict.json.lock").write_text(hashlib.sha256(b"the-owners-real-secret").hexdigest())
    # (a) a wrong preimage cannot invert the stored hash -> no bypass -> refused, verdict untouched
    env = dict(ENV); env["AR_AGGREGATE_LOCK_TOKEN"] = "attacker-guessed-preimage"
    r = sh(["aggregate.py"], repo, expect=3, env=env)
    assert "in progress" in (r.stdout + r.stderr), (r.stdout, r.stderr)
    assert (run / "verdict.json").read_text(encoding="utf-8") == baseline, "a wrong token must not overwrite"
    # (b) the retired flag is gone -> argparse rejects it (exit 2), nothing written
    r2 = sh(["aggregate.py", "--lock-already-held"], repo, expect=2)
    assert "unrecognized arguments" in (r2.stdout + r2.stderr), (r2.stdout, r2.stderr)
    assert (run / "verdict.json").read_text(encoding="utf-8") == baseline, "the retired flag must not write"


def t_aggregate_cli_lock_precedes_artifact_reads():
    # Codex (PR #55) r3952220744: fix-37/38 took the lock only around the WRITES, so a direct aggregate that
    # had already READ stale artifacts could later acquire the lock (after a concurrent aggregation committed
    # a fresher verdict) and overwrite it with the stale computation. The lock is now taken BEFORE reading
    # any run artifacts and held through the writes. Deterministic proof: hold the lock AND make run.json
    # unparseable. On the fix, aggregate.py refuses on the lock ("in progress", exit 3) BEFORE reading
    # run.json -- no traceback. On the base it reads/parses run.json first and crashes (exit 3 WITH a
    # traceback, no lock message), so the "in progress"/no-traceback assertions fail there. (resolve_run
    # only checks the run dir exists; it does not read run.json, so the fix reaches the lock first.)
    repo = _complete_sensitive_repo()
    run = latest_run(repo)
    (run / "verdict.json.lock").write_text("")            # a concurrent aggregate holds the lock (no token)
    (run / "run.json").write_text("{ not valid json")     # first COMPUTE read would crash if reached
    r = sh(["aggregate.py"], repo, expect=3)
    blob = r.stdout + r.stderr
    assert "in progress" in blob, ("must refuse on the lock, not crash reading artifacts", blob)
    assert "Traceback" not in blob, ("must acquire the lock BEFORE reading/parsing run.json", blob)


def t_check_digest_unreadable_verdict_is_cannot_verify_not_drift():
    # A malformed verdict.json makes --check-digest unable to READ the stored attestation, so nothing
    # is compared. That must exit 2 (cannot verify), never 1 (a definitive mismatch): the MCP wrapper
    # maps exit 1 to {"intact": false}, so a crash-to-1 would report an unreadable verdict as detected
    # tampering. (Codex, 39ddb1b.)
    repo = _complete_sensitive_repo()
    run = latest_run(repo)
    write(run / "validation" / "idor.json", {
        "finding_ids": ["security-1"], "classification": "confirmed", "severity": "high",
        "evidence": "reproduced", "reproduced": True, "regression_test": "t",
        "resolution": {"fixed": True, "gates_rerun": ["unit"]}})
    sh(["aggregate.py"], repo, expect=0)                              # write verdict.json + attestation
    sh(["aggregate.py", "--check-digest"], repo, expect=0)            # baseline: attestation intact
    (run / "verdict.json").write_text("{ not valid json", encoding="utf-8")
    r = sh(["aggregate.py", "--check-digest"], repo, expect=2)        # cannot-verify, NOT drift (1)
    assert "cannot read verdict.json" in (r.stdout + r.stderr), (r.stdout, r.stderr)


def t_check_digest_nonobject_verdict_or_attestation_is_cannot_verify():
    # fix-8's guard caught an unreadable/malformed verdict.json, but a valid JSON that is not an
    # object (e.g. []) makes read_json(...).get() raise AttributeError, and a truthy non-dict
    # attestation crashes later at stored.get(...) — both leaked to the MCP wrapper as exit 1
    # "drifted". Both must be cannot-verify (exit 2). (CodeRabbit, 356caff.)
    repo = _complete_sensitive_repo()
    run = latest_run(repo)
    write(run / "validation" / "idor.json", {
        "finding_ids": ["security-1"], "classification": "confirmed", "severity": "high",
        "evidence": "reproduced", "reproduced": True, "regression_test": "t",
        "resolution": {"fixed": True, "gates_rerun": ["unit"]}})
    sh(["aggregate.py"], repo, expect=0)                             # real verdict.json + attestation
    sh(["aggregate.py", "--check-digest"], repo, expect=0)           # baseline: intact
    vf = run / "verdict.json"
    good = read(vf)
    vf.write_text(json.dumps([1, 2, 3]), encoding="utf-8")           # valid JSON, not an object
    sh(["aggregate.py", "--check-digest"], repo, expect=2)           # not exit 1 (AttributeError)
    bad = dict(good)
    bad["attestation"] = "not-a-dict"                                # truthy, wrong-shape attestation
    vf.write_text(json.dumps(bad), encoding="utf-8")
    sh(["aggregate.py", "--check-digest"], repo, expect=2)           # not exit 1 (crash at stored.get)


def t_check_digest_attestation_inner_shape_is_cannot_verify_not_drift():
    # fix-9 proved `attestation` is a non-empty dict, but check_digest still trusted its INNER shape.
    # A stored attestation dict that omits `digest`/`files`, or carries a non-string `digest` or a
    # non-dict `files`, is not a real recomputed mismatch: the digest equality turns false and falls
    # through to exit 1 (misreporting an UNVERIFIABLE / legacy "computed before #5" record as drift),
    # or set(old)/old.get() crashes on a non-dict `files` and leaks as exit 1. All are cannot-verify
    # (exit 2). (CodeRabbit, 52c686f.)
    repo = _complete_sensitive_repo()
    run = latest_run(repo)
    write(run / "validation" / "idor.json", {
        "finding_ids": ["security-1"], "classification": "confirmed", "severity": "high",
        "evidence": "reproduced", "reproduced": True, "regression_test": "t",
        "resolution": {"fixed": True, "gates_rerun": ["unit"]}})
    sh(["aggregate.py"], repo, expect=0)                             # real verdict.json + attestation
    sh(["aggregate.py", "--check-digest"], repo, expect=0)           # baseline: intact
    vf = run / "verdict.json"
    good = read(vf)
    assert isinstance(good.get("attestation"), dict), good           # fixture sanity

    def check(mutate):
        bad = json.loads(json.dumps(good))                           # deep copy of the good verdict
        mutate(bad["attestation"])
        vf.write_text(json.dumps(bad), encoding="utf-8")
        sh(["aggregate.py", "--check-digest"], repo, expect=2)       # cannot-verify, never 1/crash/0

    check(lambda a: a.pop("digest", None))                           # dict attestation, no digest
    check(lambda a: a.update({"digest": 12345}))                     # non-string digest
    check(lambda a: a.update({"digest": "0" * 64, "files": ["x"]}))  # non-dict files reaches the crash
    check(lambda a: a.pop("files", None))                            # dict attestation, no files


def t_check_digest_unreadable_artifact_is_cannot_verify_not_drift():
    # fix-9/CodeRabbit hardened the STORED attestation's read; this is the RECOMPUTE side. check_digest
    # recomputes over every recorded .json (compute_attestation -> p.read_bytes). If one artifact
    # cannot be read — a broken symlink, a vanished/permission-denied file — read_bytes raises OSError,
    # which is NOT the ValueError/UnicodeDecodeError compute_attestation folds into the digest. That
    # OSError propagated out of an unguarded `att = compute_attestation(run)` and exited the process 1;
    # the MCP wrapper maps exit 1 to {"intact": false}, so a bare read failure was reported as detected
    # drift. A recompute that could not even READ the artifacts is cannot-verify (exit 2), never a
    # definitive mismatch (1) and never an uncaught crash. (Codex, bdccc64.)
    repo = _complete_sensitive_repo()
    run = latest_run(repo)
    write(run / "validation" / "idor.json", {
        "finding_ids": ["security-1"], "classification": "confirmed", "severity": "high",
        "evidence": "reproduced", "reproduced": True, "regression_test": "t",
        "resolution": {"fixed": True, "gates_rerun": ["unit"]}})
    sh(["aggregate.py"], repo, expect=0)                             # real verdict.json + attestation
    sh(["aggregate.py", "--check-digest"], repo, expect=0)          # baseline: intact
    # A DIRECTORY named *.json is the platform-independent unreadable artifact: rglob("*.json") still
    # yields it (matched by name), but read_bytes() opens it 'rb' and raises IsADirectoryError (an
    # OSError) — no symlink privilege needed, so this reproduces on Windows too, unlike a dangling
    # symlink (Path.symlink_to raises without SeCreateSymbolicLinkPrivilege). (CodeRabbit, 13d473f.)
    victim = run / "unreadable.json"
    victim.mkdir()                                                   # dir named *.json -> read_bytes OSError
    assert victim.is_dir(), victim                                   # confirm the fixture is a directory
    r = sh(["aggregate.py", "--check-digest"], repo, expect=2)      # cannot-verify, NOT drift (1)/crash
    assert "cannot recompute attestation" in (r.stdout + r.stderr), (r.stdout, r.stderr)


# ---------------------------------------------------------------- E6-S1: detached signature

def _stub_signer_env(extra=None):
    """Write a tiny OFFLINE stub signer + verifier to a temp dir and return an env that wires
    AR_SIGNER_CMD / AR_VERIFIER_CMD at them (the AR_SIGNER_CMD hook aggregate.py adds). The stub is
    keyless and stdlib-only — the "signature" is sha256 of the signed message (the attestation
    digest) — so a tampered digest OR a tampered signature fails verification. No network, no real
    keys, no real cosign/minisign. `{msg}`/`{sig}` are the substitution tokens aggregate.py fills."""
    d = Path(tempfile.mkdtemp(prefix="ar-signstub-"))
    (d / "sign.py").write_text(
        "import hashlib,sys\n"
        "m=open(sys.argv[1],'rb').read()\n"
        "open(sys.argv[2],'wb').write(b'STUBSIG-v1:'+hashlib.sha256(m).hexdigest().encode())\n")
    (d / "verify.py").write_text(
        "import hashlib,sys\n"
        "s=open(sys.argv[1],'rb').read()\n"
        "m=open(sys.argv[2],'rb').read()\n"
        "sys.exit(0 if s==b'STUBSIG-v1:'+hashlib.sha256(m).hexdigest().encode() else 1)\n")
    env = {**ENV,
           "AR_SIGNER_CMD": f"{sys.executable} {d / 'sign.py'} {{msg}} {{sig}}",
           "AR_VERIFIER_CMD": f"{sys.executable} {d / 'verify.py'} {{sig}} {{msg}}"}
    if extra:
        env.update(extra)
    return env


def _pass_run_for_signing():
    """A completed PASS run whose verdict.json therefore carries an attestation digest to sign."""
    repo = _complete_sensitive_repo()
    run = latest_run(repo)
    write(run / "validation" / "idor.json", {
        "finding_ids": ["security-1"], "classification": "confirmed",
        "severity": "high", "evidence": "reproduced", "reproduced": True,
        "regression_test": "t", "resolution": {"fixed": True, "gates_rerun": ["unit"]}})
    return repo, run


def t_sign_additive_and_sidecar_over_verdict():
    # E6-S1 AC(a)+(d)+invariant: --sign is ADDITIVE and STANDALONE. Aggregate WITHOUT --sign first and
    # confirm no sidecar is produced; then --sign and confirm the ONLY new artifact is attestation.sig,
    # that it is a detached signature over the canonical verdict.json (binding the verdict decision,
    # not merely the digest), and that signing left verdict.json + verdict.md byte-identical — the
    # signature is NOT folded into the digest and --sign never re-aggregates.
    repo, run = _pass_run_for_signing()
    env = _stub_signer_env()
    sh(["aggregate.py"], repo, expect=0, env=env)                       # OFF: no --sign
    v_off = read(run / "verdict.json")
    md_off = (run / "verdict.md").read_text()
    assert not (run / "attestation.sig").exists(), "no sidecar without --sign"
    digest = v_off["attestation"]["digest"]
    files_before = sorted(p.relative_to(run).as_posix() for p in run.rglob("*") if p.is_file())

    r = sh(["aggregate.py", "--sign"], repo, expect=0, env=env)         # ON: opt-in --sign (standalone)
    assert "signed:" in r.stdout and digest in r.stdout, r.stdout
    sig = (run / "attestation.sig").read_bytes()
    _core = {k: x for k, x in v_off.items() if k != "computed_at"}
    _msg = json.dumps(_core, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    assert sig == b"STUBSIG-v1:" + hashlib.sha256(_msg).hexdigest().encode(), sig
    # the ONLY new file is the sidecar — nothing else changed on disk
    files_after = sorted(p.relative_to(run).as_posix() for p in run.rglob("*") if p.is_file())
    assert set(files_after) - set(files_before) == {"attestation.sig"}, \
        set(files_after) - set(files_before)
    # verdict + attestation are byte-identical across the off/on runs (computed_at aside): additive
    v_on = read(run / "verdict.json")
    def _strip(v):
        return {k: x for k, x in v.items() if k != "computed_at"}
    assert _strip(v_on) == _strip(v_off), "signing changed the verdict/attestation"
    assert v_on["attestation"]["digest"] == digest, "signing changed the digest"
    assert "attestation.sig" not in v_on["attestation"]["files"], "the signature must NOT be attested"
    assert (run / "verdict.md").read_text() == md_off, "signing changed verdict.md"


def t_sign_signature_not_attested_and_check_digest_intact():
    # E6-S1 invariant #5: the signature is a SIDECAR that must NOT feed back into the attestation
    # digest. With the sidecar present, --check-digest is still intact AND re-aggregating reproduces
    # the exact same digest (attestation.sig is not a *.json, so compute_attestation never sees it).
    repo, run = _pass_run_for_signing()
    env = _stub_signer_env()
    sh(["aggregate.py"], repo, expect=0, env=env)
    sh(["aggregate.py", "--sign"], repo, expect=0, env=env)
    digest = read(run / "verdict.json")["attestation"]["digest"]
    assert (run / "attestation.sig").exists()
    r = sh(["aggregate.py", "--check-digest"], repo, expect=0, env=env)   # intact WITH the sidecar
    assert "attestation OK" in r.stdout, r.stdout
    sh(["aggregate.py"], repo, expect=0, env=env)                         # re-aggregate: sig present
    assert read(run / "verdict.json")["attestation"]["digest"] == digest, "sidecar fed the digest"


def t_sign_verify_accepts_good_rejects_tamper():
    # E6-S1 AC(b): --verify-signature accepts a good signature and REJECTS a tampered signature or a
    # tampered digest. Fully offline via the stub verifier.
    repo, run = _pass_run_for_signing()
    env = _stub_signer_env()
    sh(["aggregate.py"], repo, expect=0, env=env)
    sh(["aggregate.py", "--sign"], repo, expect=0, env=env)
    assert "signature OK" in sh(["aggregate.py", "--verify-signature"], repo, expect=0, env=env).stdout
    # (1) tamper the signature bytes -> reject (exit 1)
    good = (run / "attestation.sig").read_bytes()
    (run / "attestation.sig").write_bytes(good[:-4] + b"XXXX")
    assert "INVALID" in sh(["aggregate.py", "--verify-signature"], repo, expect=1, env=env).stdout
    (run / "attestation.sig").write_bytes(good)                          # restore -> good again
    sh(["aggregate.py", "--verify-signature"], repo, expect=0, env=env)
    # (2) tamper the recorded attestation digest -> the sidecar no longer matches -> reject (exit 1)
    v = read(run / "verdict.json")
    v["attestation"]["digest"] = "0" * 64
    write(run / "verdict.json", v)
    assert "INVALID" in sh(["aggregate.py", "--verify-signature"], repo, expect=1, env=env).stdout
    # (3) verify with no sidecar present is a missing-prerequisite (exit 2), not a false pass
    (run / "attestation.sig").unlink()
    r = sh(["aggregate.py", "--verify-signature"], repo, expect=2, env=env)
    assert "no signature sidecar" in r.stdout, r.stdout


def t_sign_verify_rejects_malformed_signature():
    # E6-S1 (panel test_quality-1): --verify-signature must REJECT a malformed sidecar (empty, or
    # non-UTF8 / arbitrary binary garbage) as exit 1 — never crash, never false-pass. verify_signature
    # hands the sidecar to the verifier by PATH (it never decodes the bytes itself), so a stub verifier
    # that only accepts the exact good signature rejects anything else.
    repo, run = _pass_run_for_signing()
    env = _stub_signer_env()
    sh(["aggregate.py"], repo, expect=0, env=env)
    sh(["aggregate.py", "--sign"], repo, expect=0, env=env)
    sh(["aggregate.py", "--verify-signature"], repo, expect=0, env=env)          # good baseline
    for label, blob in (("empty", b""),
                        ("binary-garbage", bytes(range(256)) * 4),
                        ("non-utf8", b"\xff\xfe\x00\x01not a signature")):
        (run / "attestation.sig").write_bytes(blob)
        r = sh(["aggregate.py", "--verify-signature"], repo, expect=1, env=env)
        assert "INVALID" in r.stdout, (label, r.stdout, r.stderr)


def t_sign_no_signer_fails_loudly():
    # E6-S1 AC(c): --sign with NO signer available fails loudly (non-zero, clear message), never a
    # silent skip and never a false success. "No signer" is forced deterministically: empty
    # AR_SIGNER_CMD + an empty PATH so cosign/minisign cannot be auto-detected even if installed on
    # the host. The verdict is still computed and written; only the signing step fails.
    repo, run = _pass_run_for_signing()
    empty = Path(tempfile.mkdtemp(prefix="ar-nopath-"))
    env = {**ENV, "PATH": str(empty), "AR_SIGNER_CMD": "", "AR_MINISIGN_KEY": ""}
    sh(["aggregate.py"], repo, expect=0, env=env)                        # verdict written first
    r = sh(["aggregate.py", "--sign"], repo, expect=None, env=env)
    assert r.returncode != 0, (r.returncode, r.stdout, r.stderr)          # non-zero
    assert "no signer available" in r.stderr, r.stderr                    # clear message
    assert not (run / "attestation.sig").exists(), "no sidecar on failure (no false success)"
    assert (run / "verdict.json").exists(), "verdict written by the prior aggregate; signing is standalone"


def t_sign_cosign_verify_requires_identity():
    # E6-S1 (panel security-1): cosign keyless `verify-blob` WITHOUT --certificate-identity /
    # --certificate-oidc-issuer accepts ANY valid Fulcio certificate, so _cosign_verify_argv must NOT
    # auto-select cosign unless BOTH identity and issuer are set; otherwise it returns None so verify
    # falls through to minisign / a loud "no verifier available".
    import importlib
    import aggregate
    importlib.reload(aggregate)
    orig_which = aggregate.shutil.which
    aggregate.shutil.which = lambda name: "/usr/bin/cosign" if name == "cosign" else orig_which(name)
    saved = {k: os.environ.get(k) for k in ("AR_COSIGN_IDENTITY", "AR_COSIGN_ISSUER")}
    try:
        for k in ("AR_COSIGN_IDENTITY", "AR_COSIGN_ISSUER"):
            os.environ.pop(k, None)
        assert aggregate._cosign_verify_argv() is None, "cosign selected without identity+issuer"
        os.environ["AR_COSIGN_IDENTITY"] = "ci@example.com"
        assert aggregate._cosign_verify_argv() is None, "issuer is still required"
        os.environ["AR_COSIGN_ISSUER"] = "https://token.actions.githubusercontent.com"
        argv = aggregate._cosign_verify_argv()
        assert argv and "--certificate-identity" in argv and "--certificate-oidc-issuer" in argv, argv
    finally:
        aggregate.shutil.which = orig_which
        for _k, _v in saved.items():
            os.environ.pop(_k, None) if _v is None else os.environ.__setitem__(_k, _v)


def t_sign_signer_command_failure_fails_loudly():
    # E6-S1 (panel test_quality-1): a signer whose external command RUNS but exits non-zero must fail
    # loudly (exit 3, clear message) and write NO sidecar -- never a false success. Deterministic via
    # an AR_SIGNER_CMD that runs /bin/false over the {msg}/{sig} tokens.
    repo, run = _pass_run_for_signing()
    env = {**ENV, "AR_SIGNER_CMD": "false {msg} {sig}"}
    sh(["aggregate.py"], repo, expect=0, env=env)
    r = sh(["aggregate.py", "--sign"], repo, expect=None, env=env)
    assert r.returncode == 3, (r.returncode, r.stderr)
    assert "exited" in r.stderr or "signer" in r.stderr, r.stderr
    assert not (run / "attestation.sig").exists(), "no sidecar on signer failure"


def t_sign_verify_detects_tampered_input_artifact():
    # E6-S1 (Codex): --verify-signature catches a tampered ATTESTED INPUT even when verdict.json and the
    # sidecar are untouched — it recomputes the attestation and requires it to match the recorded
    # digest. Sign a good run, mutate an attested input (gates/unit.json) -> verify fails (exit 1).
    repo, run = _pass_run_for_signing()
    env = _stub_signer_env()
    sh(["aggregate.py"], repo, expect=0, env=env)
    sh(["aggregate.py", "--sign"], repo, expect=0, env=env)
    assert "signature OK" in sh(["aggregate.py", "--verify-signature"], repo, expect=0, env=env).stdout
    gpath = run / "gates" / "unit.json"
    g = read(gpath); g["summary"] = (g.get("summary", "") + " tampered"); write(gpath, g)
    r = sh(["aggregate.py", "--verify-signature"], repo, expect=1, env=env)
    assert "INVALID" in r.stdout and "drift" in r.stdout, r.stdout


def t_sign_verify_detects_relabeled_verdict():
    # E6-S1 (Codex): the signature binds the COMPUTED VERDICT, not only its input digest. Relabel the
    # verdict in verdict.json (inputs — and thus the attestation digest — untouched) and
    # --verify-signature rejects it (exit 1): the sidecar signs canonical verdict.json.
    repo, run = _pass_run_for_signing()
    env = _stub_signer_env()
    sh(["aggregate.py"], repo, expect=0, env=env)
    sh(["aggregate.py", "--sign"], repo, expect=0, env=env)
    v = read(run / "verdict.json")
    v["verdict"] = "BLOCKED" if v["verdict"] != "BLOCKED" else "PASS"   # flip the decision only
    write(run / "verdict.json", v)
    r = sh(["aggregate.py", "--verify-signature"], repo, expect=1, env=env)
    assert "INVALID" in r.stdout, r.stdout


def t_sign_refuses_drift():
    # E6-S1 (Codex): --sign REFUSES a run whose artifacts drifted since the verdict was computed, rather
    # than silently re-attesting the changed state. Aggregate, mutate an attested input, --sign ->
    # refuse (exit 1), no sidecar written.
    repo, run = _pass_run_for_signing()
    env = _stub_signer_env()
    sh(["aggregate.py"], repo, expect=0, env=env)
    gpath = run / "gates" / "unit.json"
    g = read(gpath); g["summary"] = (g.get("summary", "") + " drift"); write(gpath, g)
    r = sh(["aggregate.py", "--sign"], repo, expect=1, env=env)
    assert "refusing to sign" in r.stderr and "drift" in r.stderr, (r.stdout, r.stderr)
    assert not (run / "attestation.sig").exists(), "no sidecar when signing is refused"


def t_sign_verify_require_current_attestation_algorithm():
    # Codex r3945556742: --sign and --verify-signature must REQUIRE the recorded attestation's algorithm
    # to be the current _ATTESTATION_ALGO before trusting the digest comparison. compute_attestation only
    # produces the current algorithm, so a digest match against a record LABELED with a legacy or
    # unrecognized/forged algorithm is not a valid check — signing/verifying it would vouch for a
    # representation this version never re-attested (the same hole check_digest closes ahead of its
    # digest-equality). Sign+verify cleanly under the current algorithm, then relabel the algorithm id to
    # an unrecognized value WITHOUT touching the (matching) digest:
    #   --sign             -> refuse (exit 1, "re-aggregate under the current algorithm"), sidecar UNCHANGED
    #   --verify-signature -> cannot-verify (exit 2), never "not verified" (exit 1 = tamper) or a false OK
    # On e51160c (no algorithm gate) the digest still matches, so --sign SIGNS the mislabeled verdict
    # (exit 0) and --verify-signature reports OK (exit 0) — so this test fails there.
    import aggregate
    repo, run = _pass_run_for_signing()
    env = _stub_signer_env()
    sh(["aggregate.py"], repo, expect=0, env=env)
    sh(["aggregate.py", "--sign"], repo, expect=0, env=env)
    sh(["aggregate.py", "--verify-signature"], repo, expect=0, env=env)          # clean baseline
    good_sig = (run / "attestation.sig").read_bytes()
    v = read(run / "verdict.json")
    assert v["attestation"]["algorithm"] == aggregate._ATTESTATION_ALGO, v["attestation"].get("algorithm")
    v["attestation"]["algorithm"] = "sha256-canonical-json-v3"                    # unrecognized future id
    write(run / "verdict.json", v)
    # sign refuses at the algorithm gate (exit 1), before any signer work, leaving the sidecar untouched
    rs = sh(["aggregate.py", "--sign"], repo, expect=1, env=env)
    assert "algorithm" in rs.stderr and "re-aggregate" in rs.stderr, (rs.returncode, rs.stderr)
    assert (run / "attestation.sig").read_bytes() == good_sig, "sidecar must be untouched on refusal"
    # verify is cannot-verify (exit 2), never 1 — the gate fires before the signature check
    rv = sh(["aggregate.py", "--verify-signature"], repo, expect=2, env=env)
    assert "CANNOT BE VERIFIED" in rv.stderr and "algorithm" in rv.stderr, (rv.returncode, rv.stderr)


def t_sign_malformed_command_template_exits_3():
    # E6-S1 (CodeRabbit): an AR_SIGNER_CMD / AR_VERIFIER_CMD with unbalanced quotes is a configuration
    # error (shlex.split raises), not a silent fallthrough — it must exit 3. Deterministic, offline.
    repo, run = _pass_run_for_signing()
    sh(["aggregate.py"], repo, expect=0, env=ENV)
    r = sh(["aggregate.py", "--sign"], repo, expect=None, env={**ENV, "AR_SIGNER_CMD": "signer 'oops"})
    assert r.returncode == 3 and "not a valid command template" in r.stderr, (r.returncode, r.stderr)
    assert not (run / "attestation.sig").exists()
    env = _stub_signer_env()
    sh(["aggregate.py", "--sign"], repo, expect=0, env=env)
    r2 = sh(["aggregate.py", "--verify-signature"], repo, expect=None,
            env={**env, "AR_VERIFIER_CMD": 'verify "oops'})
    assert r2.returncode == 3 and "not a valid command template" in r2.stderr, (r2.returncode, r2.stderr)


def t_sign_subprocess_timeout_exits_3():
    # E6-S1 (CodeRabbit/Codex): a hung signer must not wedge the gate — a bounded timeout converts to
    # the tooling-error exit (3). Forced offline with a tiny AR_SIGN_TIMEOUT and a sleeping signer.
    repo, run = _pass_run_for_signing()
    env = {**ENV, "AR_SIGN_TIMEOUT": "1",
           "AR_SIGNER_CMD": sys.executable + ' -c "import time;time.sleep(5)" {msg} {sig}'}
    sh(["aggregate.py"], repo, expect=0, env=env)
    r = sh(["aggregate.py", "--sign"], repo, expect=None, env=env)
    assert r.returncode == 3 and "timed out" in r.stderr, (r.returncode, r.stderr)
    assert not (run / "attestation.sig").exists()


def t_minisign_verify_flag_inline_vs_file():
    # E6-S1 (panel security-1): the minisign verify key is chosen by WHICH env var is set, never by
    # probing the filesystem. AR_MINISIGN_PUBKEY_FILE -> `-p <file>`; AR_MINISIGN_PUBKEY -> `-P <inline>`.
    # Regression: an inline value that happens to equal an existing filename in CWD must STILL verify
    # with `-P`, so an attacker who plants a file named like the operator's PUBLIC inline key cannot
    # swap in an attacker-chosen verification key.
    import importlib
    import aggregate
    importlib.reload(aggregate)
    _saved_pub = os.environ.get("AR_MINISIGN_PUBKEY")
    _saved_file = os.environ.get("AR_MINISIGN_PUBKEY_FILE")
    orig_which = aggregate.shutil.which
    aggregate.shutil.which = lambda name: "/usr/bin/minisign" if name == "minisign" else orig_which(name)
    tmpd = Path(tempfile.mkdtemp(prefix="ar-minipub-"))
    keyfile = tmpd / "ar.pub"
    keyfile.write_text("RWQexampleexamplekey\n")
    _cwd = os.getcwd()
    try:
        os.environ.pop("AR_MINISIGN_PUBKEY_FILE", None)
        os.environ["AR_MINISIGN_PUBKEY"] = "RWQinlinekeyvaluenofilehere123456"   # inline -> -P
        argv = aggregate._minisign_verify_argv()
        assert argv and "-P" in argv and "-p" not in argv, argv
        # regression: inline value collides with a real file in CWD -> STILL -P (attack closed)
        os.chdir(tmpd)
        collide = "RWQcollide12345"
        Path(collide).write_text("attacker key\n")
        os.environ["AR_MINISIGN_PUBKEY"] = collide
        argv = aggregate._minisign_verify_argv()
        assert argv and "-P" in argv and collide in argv and "-p" not in argv, argv
        os.chdir(_cwd)
        # explicit key FILE -> -p <file>
        os.environ.pop("AR_MINISIGN_PUBKEY", None)
        os.environ["AR_MINISIGN_PUBKEY_FILE"] = str(keyfile)
        argv = aggregate._minisign_verify_argv()
        assert argv and "-p" in argv and str(keyfile) in argv and "-P" not in argv, argv
    finally:
        os.chdir(_cwd)
        aggregate.shutil.which = orig_which
        for _var, _saved in (("AR_MINISIGN_PUBKEY", _saved_pub), ("AR_MINISIGN_PUBKEY_FILE", _saved_file)):
            os.environ.pop(_var, None) if _saved is None else os.environ.__setitem__(_var, _saved)


def t_gate_blocked_status_yields_blocked_not_fail():
    repo = _complete_sensitive_repo()
    run = latest_run(repo)
    write(run / "validation" / "idor.json", {
        "finding_ids": ["security-1"], "classification": "confirmed",
        "severity": "high", "evidence": "reproduced", "reproduced": True,
        "regression_test": "t", "resolution": {"fixed": True, "gates_rerun": ["unit"]}})
    sh(["aggregate.py"], repo, expect=0)  # baseline PASS
    r = sh(["gate.py", "record", "--name", "sast", "--status", "BLOCKED",
            "--summary", "opengrep does not support this stack"], repo)
    assert "BLOCKED" in r.stdout
    r = sh(["aggregate.py"], repo, expect=2)
    assert "gate 'sast' blocked" in r.stdout and "failed" not in r.stdout
    # BLOCKED without a summary must be refused; without exit code, non-BLOCKED refused
    sh(["gate.py", "record", "--name", "x", "--status", "BLOCKED", "--summary", ""],
       repo, expect=1)
    sh(["gate.py", "record", "--name", "y", "--summary", "no exit"], repo, expect=1)


def t_release_blocking_medium_requires_triage():
    repo = _complete_sensitive_repo()
    run = latest_run(repo)
    write(run / "validation" / "idor.json", {
        "finding_ids": ["security-1"], "classification": "confirmed",
        "severity": "high", "evidence": "reproduced", "reproduced": True,
        "regression_test": "t", "resolution": {"fixed": True, "gates_rerun": ["unit"]}})
    sh(["aggregate.py"], repo, expect=0)  # baseline PASS
    corr = read(run / "panel" / "correctness.json")
    corr["findings"].append({
        "id": "correctness-2", "title": "config drift on retry path",
        "severity": "medium", "confidence": 0.6, "file": "retry.py", "line": 7,
        "evidence": "e", "scenario": "s", "reproduction": ["r"], "fix": "f",
        "regression_test": "t", "release_blocking": True})
    write(run / "panel" / "correctness.json", corr)
    r = sh(["aggregate.py"], repo, expect=2)
    assert "release-blocking findings without triage" in r.stdout
    write(run / "validation" / "drift.json", {
        "finding_ids": ["correctness-2"], "classification": "false_positive",
        "severity": "medium", "evidence": "retry path is dev-only, flag-gated",
        "reproduced": False, "regression_test": ""})  # medium: no concurrence needed
    sh(["aggregate.py"], repo, expect=0)


def t_output_fidelity_attestation_gates_verdict():
    # P1 (external bots caught this) + the panel's own hardening (security-1/2, test_quality-1/2/3):
    # a reviewer recording states_truth=false must gate the verdict. aggregate.py BLOCKS a false
    # attestation unless it is linked (finding_id) to a finding THE SAME REVIEWER raised that is
    # RESOLVED (confirmed/false_positive/accepted_risk — not merely `unresolved`), regardless of
    # severity. The link and rendered text are untrusted and are escaped before interpolation.
    repo = _complete_sensitive_repo()
    run = latest_run(repo)
    write(run / "validation" / "idor.json", {
        "finding_ids": ["security-1"], "classification": "confirmed",
        "severity": "high", "evidence": "reproduced", "reproduced": True,
        "regression_test": "t", "resolution": {"fixed": True, "gates_rerun": ["unit"]}})
    sh(["aggregate.py"], repo, expect=0)   # baseline PASS: all attestations state truth

    def set_false(finding_id, rendered="Deleted 0 rows. Your account was removed."):
        c = read(run / "panel" / "correctness.json")   # read-modify-write preserves findings
        c["output_statements_checked"] = [{"rendered": rendered, "states_truth": False,
                                           "note": "false output", "finding_id": finding_id}]
        write(run / "panel" / "correctness.json", c)

    # (1) EMPTY finding_id (the schema-valid shape for "no link": finding_id is a required key,
    # so a real report carries "" not a missing key — test_quality-2) -> BLOCK.
    set_false("")
    assert "no finding_id" in sh(["aggregate.py"], repo, expect=2).stdout

    # (2) Linked to a finding THIS reviewer did not raise -> BLOCK. Covers a nonexistent id AND a
    # FOREIGN-but-real-and-triaged id (security-1): an unrelated triaged finding must not satisfy
    # the gate (panel finding security-2).
    for foreign in ("correctness-9", "security-1"):
        set_false(foreign)
        assert "not a finding this reviewer raised" in sh(["aggregate.py"], repo, expect=2).stdout, foreign

    # give correctness its own finding for the remaining cases
    c = read(run / "panel" / "correctness.json")
    c["findings"].append({
        "id": "correctness-7", "title": "success message on failed delete", "severity": "medium",
        "confidence": 0.9, "file": "acct.py", "line": 10, "evidence": "e", "scenario": "s",
        "reproduction": ["r"], "fix": "f", "regression_test": "t", "release_blocking": False})
    write(run / "panel" / "correctness.json", c)

    # (3) Own finding, but UNTRIAGED -> BLOCK even though only MEDIUM (severity-blind).
    set_false("correctness-7")
    r = sh(["aggregate.py"], repo, expect=2)
    assert "is untriaged" in r.stdout and "correctness-7" in r.stdout, r.stdout

    # (3b) A merely `unresolved` validation record does NOT clear it (panel finding test_quality-1).
    write(run / "validation" / "fmsg.json", {
        "finding_ids": ["correctness-7"], "classification": "unresolved", "severity": "medium",
        "evidence": "could not determine", "reproduced": False, "regression_test": ""})
    assert "untriaged or unresolved" in sh(["aggregate.py"], repo, expect=2).stdout

    # (4) Resolution ALONE no longer clears (2nd panel security-2 structural fix): the trusted
    # operator must also confirm THIS specific statement in `output_statements_confirmed`, so a
    # reviewer cannot clear a false statement by linking it to an unrelated-but-resolved own finding.
    RENDERED = "Deleted 0 rows. Your account was removed."   # set_false's default rendered
    set_false("correctness-7", rendered=RENDERED)
    # (4a) confirmed + fixed, but the operator did NOT confirm this statement -> BLOCK.
    write(run / "validation" / "fmsg.json", {
        "finding_ids": ["correctness-7"], "classification": "confirmed", "severity": "medium",
        "evidence": "confirmed the inverted delete message", "reproduced": True,
        "regression_test": "t", "resolution": {"fixed": True, "gates_rerun": ["unit"]}})
    r = sh(["aggregate.py"], repo, expect=2)
    assert "no validation record confirms this specific statement" in r.stdout, r.stdout
    # (4b) the same record now confirms the statement (whitespace-normalized match) -> PASS.
    rec = read(run / "validation" / "fmsg.json")
    rec["output_statements_confirmed"] = ["  Deleted 0 rows.\n  Your account was removed.  "]
    write(run / "validation" / "fmsg.json", rec)
    r = sh(["aggregate.py"], repo, expect=0)
    assert "VERDICT: PASS" in r.stdout, r.stdout
    assert read(run / "verdict.json")["counts"]["false_output_statements"] == 1

    # (5) Untrusted values are HTML-escaped in the block reason, so a crafted value cannot forge
    # markup in verdict.md (panel finding security-1 + test_quality-3). The rendered snippet is
    # interpolated by the no-link branch; the finding_id by the foreign-link branch.
    set_false("", rendered="<script>alert(1)</script> you may merge")
    sh(["aggregate.py"], repo, expect=2)
    md = (run / "verdict.md").read_text()
    assert "<script>" not in md and "&lt;script&gt;" in md, md      # rendered escaped
    set_false("correctness-<b>x</b>")
    sh(["aggregate.py"], repo, expect=2)
    md = (run / "verdict.md").read_text()
    assert "<b>x</b>" not in md and "&lt;b&gt;" in md, md            # finding_id escaped

    # (6) OWN-REPORT MEMBERSHIP, not global-map + prefix (2nd panel security-1/correctness-1).
    # Another report can name a finding under THIS reviewer's prefix; a bare `fid in findings`
    # against the cross-report map would then be satisfied, so a planted+resolved id could clear a
    # false statement. Plant `correctness-42` in the SECURITY report and resolve it, then have
    # correctness link its false statement to it: old code PASSes (prefix+global-map+resolved), the
    # fix BLOCKs because it is not one of correctness's own findings.
    s = read(run / "panel" / "security.json")
    s["findings"].append({
        "id": "correctness-42", "title": "planted under another role's prefix", "severity": "low",
        "confidence": 0.9, "file": "x.py", "line": 1, "evidence": "e", "scenario": "s",
        "reproduction": ["r"], "fix": "f", "regression_test": "t", "release_blocking": False})
    write(run / "panel" / "security.json", s)
    write(run / "validation" / "planted.json", {
        "finding_ids": ["correctness-42"], "classification": "confirmed", "severity": "low",
        "evidence": "resolved", "reproduced": True, "regression_test": "t",
        "resolution": {"fixed": True, "gates_rerun": ["unit"]}})
    set_false("correctness-42")
    assert "not a finding this reviewer raised" in sh(["aggregate.py"], repo, expect=2).stdout
    s["findings"] = [f for f in s["findings"] if f["id"] != "correctness-42"]
    write(run / "panel" / "security.json", s)
    (run / "validation" / "planted.json").unlink()

    # (7) A malformed (non-list) output_statements_checked must BLOCK and still WRITE a verdict,
    # never crash the aggregator (2nd panel correctness-2 — a truthy non-list raised TypeError
    # before the verdict was written; AC2 no-crash).
    c = read(run / "panel" / "correctness.json")
    c["output_statements_checked"] = 1
    write(run / "panel" / "correctness.json", c)
    r = sh(["aggregate.py"], repo, expect=2)
    assert "malformed" in r.stdout, r.stdout
    assert (run / "verdict.json").exists()
    c["output_statements_checked"] = []
    write(run / "panel" / "correctness.json", c)

    # (8) false_positive and accepted_risk are resolving classifications too — only `confirmed`
    # was exercised before (2nd panel test_quality-2). correctness-7 is medium, so false_positive
    # needs no concurrence; accepted_risk needs a matching suppression.
    set_false("correctness-7", rendered=RENDERED)
    write(run / "validation" / "fmsg.json", {
        "finding_ids": ["correctness-7"], "classification": "false_positive", "severity": "medium",
        "evidence": "on reflection the message is correct", "reproduced": False, "regression_test": "t",
        "output_statements_confirmed": [RENDERED]})
    assert "VERDICT: PASS" in sh(["aggregate.py"], repo, expect=0).stdout
    write(run / "suppressions.json", [{"finding_id": "correctness-7", "evidence": "known copy",
        "owner": "Paul", "expires": "2099-01-01"}])
    write(run / "validation" / "fmsg.json", {
        "finding_ids": ["correctness-7"], "classification": "accepted_risk", "severity": "medium",
        "evidence": "accepted", "reproduced": True, "regression_test": "t",
        "output_statements_confirmed": [RENDERED]})
    assert "VERDICT: PASS" in sh(["aggregate.py"], repo, expect=0).stdout
    (run / "suppressions.json").unlink()

    # (9) The UNRESOLVED branch also interpolates the untrusted finding_id — it must be escaped
    # too (2nd panel test_quality-3; only the no-link and foreign-link branches were checked).
    c = read(run / "panel" / "correctness.json")
    c["findings"].append({
        "id": "correctness-<b>z</b>", "title": "t", "severity": "low", "confidence": 0.5,
        "file": "x.py", "line": 1, "evidence": "e", "scenario": "s", "reproduction": ["r"],
        "fix": "f", "regression_test": "t", "release_blocking": False})
    write(run / "panel" / "correctness.json", c)
    (run / "validation" / "fmsg.json").unlink()   # leave correctness-7/<b>z</b> unresolved
    set_false("correctness-<b>z</b>")
    sh(["aggregate.py"], repo, expect=2)
    md = (run / "verdict.md").read_text()
    assert "<b>z</b>" not in md and "&lt;b&gt;z&lt;/b&gt;" in md, md

    # (10) The operator-confirmation requirement applies to EVERY resolving class, not just
    # confirmed (3rd panel test_quality-1): false_positive / accepted_risk WITHOUT
    # output_statements_confirmed must still BLOCK.
    c = read(run / "panel" / "correctness.json")
    c["findings"] = [f for f in c["findings"] if f["id"] != "correctness-<b>z</b>"]
    write(run / "panel" / "correctness.json", c)
    set_false("correctness-7", rendered=RENDERED)
    write(run / "validation" / "fmsg.json", {
        "finding_ids": ["correctness-7"], "classification": "false_positive", "severity": "medium",
        "evidence": "e", "reproduced": False, "regression_test": "t"})   # no output_statements_confirmed
    assert "no validation record confirms this specific statement" in sh(["aggregate.py"], repo, expect=2).stdout
    write(run / "suppressions.json", [{"finding_id": "correctness-7", "evidence": "k",
        "owner": "Paul", "expires": "2099-01-01"}])
    write(run / "validation" / "fmsg.json", {
        "finding_ids": ["correctness-7"], "classification": "accepted_risk", "severity": "medium",
        "evidence": "e", "reproduced": True, "regression_test": "t"})   # no output_statements_confirmed
    assert "no validation record confirms this specific statement" in sh(["aggregate.py"], repo, expect=2).stdout
    (run / "suppressions.json").unlink()

    # (11) Confirmation is EXACT (a substring of a confirmed statement must not clear it —
    # 3rd panel test_quality-3); non-string entries in output_statements_confirmed are ignored
    # but a co-listed exact string still clears (test_quality-4).
    write(run / "validation" / "fmsg.json", {
        "finding_ids": ["correctness-7"], "classification": "confirmed", "severity": "medium",
        "evidence": "e", "reproduced": True, "regression_test": "t",
        "resolution": {"fixed": True, "gates_rerun": ["unit"]},
        "output_statements_confirmed": ["Deleted 0 rows."]})   # only a PREFIX of RENDERED
    assert "no validation record confirms this specific statement" in sh(["aggregate.py"], repo, expect=2).stdout
    rec = read(run / "validation" / "fmsg.json")
    rec["output_statements_confirmed"] = [123, RENDERED]   # non-string ignored, exact string clears
    write(run / "validation" / "fmsg.json", rec)
    assert "VERDICT: PASS" in sh(["aggregate.py"], repo, expect=0).stdout


def t_gate_fail_safe_on_malformed_artifacts():
    # AC2 (no-crash) + AC1 (fail-safe) for the verdict emitter: a hand-recorded / ingest-bypassing
    # artifact with a malformed shape must BLOCK and still WRITE a verdict, never crash and never
    # fail-open (3rd panel: correctness-1 findings, correctness-2 finding_ids/confirmations,
    # correctness-3 non-string rendered coercion, correctness-4 malformed attestation items,
    # output_fidelity-1 non-list confirmations).
    def check(mutate):
        repo = _complete_sensitive_repo()
        run = latest_run(repo)
        write(run / "validation" / "idor.json", {
            "finding_ids": ["security-1"], "classification": "confirmed", "severity": "high",
            "evidence": "e", "reproduced": True, "regression_test": "t",
            "resolution": {"fixed": True, "gates_rerun": ["unit"]}})
        mutate(run)
        r = sh(["aggregate.py"], repo, expect=2)          # never exit 0, never a crash traceback
        assert (run / "verdict.json").exists(), "verdict must still be written (no crash)"
        return r.stdout

    def setf(run, **item):
        c = read(run / "panel" / "correctness.json")
        c["output_statements_checked"] = [item]
        write(run / "panel" / "correctness.json", c)

    # findings container / item malformed
    def m_findings_nonlist(run):
        c = read(run / "panel" / "correctness.json"); c["findings"] = 1
        write(run / "panel" / "correctness.json", c)
    assert "malformed" in check(m_findings_nonlist)
    def m_findings_item(run):
        c = read(run / "panel" / "correctness.json"); c["findings"] = [None]
        write(run / "panel" / "correctness.json", c)
    assert "malformed finding" in check(m_findings_item)
    # validation record malformed
    def m_finding_ids(run):
        write(run / "validation" / "bad.json", {"finding_ids": 1, "classification": "confirmed"})
    assert "finding_ids is malformed" in check(m_finding_ids)
    # attestation container / item / field malformed
    assert "malformed" in check(lambda run: setf(run, states_truth=False, rendered=1, finding_id=""))
    assert "non-boolean states_truth" in check(lambda run: setf(run, states_truth="false", rendered="x", finding_id=""))
    def m_osc_nonlist(run):
        c = read(run / "panel" / "correctness.json"); c["output_statements_checked"] = 1
        write(run / "panel" / "correctness.json", c)
    assert "output_statements_checked is malformed" in check(m_osc_nonlist)
    # non-list output_statements_confirmed on a resolving record must not crash and must not clear
    def m_conf_nonlist(run):
        c = read(run / "panel" / "correctness.json")
        c["findings"].append({"id": "correctness-9", "title": "t", "severity": "low", "confidence": 0.5,
            "file": "x.py", "line": 1, "evidence": "e", "scenario": "s", "reproduction": ["r"],
            "fix": "f", "regression_test": "t", "release_blocking": False})
        c["output_statements_checked"] = [{"states_truth": False, "rendered": "boom", "finding_id": "correctness-9"}]
        write(run / "panel" / "correctness.json", c)
        write(run / "validation" / "c9.json", {"finding_ids": ["correctness-9"], "classification": "confirmed",
            "severity": "low", "evidence": "e", "reproduced": True, "regression_test": "t",
            "resolution": {"fixed": True, "gates_rerun": ["unit"]}, "output_statements_confirmed": 1})
    assert "no validation record confirms this specific statement" in check(m_conf_nonlist)


def t_gate_fail_safe_round4():
    # 4th-panel regressions on the verdict emitter: the findings-map clobber (security-2), the
    # own_ids unhashable-id crash (security-1/correctness-1), malformed suppressions.json
    # (security-3/correctness-2), non-string finding_ids members (correctness-3), and the
    # test-coverage gaps (test_quality-1..5). Every crafted / hand-recorded artifact must BLOCK
    # with a SPECIFIC reason and still write a verdict — never crash, never fail-open
    # (test_quality-5: assert the exact reason, not merely that it blocked).
    def check(mutate):
        repo = _complete_sensitive_repo()
        run = latest_run(repo)
        write(run / "validation" / "idor.json", {
            "finding_ids": ["security-1"], "classification": "confirmed", "severity": "high",
            "evidence": "e", "reproduced": True, "regression_test": "t",
            "resolution": {"fixed": True, "gates_rerun": ["unit"]}})
        mutate(run)
        r = sh(["aggregate.py"], repo, expect=2)          # never exit 0, never a crash traceback
        assert (run / "verdict.json").exists(), "verdict must still be written (no crash)"
        return r.stdout

    def corr_finding(fid, sev="low"):
        return {"id": fid, "title": "t", "severity": sev, "confidence": 0.5, "file": "x.py",
                "line": 1, "evidence": "e", "scenario": "s", "reproduction": ["r"], "fix": "f",
                "regression_test": "t", "release_blocking": False}

    # own_ids: an unhashable id ([]) on a dict finding + a false attestation previously raised
    # TypeError before verdict.json; must BLOCK on the malformed finding and still write a verdict.
    def m_unhashable_id(run):
        c = read(run / "panel" / "correctness.json")
        c["findings"] = [{"id": [], "severity": "high"}]
        c["output_statements_checked"] = [{"states_truth": False, "rendered": "x",
                                           "finding_id": "correctness-1"}]
        write(run / "panel" / "correctness.json", c)
    assert "malformed finding (needs a string id" in check(m_unhashable_id)  # exact reason (tq-2)

    # findings-map clobber: a second report reusing an existing id (security-1) must BLOCK, not
    # silently overwrite and hide the earlier finding from the high/critical coverage check.
    def m_duplicate_id(run):
        c = read(run / "panel" / "correctness.json")
        c["findings"].append(corr_finding("security-1"))
        write(run / "panel" / "correctness.json", c)
    assert "duplicate finding id" in check(m_duplicate_id)

    # test_quality-1: non-list findings WITH a false attestation — the container BLOCK and the
    # empty-own_ids attestation BLOCK both fire, no crash.
    def m_nonlist_findings_false(run):
        c = read(run / "panel" / "correctness.json")
        c["findings"] = 1
        c["output_statements_checked"] = [{"states_truth": False, "rendered": "boom",
                                           "finding_id": "correctness-1"}]
        write(run / "panel" / "correctness.json", c)
    out = check(m_nonlist_findings_false)   # specific reasons, not a bare "malformed" (tq-3)
    assert "findings is malformed (not a list)" in out and "not a finding this reviewer raised" in out, out

    # test_quality-2: a validation record that is not a dict (a JSON list) must BLOCK, not crash.
    def m_nondict_record(run):
        (run / "validation" / "bad.json").write_text("[1, 2]")
    assert "malformed record (not an object)" in check(m_nondict_record)

    # test_quality-3: output_statements_confirmed as a list of ONLY non-strings confirms nothing,
    # so a false statement linked to the resolved finding still BLOCKs.
    def m_conf_all_nonstring(run):
        c = read(run / "panel" / "correctness.json")
        c["findings"].append(corr_finding("correctness-9"))
        c["output_statements_checked"] = [{"states_truth": False, "rendered": "boom",
                                           "finding_id": "correctness-9"}]
        write(run / "panel" / "correctness.json", c)
        write(run / "validation" / "c9.json", {"finding_ids": ["correctness-9"],
            "classification": "confirmed", "severity": "low", "evidence": "e", "reproduced": True,
            "regression_test": "t", "resolution": {"fixed": True, "gates_rerun": ["unit"]},
            "output_statements_confirmed": [123, 456]})
    assert "no validation record confirms this specific statement" in check(m_conf_all_nonstring)

    # test_quality-4: a finding with a valid id but an invalid severity must BLOCK.
    def m_bad_severity(run):
        c = read(run / "panel" / "correctness.json")
        c["findings"] = [dict(corr_finding("correctness-1"), severity="bogus")]
        write(run / "panel" / "correctness.json", c)
    assert "malformed finding" in check(m_bad_severity)

    # correctness-3: a non-string finding_ids member on a validation record must BLOCK (uniform
    # malformed -> BLOCK, no silent drop).
    def m_finding_ids_member(run):
        write(run / "validation" / "bad2.json", {"finding_ids": ["security-1", 123],
            "classification": "confirmed", "resolution": {"fixed": True, "gates_rerun": ["unit"]}})
    assert "non-string member" in check(m_finding_ids_member)

    # security-3/correctness-2: malformed suppressions.json (non-list, and a non-dict entry) must
    # BLOCK, not crash.
    assert "is malformed (not a list)" in check(lambda run: (run / "suppressions.json").write_text("{}"))
    assert "malformed entry (not an object)" in check(lambda run: (run / "suppressions.json").write_text("[null]"))
    # a non-dict, non-null entry (a bare string) must BLOCK the same way.
    assert "malformed entry (not an object)" in check(
        lambda run: write(run / "suppressions.json", ["oops"]))

    # 5th-panel security-1/correctness-1: a suppression entry whose finding_id is UNHASHABLE ([]) is
    # used as a dict key and previously crashed before verdict.json. Must BLOCK, not crash.
    assert "non-string finding_id" in check(
        lambda run: write(run / "suppressions.json", [{"finding_id": [], "evidence": "x"}]))

    # 5th-panel test_quality-1: a WITHIN-report duplicate id (same id twice in ONE report) must
    # BLOCK too, not only cross-report duplicates.
    def m_dup_within(run):
        c = read(run / "panel" / "correctness.json")
        c["findings"] = [corr_finding("correctness-1"), corr_finding("correctness-1", "high")]
        write(run / "panel" / "correctness.json", c)
    assert "duplicate finding id" in check(m_dup_within)

    # 5th-panel test_quality-4: the duplicate-id guard must protect high/critical COVERAGE. A low
    # finding reusing a real high finding's id (security-1, triaged by idor.json) must not hide it
    # and reach PASS — the run must still BLOCK (check() asserts exit 2), and the high finding must
    # remain counted as high/critical rather than silently downgraded to the low duplicate.
    def m_dup_hides_high(run):
        c = read(run / "panel" / "correctness.json")
        c["findings"].append(corr_finding("security-1", "low"))
        write(run / "panel" / "correctness.json", c)
        return run
    repo = _complete_sensitive_repo(); run = latest_run(repo)
    write(run / "validation" / "idor.json", {
        "finding_ids": ["security-1"], "classification": "confirmed", "severity": "high",
        "evidence": "e", "reproduced": True, "regression_test": "t",
        "resolution": {"fixed": True, "gates_rerun": ["unit"]}})
    m_dup_hides_high(run)
    r = sh(["aggregate.py"], repo, expect=2)
    assert "duplicate finding id" in r.stdout, r.stdout
    v = read(run / "verdict.json")
    assert v["counts"]["findings_high_critical"] >= 1, v["counts"]  # high not hidden/downgraded


def t_http_json_scheme_allowlist():
    # panel.http_json must refuse any non-HTTP(S) URL before urlopen, so a misconfigured or
    # untrusted AR_BASE_URL cannot be steered to file:// (local-file read) or another scheme.
    import panel
    for bad in ("file:///etc/passwd", "ftp://example.com/x", "gopher://example.com/x"):
        try:
            panel.http_json(bad, timeout=1)
            raise AssertionError(f"http_json should have refused {bad}")
        except SystemExit as e:
            assert e.code == 2, (bad, e.code)
    # Positive path (6th-panel test_quality-3) + case/whitespace (test_quality-1 / correctness-2):
    # urlparse lower-cases the scheme and strips surrounding whitespace, so "HTTP://" and "  http://"
    # resolve to http and pass (still http — not a bypass). 7th-panel test_quality-2: use a port that
    # is *guaranteed closed* (bind :0, read the assigned port, close it) instead of the discard port 9
    # which may actually be listening on some hosts and mask a removed scheme check. Each accepted URL
    # must therefore raise a real connection error (URLError), NOT the exit-2 scheme refusal.
    # 8th-panel correctness-1: do NOT assert a specific exception type here. A whitespace-padded URL
    # reaches the connection stage on this build as a URLError, but stricter urllib builds can raise
    # http.client.InvalidURL (NOT a URLError subclass) instead. What this positive path must prove is
    # only that the scheme check ACCEPTS these (no exit-2 refusal) and that they are not a silent pass
    # — the guaranteed-closed port ensures any accepted URL fails at connect rather than returning.
    import socket
    _s = socket.socket(); _s.bind(("127.0.0.1", 0)); _closed = _s.getsockname()[1]; _s.close()
    for good in (f"http://127.0.0.1:{_closed}/x", f"https://127.0.0.1:{_closed}/x",
                 f"HTTP://127.0.0.1:{_closed}/x", f"  https://127.0.0.1:{_closed}/x  "):
        try:
            panel.http_json(good, timeout=1)
        except SystemExit:
            raise AssertionError(f"{good!r} normalizes to http(s) and must pass the allowlist")
        except Exception:
            continue  # scheme accepted; connection to the closed port failed (URLError / InvalidURL)
        raise AssertionError(f"{good!r} should reach the connection stage and fail there")
    # a non-http(s) scheme is still refused regardless of case or padding
    for bad in ("FILE:///etc/passwd", "  ftp://x/y"):
        try:
            panel.http_json(bad, timeout=1)
            raise AssertionError(f"{bad!r} must be refused")
        except SystemExit as e:
            assert e.code == 2, (bad, e.code)


def t_http_json_refuses_all_redirects():
    # 7th-panel security-1/2, correctness-1, test_quality-1/4/5 + 8th-panel test_quality-1/2/4/5:
    # drive the REAL production fetch path (panel.http_json -> _HTTPS_OPENER.open) through a loopback
    # http.server. Proves: (a) the opener performs a real http fetch and returns the parsed body
    # (default HTTP handler present); (b) EVERY redirect is refused with the refusal HTTPError, across
    # methods (GET+302, POST+307) and Location kinds (relative, protocol-relative, cross-host absolute,
    # non-http(s)); (c) the Bearer key IS sent on the first hop but is NEVER forwarded to a redirect
    # target. Fails if a regression reverted http_json to urllib.request.urlopen, dropped _NoRedirect
    # from the opener, or re-allowed any redirect.
    import panel, threading, http.server, urllib.error

    sink_auth = []     # Authorization seen at a redirect TARGET => a key leak (must stay empty)
    initial_auth = []  # Authorization seen on the FIRST hop => proves the key was actually sent

    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass  # keep test output clean

        def _json(self, body):
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(body)

        def _redirect(self, code, location):
            initial_auth.append(self.headers.get("Authorization"))  # key present on the first hop
            self.send_response(code)
            self.send_header("Location", location)
            self.end_headers()

        def _route(self):
            host = f"127.0.0.1:{self.server.server_address[1]}"
            p = self.path
            if p == "/ok":            self._json(b'{"ok": true}')                 # positive path
            elif p == "/sink":        (sink_auth.append(self.headers.get("Authorization")),
                                       self._json(b'{"leaked": true}'))           # leak target
            elif p == "/redirect":    self._redirect(302, "/sink")               # same-host relative
            elif p == "/protorel":    self._redirect(302, f"//{host}/sink")      # protocol-relative
            elif p == "/crosshost":   self._redirect(302, "http://127.0.0.2:9/sink")  # cross-host absolute
            elif p == "/ftpredir":    self._redirect(302, "ftp://127.0.0.1/x")   # non-http(s) target
            elif p == "/postredir":   self._redirect(307, "/sink")               # 307 preserves POST
            else:                     (self.send_response(404), self.end_headers())

        do_GET = _route
        do_POST = _route

    srv = http.server.HTTPServer(("127.0.0.1", 0), Handler)  # loopback only; ephemeral port
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{port}"
    try:
        # positive path — the opener really routes http and returns the parsed body (default handlers)
        assert panel.http_json(base + "/ok", timeout=5) == {"ok": True}
        # every GET redirect is refused with the REFUSAL HTTPError (not some other 30x/4xx), across
        # Location kinds: relative, protocol-relative, cross-host absolute, and non-http(s).
        for path in ("/redirect", "/protorel", "/crosshost", "/ftpredir"):
            try:
                panel.http_json(base + path, key="CANARY-SECRET", timeout=5)
                raise AssertionError(f"{path}: a redirect must be refused, not followed")
            except urllib.error.HTTPError as e:
                assert "refus" in str(e.reason).lower(), (path, e.reason)
        # a POST that 307-redirects (method + body preserved by urllib) must also be refused
        try:
            panel.http_json(base + "/postredir", payload={"x": 1}, key="CANARY-SECRET", timeout=5)
            raise AssertionError("/postredir: a POST redirect must be refused")
        except urllib.error.HTTPError as e:
            assert "refus" in str(e.reason).lower(), e.reason
        # the key WAS sent on the first hop (so a leak would be observable) but NEVER forwarded onward
        assert initial_auth and all(a == "Bearer CANARY-SECRET" for a in initial_auth), initial_auth
        assert sink_auth == [], f"Bearer key leaked to a redirect target: {sink_auth}"
    finally:
        srv.shutdown(); srv.server_close()


def t_gitleaks_baseline_allowlist_anchored():
    # 6th-panel correctness-3 / test_quality-5 + 7th-panel test_quality-3: EVERY gitleaks path
    # allowlist entry must be anchored to the repository root (^...$) so a nested file named
    # `.secrets.baseline` is NOT silently exempted. The prior test only inspected the FIRST
    # triple-quoted pattern (pats[0]); check the WHOLE list. Stdlib-only on purpose — the CI matrix
    # includes Python 3.9, where tomllib (3.11+) is unavailable, so parse the triple-quoted path
    # patterns directly rather than importing tomllib.
    cfg = (SKILL / ".gitleaks.toml").read_text()
    paths = re.findall(r"'''(.*?)'''", cfg)  # all triple-quoted allowlist path patterns
    assert paths, "no allowlist path patterns found in .gitleaks.toml"
    for pat in paths:
        assert pat.startswith("^") and pat.endswith("$"), \
            f"every allowlist path regex must anchor to repo root (^...$), got {pat!r}"
    compiled = [re.compile(p) for p in paths]
    # the repo-root baseline stays exempted; a nested lookalike must NOT be exempted by ANY pattern
    assert any(rx.search(".secrets.baseline") for rx in compiled), \
        "root .secrets.baseline should match the allowlist"
    assert not any(rx.search("evil/.secrets.baseline") for rx in compiled), \
        "nested .secrets.baseline must NOT be exempted by any allowlist path"


def t_rebuttal_policy_matrix():
    # contention (default): SENSITIVE + findings, no rebuttal -> BLOCKED
    repo = fresh_repo()
    sh(["panel.py", "init", "--risk", "SENSITIVE", "--dev-providers", "anthropic"], repo)
    sh(["panel.py", "assign"], repo)
    sh(["panel.py", "run", "--context-file", "context.md"], repo)
    sh(["gate.py", "plan", "--require", "build,unit,secrets,deps,sast",
        "--waive", "mutation", "--authorized-by", "Paul"], repo)
    for g in ["build", "unit", "secrets", "deps", "sast"]:
        sh(["gate.py", "record", "--name", g, "--exit-code", "0", "--summary", "ok"], repo)
    run = latest_run(repo)
    write(run / "validation" / "idor.json", {
        "finding_ids": ["security-1"], "classification": "confirmed",
        "severity": "high", "evidence": "reproduced", "reproduced": True,
        "regression_test": "t", "resolution": {"fixed": True, "gates_rerun": ["unit"]}})
    r = sh(["aggregate.py"], repo, expect=2)
    assert "rebuttal round required" in r.stdout
    # policy critical: same setup passes without rebuttal at SENSITIVE
    repo2 = fresh_repo()
    sh(["panel.py", "init", "--risk", "SENSITIVE", "--dev-providers", "anthropic",
        "--rebuttal-policy", "critical"], repo2)
    sh(["panel.py", "assign"], repo2)
    sh(["panel.py", "run", "--context-file", "context.md"], repo2)
    sh(["gate.py", "plan", "--require", "build,unit,secrets,deps,sast",
        "--waive", "mutation", "--authorized-by", "Paul"], repo2)
    for g in ["build", "unit", "secrets", "deps", "sast"]:
        sh(["gate.py", "record", "--name", g, "--exit-code", "0", "--summary", "ok"], repo2)
    run2 = latest_run(repo2)
    write(run2 / "validation" / "idor.json", {
        "finding_ids": ["security-1"], "classification": "confirmed",
        "severity": "high", "evidence": "reproduced", "reproduced": True,
        "regression_test": "t", "resolution": {"fixed": True, "gates_rerun": ["unit"]}})
    r = sh(["aggregate.py"], repo2, expect=0)
    assert "rebuttal not required" in r.stdout
    # policy any: NORMAL + findings requires rebuttal
    repo3 = fresh_repo()
    sh(["panel.py", "init", "--risk", "NORMAL", "--dev-providers", "anthropic",
        "--rebuttal-policy", "any"], repo3)
    sh(["panel.py", "assign"], repo3)
    sh(["panel.py", "run", "--context-file", "context.md"], repo3)
    sh(["gate.py", "plan", "--require", "build,unit,secrets,deps,sast"], repo3)
    for g in ["build", "unit", "secrets", "deps", "sast"]:
        sh(["gate.py", "record", "--name", g, "--exit-code", "0", "--summary", "ok"], repo3)
    run3 = latest_run(repo3)
    write(run3 / "validation" / "idor.json", {
        "finding_ids": ["security-1"], "classification": "confirmed",
        "severity": "high", "evidence": "reproduced", "reproduced": True,
        "regression_test": "t", "resolution": {"fixed": True, "gates_rerun": ["unit"]}})
    r = sh(["aggregate.py"], repo3, expect=2)
    assert "rebuttal round required" in r.stdout
    sh(["panel.py", "rebuttal"], repo3)
    sh(["aggregate.py"], repo3, expect=0)


def t_verdict_md_and_meta_telemetry():
    repo = _complete_sensitive_repo()
    run = latest_run(repo)
    write(run / "validation" / "idor.json", {
        "finding_ids": ["security-1"], "classification": "confirmed",
        "severity": "high", "evidence": "reproduced", "reproduced": True,
        "regression_test": "t", "resolution": {"fixed": True, "gates_rerun": ["unit"]}})
    sh(["aggregate.py"], repo, expect=0)
    md = (run / "verdict.md").read_text()
    assert "# Release verdict: PASS" in md and "Counts:" in md
    for role in read(run / "panel" / "plan.json")["roles"]:
        meta = read(run / "panel" / "meta" / f"{role}.json")
        assert isinstance(meta["latency_ms"], int) and "cost" in meta, meta


def t_init_never_reuses_run_dir():
    repo = fresh_repo()
    sh(["panel.py", "init", "--risk", "NORMAL", "--dev-providers", "anthropic"], repo)
    sh(["panel.py", "init", "--risk", "NORMAL", "--dev-providers", "anthropic"], repo)
    runs = sorted((repo / ".adversarial-review").glob("run-*"))
    assert len(runs) == 2 and runs[0] != runs[1], runs


def t_critical_requires_rebuttal():
    repo = fresh_repo()
    sh(["panel.py", "init", "--risk", "CRITICAL", "--dev-providers", "anthropic"], repo)
    sh(["panel.py", "assign"], repo)
    sh(["panel.py", "run", "--context-file", "context.md"], repo)
    sh(["gate.py", "plan", "--require", "build,unit,secrets,deps,sast",
        "--waive", "mutation", "--authorized-by", "Paul"], repo)
    for g in ["build", "unit", "secrets", "deps", "sast"]:
        sh(["gate.py", "record", "--name", g, "--exit-code", "0", "--summary", "ok"], repo)
    run = latest_run(repo)
    write(run / "validation" / "idor.json", {
        "finding_ids": ["security-1"], "classification": "confirmed",
        "severity": "high", "evidence": "reproduced", "reproduced": True,
        "regression_test": "t", "resolution": {"fixed": True, "gates_rerun": ["unit"]}})
    r = sh(["aggregate.py"], repo, expect=2)
    assert "rebuttal" in r.stdout
    sh(["panel.py", "rebuttal"], repo)
    for role in read(run / "panel" / "plan.json")["roles"]:
        p = run / "rebuttal" / f"{role}.json"
        assert p.exists(), f"missing rebuttal for {role}"
    sh(["aggregate.py"], repo, expect=0)


def t_prepare_ingest_mcp_path():
    import urllib.request
    mock_router.reset()
    mock_router.STATE["reviewer_cost"] = 0.03   # router reports cost only under usage.cost
    try:
        repo = fresh_repo()
        sh(["panel.py", "init", "--risk", "NORMAL", "--dev-providers", "anthropic"], repo)
        sh(["panel.py", "assign"], repo)
        sh(["panel.py", "prepare", "--context-file", "context.md"], repo)
        run = latest_run(repo)
        plan = read(run / "panel" / "plan.json")
        for role in plan["roles"]:
            body = read(run / "panel" / "requests" / f"{role}.json")
            # nosemgrep: python.lang.security.audit.insecure-transport.urllib.insecure-request-object.insecure-request-object
            req = urllib.request.Request(
                f"http://127.0.0.1:{PORT}/v1/chat/completions",   # loopback test mock; https would break it
                data=json.dumps(body).encode(),
                headers={"Content-Type": "application/json"})
            # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected
            resp = urllib.request.urlopen(req, timeout=10).read().decode()  # hardcoded 127.0.0.1 mock
            rf = run / f"mcp-response-{role}.json"
            rf.write_text(resp)
            sh(["panel.py", "ingest", "--role", role, "--response-file", str(rf)], repo)
            assert (run / "panel" / f"{role}.json").exists()
        # ingest records cost only under usage; aggregate must read the nested usage.cost so an
        # MCP-transport run isn't metered as $0 (E4-S2). 4 NORMAL reviewers * $0.03 = $0.12.
        sh(["aggregate.py"], repo, expect=None)
        cov = read(run / "verdict.json")["coverage"]
        assert abs(cov["cost_usd"] - 0.12) < 1e-6, cov["cost_usd"]
    finally:
        mock_router.reset()


def t_prepared_requests_inline_schema():
    # Issue #2: MCP transports (e.g. Composio) drop response_format, so the schema
    # must live in the system message for all three request kinds: report (prepare;
    # run_one_role flows through the same build_request), rebuttal, and concurrence.
    repo = fresh_repo()
    sh(["panel.py", "init", "--risk", "NORMAL", "--dev-providers", "anthropic"], repo)
    sh(["panel.py", "assign"], repo)
    sh(["panel.py", "prepare", "--context-file", "context.md"], repo)
    run = latest_run(repo)
    plan = read(run / "panel" / "plan.json")
    for role, info in plan["roles"].items():
        body = read(run / "panel" / "requests" / f"{role}.json")
        sysmsg = body["messages"][0]
        assert sysmsg["role"] == "system", f"{role}: first message not system"
        for marker in ("REQUIRED RESPONSE SCHEMA", '"top_residual_risks"',
                       '"injection_suspected"', '"minItems":1'):
            assert marker in sysmsg["content"], f"{role}: schema marker {marker!r} missing"
        if info["structured_outputs"]:
            assert body["response_format"]["json_schema"]["strict"] is True, \
                f"{role}: response_format must stay alongside the inlined schema"
    # rebuttal kind (panel finding test_quality-1): synthesize one high finding,
    # then check the prepared rebuttal requests carry the REBUTTAL_SCHEMA.
    roles = list(plan["roles"])
    write(run / "panel" / f"{roles[0]}.json", {
        "role": roles[0], "model_id": "m", "findings": [{
            "id": f"{roles[0]}-1", "title": "t", "severity": "high", "file": "f",
            "line": 1, "evidence": "e", "scenario": "s"}]})
    sh(["panel.py", "rebuttal", "--prepare"], repo)
    for role in roles[1:]:
        reb = read(run / "rebuttal" / "requests" / f"{role}.json")
        for marker in ("REQUIRED RESPONSE SCHEMA", '"position"', '"refute"'):
            assert marker in reb["messages"][0]["content"], \
                f"rebuttal {role}: schema marker {marker!r} missing"
    # concurrence kind — multi-marker, same rigor as above (finding test_quality-3)
    (repo / "dismissal.md").write_text("finding X evidence Y")
    sh(["panel.py", "concur", "--prompt-file", "dismissal.md", "--prepare"], repo)
    concur = read(run / "validation" / "concur-request.json")
    for marker in ("REQUIRED RESPONSE SCHEMA", '"agrees_false_positive"', '"reasoning"'):
        assert marker in concur["messages"][0]["content"], \
            f"concurrence: schema marker {marker!r} missing"


def t_build_request_unit_edges():
    # Direct unit checks on build_request (panel findings correctness-1 and
    # test_quality-2): None/missing system content must not crash or misplace the
    # schema, and the caller's messages list must never be mutated in place.
    sys.path.insert(0, str(SKILL / "scripts"))
    import panel  # noqa: E402
    # system message with no content key at all
    body, _ = panel.build_request("prov/model", [{"role": "system"}],
                                  panel.CONCUR_SCHEMA, "concurrence", True, "NORMAL")
    assert body["messages"][0]["role"] == "system"
    assert "REQUIRED RESPONSE SCHEMA" in body["messages"][0]["content"]
    # immutability: original list and dicts untouched
    original = [{"role": "system", "content": "S"}, {"role": "user", "content": "U"}]
    snapshot = json.loads(json.dumps(original))
    body, _ = panel.build_request("prov/model", original, panel.CONCUR_SCHEMA,
                                  "concurrence", True, "NORMAL")
    assert original == snapshot, "build_request mutated the caller's messages"
    assert body["messages"][0]["content"].startswith("S")
    assert body["messages"][1] == {"role": "user", "content": "U"}
    # no leading system message: one is prepended, caller messages preserved in order
    body, _ = panel.build_request("prov/model", [{"role": "user", "content": "U"}],
                                  panel.CONCUR_SCHEMA, "concurrence", True, "NORMAL")
    assert body["messages"][0]["role"] == "system"
    assert "REQUIRED RESPONSE SCHEMA" in body["messages"][0]["content"]
    assert body["messages"][1] == {"role": "user", "content": "U"}


def t_keyless_run_blocks_with_guidance():
    repo = fresh_repo()
    sh(["panel.py", "init", "--risk", "NORMAL", "--dev-providers", "anthropic"], repo)
    sh(["panel.py", "assign"], repo)
    env = {k: v for k, v in ENV.items()
           if k not in ("AR_API_KEY", "OPENROUTER_API_KEY")}
    r = sh(["panel.py", "run", "--context-file", "context.md"], repo, expect=2, env=env)
    assert "prepare" in r.stderr


# Mirrors the issue #6 example: trailing comments, flow lists, a nested per-tier
# map (with both flow and block list values), and an empty flow map.
POLICY_YML = """\
risk: SENSITIVE            # default tier for this repo
dev_providers: [anthropic] # always-excluded families
rebuttal_policy: contention
required_gates:
  NORMAL: [build, unit, secrets, deps, sast]
  SENSITIVE:
    - build
    - unit
pins: {}                   # role: provider/model-slug
"""


def t_policy_file_provides_defaults():
    repo = fresh_repo()
    (repo / ".adversarial-review.yml").write_text(POLICY_YML)
    sh(["panel.py", "init"], repo)  # zero flags: everything from the policy
    meta = read(latest_run(repo) / "run.json")
    assert meta["risk"] == "SENSITIVE", meta["risk"]
    assert meta["dev_providers"] == ["anthropic"], meta["dev_providers"]
    assert meta["rebuttal_policy"] == "contention"
    assert meta["sources"] == {"risk": "policy", "dev_providers": "policy",
                               "rebuttal_policy": "policy"}, meta["sources"]
    want_sha = hashlib.sha256(POLICY_YML.encode()).hexdigest()
    assert meta["policy"] == {"file": ".adversarial-review.yml",
                              "sha256": want_sha}, meta["policy"]
    snap = read(latest_run(repo) / "policy.snapshot.json")
    assert snap["text"] == POLICY_YML and snap["sha256"] == want_sha
    sh(["gate.py", "plan"], repo)  # no --require: tier list from the policy
    req = read(latest_run(repo) / "gates" / "_required.json")
    assert req["requested_source"] == "policy", req
    assert req["requested"] == ["build", "unit"], req["requested"]
    assert "mutation" in req["required"], "SENSITIVE floor must still union in"


def t_policy_precedence_cli_env_file():
    repo = fresh_repo()
    (repo / ".adversarial-review.yml").write_text(POLICY_YML)
    sh(["panel.py", "init"], repo, env={**ENV, "AR_RISK": "NORMAL"})
    meta = read(latest_run(repo) / "run.json")
    assert meta["risk"] == "NORMAL" and meta["sources"]["risk"] == "env", meta
    sh(["panel.py", "init", "--risk", "CRITICAL"], repo,
       env={**ENV, "AR_RISK": "NORMAL"})
    meta = read(latest_run(repo) / "run.json")
    assert meta["risk"] == "CRITICAL" and meta["sources"]["risk"] == "cli", meta
    sh(["panel.py", "init"], repo, env={**ENV, "AR_DEV_PROVIDERS": "openai"})
    meta = read(latest_run(repo) / "run.json")
    assert meta["dev_providers"] == ["openai"], meta
    assert meta["sources"]["dev_providers"] == "env", meta["sources"]
    assert meta["sources"]["risk"] == "policy", meta["sources"]
    sh(["gate.py", "plan"], repo, env={**ENV, "AR_REQUIRE": "build,unit,fuzz"})
    req = read(latest_run(repo) / "gates" / "_required.json")
    assert req["requested_source"] == "env" and "fuzz" in req["required"], req


def t_policy_malformed_is_loud():
    # Malformed policy dies even when CLI flags would have sufficed — a policy
    # is never silently ignored (acceptance criterion in issue #6).
    full_flags = ["panel.py", "init", "--risk", "NORMAL",
                  "--dev-providers", "anthropic"]
    cases = [
        ("risque: NORMAL\n", "unknown key"),
        ("risk: EXTREME\n", "invalid risk"),
        ("dev_providers:\n\t- anthropic\n", "tab"),
        ("pins:\n  a:\n    b: c\n", "nesting"),
        ("risk: NORMAL\nrisk: SENSITIVE\n", "duplicate"),
        ("dev_providers: [anthropic\n", "unterminated"),
        ("risk: NORMAL\ndev_providers: []\n", "non-empty"),
        ("", "empty"),
    ]
    for text, needle in cases:
        repo = fresh_repo()
        (repo / ".adversarial-review.yml").write_text(text)
        r = sh(full_flags, repo, expect=1)
        assert needle in r.stderr, f"{text!r}: expected {needle!r} in {r.stderr!r}"
    repo = fresh_repo()
    (repo / ".adversarial-review.json").write_text("{nope")
    r = sh(full_flags, repo, expect=1)
    assert "invalid JSON" in r.stderr, r.stderr
    repo = fresh_repo()
    (repo / ".adversarial-review.yml").write_text(POLICY_YML)
    (repo / ".adversarial-review.json").write_text("{}")
    r = sh(full_flags, repo, expect=1)
    assert "exactly one" in r.stderr, r.stderr
    # gate.py plan hits the same wall: corrupting the policy after init blocks
    # planning even with an explicit --require.
    repo = fresh_repo()
    (repo / ".adversarial-review.yml").write_text(POLICY_YML)
    sh(["panel.py", "init"], repo)
    (repo / ".adversarial-review.yml").write_text("risk: EXTREME\n")
    r = sh(["gate.py", "plan", "--require", "build"], repo, expect=1)
    assert "invalid risk" in r.stderr, r.stderr


def t_policy_missing_is_identical():
    # No policy file: nothing becomes optional, nothing changes shape.
    repo = fresh_repo()
    sh(["panel.py", "init"], repo, expect=1)
    sh(["gate.py", "plan"], repo, expect=1)
    sh(["panel.py", "init", "--risk", "NORMAL",
        "--dev-providers", "anthropic"], repo)
    meta = read(latest_run(repo) / "run.json")
    assert meta["sources"] == {"risk": "cli", "dev_providers": "cli",
                               "rebuttal_policy": "default"}, meta["sources"]
    assert meta["policy"] is None
    assert not (latest_run(repo) / "policy.snapshot.json").exists()
    r = sh(["gate.py", "plan"], repo, expect=1)
    assert "unresolved" in r.stderr, r.stderr
    sh(["gate.py", "plan", "--require", "build,unit"], repo)
    req = read(latest_run(repo) / "gates" / "_required.json")
    assert req["requested_source"] == "cli", req


def t_policy_mutation_budget():
    # A valid scoped-mutation budget parses, is captured in the attested policy snapshot
    # (so a bounded run's coverage reduction is on the record), and structures correctly.
    good = ("risk: SENSITIVE\ndev_providers: [anthropic]\n"
            "mutation:\n"
            "  scope: changed\n"
            "  threshold: 60\n"
            "  max_mutants: 500\n"
            "  sample_pct: 100\n"
            "  concurrency: 4\n"
            "  timeout_s: 60\n"
            "  exclude_files: [generated/pb2.py]\n"
            "  exclude_tests: [tests/test_snapshot.py]\n")
    repo = fresh_repo()
    (repo / ".adversarial-review.yml").write_text(good)
    sh(["panel.py", "init"], repo)  # parses clean with zero flags
    snap = read(latest_run(repo) / "policy.snapshot.json")
    assert "mutation:" in snap["text"] and "exclude_tests" in snap["text"], snap
    import _common
    pol = _common.load_policy(str(repo))["data"]["mutation"]
    assert pol["scope"] == "changed", pol
    assert pol["exclude_tests"] == ["tests/test_snapshot.py"], pol
    # Malformed budgets die loudly even though risk/dev_providers are valid on the CLI —
    # a policy is never silently ignored.
    full = ["panel.py", "init", "--risk", "NORMAL", "--dev-providers", "anthropic"]
    bad = [
        ("mutation:\n  scope: sometimes\n", "mutation.scope"),
        ("mutation:\n  max_mutants: 0\n", "positive integer"),
        ("mutation:\n  max_mutants: 3.5\n", "positive integer"),
        ("mutation:\n  max_mutants: 9007199254740992.5\n", "positive integer"),  # >=2**53 rounds to int
        ("mutation:\n  max_mutants: inf\n", "positive integer"),   # non-finite must die, not crash
        ("mutation:\n  concurrency: nan\n", "positive integer"),   # int(nan) would raise — regression
        ("mutation:\n  sample_pct: inf\n", "[0, 100]"),
        ("mutation:\n  sample_pct: 150\n", "[0, 100]"),
        ("mutation:\n  threshold: high\n", "[0, 100]"),
        ("mutation:\n  budget: 10\n", "unknown key"),
        ("mutation: 10\n", "mapping"),
        ("mutation:\n  exclude_files: notalist\n", "list of non-empty"),
    ]
    for text, needle in bad:
        repo = fresh_repo()
        (repo / ".adversarial-review.yml").write_text(text)
        r = sh(full, repo, expect=1)
        assert needle in r.stderr, f"{text!r}: expected {needle!r} in {r.stderr!r}"
    # JSON policy variant (.adversarial-review.json): numbers/bools arrive as native
    # types, exercising a different _policy_number path than the YAML string subset.
    good_json = ('{"risk":"NORMAL","dev_providers":["anthropic"],'
                 '"mutation":{"scope":"changed","max_mutants":500,"sample_pct":99.5,'
                 '"exclude_files":["gen/pb2.py"]}}')
    repo = fresh_repo()
    (repo / ".adversarial-review.json").write_text(good_json)
    sh(["panel.py", "init"], repo)  # native int/float budget parses clean
    mut = _common.load_policy(str(repo))["data"]["mutation"]
    assert mut["max_mutants"] == 500 and mut["sample_pct"] == 99.5, mut
    bad_json = [
        ('{"mutation":{"max_mutants":true}}', "positive integer"),   # native bool rejected
        ('{"mutation":{"max_mutants":3.5}}', "positive integer"),    # native non-integral float
        ('{"mutation":{"max_mutants":9007199254740992.5}}', "positive integer"),  # >=2**53
        ('{"mutation":{"exclude_files":["  "]}}', "list of non-empty"),  # whitespace-only element
    ]
    for text, needle in bad_json:
        repo = fresh_repo()
        (repo / ".adversarial-review.json").write_text(text)
        r = sh(full, repo, expect=1)
        assert needle in r.stderr, f"{text!r}: expected {needle!r} in {r.stderr!r}"


def t_policy_required_gates_missing_tier():
    # Policy present WITH required_gates, but not for this run's tier: that is
    # "not provided", and with no other source plan must die naming the tier.
    repo = fresh_repo()
    (repo / ".adversarial-review.yml").write_text(
        "dev_providers: [anthropic]\nrequired_gates:\n  NORMAL: [build]\n")
    sh(["panel.py", "init", "--risk", "SENSITIVE"], repo)
    r = sh(["gate.py", "plan"], repo, expect=1)
    assert "unresolved for tier SENSITIVE" in r.stderr, r.stderr


def t_policy_rebuttal_precedence():
    repo = fresh_repo()
    (repo / ".adversarial-review.yml").write_text(
        "risk: NORMAL\ndev_providers: [anthropic]\nrebuttal_policy: critical\n")
    sh(["panel.py", "init"], repo, env={**ENV, "AR_REBUTTAL": "any"})
    meta = read(latest_run(repo) / "run.json")
    assert meta["rebuttal_policy"] == "any", meta
    assert meta["sources"]["rebuttal_policy"] == "env", meta["sources"]
    sh(["panel.py", "init", "--rebuttal-policy", "contention"], repo,
       env={**ENV, "AR_REBUTTAL": "any"})
    meta = read(latest_run(repo) / "run.json")
    assert meta["rebuttal_policy"] == "contention", meta
    assert meta["sources"]["rebuttal_policy"] == "cli", meta["sources"]
    sh(["panel.py", "init"], repo)
    meta = read(latest_run(repo) / "run.json")
    assert meta["rebuttal_policy"] == "critical", meta
    assert meta["sources"]["rebuttal_policy"] == "policy", meta["sources"]


def t_packaging_version_sync():
    # pyproject.toml [project] version and scripts/__init__.py __version__ must
    # agree — both are hand-written; this is the automation that enforces it.
    py = (SKILL / "pyproject.toml").read_text()
    m = re.search(r'^version = "([^"]+)"$', py, re.M)
    assert m, "no version in pyproject.toml"
    init = (SKILL / "scripts" / "__init__.py").read_text()
    m2 = re.search(r'^__version__ = "([^"]+)"$', init, re.M)
    assert m2, "no __version__ in scripts/__init__.py"
    assert m.group(1) == m2.group(1), (m.group(1), m2.group(1))


def t_packaging_stays_stdlib_only():
    # The stdlib-only invariant, enforced durably in CI: the manifest must
    # declare an explicitly empty dependency list and no other dependency
    # surface (optional-dependencies, dynamic) that could smuggle one in.
    py = (SKILL / "pyproject.toml").read_text()
    assert re.search(r"^dependencies = \[\]$", py, re.M), \
        "pyproject.toml must declare dependencies = [] (stdlib-only invariant)"
    assert "optional-dependencies" not in py, "no optional dependency surface"
    assert not re.search(r"^dynamic\s*=", py, re.M), "no dynamic metadata"


def t_packaging_entrypoints_resolve():
    # Every [project.scripts] target must point at adversarial_review.<mod>:main
    # where scripts/<mod>.py exists and defines a module-level main().
    py = (SKILL / "pyproject.toml").read_text()
    targets = re.findall(r'^(ar-[a-z]+) = "([^"]+)"$', py, re.M)
    assert len(targets) == 4, targets
    for name, target in targets:
        modpath, _, func = target.partition(":")
        pkg, _, mod = modpath.partition(".")
        assert pkg == "adversarial_review" and func == "main", target
        src = (SKILL / "scripts" / (mod + ".py")).read_text()
        assert re.search(r"^def main\(\):", src, re.M), f"{mod}.py lacks main()"


def t_llms_txt_link_integrity():
    # llms.txt is only useful if its links resolve — guard against rot.
    txt = (SKILL / "llms.txt").read_text()
    lines = txt.splitlines()
    assert lines[0].startswith("# "), "llms.txt must start with an H1 title"
    assert any(l.startswith("> ") for l in lines[:5]), "needs a blockquote summary"
    for target in re.findall(r"\]\(([^)]+)\)", txt):
        if target.startswith(("http://", "https://", "#")):
            continue
        assert (SKILL / target).exists(), f"llms.txt links a missing path: {target}"


def t_push_integrity_snippet_hygiene():
    # Lock in the push-integrity snippet's hardening (issue #17): it must compare the
    # full ls-tree (not a lossy blob-sha subset), pin the intended commit, use mktemp
    # rather than predictable temp paths, and hard-stop on mismatch.
    skill = (SKILL / "SKILL.md").read_text()
    assert "Push integrity" in skill, "SKILL.md must document push integrity"
    lo = skill.index("Push integrity")
    snippet = skill[lo:lo + 1600]
    assert "git ls-tree -r" in snippet, "must compare the git tree"
    assert "mktemp" in snippet, "must use mktemp, not a predictable /tmp path"
    assert "rev-parse" in snippet, "must pin the intended commit, not a moving HEAD"
    assert "exit 1" in snippet, "a mismatch must hard-stop, not just print"


def t_action_definition_hygiene():
    # Regression cover for the composite GitHub Action (issue #7b). Stdlib-only
    # (no YAML dep), so these are structural string assertions — the fuller
    # YAML-parse + bash -n smoke runs as the action-syntax gate at review time.
    act = (SKILL / "action.yml").read_text()
    assert "using: 'composite'" in act, "action must be composite"
    for step in ("Initialize run and plan gates", "Run and record gates",
                 "Independent reviewer panel", "Compute verdict"):
        assert step in act, f"missing step: {step}"
    # Injection hygiene, enforced: a ${{ ... }} template may appear only as an
    # env/output mapping value (KEY: ${{ ... }}) — never interpolated into a
    # run: script body, where an input could smuggle shell.
    for line in act.splitlines():
        if "${{" in line:
            s = line.strip()
            assert re.match(r"^[A-Za-z_-]+: \$\{\{", s) or s.startswith("value:"), \
                f"template outside an env/value mapping (injection risk): {line!r}"
    # The gate loops guard malformed lines rather than silently mis-parsing.
    assert act.count("gate line missing '='") == 2, "both loops must guard '='"
    assert "empty name" in act, "loops must reject empty gate names"
    wf = (SKILL / "examples" / "adversarial-review.yml").read_text()
    assert "SathiaAI/adversarial-review@" in wf, "example must use the action"
    assert "fetch-depth: 0" in wf, "panel needs full history"


def t_ci_docs_and_gitlab_mirror_action():
    # E2-S3 drift guard. The CI-integration guide must mirror the ACTUAL action.yml inputs (a new
    # or renamed input forces a doc update instead of drifting), and the GitLab template must keep
    # aggregate.py as its terminal pipeline command so the job exit code IS the verdict. Structural
    # string checks (no YAML dep), doc/template-vs-code — the same discipline as gates.md/README.
    act = (SKILL / "action.yml").read_text(encoding="utf-8")
    inputs_block = act.split("\ninputs:", 1)[1].split("\noutputs:", 1)[0]
    input_names = re.findall(r"(?m)^  ([a-z][a-z0-9-]*):", inputs_block)
    assert len(input_names) >= 5, f"action.yml input extraction looks wrong: {input_names}"

    doc = (SKILL / "docs" / "ci-integration.md").read_text(encoding="utf-8")
    for name in input_names:  # every real Action input is documented by its backticked name
        assert "`%s`" % name in doc, f"docs/ci-integration.md omits action input `{name}`"
    for token in ("GitHub", "GitLab", "Marketplace", "v1",
                  "examples/.gitlab-ci.yml", "examples/adversarial-review.yml"):
        assert token in doc, f"docs/ci-integration.md missing {token!r}"

    gl = (SKILL / "examples" / ".gitlab-ci.yml").read_text(encoding="utf-8")
    for call in ("panel.py init", "gate.py plan", "aggregate.py"):
        assert call in gl, f".gitlab-ci.yml missing real entrypoint {call!r}"
    for fake in ("--fail-on", "--gates"):  # Action inputs, not script flags — never invented here
        assert fake not in gl, f".gitlab-ci.yml invents a non-existent flag {fake!r}"
    # E2-S3 (panel/Codex): aggregate.py must be the TERMINAL command of ar-panel's script — not
    # merely appear after the panel textually. A command appended after it could replace the job's
    # exit status and defeat the verdict contract. Extract ar-panel's `script:` list and assert its
    # LAST item runs aggregate.py, and that nothing else does.
    panel_block = gl.split("\nar-panel:", 1)[1]
    m0 = re.search(r"(?m)^  script:\s*$", panel_block)
    assert m0, "ar-panel has no script: block"
    script_body = panel_block[m0.end():]
    m1 = re.search(r"(?m)^  \w[\w-]*:", script_body)   # next job-level (2-space) key, e.g. artifacts:
    if m1:
        script_body = script_body[:m1.start()]
    items = re.findall(r"(?m)^    - (.+)$", script_body)   # 4-space script list items only
    assert items, "ar-panel script has no commands"
    assert "aggregate.py" in items[-1], \
        f"aggregate.py must be ar-panel's LAST command, got: {items[-1]!r}"
    assert not any("aggregate.py" in it for it in items[:-1]), \
        "aggregate.py must appear only as the terminal command"
    assert "OPENROUTER_API_KEY" in gl and "BLOCKED" in gl, "keyless→BLOCKED honesty must be documented"
    assert "allow_failure" in gl and "exit_codes: 2" in gl, "fail-on=fail equivalent must be documented"
    # E2-S3 (panel test_quality-1): the doc must document the Action's OUTPUTS too, not just inputs,
    # so a renamed/removed output forces a doc update instead of drifting.
    outputs_block = act.split("\noutputs:", 1)[1].split("\nruns:", 1)[0]
    output_names = re.findall(r"(?m)^  ([a-z][a-z0-9-]*):", outputs_block)
    assert set(output_names) >= {"verdict", "exit-code"}, output_names
    for name in output_names:
        assert "`%s`" % name in doc, "docs/ci-integration.md omits Action output `%s`" % name
    # (panel correctness-2): the verdict->exit-code contract is stated explicitly in the doc.
    assert "exit code" in doc.lower()
    for word in ("PASS", "FAIL", "BLOCKED"):
        assert word in doc, "verdict word %r missing from ci-integration.md" % word
    # (CodeRabbit): assert the EXACT verdict->exit-code mapping is documented, not just the words,
    # so a drifted mapping (e.g. BLOCKED renumbered) forces a doc update instead of passing silently.
    for pair in ("`0` PASS", "`1` FAIL", "`2` BLOCKED"):
        assert pair in doc, "ci-integration.md must state the exact exit-code mapping %r" % pair
    # (panel test_quality-2): the GitLab template must surface the Action's required inputs through its
    # AR_* variables (risk, dev-providers, diff-ref/base, gate set) so the two CI paths stay in lockstep.
    for var in ("AR_RISK", "AR_DEV_PROVIDERS", "AR_DIFF", "AR_REQUIRE"):
        assert var in gl, ".gitlab-ci.yml omits %s (Action-input equivalent)" % var
    # E2-S3 (CodeRabbit Critical + Minor): the secrets-before-transmit guard must be an EXECUTABLE
    # check in the reviewer-panel STEP, bound to THIS run's exact directory (RUN_DIR from panel.py
    # init) — never a glob a committed/older run-* could satisfy — and it must run before
    # `panel.py run` transmits the diff. Assert on the extracted panel-step block, not the whole file.
    panel_step = act.split("Independent reviewer panel", 1)[1].split("\n    - name:", 1)[0]
    assert "secrets.json" in panel_step and '"$RUN_DIR"' in panel_step, \
        "panel step must check THIS run's secrets.json pinned to RUN_DIR"
    assert "glob.glob(" not in panel_step, \
        "secrets check must not glob run-* (a committed run dir could satisfy it)"
    assert panel_step.index("secrets.json") < panel_step.index('panel.py\" run'), \
        "the secrets PASS check must occur before panel.py run transmits the diff"
    # every gate/panel/aggregate step pins to the init run dir (panel test_quality-2: assert EACH
    # step, not just a count), so a committed .adversarial-review/run-* can't hijack the pipeline.
    assert "steps.init.outputs.run_dir" in act, "action.yml must expose init's run dir as an output"
    for needle in ('gate.py" plan --run "$run_dir"', 'gate.py" run --run "$RUN_DIR"',
                   'panel.py" assign --run "$RUN_DIR"', 'panel.py" run --run "$RUN_DIR"',
                   'aggregate.py" --run "$RUN_DIR"'):
        assert needle in act, "action.yml step not pinned to the run dir: %r" % needle
    # the documented starter workflow BLOCK must configure the full NORMAL floor incl. secrets.
    starter = doc.split("```yaml", 1)[1].split("```", 1)[0]
    for g in ("build=", "unit=", "secrets=", "deps=", "sast="):
        assert g in starter, "ci-integration.md starter workflow omits a `%s` gate" % g


def t_action_secrets_guard_behaviour():
    # E2-S3 (panel security-1 + test_quality-1; CodeRabbit): the reviewer-panel secrets precondition
    # must (a) run ISOLATED (`python -I`, so a repo-committed json.py/sitecustomize.py can't execute
    # with the key in env), (b) authorize transmission ("1") ONLY when THIS run's gates/secrets.json is
    # recorded PASS, and (c) fail SAFE — a missing, malformed, or non-object record returns "0" WITHOUT
    # crashing (a raise under `set -euo pipefail` would abort the step before aggregate.py emits BLOCKED).
    # The guard spans multiple lines, so it is EXTRACTED whole from action.yml and run against real dirs.
    import subprocess as _sp, tempfile as _tf, json as _json, os as _os, re as _re
    act = (SKILL / "action.yml").read_text(encoding="utf-8")
    m = _re.search(r'secrets_ok="\$\((.*?)\)"', act, _re.S)
    assert m, 'secrets guard (secrets_ok="$(...)") not found in action.yml'
    cmd = m.group(1)
    assert "python -I -c" in cmd, ("guard must be isolated with -I", cmd)
    def check(body, raw=False):
        d = _tf.mkdtemp(prefix="ar-guard-")
        if body is not None:
            _os.makedirs(_os.path.join(d, "gates"))
            content = body if raw else _json.dumps({"status": body})
            (Path(d) / "gates" / "secrets.json").write_text(content)
        r = _sp.run(["bash", "-c", cmd.replace('"$RUN_DIR"', '"%s"' % d)], capture_output=True, text=True)
        assert r.returncode == 0, ("guard must exit 0, never crash the panel step", r.returncode, r.stderr)
        return r.stdout.strip()
    assert check("PASS") == "1", "a recorded PASS secrets gate must authorize transmission"
    assert check("FAIL") == "0", "a FAILED secrets scan must NOT authorize transmission"
    assert check(None) == "0", "a missing secrets.json must NOT authorize transmission"
    assert check("{not valid json", raw=True) == "0", "a malformed secrets.json must DENY, not crash"
    assert check("[1, 2, 3]", raw=True) == "0", "a non-object secrets.json must DENY, not crash"


def t_policy_pins_precedence():
    repo = fresh_repo()
    (repo / ".adversarial-review.yml").write_text(
        "risk: NORMAL\ndev_providers: [anthropic]\n"
        "pins:\n  correctness: mistralai/mistral-large-3\n")
    sh(["panel.py", "init"], repo)
    sh(["panel.py", "assign"], repo)
    role = read(latest_run(repo) / "panel" / "plan.json")["roles"]["correctness"]
    assert role["model"] == "mistralai/mistral-large-3" and role["pinned"]
    assert role["pin_source"] == "policy", role
    env = {**ENV, "AR_PINS": "correctness=qwen/qwen3.8-max"}
    sh(["panel.py", "assign"], repo, env=env)
    role = read(latest_run(repo) / "panel" / "plan.json")["roles"]["correctness"]
    assert role["model"] == "qwen/qwen3.8-max" and role["pin_source"] == "env"
    sh(["panel.py", "assign", "--pin", "correctness=openai/gpt-5.6-luna-pro"],
       repo, env=env)
    plan = read(latest_run(repo) / "panel" / "plan.json")["roles"]
    assert plan["correctness"]["model"] == "openai/gpt-5.6-luna-pro"
    assert plan["correctness"]["pin_source"] == "cli", plan["correctness"]
    unpinned = [r for r, v in plan.items() if r != "correctness"]
    assert all(plan[r]["pin_source"] is None for r in unpinned), plan
    # A typo'd pin role — from any source — dies loudly instead of being ignored.
    r = sh(["panel.py", "assign", "--pin", "corectness=x-ai/grok-4.5"],
           repo, expect=2)
    assert "unknown role" in r.stderr, r.stderr


def _mcp_call(repo, name, arguments):
    """Invoke one MCP tool through the server's dispatcher with the repo as cwd,
    restoring cwd afterwards. Returns the tool result object."""
    cwd0 = os.getcwd()
    try:
        os.chdir(repo)
        resp = mcpsrv.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                              "params": {"name": name, "arguments": arguments}})
    finally:
        os.chdir(cwd0)
    assert "result" in resp, resp
    return resp["result"]


def t_mcp_protocol_handshake():
    # initialize echoes a supported protocol version and advertises tools
    r = mcpsrv.handle({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                       "params": {"protocolVersion": "2025-06-18"}})
    assert r["result"]["protocolVersion"] == "2025-06-18", r
    assert r["result"]["serverInfo"]["name"] == "adversarial_review_mcp", r
    assert "tools" in r["result"]["capabilities"], r
    # an unsupported client version falls back to our latest, never crashes
    r2 = mcpsrv.handle({"jsonrpc": "2.0", "id": 2, "method": "initialize",
                        "params": {"protocolVersion": "1.0.0"}})
    assert r2["result"]["protocolVersion"] == "2025-06-18", r2
    # tools/list exposes the pipeline with well-formed schemas + annotations
    tl = mcpsrv.handle({"jsonrpc": "2.0", "id": 3, "method": "tools/list"})
    names = {t["name"] for t in tl["result"]["tools"]}
    assert {"ar_init", "ar_gate_plan", "ar_gate_record", "ar_panel_assign",
            "ar_panel_prepare", "ar_panel_ingest", "ar_aggregate",
            "ar_check_digest", "ar_get_verdict"} <= names, names
    # the server is deliberately NOT an arbitrary-command surface: no gate-run tool
    assert not any("run" in n and "gate" in n for n in names), names
    for t in tl["result"]["tools"]:
        assert t["inputSchema"]["type"] == "object" and "annotations" in t, t
    # a notification (no id) is never answered
    assert mcpsrv.handle({"jsonrpc": "2.0", "method": "notifications/initialized"}) is None
    # unknown method -> JSON-RPC method-not-found
    assert mcpsrv.handle({"jsonrpc": "2.0", "id": 4, "method": "nope"})["error"]["code"] == -32601
    assert mcpsrv.handle({"jsonrpc": "2.0", "id": 5, "method": "ping"})["result"] == {}


def t_mcp_rejects_run_path_traversal():
    # a run id carrying a path separator / .. must be refused before it can reach
    # resolve_run() and escape .adversarial-review/
    for bad in ["../../etc", "run-1/../..", "/etc/passwd", ".."]:
        r = mcpsrv.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                           "params": {"name": "ar_get_verdict", "arguments": {"run": bad}}})
        res = r["result"]
        assert res["isError"] and "invalid run id" in res["content"][0]["text"], (bad, res)
    # bad enum on init is a clean tool error, not a crash
    r2 = mcpsrv.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                        "params": {"name": "ar_init",
                                   "arguments": {"risk": "WHATEVER", "dev_providers": ["anthropic"]}}})
    assert r2["result"]["isError"] and "risk must be" in r2["result"]["content"][0]["text"], r2
    # unknown tool -> protocol-level error
    r3 = mcpsrv.handle({"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                        "params": {"name": "ar_nope", "arguments": {}}})
    assert r3["error"]["code"] == -32602, r3


def t_mcp_drives_local_pipeline():
    # the subprocess bridge really drives init -> plan -> record and writes artifacts
    repo = fresh_repo()
    res = _mcp_call(repo, "ar_init",
                    {"risk": "NORMAL", "dev_providers": ["anthropic"], "diff_ref": "main...HEAD"})
    assert not res.get("isError"), res
    run_id = res["structuredContent"]["run_id"]
    assert run_id and run_id.startswith("run-"), res
    assert not _mcp_call(repo, "ar_gate_plan",
                         {"require": ["build", "unit", "secrets", "deps", "sast"]}).get("isError")
    for g in ["build", "unit", "secrets", "deps", "sast"]:
        res = _mcp_call(repo, "ar_gate_record", {"name": g, "exit_code": 0, "summary": "ok"})
        assert not res.get("isError"), (g, res)
    run = latest_run(repo)
    for g in ["build", "unit", "secrets", "deps", "sast"]:
        assert (run / "gates" / f"{g}.json").is_file(), g
    # aggregate returns a structured, machine-computed verdict (BLOCKED here: no panel)
    res = _mcp_call(repo, "ar_aggregate", {})
    assert "structuredContent" in res, res
    assert res["structuredContent"]["verdict"] == "BLOCKED", res


def t_mcp_reads_passing_verdict():
    # against a genuine passing run, the read/aggregate tools surface PASS + intact digest
    repo = _complete_sensitive_repo()
    run = latest_run(repo)
    write(run / "validation" / "idor.json", {
        "finding_ids": ["security-1"], "classification": "confirmed", "severity": "high",
        "evidence": "reproduced then fixed", "reproduced": True,
        "regression_test": "tests/test_invoices.py::t_x",
        "resolution": {"fixed": True, "gates_rerun": ["unit", "sast"]}})
    res = _mcp_call(repo, "ar_aggregate", {})
    assert res["structuredContent"]["verdict"] == "PASS", res
    assert not res.get("isError"), res
    res2 = _mcp_call(repo, "ar_get_verdict", {})
    assert res2["structuredContent"]["verdict"] == "PASS", res2
    res3 = _mcp_call(repo, "ar_check_digest", {})
    assert res3["structuredContent"]["intact"] is True, res3


def t_mcp_hardening():
    # regressions for panel findings on scripts/mcp_server.py
    # security-1: a truthy non-dict `params` must not crash the handler
    for bad in ["str", [1, 2], 123, True]:
        r = mcpsrv.handle({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": bad})
        assert "result" in r or "error" in r, (bad, r)
    # correctness-1: an explicit empty/whitespace `run` is rejected, never silently 'newest'
    r = mcpsrv.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                       "params": {"name": "ar_get_verdict", "arguments": {"run": ""}}})
    assert r["result"]["isError"] and "invalid run id" in r["result"]["content"][0]["text"], r
    # test_quality-4: catalog_file path traversal is refused
    for bad in ["../../etc/shadow", "/etc/passwd", "a/../b"]:
        r = mcpsrv.handle({"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                           "params": {"name": "ar_panel_assign", "arguments": {"catalog_file": bad}}})
        assert r["result"]["isError"] and "catalog_file" in r["result"]["content"][0]["text"], (bad, r)
    # list args passed as a bare string are rejected, never iterated per-character
    r = mcpsrv.handle({"jsonrpc": "2.0", "id": 4, "method": "tools/call",
                       "params": {"name": "ar_gate_plan", "arguments": {"waive": "sast"}}})
    assert r["result"]["isError"] and "waive must be a list" in r["result"]["content"][0]["text"], r
    r = mcpsrv.handle({"jsonrpc": "2.0", "id": 5, "method": "tools/call",
                       "params": {"name": "ar_panel_assign", "arguments": {"pin": "security=google/x"}}})
    assert r["result"]["isError"] and "pin must be a list" in r["result"]["content"][0]["text"], r
    # test_quality-3: exit_code bool guard and role regex are enforced
    r = mcpsrv.handle({"jsonrpc": "2.0", "id": 6, "method": "tools/call",
                       "params": {"name": "ar_gate_record",
                                  "arguments": {"name": "build", "summary": "x", "exit_code": True}}})
    assert r["result"]["isError"] and "exit_code must be an integer" in r["result"]["content"][0]["text"], r
    r = mcpsrv.handle({"jsonrpc": "2.0", "id": 7, "method": "tools/call",
                       "params": {"name": "ar_panel_ingest", "arguments": {"role": "123", "response": "{}"}}})
    assert r["result"]["isError"] and "invalid role" in r["result"]["content"][0]["text"], r


def t_mcp_stdio_parse_error_survives():
    # test_quality-1 + security-1 at the wire level: drive the real main() loop over
    # stdio — a malformed line yields -32700, and a non-dict params is still answered
    # (the loop survives both instead of crashing).
    srv = str(SKILL / "scripts" / "mcp_server.py")
    inp = "{bad json\n" + json.dumps(
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": "nope"}) + "\n"
    p = subprocess.run([sys.executable, srv], input=inp, capture_output=True, text=True,
                       timeout=30, cwd=tempfile.mkdtemp())
    lines = [json.loads(x) for x in p.stdout.splitlines() if x.strip()]
    assert any(o.get("error", {}).get("code") == -32700 for o in lines), lines
    assert any("result" in o and o.get("id") == 1 for o in lines), lines


def t_mcp_stdio_transport_framing():
    # E3-S1: the stdio framing is extracted into StdioTransport around the transport-agnostic
    # serve_message() core (handle() dispatch is untouched). Drive the class with injected
    # streams and assert newline framing, parse-error framing, notification suppression, and
    # empty-line skipping in-process — the seam a future HTTP transport reuses.
    import io
    feed = "\n".join([
        json.dumps({"jsonrpc": "2.0", "id": 1, "method": "server/discover"}),
        "",                                                                     # blank: skipped
        "   ",                                                                  # whitespace-only: skipped
        "not json {{{",                                                         # unparseable -> -32700 (id null)
        json.dumps([1, 2, 3]),                                                  # valid JSON, non-object -> -32600 (id null)
        json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}),  # notification: no reply
        json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}),
    ]) + "\n"
    out = io.StringIO()
    mcpsrv.StdioTransport(stdin=io.StringIO(feed), stdout=out).serve_forever()
    replies = [json.loads(x) for x in out.getvalue().splitlines() if x]
    # framed replies in order: discover(id 1), parse-error(id null), invalid-request(id null),
    # list(id 2). Both the blank and the whitespace-only line are skipped; the notification is
    # unanswered — so a non-dict JSON value frames as -32600, it does not vanish or crash.
    assert [r.get("id") for r in replies] == [1, None, None, 2], replies
    assert replies[1]["error"]["code"] == -32700, replies[1]   # unparseable bytes
    assert replies[2]["error"]["code"] == -32600, replies[2]   # valid JSON, not a JSON-RPC object
    assert "tools" in replies[3]["result"], replies[3]
    # serve_message() itself returns None for a notification — nothing to frame
    assert mcpsrv.serve_message(json.dumps({"jsonrpc": "2.0", "method": "notifications/x"})) is None
    # a parse failure frames as a -32700 error with a null id — asserted structurally rather
    # than by reconstructing the expected string through _error (which would be tautological)
    perr = json.loads(mcpsrv.serve_message("garbage {"))
    assert perr["error"]["code"] == -32700 and perr["id"] is None, perr
    # pathologically nested JSON overflows the decoder (RecursionError); it must frame as a
    # parse error, not escape serve_message and kill the transport (panel finding correctness-1)
    deep = json.loads(mcpsrv.serve_message("[" * 20000 + "]" * 20000))
    assert deep["error"]["code"] == -32700 and deep["id"] is None, deep
    # bytes carrying invalid UTF-8 raise UnicodeDecodeError in the decoder; serve_message is the
    # transport-agnostic core a future bytes/HTTP transport reuses, so it too must frame as a
    # parse error, never escape (CodeRabbit stability review)
    ub = json.loads(mcpsrv.serve_message(b"\xff"))
    assert ub["error"]["code"] == -32700 and ub["id"] is None, ub


def t_mcp_serve_message_handler_crash_is_framed():
    # E3-S1 acceptance guarantee: serve_message() converts a handler crash into a JSON-RPC
    # -32603 error (preserving the request id) instead of letting the exception escape and
    # kill the transport. handle() is deliberately defensive, so the -32603 path is reached
    # by forcing handle to raise — this is the seam's explicit contract (panel finding
    # test_quality-1, previously untested).
    orig = mcpsrv.handle
    try:
        def boom(msg):
            raise RuntimeError("handler kaboom")
        mcpsrv.handle = boom
        out = mcpsrv.serve_message(json.dumps({"jsonrpc": "2.0", "id": 7, "method": "tools/list"}))
        err = json.loads(out)
        assert err["error"]["code"] == -32603, err
        assert err["id"] == 7, err            # id propagated from the crashing request
    finally:
        mcpsrv.handle = orig


def t_mcp_subprocess_timeout_surfaced():
    # test_quality-2: a CLI timeout is surfaced as a tool error, not a hang/crash
    orig = mcpsrv.subprocess.run
    def _boom(*a, **k):
        raise subprocess.TimeoutExpired(cmd="x", timeout=1)
    mcpsrv.subprocess.run = _boom
    try:
        r = mcpsrv.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                           "params": {"name": "ar_gate_plan", "arguments": {}}})
        assert r["result"]["isError"] and "timed out" in r["result"]["content"][0]["text"], r
    finally:
        mcpsrv.subprocess.run = orig


def t_mcp_fail_verdict():
    # test_quality-5: the FAIL verdict path is exercised through the server
    repo = fresh_repo()
    _mcp_call(repo, "ar_init", {"risk": "NORMAL", "dev_providers": ["anthropic"]})
    _mcp_call(repo, "ar_gate_plan", {"require": ["build"]})
    _mcp_call(repo, "ar_gate_record", {"name": "build", "exit_code": 1, "summary": "boom"})
    res = _mcp_call(repo, "ar_aggregate", {})
    assert res["structuredContent"]["verdict"] == "FAIL", res


# --- MCP 2026-07-28 stateless dual-era support -----------------------------------
# These assert the exact wire shapes the 2026-07-28 spec requires: per-request version
# negotiation, server/discover, UnsupportedProtocolVersion (-32022), the required
# resultType, and CacheableResult (ttlMs/cacheScope) on tools/list.

def _modern_req(method, params=None, version="2026-07-28", caps=True):
    """Dispatch a modern (2026-07-28) request: the protocol version — and, unless
    caps=False, client capabilities — carried in params._meta, as the stateless spec
    requires."""
    p = dict(params or {})
    meta = {"io.modelcontextprotocol/protocolVersion": version}
    if caps:
        meta["io.modelcontextprotocol/clientCapabilities"] = {}
    p["_meta"] = meta
    return mcpsrv.handle({"jsonrpc": "2.0", "id": 1, "method": method, "params": p})


def t_mcp_discover_advertises_versions():
    # server/discover MUST be implemented; it advertises supported versions, capabilities,
    # and identity in one round-trip (and is the stdio backward-compat probe).
    res = _modern_req("server/discover")["result"]
    assert res["resultType"] == "complete", res
    assert "2026-07-28" in res["supportedVersions"], res
    # legacy versions remain advertised too — this is a dual-era server
    assert "2025-06-18" in res["supportedVersions"], res
    assert "tools" in res["capabilities"], res
    assert res["_meta"]["io.modelcontextprotocol/serverInfo"]["name"] == "adversarial_review_mcp", res
    assert isinstance(res["ttlMs"], int) and res["ttlMs"] > 0, res
    assert res["cacheScope"] in ("public", "private"), res
    # discovery answers even without client capabilities — it is the bootstrap probe
    assert "2026-07-28" in _modern_req("server/discover", caps=False)["result"]["supportedVersions"]
    # ...and it is answered on the LEGACY path too (no _meta at all): server/discover is
    # new in this revision and version-agnostic, so it is served in both eras (per docstring).
    leg = mcpsrv.handle({"jsonrpc": "2.0", "id": 1, "method": "server/discover"})["result"]
    assert "2026-07-28" in leg["supportedVersions"] and leg["resultType"] == "complete", leg
    # ...and a modern discovery declaring an UNSUPPORTED version is still answered with a
    # complete DiscoverResult advertising the supported set (discovery bypasses version
    # validation by design, so a stale client can always learn what to negotiate to).
    uns = _modern_req("server/discover", version="1900-01-01", caps=False)["result"]
    assert uns["resultType"] == "complete" and "2026-07-28" in uns["supportedVersions"], uns


def t_mcp_modern_tools_list_is_cacheable():
    # a modern tools/list carries resultType, server identity, and the CacheableResult hints
    res = _modern_req("tools/list")["result"]
    assert res["resultType"] == "complete", res
    assert res["_meta"]["io.modelcontextprotocol/serverInfo"]["name"] == "adversarial_review_mcp", res
    assert isinstance(res["ttlMs"], int) and res["ttlMs"] > 0, res
    assert res["cacheScope"] == "public", res
    names = {t["name"] for t in res["tools"]}
    assert "ar_init" in names and "ar_aggregate" in names, names


def t_mcp_modern_unsupported_version_rejected():
    # a version we do not implement returns UnsupportedProtocolVersionError (-32022) whose
    # data names what we support and echoes what was requested
    err = _modern_req("tools/list", version="1900-01-01")["error"]
    assert err["code"] == -32022, err
    assert "2026-07-28" in err["data"]["supported"], err
    assert err["data"]["requested"] == "1900-01-01", err
    # ...but server/discover still answers, so a client can still learn the supported set
    assert "2026-07-28" in _modern_req("server/discover", version="1900-01-01")["result"]["supportedVersions"]


def t_mcp_modern_missing_capabilities_is_invalid_params():
    # clientCapabilities is a required per-request _meta field; omitting it on a modern
    # request is malformed -> -32602 (Invalid params)
    r = _modern_req("tools/list", caps=False)
    assert r["error"]["code"] == -32602, r
    assert "clientCapabilities" in r["error"]["message"], r


def t_mcp_modern_tool_call_finalized():
    # a modern tools/call is finalized too: even a tool-level error result is resultType
    # "complete" (the RPC itself completed) and carries server identity
    res = _modern_req("tools/call",
                      {"name": "ar_get_verdict", "arguments": {"run": ""}})["result"]
    assert res["resultType"] == "complete", res
    assert res["isError"] and "invalid run id" in res["content"][0]["text"], res
    assert res["_meta"]["io.modelcontextprotocol/serverInfo"]["name"] == "adversarial_review_mcp", res


def t_mcp_modern_successful_tool_call():
    # a *successful* modern tools/call (not just the error path) is finalized: resultType
    # complete, server _meta, and the real tool result present — proving success results,
    # not only tool-level errors, get the modern decoration.
    repo = fresh_repo()
    cwd0 = os.getcwd()
    try:
        os.chdir(repo)
        res = _modern_req("tools/call",
                          {"name": "ar_init",
                           "arguments": {"risk": "NORMAL", "dev_providers": ["anthropic"]}})["result"]
    finally:
        os.chdir(cwd0)
    assert res["resultType"] == "complete", res
    assert not res.get("isError"), res
    assert res["_meta"]["io.modelcontextprotocol/serverInfo"]["name"] == "adversarial_review_mcp", res
    assert res["structuredContent"]["run_id"].startswith("run-"), res


def t_mcp_legacy_responses_unchanged():
    # dual-era must not leak modern fields into legacy responses: a legacy tools/list (no
    # _meta) has neither resultType nor the CacheableResult hints, and initialize is intact
    tl = mcpsrv.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})["result"]
    assert "resultType" not in tl and "ttlMs" not in tl and "cacheScope" not in tl, tl
    assert "_meta" not in tl, tl
    init = mcpsrv.handle({"jsonrpc": "2.0", "id": 2, "method": "initialize",
                          "params": {"protocolVersion": "2025-06-18"}})["result"]
    assert init["protocolVersion"] == "2025-06-18", init
    assert "resultType" not in init, init


def t_mcp_modern_ping_is_method_not_found():
    # 2026-07-28 removed ping; a modern ping must not return a bare {} (which would omit the
    # required resultType) — it is method-not-found. The legacy ping still returns {}.
    assert _modern_req("ping")["error"]["code"] == -32601
    assert mcpsrv.handle({"jsonrpc": "2.0", "id": 9, "method": "ping"})["result"] == {}


def t_mcp_null_protocol_version_rejected():
    # a modern request that carries the version key as null is a modern request with an
    # unsupported version (-32022), not a legacy request served silently
    r = mcpsrv.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/list",
                       "params": {"_meta": {"io.modelcontextprotocol/protocolVersion": None,
                                            "io.modelcontextprotocol/clientCapabilities": {}}}})
    assert r["error"]["code"] == -32022, r
    assert r["error"]["data"]["requested"] is None, r


def t_mcp_initialize_notification_not_answered():
    # an initialize sent as a notification (no id) must not be answered, per JSON-RPC;
    # a normal initialize (with id) still is
    assert mcpsrv.handle({"jsonrpc": "2.0", "method": "initialize",
                          "params": {"protocolVersion": "2025-06-18"}}) is None
    assert mcpsrv.handle({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                          "params": {"protocolVersion": "2025-06-18"}})["result"]["protocolVersion"] == "2025-06-18"


def t_mcp_modern_invalid_tools_call_rejected_before_side_effects():
    # A modern tools/call for a state-changing tool (ar_init) must be rejected by protocol
    # validation BEFORE the handler runs — neither an unsupported version nor missing
    # clientCapabilities may create a run on disk. The existing t_mcp_modern_*_rejected tests
    # only exercise the non-side-effecting tools/list, so this pins validate-before-dispatch.
    repo = fresh_repo()
    cwd0 = os.getcwd()
    try:
        os.chdir(repo)
        call = {"name": "ar_init", "arguments": {"risk": "NORMAL", "dev_providers": ["anthropic"]}}
        assert _modern_req("tools/call", call, version="1900-01-01")["error"]["code"] == -32022
        assert _modern_req("tools/call", call, caps=False)["error"]["code"] == -32602
        # the handler never ran: no run directory was created
        assert list((repo / ".adversarial-review").glob("run-*")) == []
    finally:
        os.chdir(cwd0)


def t_mcp_notification_never_answered_for_any_method():
    # A JSON-RPC notification (no id) is never answered for ANY method — the check sits at the
    # top of handle(), ahead of method dispatch — so a side-effecting tools/call notification
    # must return nothing AND not execute its handler. Existing coverage is initialize-only;
    # this guards against the notification check being moved below method handling.
    for method in ("tools/list", "server/discover", "ping", "nonexistent/method"):
        assert mcpsrv.handle({"jsonrpc": "2.0", "method": method, "params": {}}) is None, method
    # ...and MODERN-shaped notifications (protocol _meta present) are equally unanswered, even
    # when the declared version is unsupported or clientCapabilities is missing — the
    # top-of-dispatch check must win over the modern -32022/-32602 validation, not the reverse.
    _mbad = {"io.modelcontextprotocol/protocolVersion": "1900-01-01"}
    _mnocaps = {"io.modelcontextprotocol/protocolVersion": "2026-07-28"}
    for meta in (_mbad, _mnocaps):
        assert mcpsrv.handle({"jsonrpc": "2.0", "method": "tools/list", "params": {"_meta": meta}}) is None, meta
    repo = fresh_repo()
    cwd0 = os.getcwd()
    try:
        os.chdir(repo)
        args = {"name": "ar_init", "arguments": {"risk": "NORMAL", "dev_providers": ["anthropic"]}}
        # a legacy-shaped AND a modern-shaped (unsupported version) tools/call notification both
        # return nothing and run no handler, so no review run is ever created on disk.
        assert mcpsrv.handle({"jsonrpc": "2.0", "method": "tools/call", "params": args}) is None
        assert mcpsrv.handle({"jsonrpc": "2.0", "method": "tools/call",
                              "params": {**args, "_meta": _mbad}}) is None
        assert list((repo / ".adversarial-review").glob("run-*")) == []
    finally:
        os.chdir(cwd0)


def t_capability_defaults_from_catalog():
    # Catalog `supported_parameters` alone yields the default profile (E0-S2).
    from _common import capability_defaults, capability_of
    d = capability_defaults({"id": "x/y", "supported_parameters": ["structured_outputs", "temperature"]})
    assert d["structured_outputs"] is True and d["temperature"] == "supported"
    e2 = {"id": "z/w", "supported_parameters": ["structured_outputs"]}
    d2 = capability_defaults(e2)
    assert d2["structured_outputs"] is True and d2["temperature"] == "default" and d2["reasoning"] == "none"
    prof, src = capability_of("z/w", e2, {})
    assert src == "catalog" and prof["max_tokens_floor"] is None


def t_capability_profile_precedence():
    # catalog < file < env, with env winning per key; numeric fields coerce from strings (E0-S2).
    from _common import load_capabilities, capability_of
    repo = Path(tempfile.mkdtemp(prefix="ar-cap-"))
    (repo / ".adversarial-review.capabilities.yml").write_text(
        "openai/gpt-5.6-luna-pro:\n  temperature: forbidden\n  max_tokens_floor: 8000\n"
        "qwen/qwen3.8-max:\n  reasoning: mandatory\n  max_tokens_floor: 16000\n")
    envf = repo / "env-caps.json"
    # env wins per key: latency_class is added, and an explicit null clears the file's floor.
    envf.write_text(json.dumps({"openai/gpt-5.6-luna-pro":
                                {"latency_class": "slow", "max_tokens_floor": None}}))
    old = os.environ.get("AR_CAP_OVERRIDES")
    os.environ["AR_CAP_OVERRIDES"] = str(envf)
    try:
        ov = load_capabilities(repo)
    finally:
        if old is None:
            os.environ.pop("AR_CAP_OVERRIDES", None)
        else:
            os.environ["AR_CAP_OVERRIDES"] = old
    assert ov["openai/gpt-5.6-luna-pro"]["temperature"] == "forbidden"   # from file
    assert ov["openai/gpt-5.6-luna-pro"]["latency_class"] == "slow"      # from env, merged in
    assert "max_tokens_floor" in ov["openai/gpt-5.6-luna-pro"]           # key retained...
    assert ov["openai/gpt-5.6-luna-pro"]["max_tokens_floor"] is None     # ...env null clears file's 8000
    assert ov["qwen/qwen3.8-max"]["reasoning"] == "mandatory"
    assert ov["qwen/qwen3.8-max"]["max_tokens_floor"] == 16000           # coerced str -> int (file, no env override)
    cat = {"id": "openai/gpt-5.6-luna-pro", "supported_parameters": ["structured_outputs"]}
    prof, src = capability_of("openai/gpt-5.6-luna-pro", cat, ov)
    assert src == "override" and prof["temperature"] == "forbidden" and prof["structured_outputs"] is True


def t_capability_profile_malformed_rejected():
    # Unknown key and bad enum both die loudly (exit 1), like the policy loader (E0-S2).
    from _common import load_capabilities
    repo = Path(tempfile.mkdtemp(prefix="ar-cap-"))
    f = repo / ".adversarial-review.capabilities.yml"
    f.write_text("x/y:\n  bogus: 1\n")
    try:
        load_capabilities(repo)
        assert False, "unknown key should have died"
    except SystemExit as e:
        assert e.code == 1
    f.write_text("x/y:\n  temperature: hot\n")
    try:
        load_capabilities(repo)
        assert False, "bad enum should have died"
    except SystemExit as e:
        assert e.code == 1


def t_build_request_capability_shaping():
    # build_request omits temperature when a model forbids it, floors max_tokens (never
    # lowers it), and emits a reasoning budget only for mandatory-reasoning models. A None
    # profile reproduces today's one-size-fits-all body exactly (E4-S1).
    import panel
    msgs = [{"role": "system", "content": "sys"}, {"role": "user", "content": "u"}]
    base = int(os.environ.get("AR_MAX_TOKENS", "8000"))
    effort = os.environ.get("AR_REASONING_EFFORT", "high")

    def mk(cap):
        return panel.build_request("x/y", msgs, panel.REPORT_SCHEMA, "reviewer_report",
                                   True, "NORMAL", cap)[0]
    b = mk(None)
    assert "temperature" in b and b["max_tokens"] == base and "reasoning" not in b
    assert "temperature" not in mk({"temperature": "forbidden"})
    assert mk({"reasoning": "mandatory"}).get("reasoning") == {"effort": effort}
    assert "reasoning" not in mk({"reasoning": "none"})
    assert mk({"max_tokens_floor": base + 50000})["max_tokens"] == base + 50000
    assert mk({"max_tokens_floor": 1})["max_tokens"] == base   # a low floor never lowers it
    # Default profile keeps the pre-E4 key order (temperature before max_tokens) so an all-default
    # request serializes byte-for-byte as before — http_json dumps dicts in insertion order.
    assert [k for k in b if k in ("temperature", "max_tokens")] == ["temperature", "max_tokens"]
    # A capability profile overrides the catalog's structured-output flag in both directions.
    assert "response_format" not in mk({"structured_outputs": False})   # catalog True, override wins
    over_true = panel.build_request("x/y", msgs, panel.REPORT_SCHEMA, "reviewer_report",
                                    False, "NORMAL", {"structured_outputs": True})[0]
    assert "response_format" in over_true                               # catalog False, override wins


def t_capability_driven_request_flow():
    # assign records each role's capability profile, and prepare shapes the request from it:
    # a temperature-forbidden pin drops `temperature`; a mandatory-reasoning pin gets a
    # reasoning budget + raised max_tokens; an un-overridden role keeps the defaults (E4-S1).
    repo = fresh_repo()
    (repo / ".adversarial-review.capabilities.yml").write_text(
        "openai/gpt-5.6-luna-pro:\n  temperature: forbidden\n"
        "qwen/qwen3.8-max:\n  reasoning: mandatory\n  max_tokens_floor: 20000\n")
    sh(["panel.py", "init", "--risk", "NORMAL", "--dev-providers", "anthropic"], repo)
    sh(["panel.py", "assign",
        "--pin", "correctness=openai/gpt-5.6-luna-pro",
        "--pin", "security=qwen/qwen3.8-max"], repo)
    run = latest_run(repo)
    plan = read(run / "panel" / "plan.json")
    assert plan["roles"]["correctness"]["capability"]["temperature"] == "forbidden"
    assert plan["roles"]["correctness"]["capability_source"] == "override"
    assert plan["roles"]["security"]["capability"]["reasoning"] == "mandatory"
    sh(["panel.py", "prepare", "--context-file", "context.md"], repo)
    corr = read(run / "panel" / "requests" / "correctness.json")
    assert "temperature" not in corr, corr
    sec = read(run / "panel" / "requests" / "security.json")
    assert sec.get("reasoning") and sec["max_tokens"] >= 20000, sec
    # an un-pinned, un-overridden role keeps the default temperature and base max_tokens
    tq = read(run / "panel" / "requests" / "test_quality.json")
    assert "temperature" in tq, tq


def t_cost_cap_aborts_panel():
    # A hard per-run cost ceiling aborts the remaining reviewers and BLOCKS — a verbose model
    # can raise the bill but never buy a silent partial PASS (E4-S2).
    mock_router.reset()
    mock_router.STATE["reviewer_cost"] = 0.50   # $0.50 per reviewer
    try:
        repo = fresh_repo()
        sh(["panel.py", "init", "--risk", "NORMAL", "--dev-providers", "anthropic"], repo)
        sh(["panel.py", "assign"], repo)
        env = {**ENV, "AR_MAX_COST_USD": "0.60"}   # trips after the 2nd reviewer ($1.00 >= $0.60)
        r = sh(["panel.py", "run", "--context-file", "context.md"], repo, expect=2, env=env)
        assert "cost cap" in r.stderr.lower(), r.stderr
        run = latest_run(repo)
        abort = read(run / "cost_abort.json")
        assert abort["cap_usd"] == 0.60 and abort["not_run"], abort
        sh(["aggregate.py"], repo, expect=2, env=env)   # BLOCKED
        vj = read(run / "verdict.json")
        assert vj["verdict"] == "BLOCKED"
        assert vj["coverage"]["cost_aborted"] is True
        assert any("cost cap" in reason.lower() for reason in vj["reasons"]), vj["reasons"]
    finally:
        mock_router.reset()


def t_cost_accounting_surfaced():
    # Total reviewer cost is summed from meta and surfaced in the verdict coverage; a run under
    # the cap is not aborted (E4-S2).
    mock_router.reset()
    mock_router.STATE["reviewer_cost"] = 0.02
    try:
        repo = fresh_repo()
        sh(["panel.py", "init", "--risk", "NORMAL", "--dev-providers", "anthropic"], repo)
        sh(["panel.py", "assign"], repo)
        sh(["panel.py", "run", "--context-file", "context.md"], repo)   # default $20 cap, no trip
        run = latest_run(repo)
        sh(["aggregate.py"], repo, expect=None)   # verdict may BLOCK on the canned finding; cost still surfaces
        cov = read(run / "verdict.json")["coverage"]
        assert abs(cov["cost_usd"] - 0.08) < 1e-6, cov["cost_usd"]   # 4 NORMAL reviewers * $0.02
        assert cov["cost_aborted"] is False
        # the enforced ceiling + its source are recorded and surfaced, not just total spend (E4-S2)
        assert cov["cost_cap_usd"] == 20.0 and cov["cost_cap_source"] == "default", cov
        assert read(run / "cost_policy.json")["cap_usd"] == 20.0
    finally:
        mock_router.reset()


def t_cost_cap_rejects_invalid_values():
    # A non-finite or negative cap is rejected loudly — at policy load and at runtime resolution —
    # so a config typo can never silently disable the spending guard (E4-S2).
    import panel
    import _common
    for bad in ("nan", "inf", "-inf", "-5", "-0.01"):
        os.environ["AR_MAX_COST_USD"] = bad
        try:
            panel.cost_cap()
            raise AssertionError(f"cost_cap accepted {bad!r}")
        except SystemExit:
            pass
        finally:
            os.environ.pop("AR_MAX_COST_USD", None)
    try:
        os.environ["AR_MAX_COST_USD"] = "none"       # documented disable token
        assert panel.cost_cap() == (None, "env")
        os.environ["AR_MAX_COST_USD"] = "12.5"        # finite value + its source
        assert panel.cost_cap() == (12.5, "env")
    finally:
        os.environ.pop("AR_MAX_COST_USD", None)       # never leak the env var if an assert fails
    for bad in (float("nan"), float("inf"), -1, "nan", "-2"):
        try:
            _common._validate_policy({"max_cost_usd": bad}, "policy")
            raise AssertionError(f"policy load accepted {bad!r}")
        except SystemExit:
            pass
    _common._validate_policy({"max_cost_usd": "off"}, "policy")   # disable token OK at load
    _common._validate_policy({"max_cost_usd": 15}, "policy")      # finite non-negative OK


def t_retry_accumulates_billed_cost():
    # A malformed-JSON retry is a second billed call; call_reviewer accumulates both attempts'
    # usage so the cap and coverage don't undercount actual spend (E4-S2).
    import _common
    mock_router.reset()
    mock_router.STATE["reviewer_cost"] = 0.10
    try:
        repo = fresh_repo()
        sh(["panel.py", "init", "--risk", "NORMAL", "--dev-providers", "anthropic"], repo)
        sh(["panel.py", "assign"], repo)
        run = latest_run(repo)
        plan = read(run / "panel" / "plan.json")
        # force the correctness reviewer's first attempt to be malformed → one internal retry
        mock_router.STATE["malformed_once"] = {plan["roles"]["correctness"]["model"]}
        sh(["panel.py", "run", "--context-file", "context.md"], repo)
        # two billed $0.10 calls recorded as $0.20 for that role; single-call roles stay $0.10
        assert abs(_common.meta_cost(read(run / "panel" / "meta" / "correctness.json")) - 0.20) < 1e-9
        assert abs(_common.meta_cost(read(run / "panel" / "meta" / "security.json")) - 0.10) < 1e-9
    finally:
        mock_router.reset()


def t_cost_cap_enforced_in_rebuttal():
    # The cost cap governs the rebuttal phase too: a panel that finished just under the ceiling
    # cannot spend past it during rebuttal (E4-S2).
    mock_router.reset()
    mock_router.STATE["reviewer_cost"] = 0.20
    try:
        repo = fresh_repo()
        sh(["panel.py", "init", "--risk", "SENSITIVE", "--dev-providers", "anthropic"], repo)
        sh(["panel.py", "assign"], repo)
        # 6 SENSITIVE reviewers * $0.20 = $1.20 total; a $1.10 cap lets the panel finish (last
        # pre-call check sees $1.00 < $1.10) yet is exceeded ($1.20) before the rebuttal round.
        env = {**ENV, "AR_MAX_COST_USD": "1.10"}
        sh(["panel.py", "run", "--context-file", "context.md"], repo, env=env)
        run = latest_run(repo)
        assert not (run / "cost_abort.json").exists()   # the panel itself did not abort
        # rebuttal is required (security raised a high finding) but the cap is already exceeded
        r = sh(["panel.py", "rebuttal"], repo, expect=2, env=env)
        assert "cost cap" in r.stderr.lower(), r.stderr
        abort = read(run / "cost_abort.json")
        assert abort["phase"] == "rebuttal"
        # skipped work is the unrun REBUTTAL roles, not an empty panel list (all reports exist)
        assert abort["not_run"], abort
    finally:
        mock_router.reset()


def t_cost_cap_persisted_across_phases():
    # The run's cost ceiling is authoritative for later phases: rebuttal reads the cap panel.py
    # persisted to cost_policy.json, so changing AR_MAX_COST_USD after the panel can neither
    # disable nor raise it out from under the run (E4-S2).
    mock_router.reset()
    mock_router.STATE["reviewer_cost"] = 0.20
    try:
        repo = fresh_repo()
        sh(["panel.py", "init", "--risk", "SENSITIVE", "--dev-providers", "anthropic"], repo)
        sh(["panel.py", "assign"], repo)
        # $1.10 cap: the 6-reviewer panel finishes at $1.20 (last check saw $1.00 < $1.10)
        sh(["panel.py", "run", "--context-file", "context.md"], repo,
           env={**ENV, "AR_MAX_COST_USD": "1.10"})
        run = latest_run(repo)
        assert not (run / "cost_abort.json").exists()
        assert read(run / "cost_policy.json")["cap_usd"] == 1.10
        # DISABLE the cap in the environment; rebuttal must still honor the persisted $1.10
        r = sh(["panel.py", "rebuttal"], repo, expect=2, env={**ENV, "AR_MAX_COST_USD": "none"})
        assert "cost cap" in r.stderr.lower(), r.stderr
        abort = read(run / "cost_abort.json")
        assert abort["phase"] == "rebuttal" and abort["cap_usd"] == 1.10, abort
        # the persisted policy was not overwritten by the later 'none'
        assert read(run / "cost_policy.json")["cap_usd"] == 1.10
    finally:
        mock_router.reset()


def t_concurrence_cost_recorded():
    # cmd_concur makes a paid call; its cost is recorded under panel/meta so it counts toward
    # panel_cost() and the verdict's coverage.cost_usd (E4-S2).
    import _common
    mock_router.reset()
    mock_router.STATE["reviewer_cost"] = 0.05
    try:
        repo = fresh_repo()
        sh(["panel.py", "init", "--risk", "SENSITIVE", "--dev-providers", "anthropic"], repo)
        sh(["panel.py", "assign"], repo)
        (repo / "fp.md").write_text("Finding X is a false positive because the check exists.")
        sh(["panel.py", "concur", "--prompt-file", "fp.md"], repo)
        run = latest_run(repo)
        metas = sorted((run / "panel" / "meta").glob("concurrence.*.json"))
        assert len(metas) == 1, metas
        assert abs(_common.meta_cost(read(metas[0])) - 0.05) < 1e-9, read(metas[0])
    finally:
        mock_router.reset()


def t_mock_router_response_provider_override():
    # A response_provider override is served in place of the default canned report and flows
    # through panel run + ingest (E0-S1); default behavior is preserved when it returns None.
    mock_router.reset()
    sentinel = "SENTINEL-OVERRIDE-9f3c"

    def provider(meta):
        if meta["kind"] == "report" and meta["role"] == "security":
            rep = mock_router._report("security", meta["model"])
            rep["summary"] = sentinel
            return rep
        return None

    mock_router.STATE["response_provider"] = provider
    try:
        repo = fresh_repo()
        sh(["panel.py", "init", "--risk", "NORMAL", "--dev-providers", "anthropic"], repo)
        sh(["panel.py", "assign"], repo)
        sh(["panel.py", "run", "--context-file", "context.md"], repo)
        run = latest_run(repo)
        assert read(run / "panel" / "security.json")["summary"] == sentinel
        # a non-overridden role still gets the default canned report verbatim
        correctness = read(run / "panel" / "correctness.json")
        assert correctness == mock_router._report("correctness", correctness["model_id"])
    finally:
        mock_router.reset()


def t_mock_router_reset():
    # reset() restores STATE to defaults, including clearing the response provider (E0-S1).
    mock_router.STATE["fail_models"].add("x/y")
    mock_router.STATE["calls"]["z"] = 3
    mock_router.STATE["concur_agrees"] = False
    mock_router.STATE["response_provider"] = lambda meta: None
    mock_router.reset()
    assert mock_router.STATE["fail_models"] == set()
    assert mock_router.STATE["calls"] == {}
    assert mock_router.STATE["concur_agrees"] is True
    assert mock_router.STATE["response_provider"] is None


def t_pyproject_metadata_complete():
    # PyPI-listing metadata must stay present (E2-S2). Pure offline file read.
    pp = (SKILL / "pyproject.toml").read_text(encoding="utf-8")
    for key in ("name =", "version =", "description =", "readme =", "license =",
                "requires-python =", "keywords =", "classifiers =", "[project.urls]",
                "[project.scripts]", "Changelog ="):
        assert key in pp, f"pyproject.toml missing {key!r}"


def _workflow_job_block(wf_text, job):
    # Return the lines of one job under `jobs:` (the `  <job>:` line and everything indented
    # beneath it), with full-line comments dropped. The suite is stdlib-only, so this is a small
    # indentation scanner rather than a YAML import — enough to assert that a setting lives in a
    # specific job, not merely somewhere in the file or inside a comment.
    lines = wf_text.splitlines()
    in_jobs = capturing = False
    out = []
    for ln in lines:
        stripped = ln.strip()
        indent = len(ln) - len(ln.lstrip(" "))
        if not in_jobs:
            if stripped == "jobs:" and indent == 0:
                in_jobs = True
            continue
        if not capturing:
            if indent == 2 and stripped == f"{job}:":
                capturing = True
            continue
        # Stop at the next sibling job (indent 2, "name:") or a new top-level key (indent 0).
        if stripped and not stripped.startswith("#"):
            if indent == 0:
                break
            if indent == 2 and stripped.endswith(":") and not stripped.startswith("-"):
                break
        out.append(ln)
    return [ln for ln in out if not ln.strip().startswith("#")]


def t_release_workflow_uses_trusted_publishing():
    # The release workflow must publish on v* tags via OIDC Trusted Publishing with NO stored
    # token, and the OIDC permission + pypi environment + publish step must live in the publish
    # JOB — not merely somewhere in the file or in a comment. Substring-only checks would pass if
    # a token were moved into a comment or an unrelated job, so this parses per-job structure and
    # also guards the version==tag gate and the 3.9 wheel smoke (E2-S2).
    wf = (SKILL / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
    assert re.search(r'(?m)^\s*tags:\s*\[\s*"v\*"\s*\]', wf), "release.yml must trigger on v* tags"
    assert "PYPI_API_TOKEN" not in wf and re.search(r'(?m)^\s*password:\s*\S', wf) is None, \
        "no stored PyPI token — Trusted Publishing only"

    publish = "\n".join(_workflow_job_block(wf, "publish"))
    assert publish, "release.yml has no publish job"
    assert re.search(r'(?m)^\s*environment:\s*pypi\b', publish), \
        "publish job must run in the protected 'pypi' environment"
    assert re.search(r'(?m)^\s*id-token:\s*write\b', publish), \
        "publish job must request job-scoped id-token: write (OIDC)"
    assert "pypa/gh-action-pypi-publish" in publish, "publish job must use the PyPA publish action"

    build = "\n".join(_workflow_job_block(wf, "build"))
    assert "GITHUB_REF_NAME" in build and "does not match the pushed tag" in build, \
        "build job must fail when the built version disagrees with the pushed tag"

    smoke = "\n".join(_workflow_job_block(wf, "smoke"))
    assert '"3.9"' in smoke, "smoke job must exercise the installed wheel on the declared 3.9 floor"
    assert "ar-mcp" in smoke and "--help" in smoke, \
        "smoke job must run the console entry points, not just test their executable bit"


def t_version_matches_changelog():
    # The pyproject version must equal the NEWEST released CHANGELOG heading, and
    # `## [Unreleased]` must sit above every release heading — guards the release ritual
    # (E0-S3). A weaker "version appears somewhere" check would pass on a stale heading.
    pyproj = (SKILL / "pyproject.toml").read_text(encoding="utf-8")
    m = re.search(r'(?m)^\s*version\s*=\s*"([^"]+)"', pyproj)
    assert m, "no version in pyproject.toml"
    version = m.group(1)
    changelog = (SKILL / "CHANGELOG.md").read_text(encoding="utf-8")
    headings = re.findall(r'(?m)^##\s+\[([^\]]+)\]', changelog)
    assert headings, "CHANGELOG has no '## [..]' headings"
    assert headings[0] == "Unreleased", (
        f"first CHANGELOG heading must be '## [Unreleased]', got {headings[0]!r}")
    releases = [h for h in headings if h != "Unreleased"]
    assert releases, "CHANGELOG has no released section under ## [Unreleased]"
    assert releases[0] == version, (
        f"pyproject version {version!r} must match the newest CHANGELOG release "
        f"heading {releases[0]!r}")


def t_docs_gate_matrix_matches_code():
    # Every floor gate in gate.py's MINIMUM_GATES must be documented in references/gates.md at
    # a tier that includes the run tier — guards code/doc drift (E5-S3). Doc-vs-code, not doc-vs-doc.
    import gate as _gate
    gates_md = (SKILL / "references" / "gates.md").read_text(encoding="utf-8")
    documented = {mo.group(1): mo.group(2)
                  for mo in re.finditer(r'(?m)^\|\s*`([a-z0-9_-]+)`\s*\|\s*([^|]+?)\s*\|', gates_md)}

    def tiers_for(cell):
        t = cell.upper()
        if t.startswith("ALL"):
            return {"NORMAL", "SENSITIVE", "CRITICAL"}
        if "SENSITIVE+" in t:
            return {"SENSITIVE", "CRITICAL"}
        if "CRITICAL" in t:
            return {"CRITICAL"}
        return set()

    for tier, gates in _gate.MINIMUM_GATES.items():
        for g in gates:
            assert g in documented, f"gate '{g}' (MINIMUM_GATES[{tier}]) is not in the gates.md matrix"
            covered = tiers_for(documented[g])
            assert tier in covered, (f"gate '{g}' documented as '{documented[g].strip()}' in gates.md "
                                     f"does not cover run tier {tier}")


def t_docs_no_hardcoded_scenario_counts():
    # The README must not hardcode a test-scenario count — it drifts (see the de-hardcode history).
    readme = (SKILL / "README.md").read_text(encoding="utf-8")
    m = re.search(r"\b\d+[\s-]+(?:end-to-end[\s-]+)?scenarios?\b", readme)
    assert not m, f"README hardcodes a scenario count: {m.group(0)!r} — describe it without a number"


def t_corpus_cases_valid_and_cover_categories():
    # Every committed corpus case validates, and the seed corpus covers each defect category
    # plus >=2 clean cases — so the offline meta-eval harness (E1-S3) has something to run on
    # day one. Cases are data; this guards the format without touching harness code.
    sys.path.insert(0, str(SKILL / "evals"))
    import corpus_schema as cs
    corpus = str(SKILL / "evals" / "corpus")
    n, errs = cs.validate_corpus(corpus)
    assert not errs, "corpus invalid:\n" + "\n".join(errs)
    assert n >= 6, f"expected >=6 seed cases, found {n}"
    cats = {}
    for d in sorted(os.listdir(corpus)):
        cd = os.path.join(corpus, d)
        if not os.path.isdir(cd):
            continue
        meta = json.loads(Path(cd, "meta.json").read_text(encoding="utf-8"))
        cats[meta["category"]] = cats.get(meta["category"], 0) + 1
    for required in ("security", "correctness", "test_quality", "output_fidelity"):
        assert cats.get(required), f"corpus missing a {required} case"
    assert cats.get("clean", 0) >= 2, f"corpus needs >=2 clean cases, has {cats.get('clean', 0)}"


def t_corpus_validator_rejects_malformed():
    # The validator must reject each class of corruption — silence is not validation
    # (mirrors the strict policy-file parsing in _common.py).
    sys.path.insert(0, str(SKILL / "evals"))
    import corpus_schema as cs
    d = Path(tempfile.mkdtemp(prefix="ar-corpus-bad-"))
    try:
        bad = d / "bad-case"
        bad.mkdir()
        (bad / "meta.json").write_text(json.dumps({
            "id": "WRONG", "title": "x", "tier": "NORMAL", "category": "nope",
            "language": "python", "source": "seeded", "extra": 1}))
        (bad / "context.md").write_text("x")
        (bad / "expected.json").write_text(json.dumps({
            "defects": [{"defect_id": "d", "must_detect": True,
                         "locators": [{"file": "a", "line_range": [9, 2]}],
                         "root_cause_tags": ["t"], "severity_floor": "HIGH"}],
            "fp_budget": -1}))
        errs = cs.validate_case(str(bad))
        joined = " | ".join(errs)
        assert any("category" in e for e in errs), joined
        assert any("directory name" in e for e in errs), joined
        assert any("unexpected field" in e for e in errs), joined
        assert any("severity_floor" in e for e in errs), joined
        assert any("start > end" in e for e in errs), joined
        assert any("fp_budget" in e for e in errs), joined

        empty = d / "empty-case"
        empty.mkdir()
        assert cs.validate_case(str(empty)), "missing-file case should be rejected"

        incoh = d / "incoh"
        incoh.mkdir()
        (incoh / "meta.json").write_text(json.dumps({
            "id": "incoh", "title": "x", "tier": "NORMAL", "category": "clean",
            "language": "python", "source": "seeded"}))
        (incoh / "context.md").write_text("x")
        (incoh / "expected.json").write_text(json.dumps({
            "defects": [{"defect_id": "d", "must_detect": True,
                         "locators": [{"file": "a", "line_range": [1, 2]}],
                         "root_cause_tags": ["t"], "severity_floor": "high"}],
            "fp_budget": 0}))
        assert any("clean" in e for e in cs.validate_case(str(incoh))), \
            "clean-category-with-defect should be rejected"

        # non-object JSON root (valid JSON, but an array/scalar is malformed, not skipped)
        nonobj = d / "nonobj"
        nonobj.mkdir()
        (nonobj / "meta.json").write_text("[]")
        (nonobj / "context.md").write_text("x")
        (nonobj / "expected.json").write_text(json.dumps({"defects": [], "fp_budget": 1}))
        assert any("expected object" in e for e in cs.validate_case(str(nonobj))), \
            "non-object meta.json root should be rejected"

        # unknown top-level field in expected.json (strict EXPECTED_SCHEMA)
        stray = d / "stray"
        stray.mkdir()
        (stray / "meta.json").write_text(json.dumps({
            "id": "stray", "title": "x", "tier": "NORMAL", "category": "clean",
            "language": "python", "source": "seeded"}))
        (stray / "context.md").write_text("x")
        (stray / "expected.json").write_text(json.dumps({
            "defects": [], "fp_budget": 1, "bogus_key": 1}))
        assert any("unexpected field" in e for e in cs.validate_case(str(stray))), \
            "unknown top-level expected field should be rejected"

        # truthy non-object scripts (a schema type error) must fall through _expected_semantics
        # cleanly, not raise AttributeError on .get() (CodeRabbit, PR #45)
        scriptstr = d / "scriptstr"
        scriptstr.mkdir()
        (scriptstr / "meta.json").write_text(json.dumps({
            "id": "scriptstr", "title": "x", "tier": "NORMAL", "category": "clean",
            "language": "python", "source": "seeded"}))
        (scriptstr / "context.md").write_text("some context")
        (scriptstr / "expected.json").write_text(json.dumps({
            "defects": [], "fp_budget": 1, "scripts": "invalid"}))
        errs_ss = cs.validate_case(str(scriptstr))   # regression: must return errors, never raise
        assert any("scripts" in e for e in errs_ss), errs_ss

        # clean category carrying ANY defect (even non-must_detect) is contradictory ground truth
        cleandef = d / "cleandef"
        cleandef.mkdir()
        (cleandef / "meta.json").write_text(json.dumps({
            "id": "cleandef", "title": "x", "tier": "NORMAL", "category": "clean",
            "language": "python", "source": "seeded"}))
        (cleandef / "context.md").write_text("some context")
        (cleandef / "expected.json").write_text(json.dumps({
            "defects": [{"defect_id": "d", "must_detect": False,
                         "locators": [{"file": "a", "line_range": [1, 2]}],
                         "root_cause_tags": ["t"], "severity_floor": "low"}],
            "fp_budget": 1}))
        assert any("empty defects" in e for e in cs.validate_case(str(cleandef))), \
            "clean category with any defect should be rejected"

        # non-positive (non-1-indexed) locator line
        nonpos = d / "nonpos"
        nonpos.mkdir()
        (nonpos / "meta.json").write_text(json.dumps({
            "id": "nonpos", "title": "x", "tier": "NORMAL", "category": "security",
            "language": "python", "source": "seeded"}))
        (nonpos / "context.md").write_text("some context")
        (nonpos / "expected.json").write_text(json.dumps({
            "defects": [{"defect_id": "d", "must_detect": True,
                         "locators": [{"file": "a", "line_range": [0, 5]}],
                         "root_cause_tags": ["t"], "severity_floor": "high"}],
            "fp_budget": 1}))
        assert any("1-indexed" in e for e in cs.validate_case(str(nonpos))), \
            "non-positive locator line should be rejected"

        # whitespace-only context.md (non-zero bytes, but no substantive content)
        blankctx = d / "blankctx"
        blankctx.mkdir()
        (blankctx / "meta.json").write_text(json.dumps({
            "id": "blankctx", "title": "x", "tier": "NORMAL", "category": "clean",
            "language": "python", "source": "seeded"}))
        (blankctx / "context.md").write_text("   \n\t\n")
        (blankctx / "expected.json").write_text(json.dumps({"defects": [], "fp_budget": 1}))
        assert any("blank" in e for e in cs.validate_case(str(blankctx))), \
            "whitespace-only context.md should be rejected"
    finally:
        shutil.rmtree(d, ignore_errors=True)


def t_trends_dashboard():
    # E5-S2: the cross-run trends tool reads a directory of immutable run artifacts and emits a
    # self-contained HTML dashboard + a deterministic JSON rollup. It must skip malformed runs,
    # tolerate old runs missing cost accounting, never write into a run dir, carry no external
    # network references, and produce the same rollup regardless of the (HTML-only) stamp.
    sys.path.insert(0, str(SKILL / "integrations"))
    import trends

    root = Path(tempfile.mkdtemp(prefix="ar-trends-"))
    try:
        runs = root / "runs"

        def mkrun(rid, body):
            d = runs / rid
            d.mkdir(parents=True)
            (d / "verdict.json").write_text(json.dumps(body))

        mkrun("run-a", {"verdict": "PASS", "risk": "NORMAL", "run_id": "run-a",
                        "computed_at": "2026-08-10T10:00:00Z",
                        "counts": {"findings_high_critical": 0, "unresolved": 0},
                        "coverage": {"findings": {"raised": 1, "triaged": 1},
                                     "gates": {"passed": [1, 2, 3], "required": [1, 2, 3]},
                                     "cost_usd": 0.21}})
        mkrun("run-b", {"verdict": "FAIL", "risk": "SENSITIVE", "run_id": "run-b",
                        "computed_at": "2026-08-12T10:00:00Z",
                        "counts": {"findings_high_critical": 2, "unresolved": 1},
                        "coverage": {"findings": {"raised": 5, "triaged": 4},
                                     "gates": {"passed": [1, 2], "required": [1, 2, 3]},
                                     "cost_usd": 0.63}})
        # run-c predates cost accounting (E4) — no cost_usd; it must still chart, cost = unknown.
        mkrun("run-c", {"verdict": "BLOCKED", "risk": "CRITICAL", "run_id": "run-c",
                        "computed_at": "2026-08-14T10:00:00Z",
                        "counts": {"findings_high_critical": 1},
                        "coverage": {"findings": {"raised": 1, "triaged": 1}}})
        bad = runs / "run-bad"
        bad.mkdir()
        (bad / "verdict.json").write_text("not json {{{")

        before = {str(p): p.read_bytes() for p in runs.rglob("verdict.json")}

        out = root / "out"
        records, summary, skipped = trends.build(str(runs), str(out), generated_at="test")

        assert len(records) == 3, [r["run_id"] for r in records]
        assert any("run-bad" in s for s in skipped), skipped
        assert summary["by_verdict"] == {"PASS": 1, "FAIL": 1, "BLOCKED": 1}, summary
        assert summary["pass_rate"] == round(1 / 3, 4), summary
        assert abs(summary["total_cost_usd"] - 0.84) < 1e-9, summary
        assert summary["runs_with_cost"] == 2, summary
        # sorted chronologically by computed_at; run-c carries no cost (unknown, not zero)
        assert records[0]["run_id"] == "run-a" and records[-1]["run_id"] == "run-c"
        assert records[-1]["cost_usd"] is None, records[-1]

        assert (out / "trends.json").is_file() and (out / "trends.html").is_file()
        assert not any((runs / r / "trends.json").exists() for r in ("run-a", "run-b", "run-c"))

        htmltext = (out / "trends.html").read_text(encoding="utf-8")
        for needle in ("http://", "https://", "src=", "cdn", "<script"):
            assert needle not in htmltext, f"HTML not self-contained: found {needle!r}"
        assert "run-a" in htmltext and "FAIL" in htmltext

        after = {str(p): p.read_bytes() for p in runs.rglob("verdict.json")}
        assert before == after, "trends must not modify run dirs (audit integrity)"

        out2 = root / "out2"
        trends.build(str(runs), str(out2), generated_at="DIFFERENT-STAMP")
        assert (out / "trends.json").read_text() == (out2 / "trends.json").read_text(), \
            "rollup must be deterministic (stamp lives only in HTML)"
    finally:
        shutil.rmtree(root, ignore_errors=True)


def t_trends_rejects_nonfinite_cost():
    # E5-S2 hardening: json.load() parses NaN/Infinity by default. A non-finite cost_usd must
    # degrade to "unknown" (None) and never enter the rollup — otherwise sum()/round() poison
    # every cost figure on the dashboard.
    sys.path.insert(0, str(SKILL / "integrations"))
    import trends

    root = Path(tempfile.mkdtemp(prefix="ar-trends-nan-"))
    try:
        runs = root / "runs"

        def mkrun(rid, verdict_text):
            d = runs / rid
            d.mkdir(parents=True)
            (d / "verdict.json").write_text(verdict_text)

        mkrun("run-ok", json.dumps({"verdict": "PASS", "run_id": "run-ok",
                                    "computed_at": "2026-08-10T10:00:00Z",
                                    "coverage": {"cost_usd": 0.50}}))
        # raw JSON tokens json.load accepts but that must not reach the rollup
        mkrun("run-nan", '{"verdict": "PASS", "run_id": "run-nan", '
                         '"computed_at": "2026-08-11T10:00:00Z", "coverage": {"cost_usd": NaN}}')
        mkrun("run-inf", '{"verdict": "PASS", "run_id": "run-inf", '
                         '"computed_at": "2026-08-12T10:00:00Z", "coverage": {"cost_usd": Infinity}}')
        # a huge int: float(10**400) AND math.isfinite(10**400) both raise OverflowError, which
        # would abort the whole dashboard if the cost guard converted before rejecting.
        mkrun("run-huge", '{"verdict": "PASS", "run_id": "run-huge", '
                          '"computed_at": "2026-08-13T10:00:00Z", "coverage": {"cost_usd": %s}}'
                          % ("9" * 400))

        records, summary, _ = trends.build(str(runs), str(root / "out"))
        by_id = {r["run_id"]: r for r in records}
        assert by_id["run-nan"]["cost_usd"] is None, by_id["run-nan"]
        assert by_id["run-inf"]["cost_usd"] is None, by_id["run-inf"]
        assert by_id["run-huge"]["cost_usd"] is None, by_id["run-huge"]
        assert by_id["run-ok"]["cost_usd"] == 0.50, by_id["run-ok"]
        # all four runs chart; only the finite cost is counted; the total stays finite and exact
        assert len(records) == 4, [r["run_id"] for r in records]
        assert summary["runs_with_cost"] == 1, summary
        assert summary["total_cost_usd"] == 0.5, summary
    finally:
        shutil.rmtree(root, ignore_errors=True)


def t_trends_aggregate_cost_overflow():
    # E5-S2 hardening: individual costs pass _finite_cost yet their SUM can overflow to inf;
    # round(inf) stays inf and json.dump would emit non-standard `Infinity`. The rollup must
    # degrade total_cost_usd to None while still counting the runs, and trends.json must parse.
    sys.path.insert(0, str(SKILL / "integrations"))
    import trends

    root = Path(tempfile.mkdtemp(prefix="ar-trends-ovf-"))
    try:
        runs = root / "runs"

        def mkrun(rid, cost, at):
            d = runs / rid
            d.mkdir(parents=True)
            (d / "verdict.json").write_text(json.dumps(
                {"verdict": "PASS", "run_id": rid, "computed_at": at,
                 "coverage": {"cost_usd": cost}}))

        mkrun("run-a", 1e308, "2026-08-10T10:00:00Z")   # finite individually
        mkrun("run-b", 1e308, "2026-08-11T10:00:00Z")   # sum(1e308, 1e308) -> inf

        out = root / "out"
        records, summary, _ = trends.build(str(runs), str(out))
        assert len(records) == 2 and summary["runs_with_cost"] == 2, summary  # both counted
        assert summary["total_cost_usd"] is None, summary                     # overflow degraded
        raw = (out / "trends.json").read_text(encoding="utf-8")
        assert "Infinity" not in raw, raw                                     # standard JSON only
    finally:
        shutil.rmtree(root, ignore_errors=True)


def t_trends_tolerates_unencodable_text():
    # E5-S2 hardening: json.load accepts lone surrogates (e.g. "\ud800") in text fields; str() and
    # html.escape() preserve them, and the UTF-8 write of the HTML report then raises
    # UnicodeEncodeError mid-stream. Such a run must degrade (sanitized text), not crash the tool.
    sys.path.insert(0, str(SKILL / "integrations"))
    import trends

    root = Path(tempfile.mkdtemp(prefix="ar-trends-uni-"))
    try:
        runs = root / "runs"
        d = runs / "run-a"
        d.mkdir(parents=True)
        # json.dumps escapes the surrogate to ASCII on disk; json.load restores it on read
        (d / "verdict.json").write_text(json.dumps(
            {"verdict": "PASS", "run_id": "bad\ud800id", "risk": "NOR\ud800MAL",
             "computed_at": "2026-08-10T10:00:00Z", "coverage": {"cost_usd": 0.1}}))

        out = root / "out"
        records, summary, _ = trends.build(str(runs), str(out))  # must not raise
        assert len(records) == 1, records
        # both outputs fully written and re-readable as UTF-8 (no lone surrogate survived)
        assert (out / "trends.json").read_text(encoding="utf-8")
        htext = (out / "trends.html").read_text(encoding="utf-8")
        assert "PASS" in htext
        assert "\ud800" not in records[0]["run_id"] and "\ud800" not in records[0]["risk"]
    finally:
        shutil.rmtree(root, ignore_errors=True)


def t_trends_refuses_write_into_run_dir():
    # E5-S2 hardening: the tool guarantees it is read-only over run dirs. build() must REFUSE
    # (ValueError, before creating anything) when --out-dir resolves to a run dir or under one,
    # so it can never overwrite an immutable audit artifact.
    sys.path.insert(0, str(SKILL / "integrations"))
    import trends

    root = Path(tempfile.mkdtemp(prefix="ar-trends-ro-"))
    try:
        runs = root / "runs"
        rd = runs / "run-a"
        rd.mkdir(parents=True)
        (rd / "verdict.json").write_text(json.dumps(
            {"verdict": "PASS", "run_id": "run-a", "computed_at": "2026-08-10T10:00:00Z",
             "coverage": {"cost_usd": 0.1}}))
        before = (rd / "verdict.json").read_bytes()

        def refuses(root_arg, out_arg, why):
            try:
                trends.build(root_arg, out_arg)
            except ValueError:
                return
            raise AssertionError("expected ValueError: " + why)

        refuses(str(runs), str(rd), "out-dir == the run dir itself")
        refuses(str(runs), str(rd / "sub"), "out-dir nested under the run dir")
        refuses(str(rd), str(rd), "root is the single run dir and out-dir == root")

        # nothing was written into the artifact; verdict.json is byte-identical
        assert not (rd / "trends.json").exists() and not (rd / "trends.html").exists()
        assert not (rd / "sub").exists()
        assert (rd / "verdict.json").read_bytes() == before

        # the sibling collection dir (holds run dirs but is not one) remains a legal target
        out = root / "out"
        records, _, _ = trends.build(str(runs), str(out))
        assert (out / "trends.json").is_file() and len(records) == 1, records
    finally:
        shutil.rmtree(root, ignore_errors=True)


def t_trends_template_token_injection_safe():
    # E5-S2 hardening: render_html substitutes @@TOKEN@@ placeholders in ONE regex pass. A crafted
    # run_id like "@@SKIPS@@" survives _esc (html.escape leaves "@" alone); a sequential
    # str.replace loop would re-scan the substituted ROWS value and strip/rewrite it. One pass
    # replaces each placeholder exactly once and never re-reads inserted values.
    sys.path.insert(0, str(SKILL / "integrations"))
    import trends

    root = Path(tempfile.mkdtemp(prefix="ar-trends-tok-"))
    try:
        runs = root / "runs"
        d = runs / "run-a"
        d.mkdir(parents=True)
        (d / "verdict.json").write_text(json.dumps(
            {"verdict": "PASS", "run_id": "run@@SKIPS@@x", "computed_at": "2026-08-10T10:00:00Z",
             "coverage": {"cost_usd": 0.1}}))
        out = root / "out"
        records, _, _ = trends.build(str(runs), str(out))
        assert records[0]["run_id"] == "run@@SKIPS@@x", records[0]
        htmltext = (out / "trends.html").read_text(encoding="utf-8")
        # the literal token from the run_id survives (the template's own @@SKIPS@@ is gone);
        # under the old sequential-replace loop it would have been stripped to "run x".
        assert "run@@SKIPS@@x" in htmltext, "token in run_id was re-substituted"
    finally:
        shutil.rmtree(root, ignore_errors=True)


def t_trends_tolerates_unreadable_root():
    # E5-S2 hardening: an unreadable run root must degrade to an empty report, not crash — the
    # tool's "never crashes on partial/malformed input" contract. os.listdir can raise OSError
    # (permissions); build() must tolerate it. (Simulated: chmod is a no-op under root/CI.)
    sys.path.insert(0, str(SKILL / "integrations"))
    import trends

    root = Path(tempfile.mkdtemp(prefix="ar-trends-perm-"))
    try:
        runs = root / "runs"
        runs.mkdir()
        real_listdir = os.listdir

        def boom(path):
            if str(path) == str(runs):
                raise PermissionError(13, "Permission denied")
            return real_listdir(path)

        os.listdir = boom
        try:
            records, summary, _ = trends.build(str(runs), str(root / "out"))  # must not raise
        finally:
            os.listdir = real_listdir
        assert records == [] and summary["total_runs"] == 0, (records, summary)
        assert (root / "out" / "trends.json").is_file()
    finally:
        shutil.rmtree(root, ignore_errors=True)


def _import_pr_publish():
    sys.path.insert(0, str(SKILL / "integrations"))
    import pr_publish
    return pr_publish


def _write_run(path, verdict="PASS", risk="NORMAL", run_id="run-x", reports=None, validations=None,
               roles_filled=None):
    """Write a minimal but well-formed run dir (verdict.json + panel/plan.json + panel/<role>.json
    + validation/) for the pr_publish tests. ``reports`` maps role -> [finding dict]. The verdict
    carries a REAL attestation over the artifacts (as a genuine run dir does), so pr_publish's
    pre-publish integrity check passes; ``roles_filled`` overrides panel coverage to simulate an
    incomplete panel."""
    sys.path.insert(0, str(SKILL / "scripts"))
    from aggregate import compute_attestation
    d = Path(path)
    (d / "panel").mkdir(parents=True, exist_ok=True)
    (d / "validation").mkdir(parents=True, exist_ok=True)
    reports = reports if reports is not None else {"security": []}
    roles = list(reports.keys())
    # write the input artifacts first, then attest over them, then write the verdict (the output)
    (d / "panel" / "plan.json").write_text(json.dumps({"roles": {r: {"model": "m/" + r} for r in roles}}))
    for role, findings in reports.items():
        (d / "panel" / (role + ".json")).write_text(json.dumps({"role": role, "findings": findings}))
    for i, rec in enumerate(validations or []):
        (d / "validation" / ("v%d.json" % i)).write_text(json.dumps(rec))
    att = compute_attestation(d)  # sha256-canonical-json-v2 over every .json except verdict.json
    (d / "verdict.json").write_text(json.dumps({
        "verdict": verdict, "risk": risk, "run_id": run_id, "computed_at": "2026-08-20T00:00:00Z",
        "counts": {"findings_high_critical": 0, "findings_medium_low": 0, "confirmed": 0, "unresolved": 0},
        "coverage": {"risk": risk, "gates": {"passed": ["build", "unit"], "required": ["build", "unit"]},
                     "panel": {"roles_filled": roles_filled if roles_filled is not None else roles,
                               "roles_required": roles},
                     "findings": {"raised": sum(len(v) for v in reports.values()), "triaged": 0},
                     "cost_usd": 0.05},
        "attestation": att}))
    return str(d)


class _FakeGitHub:
    """Stateful in-memory GitHub double: create/update/delete/list actually mutate a store, so a
    second publish sees the first's comments (the point of the idempotency tests). Author-aware —
    every comment carries a login — so the ownership filtering is genuinely exercised."""
    LOGIN = "ar-bot"

    def __init__(self, errcls, fail_create_422=False):
        self.issue, self.review, self.statuses = {}, {}, []
        self._n = 1000
        self._errcls = errcls
        self._fail = fail_create_422
        self.head_sha = None  # when set, get_pull reports it → head-sha binding is exercised

    def _id(self):
        self._n += 1
        return self._n

    def whoami(self):
        return self.LOGIN

    def get_pull(self, pr):
        return {"head": {"sha": self.head_sha}} if self.head_sha else {}

    def list_issue_comments(self, pr):
        return [{"id": i, "body": c["body"], "user": {"login": c["user"]}} for i, c in self.issue.items()]

    def create_issue_comment(self, pr, body):
        i = self._id()
        self.issue[i] = {"body": body, "user": self.LOGIN}
        return {"id": i, "user": {"login": self.LOGIN}}  # real GitHub returns the created comment

    def update_issue_comment(self, cid, body):
        self.issue[cid]["body"] = body
        return {"id": cid}

    def delete_issue_comment(self, cid):
        self.issue.pop(cid, None)
        return {}

    def list_review_comments(self, pr):
        return [{"id": i, "body": c["body"], "line": c["line"], "user": {"login": c["user"]}}
                for i, c in self.review.items()]

    def create_review_comment(self, pr, sha, path, line, body):
        if self._fail:
            raise self._errcls(422, "line not part of the diff")
        i = self._id()
        self.review[i] = {"body": body, "path": path, "line": line, "user": self.LOGIN}
        return {"id": i, "user": {"login": self.LOGIN}}

    def update_review_comment(self, cid, body):
        self.review[cid]["body"] = body
        return {"id": cid}

    def delete_review_comment(self, cid):
        self.review.pop(cid, None)
        return {}

    def set_status(self, sha, state, description, target_url=None):
        self.statuses.append(state)
        return {}

    # helpers for tests: inject a comment authored by someone else (a human / attacker)
    def inject_issue(self, body, user="mallory"):
        i = self._id()
        self.issue[i] = {"body": body, "user": user}
        return i

    def inject_review(self, body, line, user="mallory"):
        i = self._id()
        self.review[i] = {"body": body, "path": "a.py", "line": line, "user": user}
        return i


def t_pr_publish_creates_and_idempotent():
    # E5-S1: first publish creates a verdict summary + one inline comment per finding and sets a
    # commit status; a re-run of the SAME run updates in place and never duplicates.
    pp = _import_pr_publish()
    root = Path(tempfile.mkdtemp(prefix="ar-prpub-"))
    try:
        rundir = _write_run(root / "run", verdict="PASS", reports={"correctness": [
            {"id": "correctness-1", "title": "Bug X", "severity": "high", "file": "a.py",
             "line": 10, "evidence": "boom", "release_blocking": True}]},
            validations=[{"finding_ids": ["correctness-1"], "classification": "confirmed",
                          "resolution": {"fixed": True, "gates_rerun": ["unit"]}}])
        gh = _FakeGitHub(pp.GitHubError)
        ctx = {"repo": "o/r", "pr": 7, "commit_sha": "deadbeef", "fail_on": "blocked"}
        p1 = pp.publish(rundir, ctx, gh)
        assert p1["created"] == 1 and p1["updated"] == 0 and p1["summary"] == "created", p1
        assert len(gh.review) == 1 and len(gh.issue) == 1, (len(gh.review), len(gh.issue))
        assert gh.statuses == ["success"], gh.statuses
        assert "confirmed" in next(iter(gh.review.values()))["body"], "triage must show on the inline comment"
        p2 = pp.publish(rundir, ctx, gh)
        assert p2["created"] == 0 and p2["updated"] == 1 and p2["summary"] == "updated", p2
        assert len(gh.review) == 1 and len(gh.issue) == 1, "re-run must not duplicate"
        assert gh.statuses == ["success", "success"], gh.statuses
    finally:
        shutil.rmtree(root, ignore_errors=True)


def t_pr_publish_retires_stale_findings():
    # E5-S1: a finding present in run A but gone in run B (same PR) has its inline comment deleted.
    pp = _import_pr_publish()
    root = Path(tempfile.mkdtemp(prefix="ar-prpub-"))
    try:
        run_a = _write_run(root / "a", reports={"correctness": [
            {"id": "correctness-1", "title": "Bug X", "severity": "high", "file": "a.py", "line": 10}]})
        run_b = _write_run(root / "b", reports={"security": []})  # clean re-review
        gh = _FakeGitHub(pp.GitHubError)
        ctx = {"repo": "o/r", "pr": 9, "commit_sha": "deadbeef", "fail_on": "blocked"}
        pp.publish(run_a, ctx, gh)
        assert len(gh.review) == 1
        p = pp.publish(run_b, ctx, gh)
        assert p["deleted"] == 1 and len(gh.review) == 0, (p, gh.review)
        assert len(gh.issue) == 1, "verdict summary stays (updated), only the finding retires"
    finally:
        shutil.rmtree(root, ignore_errors=True)


def t_pr_publish_status_maps_verdict():
    # E5-S1: commit status state is faithful to the verdict (BLOCKED = error, not failure).
    pp = _import_pr_publish()
    root = Path(tempfile.mkdtemp(prefix="ar-prpub-"))
    try:
        for verdict, state in (("PASS", "success"), ("FAIL", "failure"), ("BLOCKED", "error")):
            gh = _FakeGitHub(pp.GitHubError)
            rundir = _write_run(root / verdict, verdict=verdict)
            pp.publish(rundir, {"repo": "o/r", "pr": 1, "commit_sha": "deadbeef", "fail_on": "blocked"}, gh)
            assert gh.statuses == [state], (verdict, gh.statuses)
    finally:
        shutil.rmtree(root, ignore_errors=True)


def t_pr_publish_dry_run_no_op():
    # E5-S1: with no token, main() uses the DryRunClient — no network, exit code still reflects the
    # verdict (PASS -> 0), and BLOCKED under fail-on=blocked -> 2.
    pp = _import_pr_publish()
    root = Path(tempfile.mkdtemp(prefix="ar-prpub-"))
    saved = {k: os.environ.pop(k) for k in ("GITHUB_TOKEN", "GH_TOKEN", "GITHUB_STEP_SUMMARY") if k in os.environ}
    try:
        ok = _write_run(root / "ok", verdict="PASS")
        assert pp.main([ok, "--repo", "o/r", "--pr", "3"]) == 0
        fail = _write_run(root / "fail", verdict="FAIL")
        assert pp.main([fail, "--repo", "o/r", "--pr", "3"]) == 1               # FAIL -> 1
        assert pp.main([fail, "--repo", "o/r", "--pr", "3", "--fail-on", "fail"]) == 1
        blk = _write_run(root / "blk", verdict="BLOCKED")
        assert pp.main([blk, "--repo", "o/r", "--pr", "3"]) == 2                # BLOCKED -> 2 (default)
        assert pp.main([blk, "--repo", "o/r", "--pr", "3", "--fail-on", "fail"]) == 0  # tolerated
    finally:
        os.environ.update(saved)
        shutil.rmtree(root, ignore_errors=True)


def t_pr_publish_scrubs_secrets():
    # E5-S1: a credential that leaked into an artifact must never reach a comment body.
    pp = _import_pr_publish()
    root = Path(tempfile.mkdtemp(prefix="ar-prpub-"))
    try:
        secret = "sk-supersecrettoken1234567890"
        rundir = _write_run(root / "run", reports={"correctness": [
            {"id": "c1", "title": "Leak", "severity": "low", "file": "a.py", "line": 1,
             "evidence": "the key is " + secret + " oops"}]})
        gh = _FakeGitHub(pp.GitHubError)
        pp.publish(rundir, {"repo": "o/r", "pr": 5, "commit_sha": "deadbeef", "fail_on": "blocked"}, gh,
                   secrets=[secret])
        for c in gh.review.values():
            assert secret not in c["body"] and "***redacted***" in c["body"], c["body"]
        for c in gh.issue.values():
            assert secret not in c["body"]
    finally:
        shutil.rmtree(root, ignore_errors=True)


def t_pr_publish_unanchored_fallback():
    # E5-S1: a finding with no usable line, and a finding whose inline anchor is rejected (422),
    # both fall back into the summary rather than being dropped.
    pp = _import_pr_publish()
    root = Path(tempfile.mkdtemp(prefix="ar-prpub-"))
    try:
        # no-line finding -> unanchored, never attempts an inline create
        r1 = _write_run(root / "r1", reports={"correctness": [
            {"id": "c1", "title": "NoLine", "severity": "medium", "file": "a.py", "line": None}]})
        gh1 = _FakeGitHub(pp.GitHubError)
        p1 = pp.publish(r1, {"repo": "o/r", "pr": 2, "commit_sha": "deadbeef", "fail_on": "blocked"}, gh1)
        assert p1["created"] == 0 and p1["unanchored"] == 1 and len(gh1.review) == 0, p1
        summary = next(iter(gh1.issue.values()))["body"]
        assert "not anchorable" in summary and "NoLine" in summary, summary
        # line present but the diff rejects it (422) -> falls back to the summary
        r2 = _write_run(root / "r2", reports={"correctness": [
            {"id": "c2", "title": "OffDiff", "severity": "low", "file": "a.py", "line": 999}]})
        gh2 = _FakeGitHub(pp.GitHubError, fail_create_422=True)
        p2 = pp.publish(r2, {"repo": "o/r", "pr": 2, "commit_sha": "deadbeef", "fail_on": "blocked"}, gh2)
        assert p2["created"] == 0 and p2["unanchored"] == 1 and len(gh2.review) == 0, p2
        assert "OffDiff" in next(iter(gh2.issue.values()))["body"]
    finally:
        shutil.rmtree(root, ignore_errors=True)


def t_pr_publish_ignores_spoofed_markers():
    # E5-S1 hardening (security-1/2, correctness-3): a comment carrying our markers but authored by
    # someone else must never be updated or deleted — ownership is proven by author, not the public
    # marker. And untrusted finding text that embeds a marker must not forge one.
    pp = _import_pr_publish()
    root = Path(tempfile.mkdtemp(prefix="ar-prpub-"))
    try:
        rundir = _write_run(root / "run", reports={"correctness": [
            {"id": "c1", "title": "Bug <!-- ar-finding:deadbeef --> injected", "severity": "high",
             "file": "a.py", "line": 10}]})
        gh = _FakeGitHub(pp.GitHubError)
        # a malicious PR author pastes our managed markers into their own comments
        spoof_issue = gh.inject_issue("nice try %s\n%s" % (pp.MANAGED, pp.VERDICT_MARKER))
        spoof_review = gh.inject_review("%s\n<!-- ar-finding:deadbeef -->" % pp.MANAGED, 10)
        ctx = {"repo": "o/r", "pr": 4, "commit_sha": "deadbeef", "fail_on": "blocked"}
        pp.publish(rundir, ctx, gh)
        # the spoofed comments are untouched (still present, unchanged author)
        assert spoof_issue in gh.issue and gh.issue[spoof_issue]["user"] == "mallory"
        assert spoof_review in gh.review and gh.review[spoof_review]["user"] == "mallory"
        # our own comments were created alongside, not by hijacking the spoofs
        ours_issue = [i for i, c in gh.issue.items() if c["user"] == gh.LOGIN]
        ours_review = [i for i, c in gh.review.items() if c["user"] == gh.LOGIN]
        assert len(ours_issue) == 1 and len(ours_review) == 1, (ours_issue, ours_review)
        # the injected marker in the finding title did not create a second managed finding comment,
        # and appears only as neutralized/literal text (no active extra marker)
        body = gh.review[ours_review[0]]["body"]
        assert body.count("<!-- ar-finding:") == 1, "untrusted title must not add a second marker"
        assert "&lt;!--" in body, "injected comment marker must be neutralized to literal text"
    finally:
        shutil.rmtree(root, ignore_errors=True)


def t_pr_publish_reanchors_on_line_drift():
    # E5-S1 (correctness-1/2): when the same finding recurs at a different line across pushes, the
    # inline comment must be deleted and re-created at the new line (its anchor can't be PATCHed).
    pp = _import_pr_publish()
    root = Path(tempfile.mkdtemp(prefix="ar-prpub-"))
    try:
        a = _write_run(root / "a", reports={"correctness": [
            {"id": "c1", "title": "Same bug", "severity": "high", "file": "a.py", "line": 10}]})
        b = _write_run(root / "b", reports={"correctness": [
            {"id": "c1", "title": "Same bug", "severity": "high", "file": "a.py", "line": 42}]})
        gh = _FakeGitHub(pp.GitHubError)
        ctx = {"repo": "o/r", "pr": 6, "commit_sha": "deadbeef", "fail_on": "blocked"}
        pp.publish(a, ctx, gh)
        assert len(gh.review) == 1 and next(iter(gh.review.values()))["line"] == 10
        p = pp.publish(b, ctx, gh)
        assert p["deleted"] == 1 and p["created"] == 1 and p["updated"] == 0, p
        assert len(gh.review) == 1 and next(iter(gh.review.values()))["line"] == 42, "anchor must move"
    finally:
        shutil.rmtree(root, ignore_errors=True)


def t_pr_publish_dedupes_across_roles():
    # E5-S1 (test_quality-4): two reviewers reporting the same (file, title) collapse into one
    # inline comment that names both roles.
    pp = _import_pr_publish()
    root = Path(tempfile.mkdtemp(prefix="ar-prpub-"))
    try:
        rundir = _write_run(root / "run", reports={
            "security": [{"id": "security-1", "title": "Dup issue", "severity": "high",
                          "file": "a.py", "line": 5}],
            "correctness": [{"id": "correctness-1", "title": "Dup issue", "severity": "medium",
                             "file": "a.py", "line": 5}]})
        gh = _FakeGitHub(pp.GitHubError)
        p = pp.publish(rundir, {"repo": "o/r", "pr": 8, "commit_sha": "deadbeef", "fail_on": "blocked"}, gh)
        assert p["created"] == 1 and len(gh.review) == 1, p
        body = next(iter(gh.review.values()))["body"]
        assert "security" in body and "correctness" in body, "both source roles must be named"
        # most-severe label wins for the merged finding
        assert body.startswith("**HIGH**"), body[:20]
    finally:
        shutil.rmtree(root, ignore_errors=True)


def t_pr_publish_no_sha_skips_status_not_silently():
    # E5-S1 (correctness-4): with no head SHA, no commit status is set and no inline anchor is
    # attempted — but the skip is surfaced in the plan, not silent, and findings fall back to summary.
    pp = _import_pr_publish()
    root = Path(tempfile.mkdtemp(prefix="ar-prpub-"))
    try:
        rundir = _write_run(root / "run", reports={"correctness": [
            {"id": "c1", "title": "Bug", "severity": "high", "file": "a.py", "line": 10}]})
        gh = _FakeGitHub(pp.GitHubError)
        p = pp.publish(rundir, {"repo": "o/r", "pr": 10, "commit_sha": None, "fail_on": "blocked"}, gh)
        assert p["status_set"] is False and "no commit sha" in p.get("status_skipped_reason", ""), p
        assert gh.statuses == [] and len(gh.review) == 0, "no status, no inline anchor without a sha"
        assert p["unanchored"] == 1 and "Bug" in next(iter(gh.issue.values()))["body"], p
    finally:
        shutil.rmtree(root, ignore_errors=True)


def t_pr_publish_bootstraps_identity_when_user_denied():
    # E5-S1 hardening (CodeRabbit, major): a write-capable client can be denied GET /user (a default
    # Actions GITHUB_TOKEN 403s it), so whoami() is None. Ownership must still be proven by author,
    # not by the public marker alone — else a human comment quoting a marker would be edited/deleted.
    # Identity is bootstrapped from a self-authored write; spoofed comments survive and re-runs stay
    # idempotent. (Under the old marker-only fallback the spoofs below would be overwritten/deleted.)
    pp = _import_pr_publish()

    class _NoUser(_FakeGitHub):
        def whoami(self):
            return None  # GET /user denied for this token

    root = Path(tempfile.mkdtemp(prefix="ar-prpub-"))
    try:
        rundir = _write_run(root / "run", reports={"correctness": [
            {"id": "c1", "title": "Bug", "severity": "high", "file": "a.py", "line": 10}]})
        gh = _NoUser(pp.GitHubError)
        # a human pastes our managed markers into their own comments
        spoof_issue = gh.inject_issue("nice try %s\n%s" % (pp.MANAGED, pp.VERDICT_MARKER))
        spoof_review = gh.inject_review("%s\n<!-- ar-finding:deadbeef -->" % pp.MANAGED, 10)
        ctx = {"repo": "o/r", "pr": 11, "commit_sha": "deadbeef", "fail_on": "blocked"}
        pp.publish(rundir, ctx, gh)
        # spoofed comments untouched (marker-only ownership would have overwritten/deleted them)
        assert spoof_issue in gh.issue and gh.issue[spoof_issue]["body"].startswith("nice try")
        assert spoof_review in gh.review and gh.review[spoof_review]["user"] == "mallory"
        ours_issue = [i for i, c in gh.issue.items() if c["user"] == gh.LOGIN]
        ours_review = [i for i, c in gh.review.items() if c["user"] == gh.LOGIN]
        assert len(ours_issue) == 1 and len(ours_review) == 1, (ours_issue, ours_review)
        # re-run under the same denied-identity client stays idempotent (no dup summary/inline)
        pp.publish(rundir, ctx, gh)
        assert len([i for i, c in gh.issue.items() if c["user"] == gh.LOGIN]) == 1, "no dup summary"
        assert len([i for i, c in gh.review.items() if c["user"] == gh.LOGIN]) == 1, "no dup inline"
        assert spoof_issue in gh.issue and spoof_review in gh.review, "human comments never touched"
    finally:
        shutil.rmtree(root, ignore_errors=True)


def t_pr_publish_severity_guard_malformed():
    # E5-S1 hardening (CodeRabbit): a malformed report with a non-string severity ([]/{}) must not
    # crash the publish — _severity degrades it to "low" instead of raising TypeError on `in`.
    pp = _import_pr_publish()
    assert pp._severity([]) == "low" and pp._severity({}) == "low" and pp._severity(None) == "low"
    assert pp._severity("high") == "high"
    root = Path(tempfile.mkdtemp(prefix="ar-prpub-"))
    try:
        rundir = _write_run(root / "run", reports={"correctness": [
            {"id": "c1", "title": "Weird", "severity": [], "file": "a.py", "line": 3}]})
        gh = _FakeGitHub(pp.GitHubError)
        p = pp.publish(rundir, {"repo": "o/r", "pr": 12, "commit_sha": "deadbeef", "fail_on": "blocked"}, gh)
        assert p["created"] == 1, p  # did not crash; posted as low severity
        assert "**LOW**" in next(iter(gh.review.values()))["body"]
    finally:
        shutil.rmtree(root, ignore_errors=True)


def t_pr_publish_repo_and_sha_validation():
    # E5-S1 hardening (CodeRabbit): repo and sha are interpolated straight into request paths, so
    # values carrying path/query characters (?, #, .., space) must be rejected, not silently used.
    pp = _import_pr_publish()
    for bad in ("owner", "own/er/name", "own er/name", "o/r?x", "o/r#x", "../etc", "o/..", "."):
        try:
            pp._resolve_repo(bad)
            raise AssertionError("expected ValueError for repo %r" % bad)
        except ValueError:
            pass
    assert pp._resolve_repo("SathiaAI/adversarial-review") == "SathiaAI/adversarial-review"
    assert pp._resolve_repo("o/my.repo-1_2") == "o/my.repo-1_2"  # dots/dashes/underscores are ok
    for bad in ("xyz", "g" * 65, "abc?d", "12 34", "../a", "dead!beef"):
        try:
            pp._resolve_sha(bad)
            raise AssertionError("expected ValueError for sha %r" % bad)
        except ValueError:
            pass
    assert pp._resolve_sha("deadbeef") == "deadbeef"
    assert pp._resolve_sha("A" * 40) == "A" * 40
    assert pp._resolve_sha("") == ""  # absent sha allowed (status then skipped + surfaced)


def t_pr_publish_job_summary_includes_unanchored():
    # E5-S1 hardening (CodeRabbit): publish() returns the unanchored findings so the Actions job
    # summary renders the same "not anchorable" section the PR comment does (it used to pass []).
    pp = _import_pr_publish()
    root = Path(tempfile.mkdtemp(prefix="ar-prpub-"))
    try:
        rundir = _write_run(root / "run", reports={"correctness": [
            {"id": "c1", "title": "NoLine", "severity": "medium", "file": "a.py", "line": None}]})
        gh = _FakeGitHub(pp.GitHubError)
        run = pp.load_run(rundir)
        p = pp.publish(rundir, {"repo": "o/r", "pr": 13, "commit_sha": "deadbeef", "fail_on": "blocked"}, gh)
        entries = p.get("unanchored_entries")
        assert entries and len(entries) == 1 and entries[0]["title"] == "NoLine", p
        summary = pp.render_verdict_summary(run, "o/r", 13, entries)
        assert "not anchorable" in summary and "NoLine" in summary
        assert "not anchorable" not in pp.render_verdict_summary(run, "o/r", 13, [])
    finally:
        shutil.rmtree(root, ignore_errors=True)


def t_pr_publish_programmatic_validation():
    # E5-S1 re-review (correctness-1, HIGH): repo/sha validation must guard the programmatic API, not
    # just the CLI. GitHubClient rejects a bad repo at construction; set_status rejects a bad sha
    # before interpolating it into the request path — both offline, before any network call.
    pp = _import_pr_publish()
    for bad in ("owner/repo?x=1", "owner", "../x", "o/..", "o/r%2e%2e", "o/r#f", "a/b/c"):
        try:
            pp.GitHubClient("tok", bad)
            raise AssertionError("expected ValueError for repo %r" % bad)
        except ValueError:
            pass
    client = pp.GitHubClient("tok", "o/r")  # valid repo; no network on construction
    for bad in ("abc?x=1", "..", "deadbeef!", "zzzzzzz", "abc"):
        try:
            client.set_status(bad, "success", "desc")
            raise AssertionError("expected ValueError for sha %r" % bad)
        except ValueError:
            pass
    assert pp._check_repo("SathiaAI/adversarial-review") == "SathiaAI/adversarial-review"
    assert pp._check_sha("A" * 40) == "A" * 40 and pp._check_sha("") == ""


def t_pr_publish_reanchors_null_line():
    # E5-S1 re-review (correctness-2): an owned inline comment the API returns with line=None must be
    # re-anchored (delete + create) when the finding has a real line — not updated in place.
    pp = _import_pr_publish()
    root = Path(tempfile.mkdtemp(prefix="ar-prpub-"))
    try:
        rundir = _write_run(root / "run", reports={"correctness": [
            {"id": "c1", "title": "Bug", "severity": "high", "file": "a.py", "line": 10}]})
        gh = _FakeGitHub(pp.GitHubError)
        key = pp._finding_key("a.py", "Bug")
        gh.inject_review("x\n%s\n<!-- ar-finding:%s -->" % (pp.MANAGED, key), None, user=gh.LOGIN)
        p = pp.publish(rundir, {"repo": "o/r", "pr": 6, "commit_sha": "deadbeef", "fail_on": "blocked"}, gh)
        assert p["deleted"] == 1 and p["created"] == 1 and p["updated"] == 0, p
        assert len(gh.review) == 1 and next(iter(gh.review.values()))["line"] == 10, "must re-anchor to 10"
    finally:
        shutil.rmtree(root, ignore_errors=True)


def t_pr_publish_summary_neutralizes_file():
    # E5-S1 re-review (correctness-3): untrusted finding *file* text must be neutralized in the summary
    # so it cannot forge a managed marker (only our own real verdict marker may appear).
    pp = _import_pr_publish()
    root = Path(tempfile.mkdtemp(prefix="ar-prpub-"))
    try:
        rundir = _write_run(root / "run", reports={"correctness": [
            {"id": "c1", "title": "NoLine", "severity": "low",
             "file": "x <!-- ar-verdict --> y", "line": None}]})
        gh = _FakeGitHub(pp.GitHubError)
        pp.publish(rundir, {"repo": "o/r", "pr": 2, "commit_sha": "deadbeef", "fail_on": "blocked"}, gh)
        body = next(iter(gh.issue.values()))["body"]
        assert body.count(pp.VERDICT_MARKER) == 1, "injected file marker must not add a second marker"
        assert "&lt;!--" in body, "injected file marker must be neutralized to literal text"
    finally:
        shutil.rmtree(root, ignore_errors=True)


def t_pr_publish_bad_verdict_json():
    # E5-S1 re-review (test_quality-1): a missing or unparseable verdict.json is surfaced as a clean
    # exit 2, not a crash.
    pp = _import_pr_publish()
    root = Path(tempfile.mkdtemp(prefix="ar-prpub-"))
    saved = {k: os.environ.pop(k) for k in ("GITHUB_TOKEN", "GH_TOKEN", "GITHUB_STEP_SUMMARY") if k in os.environ}
    try:
        missing = root / "missing"
        missing.mkdir()
        assert pp.main([str(missing), "--repo", "o/r", "--pr", "1"]) == 2  # no verdict.json
        bad = root / "bad"
        bad.mkdir()
        (bad / "verdict.json").write_text("{ not json")
        assert pp.main([str(bad), "--repo", "o/r", "--pr", "1"]) == 2      # unparseable
        for d in (missing, bad):
            try:
                pp.load_run(str(d))
                raise AssertionError("load_run must raise on %s" % d)
            except (FileNotFoundError, ValueError):
                pass
    finally:
        os.environ.update(saved)
        shutil.rmtree(root, ignore_errors=True)


def t_pr_publish_verifies_attestation_before_publishing():
    # E5-S1 PR #43 (Codex P1): if a run's artifacts drift after aggregate.py wrote the verdict, the
    # stored attestation no longer matches — publish must refuse BEFORE any network write, so a PASS
    # is never attached to inputs the verdict was not computed over.
    pp = _import_pr_publish()
    root = Path(tempfile.mkdtemp(prefix="ar-prpub-"))
    try:
        rundir = _write_run(root / "run", reports={"security": [
            {"id": "s1", "title": "Bug", "severity": "high", "file": "a.py", "line": 10}]})
        gh = _FakeGitHub(pp.GitHubError)
        # untouched run publishes fine (attestation matches)
        pp.publish(rundir, {"repo": "o/r", "pr": 1, "commit_sha": "deadbeef", "fail_on": "blocked"}, gh)
        assert gh.issue or gh.review, "a clean run should publish"
        # tamper a panel artifact after the verdict was written
        p = Path(rundir) / "panel" / "security.json"
        p.write_text(json.dumps({"role": "security", "findings": [
            {"id": "s1", "title": "Bug", "severity": "low", "file": "a.py", "line": 10}]}))
        gh2 = _FakeGitHub(pp.GitHubError)
        try:
            pp.publish(rundir, {"repo": "o/r", "pr": 1, "commit_sha": "deadbeef", "fail_on": "blocked"}, gh2)
            raise AssertionError("tampered run must abort before publishing")
        except ValueError as exc:
            assert "attestation mismatch" in str(exc)
        assert not gh2.issue and not gh2.review and not gh2.statuses, "no write on a tampered run"
    finally:
        shutil.rmtree(root, ignore_errors=True)


def t_pr_publish_binds_to_reviewed_head():
    # E5-S1 PR #43 (Codex P1): the status/comments must bind to the reviewed PR head. When the PR
    # head is known and the provided --sha is a different commit (e.g. the pull_request merge
    # commit), publish fails closed rather than marking bytes the run never reviewed. A matching (or
    # unresolved) head proceeds.
    pp = _import_pr_publish()
    root = Path(tempfile.mkdtemp(prefix="ar-prpub-"))
    try:
        rundir = _write_run(root / "run", reports={"security": []})
        # mismatch → abort, no writes
        gh = _FakeGitHub(pp.GitHubError)
        gh.head_sha = "cafebabecafebabecafebabecafebabecafebabe"
        try:
            pp.publish(rundir, {"repo": "o/r", "pr": 7, "commit_sha": "deadbeef", "fail_on": "blocked"}, gh)
            raise AssertionError("must refuse to publish to a non-head sha")
        except pp.GitHubError as exc:
            assert "not the head" in str(exc)
        assert not gh.issue and not gh.statuses, "no write when head sha mismatches"
        # matching head (short --sha is a prefix of the full head) → proceeds
        gh2 = _FakeGitHub(pp.GitHubError)
        gh2.head_sha = "deadbeef00000000000000000000000000000000"
        pp.publish(rundir, {"repo": "o/r", "pr": 7, "commit_sha": "deadbeef", "fail_on": "blocked"}, gh2)
        assert gh2.statuses == ["success"], gh2.statuses
    finally:
        shutil.rmtree(root, ignore_errors=True)


def t_pr_publish_scrubs_password_named_secret():
    # E5-S1 PR #43 (Codex P1): a password/credential-named env value is a secret too and must be
    # redacted from bodies — the old TOKEN/KEY/SECRET-only allowlist leaked e.g. DB_PASSWORD.
    pp = _import_pr_publish()
    root = Path(tempfile.mkdtemp(prefix="ar-prpub-"))
    secret = "hunter2-db-password-value"
    saved = {k: os.environ.get(k) for k in ("GITHUB_TOKEN", "GH_TOKEN", "DB_PASSWORD", "GITHUB_STEP_SUMMARY")}
    for k in ("GH_TOKEN", "GITHUB_STEP_SUMMARY"):
        os.environ.pop(k, None)
    try:
        # a finding whose text echoes the password (defense-in-depth: bodies come from artifacts)
        rundir = _write_run(root / "run", reports={"security": [
            {"id": "s1", "title": "leak " + secret, "severity": "high", "file": "a.py", "line": 3,
             "evidence": secret}]})
        os.environ["GITHUB_TOKEN"] = "x"        # force non-dry-run path in main()
        os.environ["DB_PASSWORD"] = secret
        # Drive publish() directly with the same secret list main() would build, on a recording fake.
        secrets = [v for k, v in os.environ.items()
                   if v and any(m in k.upper() for m in ("TOKEN", "KEY", "SECRET", "PASSWORD", "PASSWD",
                                                          "CREDENTIAL", "PASSPHRASE"))]
        assert secret in secrets, "DB_PASSWORD must be collected as a secret"
        gh = _FakeGitHub(pp.GitHubError)
        pp.publish(rundir, {"repo": "o/r", "pr": 9, "commit_sha": "deadbeef", "fail_on": "blocked"},
                   gh, secrets=secrets)
        bodies = "".join(c["body"] for c in gh.issue.values()) + "".join(c["body"] for c in gh.review.values())
        assert bodies, "expected a published body"
        assert secret not in bodies, "the password value must be redacted from every body"
        assert "***redacted***" in bodies
    finally:
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        shutil.rmtree(root, ignore_errors=True)


def t_pr_publish_tolerates_malformed_plan_json():
    # E5-S1 PR #43 (CodeRabbit): a malformed panel/plan.json must not abort publish — only
    # verdict.json can (the role fallback handles a missing/broken plan).
    pp = _import_pr_publish()
    root = Path(tempfile.mkdtemp(prefix="ar-prpub-"))
    try:
        rundir = _write_run(root / "run", reports={"security": [
            {"id": "s1", "title": "Bug", "severity": "high", "file": "a.py", "line": 10}]})
        # a run whose plan.json was malformed when aggregated: corrupt it, then re-attest so the
        # stored digest covers the malformed bytes (aggregate.py hashes an unparseable .json raw)
        (Path(rundir) / "panel" / "plan.json").write_text("{ not json")
        sys.path.insert(0, str(SKILL / "scripts"))
        from aggregate import compute_attestation
        v = json.loads((Path(rundir) / "verdict.json").read_text())
        v["attestation"] = compute_attestation(Path(rundir))
        (Path(rundir) / "verdict.json").write_text(json.dumps(v))
        run = pp.load_run(rundir)                      # must not raise
        assert run["plan"] == {} and "security" in run["reports"], run["plan"]
        gh = _FakeGitHub(pp.GitHubError)
        pp.publish(rundir, {"repo": "o/r", "pr": 1, "commit_sha": "deadbeef", "fail_on": "blocked"}, gh)
        assert gh.review, "publish should still post the finding despite a broken plan.json"
    finally:
        shutil.rmtree(root, ignore_errors=True)


def t_pr_publish_summary_id_is_stable_across_bootstrap_runs():
    # E5-S1 PR #43 (CodeRabbit): under the identity-bootstrap path (GET /user denied), re-runs must
    # keep ONE stable summary comment id instead of churning a fresh comment (and notification) each
    # time.
    pp = _import_pr_publish()

    class _NoUser(_FakeGitHub):
        def whoami(self):
            return None

    root = Path(tempfile.mkdtemp(prefix="ar-prpub-"))
    try:
        rundir = _write_run(root / "run", reports={"security": []})
        gh = _NoUser(pp.GitHubError)
        ctx = {"repo": "o/r", "pr": 2, "commit_sha": "deadbeef", "fail_on": "blocked"}
        pp.publish(rundir, ctx, gh)
        ids1 = sorted(i for i, c in gh.issue.items() if c["user"] == gh.LOGIN)
        assert len(ids1) == 1, ids1
        plan2 = pp.publish(rundir, ctx, gh)     # second run under the same denied-identity client
        pp.publish(rundir, ctx, gh)     # and a third
        ids2 = sorted(i for i, c in gh.issue.items() if c["user"] == gh.LOGIN)
        assert ids2 == ids1, "the summary comment id must be stable across bootstrap re-runs"
        # CodeRabbit PR #43: retiring the throwaway bootstrap comment is a summary retirement, not an
        # inline deletion — it must not inflate the "-N inline" counter.
        assert plan2["summary_retired"] >= 1, plan2
        assert plan2["deleted"] == 0, plan2
    finally:
        shutil.rmtree(root, ignore_errors=True)


def t_pr_publish_preserves_findings_when_panel_incomplete():
    # E5-S1 PR #43 (Codex P1): a later BLOCKED/incomplete re-run (reviewer reports missing) must not
    # delete the prior run's finding comments — missing panel output is not proof the issue is fixed.
    pp = _import_pr_publish()
    root = Path(tempfile.mkdtemp(prefix="ar-prpub-"))
    try:
        # run 1: complete panel posts one inline finding
        r1 = _write_run(root / "r1", reports={"security": [
            {"id": "s1", "title": "Bug", "severity": "high", "file": "a.py", "line": 10}]})
        gh = _FakeGitHub(pp.GitHubError)
        ctx = {"repo": "o/r", "pr": 5, "commit_sha": "deadbeef", "fail_on": "blocked"}
        pp.publish(r1, ctx, gh)
        assert len(gh.review) == 1, gh.review
        # run 2: the finding is gone AND the panel is incomplete (roles_filled < required) → preserve
        r2 = _write_run(root / "r2", verdict="BLOCKED", reports={"security": []},
                        roles_filled=[])   # required=["security"], filled=[] → incomplete
        p = pp.publish(r2, ctx, gh)
        assert len(gh.review) == 1, "stale finding comment preserved while panel is incomplete"
        assert p.get("reconcile_held") == 1, p
        # run 3: complete panel, finding still gone → now it is retired
        r3 = _write_run(root / "r3", reports={"security": []})
        pp.publish(r3, ctx, gh)
        assert len(gh.review) == 0, "a complete clean re-run retires the stale finding comment"
    finally:
        shutil.rmtree(root, ignore_errors=True)



# --- Reviewer meta-eval scorer tests (E1-S2). Recovered here: these 100%-branch-coverage
# tests were added on the E1-S2 branch (evals/score.py) but dropped from tests/run_tests.py
# by the #44 merge into main; evals/score.py shipped untested. Restored with E1-S3, which
# scores through this module. ---
def _import_score():
    sys.path.insert(0, str(SKILL / "evals"))
    import score
    return score


def _f(file="a.py", line=10, severity="high", title="", evidence="", scenario="", fix=""):
    """Build a minimal reviewer finding for scoring tests."""
    return {"file": file, "line": line, "severity": severity, "title": title,
            "evidence": evidence, "scenario": scenario, "fix": fix}


def t_eval_score_file_overlaps():
    # E1-S2: file match is exact-after-normalization or a basename fallback (tolerates a/ b/ ./ diff
    # prefixes and a reviewer citing the bare filename); empty either side never overlaps.
    s = _import_score()
    assert s.file_overlaps("api/invoices.py", "api/invoices.py")
    assert s.file_overlaps("b/api/invoices.py", "a/api/invoices.py")       # diff prefixes stripped
    assert s.file_overlaps("./invoices.py", "api/invoices.py")             # basename fallback
    assert s.file_overlaps("api\\invoices.py", "api/invoices.py")          # backslash normalized
    assert not s.file_overlaps("api/orders.py", "api/invoices.py")
    assert not s.file_overlaps("", "api/invoices.py") and not s.file_overlaps("x.py", "")


def t_eval_score_line_in_range():
    # E1-S2: line path honors +/- tolerance at both edges; a non-int/absent line or a malformed range
    # never satisfies it (must qualify via the tag path instead); a reversed range is tolerated.
    s = _import_score()
    assert s.line_in_range(10, [10, 12]) and s.line_in_range(12, [10, 12])
    assert s.line_in_range(13, [10, 12], line_tol=1) and not s.line_in_range(14, [10, 12], line_tol=1)
    assert s.line_in_range(7, [10, 12], line_tol=3) and not s.line_in_range(6, [10, 12], line_tol=3)
    assert s.line_in_range(11, [12, 10])                                    # reversed range tolerated
    assert not s.line_in_range(None, [10, 12]) and not s.line_in_range(True, [10, 12])
    assert not s.line_in_range(10, [10]) and not s.line_in_range(10, "nope")
    # A malformed locator endpoint (None/string/boolean) or a bad line_tol must be a non-match, not a
    # crash — a corrupt corpus label cannot stop scoring (PR #44 CodeRabbit).
    assert not s.line_in_range(10, [None, 12]) and not s.line_in_range(10, ["x", 12])
    assert not s.line_in_range(10, [10, None]) and not s.line_in_range(10, [True, 12])
    assert not s.line_in_range(10, [10, 12], line_tol=-1)
    assert not s.line_in_range(10, [10, 12], line_tol=True) and not s.line_in_range(10, [10, 12], line_tol="3")


def t_eval_score_tag_intersects():
    # E1-S2: a tag matches only when ALL its words appear as tokens in the finding text; a single-token
    # tag is a substring-token match; empty tags never match.
    s = _import_score()
    ok, tag = s.tag_intersects(["missing-ownership-check", "idor"],
                               _f(evidence="This is a missing ownership check on the object"))
    assert ok and tag == "missing-ownership-check"
    ok2, tag2 = s.tag_intersects(["idor"], _f(title="Classic IDOR on invoice id"))
    assert ok2 and tag2 == "idor"
    assert not s.tag_intersects(["missing-ownership-check"], _f(evidence="ownership only"))[0]  # not all words
    assert not s.tag_intersects([], _f(evidence="anything"))[0]


def t_eval_score_match_finding_to_defect():
    # E1-S2: location match (right file + near line), root-cause match (right file + tag named though
    # line is off), no match when the tag is named in the WRONG file, and non-dict inputs are safe.
    s = _import_score()
    defect = {"defect_id": "idor-1", "must_detect": True, "severity_floor": "high",
              "locators": [{"file": "api/invoices.py", "line_range": [10, 12]}],
              "root_cause_tags": ["idor", "authz"]}
    assert s.match_finding_to_defect(_f(file="api/invoices.py", line=11), defect)[1] == "location"
    off = s.match_finding_to_defect(_f(file="api/invoices.py", line=200, title="IDOR authz gap"), defect)
    assert off == (True, "root_cause")                                      # right file, tag names it
    # tag named but in the WRONG file -> not a match (root-cause path still requires file overlap)
    assert not s.match_finding_to_defect(_f(file="other.py", line=1, title="IDOR authz"), defect)[0]
    assert s.match_finding_to_defect("nope", defect) == (False, None)


def t_eval_score_case_tp_partial_fn():
    # E1-S2: a must_detect defect is TP when matched at/above its severity floor, PARTIAL when matched
    # below the floor (noticed but under-rated), FN when unmatched.
    s = _import_score()
    defect = {"defect_id": "d1", "must_detect": True, "severity_floor": "high",
              "locators": [{"file": "a.py", "line_range": [10, 10]}], "root_cause_tags": ["boom"]}
    exp = {"defects": [defect], "fp_budget": 0}
    tp = s.score_case(exp, [_f(file="a.py", line=10, severity="high")])
    assert tp["tp"] == 1 and tp["partial"] == 0 and tp["fn"] == 0
    part = s.score_case(exp, [_f(file="a.py", line=10, severity="low")])
    assert part["partial"] == 1 and part["tp"] == 0 and part["fn"] == 0
    miss = s.score_case(exp, [_f(file="zzz.py", line=99, severity="high", title="unrelated")])
    assert miss["fn"] == 1 and miss["tp"] == 0
    assert miss["defect_outcomes"][0]["outcome"] == "fn"


def t_eval_score_case_informational_and_fp():
    # E1-S2: a must_detect:false defect never scores FN/TP (bonus if matched). FP rules: on a clean
    # case any finding beyond fp_budget is FP; on a defect case only unmatched high/critical beyond
    # budget is FP (unmatched low/medium is noise, not a false alarm). A bad fp_budget floors to 0.
    s = _import_score()
    info = {"defect_id": "opt", "must_detect": False, "severity_floor": "low",
            "locators": [{"file": "a.py", "line_range": [1, 1]}], "root_cause_tags": ["x"]}
    r = s.score_case({"defects": [info], "fp_budget": 0}, [_f(file="a.py", line=1, severity="low", title="x")])
    assert r["tp"] == 0 and r["fn"] == 0 and r["defect_outcomes"][0]["outcome"] == "informational"
    # clean case: 2 findings, budget 1 -> exactly 1 FP
    clean = s.score_case({"defects": [], "fp_budget": 1}, [_f(severity="low"), _f(severity="low")])
    assert clean["fp"] == 1 and clean["fp_candidates"] == 2
    # defect case: an unmatched HIGH is an FP (budget 0); an unmatched LOW is noise, not FP
    defect = {"defect_id": "d", "must_detect": True, "severity_floor": "high",
              "locators": [{"file": "a.py", "line_range": [5, 5]}], "root_cause_tags": ["q"]}
    d = s.score_case({"defects": [defect], "fp_budget": 0},
                     [_f(file="a.py", line=5, severity="high", title="q"),      # the TP
                      _f(file="z.py", line=1, severity="critical", title="bogus"),  # unmatched high -> FP
                      _f(file="z.py", line=2, severity="low", title="nit")])        # unmatched low -> noise
    assert d["tp"] == 1 and d["fp"] == 1 and d["noise"] == 1
    bad = s.score_case({"defects": [], "fp_budget": -5}, [_f(severity="low")])
    assert bad["fp"] == 1 and bad["fp_budget"] == 0                          # negative budget floored


def t_eval_score_case_nondict_finding():
    # E1-S2 (correctness-1 regression): match_finding_to_defect already refuses a non-dict finding, so
    # such an entry lands in `unmatched` and reaches the FP severity tally. That tally must tolerate it
    # (floor to 0) instead of raising AttributeError on `.get`. A non-dict is never high/critical, so on
    # a defect case it is noise, not a false alarm; on a clean case it still counts toward fp_budget.
    s = _import_score()
    defect = {"defect_id": "d", "must_detect": True, "severity_floor": "high",
              "locators": [{"file": "a.py", "line_range": [10, 12]}], "root_cause_tags": ["idor"]}
    d = s.score_case({"defects": [defect], "fp_budget": 0},
                     [_f(file="a.py", line=11, severity="high", title="idor"),  # the TP
                      "not-a-dict", None])                                       # malformed -> noise, no crash
    assert d["tp"] == 1 and d["fp"] == 0 and d["noise"] == 2
    # clean case: two malformed entries are candidate FPs beyond a budget of 1 -> exactly 1 FP, no crash
    clean = s.score_case({"defects": [], "fp_budget": 1}, ["x", None])
    assert clean["fp"] == 1 and clean["fp_candidates"] == 2


def t_eval_score_case_one_finding_one_defect():
    # E1-S2 (PR #44 Codex P1 regression): a single reviewer finding must credit at most one defect.
    # When two must_detect defects sit within tolerance (or share a tag) in the same file, one finding
    # scored both defects as TP -> tp:2, inflating detection. Assignment is now one-to-one.
    s = _import_score()
    D = lambda n, floor="high": {"defect_id": "d%d" % n, "must_detect": True, "severity_floor": floor,
                                 "locators": [{"file": "a.py", "line_range": [n, n]}], "root_cause_tags": ["t%d" % n]}
    F = lambda ln, sev="high": _f(file="a.py", line=ln, severity=sev, title="x")
    # one finding, two overlapping defects -> exactly one TP (the other is an FN), never tp:2
    one = s.score_case({"defects": [D(10), D(11)], "fp_budget": 0}, [F(10)])
    assert (one["tp"], one["partial"], one["fn"]) == (1, 0, 1), one
    assert sorted(o["outcome"] for o in one["defect_outcomes"]) == ["fn", "tp"]
    assert sum(len(o["matched_finding_indices"]) for o in one["defect_outcomes"]) == 1  # finding used once
    # two findings covering two overlapping defects -> both detected (no under-counting from greedy)
    two = s.score_case({"defects": [D(10), D(11)], "fp_budget": 0}, [F(10), F(11)])
    assert (two["tp"], two["partial"], two["fn"]) == (2, 0, 0), two
    # a below-floor finding on one of two overlapping defects is a PARTIAL, and it is still consumed
    part = s.score_case({"defects": [D(10), D(11)], "fp_budget": 0}, [F(10, "low")])
    assert (part["tp"], part["partial"], part["fn"]) == (0, 1, 1), part


def t_eval_score_aggregate():
    # E1-S2: aggregate rolls up overall + per-category + per-tier; detection_rate counts only TPs and
    # is None when a bucket has no must_detect defects (clean-only).
    s = _import_score()
    r_tp = {"tp": 1, "partial": 0, "fn": 0, "fp": 0, "noise": 0, "must_detect_total": 1}
    r_fn = {"tp": 0, "partial": 1, "fn": 1, "fp": 2, "noise": 0, "must_detect_total": 2}
    r_clean = {"tp": 0, "partial": 0, "fn": 0, "fp": 0, "noise": 0, "must_detect_total": 0}
    agg = s.aggregate([({"category": "security", "tier": "NORMAL"}, r_tp),
                       ({"category": "correctness", "tier": "NORMAL"}, r_fn),
                       ({"category": "clean", "tier": "NORMAL"}, r_clean)])
    assert agg["overall"]["tp"] == 1 and agg["overall"]["fn"] == 1 and agg["overall"]["fp"] == 2
    assert agg["overall"]["detection_rate"] == round(1 / 3, 4)
    assert agg["by_category"]["clean"]["detection_rate"] is None            # no must_detect defects
    assert agg["by_category"]["security"]["detection_rate"] == 1.0
    assert agg["by_tier"]["NORMAL"]["cases"] == 3


def t_eval_score_on_real_corpus():
    # E1-S2: the scorer runs against the committed E1-S1 corpus. A finding placed on each defect's
    # locator scores TP; a clean case with no findings has zero FP.
    s = _import_score()
    corpus = SKILL / "evals" / "corpus"
    scored = 0
    for d in sorted(os.listdir(corpus)):
        cd = corpus / d
        if not cd.is_dir():
            continue
        exp = json.loads((cd / "expected.json").read_text(encoding="utf-8"))
        defs = exp.get("defects", [])
        if defs:
            loc = defs[0]["locators"][0]
            find = _f(file=loc["file"], line=loc["line_range"][0],
                      severity=defs[0]["severity_floor"], title=" ".join(defs[0]["root_cause_tags"]))
            res = s.score_case(exp, [find])
            assert res["tp"] == 1, (d, res)
        else:  # clean case, no findings -> no false positives
            assert s.score_case(exp, [])["fp"] == 0, d
        scored += 1
    assert scored >= 6


def _run_eval_offline(only, extra=()):
    """Invoke evals/run.py --mode offline as a subprocess (its real CLI) and return
    (parsed_result, raw_stdout). run.py starts its own ephemeral mock router, so it never
    collides with this suite's server on :PORT."""
    r = subprocess.run(
        [sys.executable, str(SKILL / "evals" / "run.py"), "--mode", "offline",
         "--no-write", "--print-result", "--quiet", "--only", *only, *extra],
        env=ENV, capture_output=True, text=True)
    assert r.returncode == 0, "evals/run.py failed (exit %d)\n%s" % (r.returncode, r.stderr)
    last = r.stdout.strip().splitlines()[-1]
    return json.loads(last), last


def t_eval_offline_harness_scores_representative_cases():
    # E1-S3: the offline harness drives the REAL panel path (assign -> run -> ingest) against
    # scripted reviewers and scores through score.py. A representative subset — a detected defect,
    # a deliberate miss, and an over-budget clean case — guards the whole assembly on every CI run.
    result, _ = _run_eval_offline(
        ["sec-idor-invoice", "corr-offbyone-pagination", "out-inverted-finalize",
         "test-weak-assert-charge", "clean-refactor-total"])
    per = {c["case_id"]: c for c in result["cases"]}
    assert (per["sec-idor-invoice"]["tp"], per["sec-idor-invoice"]["fp"]) == (1, 0), per["sec-idor-invoice"]
    assert per["corr-offbyone-pagination"]["tp"] == 1, per["corr-offbyone-pagination"]
    assert per["out-inverted-finalize"]["partial"] == 1, per["out-inverted-finalize"]  # found, under-rated
    assert (per["test-weak-assert-charge"]["fn"], per["test-weak-assert-charge"]["noise"]) == (1, 1), \
        per["test-weak-assert-charge"]  # reviewer looked but missed -> FN + a low unmatched nit = noise
    assert per["clean-refactor-total"]["fp"] == 1, per["clean-refactor-total"]  # over fp_budget
    ov = result["aggregate"]["overall"]
    assert (ov["tp"], ov["partial"], ov["fn"], ov["fp"]) == (2, 1, 1, 1), ov
    assert result["skipped"] == [], result["skipped"]


def t_eval_offline_harness_deterministic():
    # Invariant 4 (deterministic audit record): same corpus + same scripts -> byte-identical scored
    # `result`. Wall-clock is stamped only OUTSIDE result (generated_at + filename), so two runs of
    # the scored payload must match exactly.
    _, a = _run_eval_offline(["corr-offbyone-pagination", "out-inverted-finalize"])
    _, b = _run_eval_offline(["corr-offbyone-pagination", "out-inverted-finalize"])
    assert a == b, "offline scored result is not deterministic across runs"


def t_eval_offline_harness_skips_and_rejects_edge_cases():
    # E1-S3: a valid case with no scripts.offline is SKIPPED and surfaced in result['skipped'] (never
    # silently), while a MALFORMED case FAILS the run — a broken self-test must not pass quietly.
    base = Path(tempfile.mkdtemp(prefix="ar-evalcorp-"))
    runpy = str(SKILL / "evals" / "run.py")
    try:
        noscript = base / "noscript"
        noscript.mkdir()
        (noscript / "meta.json").write_text(json.dumps({"id": "noscript", "title": "x", "tier": "NORMAL",
            "category": "clean", "language": "python", "source": "seeded"}))
        (noscript / "context.md").write_text("diff --git a/x b/x\n+clean\n")
        (noscript / "expected.json").write_text(json.dumps({"defects": [], "fp_budget": 1}))
        r = subprocess.run([sys.executable, runpy, "--mode", "offline", "--corpus", str(base),
                            "--no-write", "--print-result", "--quiet"], env=ENV,
                           capture_output=True, text=True)
        assert r.returncode == 0, r.stderr
        result = json.loads(r.stdout.strip().splitlines()[-1])
        assert result["skipped"] == ["noscript"], result["skipped"]
        assert result["cases"] == [], result["cases"]

        bad = base / "bad"        # meta.id != dir name -> validate_case rejects it
        bad.mkdir()
        (bad / "meta.json").write_text(json.dumps({"id": "WRONGID", "title": "x", "tier": "NORMAL",
            "category": "clean", "language": "python", "source": "seeded"}))
        (bad / "context.md").write_text("x")
        (bad / "expected.json").write_text(json.dumps({"defects": [], "fp_budget": 1,
            "scripts": {"offline": {}}}))
        r2 = subprocess.run([sys.executable, runpy, "--mode", "offline", "--corpus", str(base),
                             "--no-write", "--quiet"], env=ENV, capture_output=True, text=True)
        assert r2.returncode != 0, "a malformed case must fail the offline run, not be skipped"
        assert "invalid" in (r2.stdout + r2.stderr).lower(), (r2.stdout + r2.stderr)[-300:]
    finally:
        shutil.rmtree(base, ignore_errors=True)


def t_eval_offline_harness_cli_hardening():
    # E1-S3 (PR #45): a negative --line-tol makes every location match fail, so the CLI must reject
    # it up front; and --print-result must keep stdout pure JSON (progress goes to stderr) so the
    # documented `... --no-write --print-result | jq` pipe works even without --quiet.
    runpy = str(SKILL / "evals" / "run.py")
    r = subprocess.run([sys.executable, runpy, "--mode", "offline", "--only", "sec-idor-invoice",
                        "--no-write", "--quiet", "--line-tol", "-1"], env=ENV,
                       capture_output=True, text=True)
    assert r.returncode != 0, "negative --line-tol must be rejected"
    assert "line-tol" in r.stderr.lower(), r.stderr[-200:]
    r2 = subprocess.run([sys.executable, runpy, "--mode", "offline", "--only", "sec-idor-invoice",
                         "--no-write", "--print-result"], env=ENV, capture_output=True, text=True)
    assert r2.returncode == 0, r2.stderr
    parsed = json.loads(r2.stdout)   # entire stdout is the canonical JSON, no progress lines mixed in
    assert parsed["cases"][0]["case_id"] == "sec-idor-invoice", parsed


def t_corpus_rejects_offtier_script_role():
    # E1-S3 (PR #45): scripts.offline may only script roles the case's tier runs. A NORMAL case
    # scripting data_privacy would have those findings silently never served/scored (a hidden FN),
    # so the validator rejects it loudly.
    sys.path.insert(0, str(SKILL / "evals"))
    import corpus_schema as cs
    d = Path(tempfile.mkdtemp(prefix="ar-corpus-tier-"))
    try:
        case = d / "offtier"
        case.mkdir()
        (case / "meta.json").write_text(json.dumps({"id": "offtier", "title": "x", "tier": "NORMAL",
            "category": "correctness", "language": "python", "source": "seeded"}))
        (case / "context.md").write_text("diff\n+x\n")
        (case / "expected.json").write_text(json.dumps({
            "defects": [{"defect_id": "d1", "must_detect": True,
                         "locators": [{"file": "a.py", "line_range": [1, 1]}],
                         "root_cause_tags": ["t"], "severity_floor": "high"}],
            "fp_budget": 1,
            "scripts": {"offline": {"data_privacy": [{"title": "x", "severity": "high",
                                                      "file": "a.py", "line": 1}]}}}))
        errs = cs.validate_case(str(case))
        assert any("not run at tier" in e for e in errs), errs
    finally:
        shutil.rmtree(d, ignore_errors=True)


def t_eval_summary_escapes_untrusted_identifiers():
    # E1-S3 (PR #45, CodeRabbit): every corpus-controlled identifier rendered into summary.md — the
    # table cells AND the corpus path and the skipped-case list — goes through _md_cell, so a `|`,
    # backtick, or newline in an external id can't forge cells/rows or break out of a code span.
    sys.path.insert(0, str(SKILL / "evals"))
    import run as evalrun
    assert evalrun._md_cell("a|b") == "a\\|b"
    assert evalrun._md_cell("a`b") == "a\\`b"
    assert evalrun._md_cell("a\nb") == "a b"          # control chars collapse to a space
    result = {
        "corpus": "corp`x|y", "line_tol": 3, "skipped": ["sk`|id"], "cases": [],
        "aggregate": {
            "overall": {"cases": 0, "must_detect_total": 0, "detection_rate": None,
                        "tp": 0, "partial": 0, "fn": 0, "fp": 0, "noise": 0},
            "by_category": {}, "by_tier": {}, "by_role": {}}}
    md = evalrun._summary_md(result, "test")
    # raw (unescaped) identifiers must not survive into the report; their escaped forms must
    assert "corp`x|y" not in md and "corp\\`x\\|y" in md, md
    assert "sk`|id" not in md and "sk\\`\\|id" in md, md
    # the corpus path is no longer wrapped in raw backticks (an embedded ` could close the span)
    assert "corpus: `" not in md, md


def _run_eval_live(only, extra=(), reviewer_cost=0.0, env=None):
    """Invoke evals/run.py --mode live against the SUITE mock router (ENV's AR_BASE_URL) with a set
    per-reviewer cost, so live-mode machinery (reps, budget, per-model/cost rollups) is exercised with
    no network and no keys. Returns (parsed_result, raw_stdout)."""
    mock_router.reset()
    mock_router.STATE["reviewer_cost"] = reviewer_cost
    try:
        r = subprocess.run(
            [sys.executable, str(SKILL / "evals" / "run.py"), "--mode", "live",
             "--no-write", "--print-result", "--quiet", "--only", *only, *extra],
            env=env or ENV, capture_output=True, text=True)
    finally:
        mock_router.reset()
    assert r.returncode == 0, "evals/run.py --mode live failed (exit %d)\n%s" % (r.returncode, r.stderr)
    return json.loads(r.stdout.strip().splitlines()[-1]), r.stdout


def t_eval_live_harness_scores_and_attributes():
    # E1-S4: live mode drives REAL panels (here against the mock router, no keys) N times per case and
    # scores each; per-model attribution, cost, and reps must all reconcile. sec-idor-invoice's IDOR is
    # exactly what the mock's default security report raises, so detection is 1.0 and deterministic here.
    result, _ = _run_eval_live(["sec-idor-invoice"], extra=["--reps", "2", "--budget-usd", "20"],
                               reviewer_cost=0.05)
    assert result["reps"] == 2, result["reps"]
    ov = result["aggregate"]["overall"]
    assert ov["detection_rate"] == 1.0 and ov["tp"] == 2 and ov["fp"] == 0, ov
    bm = result["aggregate"]["by_model"]
    assert bm, "per-model rollup must be populated"
    assert sum(m["tp"] for m in bm.values()) == 2, bm          # security caught the IDOR both reps
    assert sum(m["emitted"] for m in bm.values()) == 2, bm     # only the security role emits by default
    total = result["spent_usd"]
    assert total > 0, total
    # cost reconciles three ways: run total == sum per-model == sum per-case
    assert round(sum(m["cost_usd"] for m in bm.values()), 6) == total, (bm, total)
    assert round(sum(c["cost_usd"] for c in result["cases"]), 6) == total, total
    assert result["cases"][0]["reps"] == 2 and result["cases"][0]["detection_rate"] == 1.0, result["cases"]
    assert result["complete"] is True and result["not_run"] == [], result


def t_eval_live_harness_budget_guard_stops():
    # E1-S4: the cumulative USD budget caps the whole run. With a budget below one panel's cost, the
    # first rep still runs (pre-panel check), then the rest are recorded in not_run — never silently
    # dropped, and overspend is bounded by the one in-flight panel.
    result, _ = _run_eval_live(["sec-idor-invoice"], extra=["--reps", "3", "--budget-usd", "0.01"],
                               reviewer_cost=0.05)
    assert result["complete"] is False, result
    assert result["cases"][0]["reps"] == 1, result["cases"]            # exactly one panel ran
    assert [u["rep"] for u in result["not_run"]] == [2, 3], result["not_run"]
    assert result["spent_usd"] > 0.01, result["spent_usd"]


def t_eval_live_harness_cli_guards():
    # E1-S4: live mode is opt-in and fails loudly when misconfigured — no key/base-url means no provider
    # (don't spend a run on no-op panels); --reps must be >= 1; and --print-result keeps stdout pure JSON
    # (progress on stderr) so `... --print-result | jq` works without --quiet.
    bare = {k: v for k, v in ENV.items()
            if k not in ("AR_BASE_URL", "AR_API_KEY", "OPENROUTER_API_KEY",
                         "OPENAI_API_KEY", "AR_KEY_FILE")}
    r = subprocess.run([sys.executable, str(SKILL / "evals" / "run.py"), "--mode", "live",
                        "--only", "sec-idor-invoice", "--no-write", "--quiet"],
                       env=bare, capture_output=True, text=True)
    assert r.returncode != 0 and "provider" in r.stderr.lower(), r.stderr[-300:]

    r2 = subprocess.run([sys.executable, str(SKILL / "evals" / "run.py"), "--mode", "live",
                         "--only", "sec-idor-invoice", "--no-write", "--quiet", "--reps", "0"],
                        env=ENV, capture_output=True, text=True)
    assert r2.returncode != 0 and "reps" in r2.stderr.lower(), r2.stderr[-300:]

    r_neg = subprocess.run([sys.executable, str(SKILL / "evals" / "run.py"), "--mode", "live",
                            "--only", "sec-idor-invoice", "--no-write", "--quiet", "--budget-usd", "-1"],
                           env=ENV, capture_output=True, text=True)
    assert r_neg.returncode != 0 and "budget" in r_neg.stderr.lower(), r_neg.stderr[-200:]

    mock_router.reset()
    try:
        r3 = subprocess.run([sys.executable, str(SKILL / "evals" / "run.py"), "--mode", "live",
                             "--only", "sec-idor-invoice", "--no-write", "--print-result"],
                            env=ENV, capture_output=True, text=True)
    finally:
        mock_router.reset()
    assert r3.returncode == 0, r3.stderr[-400:]
    parsed = json.loads(r3.stdout)   # entire stdout parses; progress went to stderr
    assert parsed["cases"][0]["case_id"] == "sec-idor-invoice", parsed


def t_eval_live_harness_rejects_malformed_case():
    # E1-S4 (PR #46, test_quality-1): live mode, like offline, must FAIL on a malformed case, not skip
    # it. Validation runs before any panel, so this needs no network.
    base = Path(tempfile.mkdtemp(prefix="ar-livecorp-"))
    try:
        bad = base / "bad"
        bad.mkdir()
        (bad / "meta.json").write_text(json.dumps({"id": "WRONGID", "title": "x", "tier": "NORMAL",
            "category": "clean", "language": "python", "source": "seeded"}))
        (bad / "context.md").write_text("x")
        (bad / "expected.json").write_text(json.dumps({"defects": [], "fp_budget": 1}))
        r = subprocess.run([sys.executable, str(SKILL / "evals" / "run.py"), "--mode", "live",
                            "--corpus", str(base), "--no-write", "--quiet"],
                           env=ENV, capture_output=True, text=True)
        assert r.returncode != 0, "a malformed case must fail the live run, not be skipped"
        assert "invalid" in (r.stdout + r.stderr).lower(), (r.stdout + r.stderr)[-300:]
    finally:
        shutil.rmtree(base, ignore_errors=True)


def t_eval_live_harness_fails_closed_without_cost_telemetry():
    # E1-S4 (PR #46, security-1): when --budget-usd is set but a completed panel reports no cost
    # telemetry (reviewer_cost 0), the harness can't enforce the dollar cap by summing costs, so it
    # stops and records why rather than silently spending on under an ineffective cap.
    result, _ = _run_eval_live(["sec-idor-invoice"], extra=["--reps", "3", "--budget-usd", "5"],
                               reviewer_cost=0.0)
    assert result["complete"] is False, result
    assert result["spent_usd"] == 0.0, result["spent_usd"]
    assert "telemetry" in (result.get("stop_reason") or ""), result.get("stop_reason")
    assert result["cases"][0]["reps"] == 1, result["cases"]        # one panel ran, then stopped
    assert [u["rep"] for u in result["not_run"]] == [2, 3], result["not_run"]


def t_eval_live_harness_ignores_inherited_run_dir():
    # E1-S4 (PR #46, CodeRabbit/Codex): a live run must not break when the operator has AR_RUN_DIR set.
    # _panel_env_live drops it so each child panel writes its run dir inside its own throwaway repo.
    env = dict(ENV)
    env["AR_RUN_DIR"] = "/tmp/ar-inherited-run-dir-should-be-ignored"
    result, _ = _run_eval_live(["sec-idor-invoice"], extra=["--reps", "1", "--budget-usd", "20"],
                               reviewer_cost=0.05, env=env)
    assert result["cases"][0]["reps"] == 1, result       # panel ran and produced a run dir
    assert result["complete"] is True, result


def t_eval_live_harness_preflights_before_paid_calls():
    # E1-S4 (PR #46, Codex): a malformed case sorted AFTER a valid one must fail the live run BEFORE any
    # panel runs — no wasted spend. Proven by the mock router receiving zero chat calls.
    base = Path(tempfile.mkdtemp(prefix="ar-livepre-"))
    try:
        good = base / "aaa-good"
        good.mkdir()
        (good / "meta.json").write_text(json.dumps({"id": "aaa-good", "title": "x", "tier": "NORMAL",
            "category": "clean", "language": "python", "source": "seeded"}))
        (good / "context.md").write_text("diff\n+x\n")
        (good / "expected.json").write_text(json.dumps({"defects": [], "fp_budget": 1}))
        bad = base / "zzz-bad"
        bad.mkdir()
        (bad / "meta.json").write_text(json.dumps({"id": "WRONGID", "title": "x", "tier": "NORMAL",
            "category": "clean", "language": "python", "source": "seeded"}))
        (bad / "context.md").write_text("x")
        (bad / "expected.json").write_text(json.dumps({"defects": [], "fp_budget": 1}))
        mock_router.reset()
        try:
            r = subprocess.run([sys.executable, str(SKILL / "evals" / "run.py"), "--mode", "live",
                                "--corpus", str(base), "--no-write", "--quiet"],
                               env=ENV, capture_output=True, text=True)
            assert r.returncode != 0 and "invalid" in (r.stdout + r.stderr).lower(), (r.stdout + r.stderr)[-200:]
            assert mock_router.STATE["calls"] == {}, "preflight must reject before any paid panel call"
        finally:
            mock_router.reset()
    finally:
        shutil.rmtree(base, ignore_errors=True)


def t_eval_live_summary_is_stop_neutral():
    # E1-S4 (PR #46, CodeRabbit): after a NON-budget early stop (cost telemetry) on a single-case run,
    # the summary must not claim "later cases ran fewer", must surface the real stop reason, and must
    # label skipped units stop-neutrally (not "budget").
    sys.path.insert(0, str(SKILL / "evals"))
    import run as evalrun
    result = {
        "corpus": "c", "line_tol": 3, "reps": 3, "budget_usd": 5.0, "spent_usd": 0.0,
        "complete": False, "stop_reason": "cost telemetry unavailable -- a completed panel reported $0",
        "not_run": [{"case": "only", "rep": 2}, {"case": "only", "rep": 3}],
        "clean_fp": 0, "clean_units": 0, "clean_fp_rate": None,
        "cases": [{"case_id": "only", "category": "security", "tier": "SENSITIVE", "reps": 1,
                   "detection_rate": 1.0, "cost_usd": 0.0}],
        "aggregate": {"overall": {"cases": 1, "must_detect_total": 1, "detection_rate": 1.0,
                                  "tp": 1, "partial": 0, "fn": 0, "fp": 0, "noise": 0},
                      "by_category": {}, "by_tier": {}, "by_role": {}, "by_model": {}}}
    md = evalrun._live_summary_md(result, "test")
    assert "later cases ran fewer" not in md, md
    assert "Not run (budget)" not in md and "Not run (early stop)" in md, md
    assert "cost telemetry" in md, md


def t_eval_live_harness_records_units_after_panel_failure():
    # E1-S4 (PR #46, CodeRabbit): when a live panel fails on the last/only case, its remaining reps must
    # still be recorded in not_run (continue, not break), and the run must stop with a report rather than
    # a traceback. Every reviewer 500s so the panel dies after retry + substitution.
    mock_router.reset()
    mock_router.STATE["fail_models"] = {m["id"] for m in mock_router.CATALOG["data"]}
    try:
        r = subprocess.run([sys.executable, str(SKILL / "evals" / "run.py"), "--mode", "live",
                            "--only", "sec-idor-invoice", "--reps", "2", "--budget-usd", "20",
                            "--no-write", "--print-result", "--quiet"],
                           env=ENV, capture_output=True, text=True)
    finally:
        mock_router.reset()
    assert r.returncode == 0, r.stderr[-400:]      # a panel failure yields a report, not a crash
    result = json.loads(r.stdout.strip().splitlines()[-1])
    assert result["complete"] is False, result
    assert [u["rep"] for u in result["not_run"]] == [1, 2], result["not_run"]   # BOTH reps recorded
    assert "live panel failed" in (result.get("stop_reason") or ""), result.get("stop_reason")
    assert result["cases"] == [], result["cases"]


def t_eval_thresholds_offline_gate():
    # E1-S5: `thresholds.py check` runs the full offline corpus and must exit 0 — proving the committed
    # evals/thresholds.json floors are DESCRIPTIVE (met by the current corpus), not aspirational, and
    # exercising the exact command the CI evals job runs. Then check_offline flags regressions.
    r = subprocess.run([sys.executable, str(SKILL / "evals" / "thresholds.py"), "check"],
                       env=ENV, capture_output=True, text=True)
    assert r.returncode == 0 and "OK" in r.stderr, (r.returncode, r.stderr[-300:])
    sys.path.insert(0, str(SKILL / "evals"))
    import thresholds as th
    thr = th.load_thresholds()
    good = {"aggregate": {"overall": {"detection_rate": 0.5, "fp": 1},
                          "by_category": {"security": {"detection_rate": 1.0},
                                          "correctness": {"detection_rate": 1.0}}}}
    assert th.check_offline(good, thr) == [], th.check_offline(good, thr)
    bad = json.loads(json.dumps(good))
    bad["aggregate"]["overall"]["detection_rate"] = 0.25
    bad["aggregate"]["overall"]["fp"] = 2
    breaches = th.check_offline(bad, thr)
    assert any("detection_rate" in b for b in breaches) and any("fp" in b for b in breaches), breaches
    bad2 = json.loads(json.dumps(good))
    bad2["aggregate"]["by_category"]["security"]["detection_rate"] = 0.0
    assert any("security" in b for b in th.check_offline(bad2, thr)), th.check_offline(bad2, thr)
    # E1-S5 fail-safe (test_quality-1): a category in thresholds but ABSENT from the result breaches.
    thr_cat = {"offline": {"overall": {}, "by_category": {"security": {"min_detection_rate": 1.0}}}}
    miss = {"aggregate": {"overall": {}, "by_category": {}}}
    assert any("security" in b and "absent" in b for b in th.check_offline(miss, thr_cat)), \
        th.check_offline(miss, thr_cat)
    # E1-S5 fail-safe (correctness-1): a null overall fp breaches instead of raising TypeError.
    thr_ofp = {"offline": {"overall": {"max_fp": 1}, "by_category": {}}}
    nullfp = {"aggregate": {"overall": {"detection_rate": 0.5, "fp": None}, "by_category": {}}}
    assert any("fp" in b for b in th.check_offline(nullfp, thr_ofp)), th.check_offline(nullfp, thr_ofp)
    # E1-S5 bot round (Codex): a present-but-non-numeric fp also fail-closes (isinstance guard).
    strfp = {"aggregate": {"overall": {"detection_rate": 0.5, "fp": "x"}, "by_category": {}}}
    assert any("fp" in b for b in th.check_offline(strfp, thr_ofp)), th.check_offline(strfp, thr_ofp)
    # E1-S5 (test_quality-5): per-category max_fp ceiling is enforced.
    thr_cfp = {"offline": {"overall": {}, "by_category": {"security": {"max_fp": 0}}}}
    catfp = {"aggregate": {"overall": {}, "by_category": {"security": {"detection_rate": 1.0, "fp": 3}}}}
    assert any("security" in b and "fp" in b for b in th.check_offline(catfp, thr_cfp)), \
        th.check_offline(catfp, thr_cfp)
    # E1-S5 (test_quality-3): a corrupt thresholds.json fails LOUD (fail-closed config), never silently.
    badthr = Path(tempfile.mkdtemp(prefix="ar-thr3-")) / "bad.json"
    badthr.write_text("{ not: valid json ]")
    try:
        raised = False
        try:
            th.load_thresholds(str(badthr))
        except ValueError:
            raised = True
        assert raised, "load_thresholds must raise on malformed JSON, not pass silently"
    finally:
        shutil.rmtree(badthr.parent, ignore_errors=True)


def t_eval_thresholds_compare_live():
    # E1-S5: compare_live flags overall/category detection drops past max_drop and per-model TP drops
    # (the "model degraded" alarm), tolerates drops within budget, and unwraps the report wrapper.
    sys.path.insert(0, str(SKILL / "evals"))
    import thresholds as th
    base = {"aggregate": {"overall": {"detection_rate": 1.0},
                          "by_category": {"security": {"detection_rate": 1.0}},
                          "by_model": {"m-a": {"tp": 2}, "m-b": {"tp": 1}}}}
    cur = {"aggregate": {"overall": {"detection_rate": 0.6},
                         "by_category": {"security": {"detection_rate": 1.0}},
                         "by_model": {"m-a": {"tp": 0}, "m-b": {"tp": 1}}}}
    regs = th.compare_live(base, cur, 0.2)
    assert any("overall detection dropped" in r for r in regs), regs
    assert any("m-a" in r and "true positives fell" in r for r in regs), regs
    assert th.compare_live(base, base, 0.2) == []
    near = {"aggregate": {"overall": {"detection_rate": 0.85}, "by_category": {}, "by_model": {}}}
    base2 = {"aggregate": {"overall": {"detection_rate": 1.0}, "by_category": {}, "by_model": {}}}
    assert th.compare_live(base2, near, 0.2) == [], "a drop within max_drop must not flag"
    assert th.compare_live({"result": base}, {"result": cur}, 0.2), "must unwrap {result: ...} reports"
    # E1-S5 robustness (correctness-2): a null tp in either report is coerced, not a TypeError.
    bnull = {"aggregate": {"overall": {"detection_rate": 1.0}, "by_category": {},
                           "by_model": {"m-a": {"tp": None}}}}
    assert th.compare_live(bnull, bnull, 0.2) == [], "null tp must not crash or spuriously flag"
    # E1-S5 (test_quality-4): a model new in current (absent from baseline) is not flagged.
    bmod = {"aggregate": {"overall": {"detection_rate": 1.0}, "by_category": {},
                          "by_model": {"m-a": {"tp": 2}}}}
    cmod = {"aggregate": {"overall": {"detection_rate": 1.0}, "by_category": {},
                          "by_model": {"m-a": {"tp": 2}, "m-new": {"tp": 5}}}}
    assert th.compare_live(bmod, cmod, 0.2) == [], "a model new in current must not flag"
    # E1-S5 (test_quality-2): a bare result and the {result: ...} wrapper unwrap to identical output.
    assert th.compare_live(base, cur, 0.2) == th.compare_live({"result": base}, {"result": cur}, 0.2), \
        "wrapped and bare reports must compare identically"
    # E1-S5 bot round (CodeRabbit Major / Codex): a baseline category absent from current is flagged.
    babs = {"aggregate": {"overall": {"detection_rate": 1.0},
                          "by_category": {"security": {"detection_rate": 1.0}}, "by_model": {}}}
    cabs = {"aggregate": {"overall": {"detection_rate": 1.0}, "by_category": {}, "by_model": {}}}
    assert any("security" in r and "absent" in r for r in th.compare_live(babs, cabs, 0.2)), \
        th.compare_live(babs, cabs, 0.2)
    # an incomplete current report (stopped early) is itself flagged, never a silent "no regression".
    cinc = {"complete": False, "stop_reason": "budget reached",
            "aggregate": {"overall": {"detection_rate": 1.0}, "by_category": {}, "by_model": {}}}
    assert any("incomplete" in r for r in th.compare_live(babs, cinc, 0.2)), th.compare_live(babs, cinc, 0.2)
    # E1-S5 bot round 2 (CodeRabbit Major): a non-numeric / NaN detection_rate is reported, never a
    # crash and never a silent clean pass.
    bstr = {"aggregate": {"overall": {"detection_rate": "0.9"}, "by_category": {}, "by_model": {}}}
    cstr = {"aggregate": {"overall": {"detection_rate": "0.1"}, "by_category": {}, "by_model": {}}}
    assert any("invalid" in r for r in th.compare_live(bstr, cstr, 0.2)), th.compare_live(bstr, cstr, 0.2)
    cnan = {"aggregate": {"overall": {"detection_rate": float("nan")}, "by_category": {}, "by_model": {}}}
    bok = {"aggregate": {"overall": {"detection_rate": 1.0}, "by_category": {}, "by_model": {}}}
    assert any("invalid" in r for r in th.compare_live(bok, cnan, 0.2)), "NaN current rate must not silently pass"
    # a non-numeric tp is coerced to no-signal, never a TypeError.
    btpstr = {"aggregate": {"overall": {"detection_rate": 1.0}, "by_category": {}, "by_model": {"m": {"tp": "5"}}}}
    assert th.compare_live(btpstr, btpstr, 0.2) == [], "string tp must not crash"
    # E1-S5 bot round 3 (CodeRabbit Major): an invalid CURRENT tp must not fake a "fell to 0"
    # degradation; it is reported as not-comparable. An absent tp still reads as no-contribution.
    bval = {"aggregate": {"overall": {"detection_rate": 1.0}, "by_category": {}, "by_model": {"m": {"tp": 3}}}}
    cbad = {"aggregate": {"overall": {"detection_rate": 1.0}, "by_category": {}, "by_model": {"m": {"tp": "x"}}}}
    rb = th.compare_live(bval, cbad, 0.2)
    assert any("invalid" in r for r in rb) and not any("fell" in r for r in rb), rb
    cgone = {"aggregate": {"overall": {"detection_rate": 1.0}, "by_category": {}, "by_model": {}}}
    assert any("fell 3 -> 0" in r for r in th.compare_live(bval, cgone, 0.2)), th.compare_live(bval, cgone, 0.2)
    # E1-S5 bot round 4 (CodeRabbit Major): a negative tp is not a valid count -> not comparable.
    cneg = {"aggregate": {"overall": {"detection_rate": 1.0}, "by_category": {}, "by_model": {"m": {"tp": -1}}}}
    rn = th.compare_live(bval, cneg, 0.2)
    assert any("invalid" in r for r in rn) and not any("fell" in r for r in rn), rn


def t_eval_thresholds_cli():
    # E1-S5: exit codes — check passes at the floor and fails past it; compare fails on a regression
    # and passes when clean. (Uses crafted result files so it adds no full-corpus run.)
    thr_py = str(SKILL / "evals" / "thresholds.py")
    d = Path(tempfile.mkdtemp(prefix="ar-thr-"))
    try:
        good = {"aggregate": {"overall": {"detection_rate": 0.5, "fp": 1},
                              "by_category": {"security": {"detection_rate": 1.0},
                                              "correctness": {"detection_rate": 1.0}}}}
        (d / "good.json").write_text(json.dumps(good))
        r = subprocess.run([sys.executable, thr_py, "check", "--result", str(d / "good.json")],
                           env=ENV, capture_output=True, text=True)
        assert r.returncode == 0 and "OK" in r.stderr, (r.returncode, r.stderr[-200:])
        bad = {"aggregate": {"overall": {"detection_rate": 0.0, "fp": 9}, "by_category": {}}}
        (d / "bad.json").write_text(json.dumps(bad))
        r2 = subprocess.run([sys.executable, thr_py, "check", "--result", str(d / "bad.json")],
                            env=ENV, capture_output=True, text=True)
        assert r2.returncode == 1 and "BREACH" in r2.stderr, (r2.returncode, r2.stderr[-200:])
        base = {"aggregate": {"overall": {"detection_rate": 1.0}, "by_category": {},
                              "by_model": {"m": {"tp": 2}}}}
        cur = {"aggregate": {"overall": {"detection_rate": 0.2}, "by_category": {},
                             "by_model": {"m": {"tp": 0}}}}
        (d / "base.json").write_text(json.dumps(base))
        (d / "cur.json").write_text(json.dumps(cur))
        r3 = subprocess.run([sys.executable, thr_py, "compare", "--baseline", str(d / "base.json"),
                             "--current", str(d / "cur.json")], env=ENV, capture_output=True, text=True)
        assert r3.returncode == 1 and "DEGRAD" in r3.stderr, (r3.returncode, r3.stderr[-200:])
        r4 = subprocess.run([sys.executable, thr_py, "compare", "--baseline", str(d / "base.json"),
                             "--current", str(d / "base.json")], env=ENV, capture_output=True, text=True)
        assert r4.returncode == 0, (r4.returncode, r4.stderr[-200:])
        r5 = subprocess.run([sys.executable, thr_py, "compare", "--baseline", str(d / "base.json"),
                             "--current", str(d / "cur.json"), "--max-drop", "nan"],
                            env=ENV, capture_output=True, text=True)
        assert r5.returncode == 2 and "finite fraction" in r5.stderr, (r5.returncode, r5.stderr[-200:])
    finally:
        shutil.rmtree(d, ignore_errors=True)


def t_high_samples_corroborates_flagged_role():
    # E4-S3: with AR_HIGH_SAMPLES=3, a role that raised a high finding is resampled to 3 total
    # samples and the cross-sample agreement rate is recorded ON that finding. Roles that raised no
    # high/critical finding are NOT resampled (a thin loop). Asserts observable artifact contents.
    mock_router.reset()

    def provider(m):
        if m["kind"] != "report" or m["role"] != "security":
            return None  # other roles -> default canned report (no findings) -> not resampled
        # do_POST increments STATE["calls"] before calling us, so this is the 1-based call index for
        # the security model: 1 = primary, 2 = sample-2, 3 = sample-3.
        rep = mock_router._report("security", m["model"])
        if mock_router.STATE["calls"][m["model"]] <= 2:
            return rep  # primary + sample-2: the SAME IDOR finding -> corroborates
        rep["findings"] = [{**rep["findings"][0], "id": "security-9",
                            "title": "Unrelated race in worker pool", "file": "workers/pool.py"}]
        return rep  # sample-3: a high finding on a DIFFERENT file -> does not corroborate

    mock_router.STATE["response_provider"] = provider
    try:
        repo = fresh_repo()
        sh(["panel.py", "init", "--risk", "NORMAL", "--dev-providers", "anthropic"], repo)
        sh(["panel.py", "assign"], repo)
        sh(["panel.py", "run", "--context-file", "context.md"], repo,
           env={**ENV, "AR_HIGH_SAMPLES": "3"})
        run = latest_run(repo)
        plan = read(run / "panel" / "plan.json")
        sec_model = plan["roles"]["security"]["model"]
        corr_model = plan["roles"]["correctness"]["model"]
        # the primary finding carries the agreement record: 2 of 3 samples agreed (primary + s2)
        fin = read(run / "panel" / "security.json")["findings"][0]
        assert fin["id"] == "security-1", fin
        assert fin["corroboration"]["samples"] == 3 and fin["corroboration"]["agreed"] == 2, fin
        assert abs(fin["corroboration"]["rate"] - round(2 / 3, 4)) < 1e-9, fin["corroboration"]
        # each extra sample was RECORDED, so the rate reproduces from the recorded artifacts
        assert read(run / "panel" / "samples" / "security.2.json")["findings"][0]["id"] == "security-1"
        assert read(run / "panel" / "samples" / "security.3.json")["findings"][0]["id"] == "security-9"
        # exactly 3 calls to the security model (primary + 2 corroboration samples)
        assert mock_router.STATE["calls"][sec_model] == 3, mock_router.STATE["calls"]
        # a role with no high/critical finding is NOT resampled: one call, no sample artifacts
        assert mock_router.STATE["calls"][corr_model] == 1, mock_router.STATE["calls"]
        assert not (run / "panel" / "samples" / "correctness.2.json").exists()
        # sample cost is metered under panel/meta so it counts against the cap + coverage
        assert (run / "panel" / "meta" / "security.sample2.json").exists()
        assert (run / "panel" / "meta" / "security.sample3.json").exists()
    finally:
        mock_router.reset()


def t_high_samples_default_one_is_unchanged():
    # E4-S3: AR_HIGH_SAMPLES defaults to 1 = exactly today's behavior. No resampling, no
    # corroboration field, no sample artifacts; the recorded report is byte-identical to the mock's
    # canned report. Explicit AR_HIGH_SAMPLES=1 is identical to the unset default.
    mock_router.reset()
    try:
        repo = fresh_repo()
        sh(["panel.py", "init", "--risk", "NORMAL", "--dev-providers", "anthropic"], repo)
        sh(["panel.py", "assign"], repo)
        sh(["panel.py", "run", "--context-file", "context.md"], repo)  # env unset -> default 1
        run = latest_run(repo)
        sec_model = read(run / "panel" / "plan.json")["roles"]["security"]["model"]
        sec = read(run / "panel" / "security.json")
        assert sec == mock_router._report("security", sec_model), sec  # byte-identical canned report
        assert "corroboration" not in sec["findings"][0]
        assert not (run / "panel" / "samples").exists()
        assert mock_router.STATE["calls"][sec_model] == 1, mock_router.STATE["calls"]
        # explicit "1" behaves identically to the default (re-run the same repo with --force)
        sh(["panel.py", "run", "--context-file", "context.md", "--force"], repo,
           env={**ENV, "AR_HIGH_SAMPLES": "1"})
        assert read(run / "panel" / "security.json") == mock_router._report("security", sec_model)
        assert not (run / "panel" / "samples").exists()
    finally:
        mock_router.reset()


def t_high_samples_disagreement_does_not_change_verdict():
    # E4-S3: corroboration is INFORMATIONAL. Whether the extra samples agree (3/3) or disagree
    # (1/3), aggregate.py returns the SAME verdict — a low agreement rate is not a majority-vote
    # override and never flips the gate.
    def run_with(sample_findings):
        mock_router.reset()

        def provider(m):
            if m["kind"] != "report" or m["role"] != "security":
                return None
            rep = mock_router._report("security", m["model"])
            if mock_router.STATE["calls"][m["model"]] == 1:
                return rep  # primary always raises the high finding (this is what gates)
            rep["findings"] = sample_findings  # samples 2..N
            return rep

        mock_router.STATE["response_provider"] = provider
        try:
            repo = fresh_repo()
            sh(["panel.py", "init", "--risk", "NORMAL", "--dev-providers", "anthropic"], repo)
            sh(["panel.py", "assign"], repo)
            sh(["panel.py", "run", "--context-file", "context.md"], repo,
               env={**ENV, "AR_HIGH_SAMPLES": "3"})
            run = latest_run(repo)
            sh(["aggregate.py"], repo, expect=None)
            v = read(run / "verdict.json")
            corr = read(run / "panel" / "security.json")["findings"][0]["corroboration"]
            return v["verdict"], corr
        finally:
            mock_router.reset()

    agree = mock_router._report("security", "x")["findings"]  # same IDOR finding -> agrees
    v_agree, c_agree = run_with(agree)
    v_dis, c_dis = run_with([])  # samples raise nothing -> disagree
    assert v_agree == v_dis == "BLOCKED", (v_agree, v_dis)  # verdict identical either way
    assert c_agree["agreed"] == 3 and abs(c_agree["rate"] - 1.0) < 1e-9, c_agree
    assert c_dis["agreed"] == 1 and abs(c_dis["rate"] - round(1 / 3, 4)) < 1e-9, c_dis


def t_high_samples_cost_cap_honored_during_resampling():
    # E4-S3: resampling is billed and honors the per-run cost cap. When corroboration would cross
    # the ceiling it stops BEFORE the next sample, records a cost_abort (phase 'corroboration'), and
    # the run BLOCKS — never a silent overspend. A failure-path assertion on real artifacts.
    mock_router.reset()
    mock_router.STATE["reviewer_cost"] = 0.20
    try:
        repo = fresh_repo()
        sh(["panel.py", "init", "--risk", "NORMAL", "--dev-providers", "anthropic"], repo)
        sh(["panel.py", "assign"], repo)
        # 4 primary reviewers * $0.20 = $0.80: the panel finishes (last pre-call check saw
        # $0.60 < $0.90). Corroborating security then spends sample-2 ($0.80<$0.90 -> runs, total
        # $1.00 >= $0.90 -> the post-record check aborts (sample-3 never starts). One sample, BLOCK.
        env = {**ENV, "AR_MAX_COST_USD": "0.90", "AR_HIGH_SAMPLES": "3"}
        r = sh(["panel.py", "run", "--context-file", "context.md"], repo, expect=2, env=env)
        assert "cost cap" in r.stderr.lower(), r.stderr
        run = latest_run(repo)
        abort = read(run / "cost_abort.json")
        assert abort["phase"] == "corroboration", abort
        assert abort["cap_usd"] == 0.90 and abort["not_run"], abort
        # the panel itself finished — all four primary reports exist; the cap tripped in resampling
        for role in ("security", "correctness", "test_quality", "output_fidelity"):
            assert (run / "panel" / f"{role}.json").exists(), role
        # exactly one corroboration sample was recorded before the abort
        assert (run / "panel" / "samples" / "security.2.json").exists()
        assert not (run / "panel" / "samples" / "security.3.json").exists()
        # aggregate BLOCKS with the cost reason surfaced on coverage + reasons
        sh(["aggregate.py"], repo, expect=2, env=env)
        vj = read(run / "verdict.json")
        assert vj["verdict"] == "BLOCKED" and vj["coverage"]["cost_aborted"] is True
        assert any("cost cap" in reason.lower() for reason in vj["reasons"]), vj["reasons"]
    finally:
        mock_router.reset()


def t_high_samples_cost_cap_final_sample_blocks():
    # E4-S3 (CodeRabbit): the cost cap must hold even when the FINAL corroboration sample is the one
    # that crosses it. With high_samples=2, sample 2 is the last: the pre-call gate lets it start
    # (under cap), it records over the cap, and only the post-record check can catch the crossing —
    # so without that check the run would silently finish over budget instead of BLOCKING.
    mock_router.reset()
    mock_router.STATE["reviewer_cost"] = 0.20
    try:
        repo = fresh_repo()
        sh(["panel.py", "init", "--risk", "NORMAL", "--dev-providers", "anthropic"], repo)
        sh(["panel.py", "assign"], repo)
        # 4 primaries * $0.20 = $0.80 < $0.90 -> panel finishes. Corroboration sample 2 pre-call sees
        # $0.80 < $0.90 -> runs, total $1.00. n=2, so there is NO sample-3 pre-call to catch it.
        env = {**ENV, "AR_MAX_COST_USD": "0.90", "AR_HIGH_SAMPLES": "2"}
        r = sh(["panel.py", "run", "--context-file", "context.md"], repo, expect=2, env=env)
        assert "cost cap" in r.stderr.lower(), r.stderr
        run = latest_run(repo)
        abort = read(run / "cost_abort.json")
        assert abort["phase"] == "corroboration", abort
        # the crossing sample WAS recorded before the abort; there is no sample 3
        assert (run / "panel" / "samples" / "security.2.json").exists()
        assert not (run / "panel" / "samples" / "security.3.json").exists()
        sh(["aggregate.py"], repo, expect=2, env=env)
        vj = read(run / "verdict.json")
        assert vj["verdict"] == "BLOCKED" and vj["coverage"]["cost_aborted"] is True
    finally:
        mock_router.reset()


def t_call_reviewer_exposes_usage_on_validation_failure():
    # E4-S3 (panel security-1): call_reviewer must attach the billed usage to the exception it raises
    # when reviewer output fails validation after the retry, so a corroboration sample that was billed
    # but then failed can be cost-metered (otherwise the pre-call cost gate under-counts and the cap
    # could be silently exceeded). The mock bills reviewer_cost on every call and the provider returns
    # an invalid report both times, forcing the after-retry failure path.
    import panel
    mock_router.reset()
    mock_router.STATE["reviewer_cost"] = 0.05
    mock_router.STATE["response_provider"] = lambda meta: {"not": "a valid report"}
    try:
        body = {"model": "x/y", "messages": [{"role": "system", "content": "Your role: security"},
                                             {"role": "user", "content": "go"}]}
        try:
            panel.call_reviewer("http://127.0.0.1:%d" % PORT, "k", body, panel.REPORT_SCHEMA)
            raise AssertionError("expected a validation failure")
        except ValueError as e:
            u = getattr(e, "usage", None)
            assert u and (u.get("cost") or 0) > 0, ("billed usage not attached to failure", u)
            # both the initial call and the corrective retry bill $0.05: the exception must carry the
            # ACCUMULATED usage ($0.10), not just the last attempt's, or the cost cap under-counts a
            # failed-but-billed sample (CodeRabbit).
            assert abs(u["cost"] - 0.10) < 1e-9, ("retry usage was not accumulated", u)
    finally:
        mock_router.reset()


def t_high_samples_rejects_invalid_values():
    # E4-S3: a non-integer / < 1 AR_HIGH_SAMPLES is rejected loudly (like the cost cap), so a typo
    # can never silently change the sampling count. Also validated at policy load.
    import panel
    import _common
    for bad in ("0", "-1", "1.5", "abc", "  ", "26", "3.0", "1e1"):   # 3.0/1e1: run rejects, so init must too
        os.environ["AR_HIGH_SAMPLES"] = bad
        try:
            panel.high_samples()
            raise AssertionError(f"high_samples accepted {bad!r}")
        except SystemExit:
            pass
        finally:
            os.environ.pop("AR_HIGH_SAMPLES", None)
    try:
        os.environ["AR_HIGH_SAMPLES"] = "3"
        assert panel.high_samples() == 3
        os.environ["AR_HIGH_SAMPLES"] = str(_common.MAX_HIGH_SAMPLES)   # upper bound is inclusive
        assert panel.high_samples() == _common.MAX_HIGH_SAMPLES
    finally:
        os.environ.pop("AR_HIGH_SAMPLES", None)
    for bad in (0, -1, 1.5, "2.5", float("nan"), True, _common.MAX_HIGH_SAMPLES + 1, 3.0, "3.0", "1e1"):
        try:
            _common._validate_policy({"high_samples": bad}, "policy")
            raise AssertionError(f"policy load accepted {bad!r}")
        except SystemExit:
            pass
    _common._validate_policy({"high_samples": 3}, "policy")    # positive integer OK
    _common._validate_policy({"high_samples": "4"}, "policy")  # YAML-subset string integer OK
    _common._validate_policy({"high_samples": _common.MAX_HIGH_SAMPLES}, "policy")  # upper bound OK


def t_high_samples_resume_does_not_recharge():
    # E4-S3 (panel/Codex): a plain `panel.py run` resume (no --force) must NOT re-buy corroboration
    # samples — the sample files overwrite in place, so a repeat would spend without the recorded cost
    # accumulating. Only roles whose PRIMARY was produced in THIS invocation are corroborated.
    mock_router.reset()
    def provider(m):
        return None if (m["kind"] != "report" or m["role"] != "security") \
            else mock_router._report("security", m["model"])
    mock_router.STATE["response_provider"] = provider
    try:
        repo = fresh_repo()
        sh(["panel.py", "init", "--risk", "NORMAL", "--dev-providers", "anthropic"], repo)
        sh(["panel.py", "assign"], repo)
        env = {**ENV, "AR_HIGH_SAMPLES": "3"}
        sh(["panel.py", "run", "--context-file", "context.md"], repo, env=env)
        run = latest_run(repo)
        sec = read(run / "panel" / "plan.json")["roles"]["security"]["model"]
        assert mock_router.STATE["calls"][sec] == 3, mock_router.STATE["calls"]        # primary + 2
        r = sh(["panel.py", "run", "--context-file", "context.md"], repo, env=env)     # resume
        assert "already complete" in r.stdout, r.stdout
        assert mock_router.STATE["calls"][sec] == 3, ("resume re-bought samples", mock_router.STATE["calls"])
        sh(["panel.py", "run", "--context-file", "context.md", "--force"], repo, env=env)  # --force redoes
        assert mock_router.STATE["calls"][sec] == 6, mock_router.STATE["calls"]        # +3 (primary+2)
    finally:
        mock_router.reset()


def t_corroboration_enriched_report_is_schema_valid():
    # E4-S3 (Codex + CodeRabbit): the persisted (enriched) report validates against the ENRICHED
    # schema, but corroboration is NOT part of the reviewer-INPUT schema — a reviewer cannot supply
    # its own corroboration (additionalProperties:false rejects it).
    import panel
    mock_router.reset()
    def provider(m):
        return None if (m["kind"] != "report" or m["role"] != "security") \
            else mock_router._report("security", m["model"])
    mock_router.STATE["response_provider"] = provider
    try:
        repo = fresh_repo()
        sh(["panel.py", "init", "--risk", "NORMAL", "--dev-providers", "anthropic"], repo)
        sh(["panel.py", "assign"], repo)
        sh(["panel.py", "run", "--context-file", "context.md"], repo, env={**ENV, "AR_HIGH_SAMPLES": "3"})
        rep = read(latest_run(repo) / "panel" / "security.json")
        assert "corroboration" in rep["findings"][0], rep["findings"][0]
        # the persisted, enriched report validates against the ENRICHED schema (superset)...
        assert not panel.validate_obj(rep, panel.REPORT_SCHEMA_ENRICHED), "enriched report not schema-valid"
        # ...and the reviewer-INPUT schema REJECTS a report carrying corroboration, so a reviewer
        # cannot inject its own agreement record (CodeRabbit: keep corroboration out of reviewer input).
        assert panel.validate_obj(rep, panel.REPORT_SCHEMA), \
            "reviewer-input REPORT_SCHEMA must reject a report carrying corroboration"
    finally:
        mock_router.reset()


def t_sample_policy_persisted():
    # E4-S3 (Codex): the run records which high_samples applied (value + source), even at the default
    # 1 where no corroboration fields exist, so an auditor can tell a policy edit from a no-op.
    mock_router.reset()
    try:
        repo = fresh_repo()
        sh(["panel.py", "init", "--risk", "NORMAL", "--dev-providers", "anthropic"], repo)
        sh(["panel.py", "assign"], repo)
        sh(["panel.py", "run", "--context-file", "context.md"], repo)                  # default 1
        sp = read(latest_run(repo) / "sample_policy.json")
        assert sp["high_samples"] == 1 and sp["source"] == "default", sp
        repo2 = fresh_repo()
        sh(["panel.py", "init", "--risk", "NORMAL", "--dev-providers", "anthropic"], repo2)
        sh(["panel.py", "assign"], repo2)
        sh(["panel.py", "run", "--context-file", "context.md"], repo2, env={**ENV, "AR_HIGH_SAMPLES": "2"})
        sp2 = read(latest_run(repo2) / "sample_policy.json")
        assert sp2["high_samples"] == 2 and sp2["source"] == "env", sp2
        assert sp2["source"] != sp["source"], (sp["source"], sp2["source"])  # configured != default
    finally:
        mock_router.reset()


def t_corroboration_cost_abort_names_later_flagged_roles():
    # E4-S3 (Codex): when the cap is hit while corroborating an earlier flagged role, _cost_abort exits
    # and every LATER flagged role is skipped too — the audit record must name them all.
    mock_router.reset()
    mock_router.STATE["reviewer_cost"] = 0.05
    def provider(m):
        if m["kind"] != "report" or m["role"] not in ("security", "correctness"):
            return None
        rep = mock_router._report("security", m["model"])          # a high finding
        rep["role"] = m["role"]
        rep["findings"] = [{**rep["findings"][0], "id": m["role"] + "-1"}]
        return rep
    mock_router.STATE["response_provider"] = provider
    try:
        repo = fresh_repo()
        sh(["panel.py", "init", "--risk", "NORMAL", "--dev-providers", "anthropic"], repo)
        sh(["panel.py", "assign"], repo)
        # 4 primaries * 0.05 = 0.20 reaches the cap before any corroboration sample is bought
        sh(["panel.py", "run", "--context-file", "context.md"], repo,
           env={**ENV, "AR_HIGH_SAMPLES": "3", "AR_MAX_COST_USD": "0.20"}, expect=None)
        abort = read(latest_run(repo) / "cost_abort.json")
        assert abort["phase"] == "corroboration", abort
        joined = " ".join(str(x) for x in abort["not_run"])
        assert "security#sample" in joined and "correctness#sample" in joined, abort["not_run"]
    finally:
        mock_router.reset()


def t_ingest_notes_corroboration_not_applied_on_mcp():
    # E4-S3 (Codex): corroboration runs only on the direct-HTTP run path; the keyless prepare/ingest
    # (MCP) path must SURFACE that it isn't applied rather than silently ignore high_samples.
    mock_router.reset()
    try:
        repo = fresh_repo()
        sh(["panel.py", "init", "--risk", "NORMAL", "--dev-providers", "anthropic"], repo)
        sh(["panel.py", "assign"], repo)
        sh(["panel.py", "prepare", "--context-file", "context.md"], repo)
        run = latest_run(repo)
        model = read(run / "panel" / "plan.json")["roles"]["security"]["model"]
        rep = mock_router._report("security", model)
        respfile = repo / "resp.json"
        write(respfile, {"choices": [{"message": {"content": json.dumps(rep)}}], "usage": {"cost": 0.0}})
        r = sh(["panel.py", "ingest", "--role", "security", "--response-file", str(respfile)], repo,
               env={**ENV, "AR_HIGH_SAMPLES": "2"})
        assert "corroboration applies only" in r.stderr, r.stderr
    finally:
        mock_router.reset()


def _http_transport(origins=(), max_bytes=4096, require_session=None, max_sessions=None, max_streams=None,
                    token=None, max_workers=None, read_timeout=None):
    """Start an HttpTransport on an ephemeral localhost port in a daemon thread; return (transport, port).
    Offline — binds 127.0.0.1 only, no external network. require_session/max_sessions/max_streams (E3-S2b)
    and token/max_workers/read_timeout (E3-S2c) default to None so the transport reads the env (require off,
    128 sessions, 64 streams, no auth, 128 workers, 30s read timeout); tests inject explicit values."""
    import threading
    t = mcpsrv.HttpTransport(host="127.0.0.1", port=0, origins=origins, max_bytes=max_bytes,
                             require_session=require_session, max_sessions=max_sessions,
                             max_streams=max_streams, token=token, max_workers=max_workers,
                             read_timeout=read_timeout)
    _host, port = t.bind()
    threading.Thread(target=t.serve_forever, daemon=True).start()
    return t, port


def _http_get(port, session_id=None, origin=None, extra=None):
    """Open a GET (SSE) and read the FIRST response chunk (status line + headers + any initial SSE
    comment) in a single recv, then close — so a live text/event-stream never blocks the test. Raw
    socket because urllib.urlopen would drain the open stream. `extra` adds request headers (e.g. an
    MCP-Protocol-Version or Accept), so era/version/Accept rejections can be exercised without hanging
    on a live 200 stream. Returns (status, raw_response_bytes)."""
    import socket
    req = b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n"
    if origin is not None:
        req += b"Origin: " + origin.encode("ascii") + b"\r\n"
    if session_id is not None:
        req += b"Mcp-Session-Id: " + session_id.encode("ascii") + b"\r\n"
    for k, v in (extra or {}).items():
        req += k.encode("ascii") + b": " + v.encode("ascii") + b"\r\n"
    req += b"\r\n"
    s = socket.create_connection(("127.0.0.1", port), timeout=5)
    try:
        s.sendall(req)
        s.settimeout(5)
        data = b""
        for _ in range(10):  # headers and the initial SSE comment can arrive in separate TCP reads
            try:
                chunk = s.recv(4096)
            except socket.timeout:
                break
            if not chunk:
                break
            data += chunk
            head, sep, body = data.partition(b"\r\n\r\n")
            if sep:
                status = int(head.split(b" ", 2)[1])
                if status != 200 or body:  # error bodies are self-contained; a 200 SSE needs its first byte
                    break
    finally:
        s.close()
    status = int(data.split(b" ", 2)[1]) if data.startswith(b"HTTP/") else 0
    return status, data


def _http_post(port, body, headers=None):
    import urllib.request
    import urllib.error
    data = body if isinstance(body, (bytes, bytearray)) else body.encode("utf-8")
    req = urllib.request.Request("http://127.0.0.1:%d/" % port, data=data, method="POST",
                                 headers=headers or {})
    try:
        r = urllib.request.urlopen(req, timeout=5)
        return r.status, r.read(), {k.lower(): v for k, v in r.headers.items()}
    except urllib.error.HTTPError as e:
        return e.code, e.read(), {k.lower(): v for k, v in e.headers.items()}


def _http_method(port, method, headers=None):
    import urllib.request
    import urllib.error
    req = urllib.request.Request("http://127.0.0.1:%d/" % port, method=method, headers=headers or {})
    try:
        r = urllib.request.urlopen(req, timeout=5)
        return r.status
    except urllib.error.HTTPError as e:
        return e.code


def _http_raw(port, request_bytes):
    """Send a hand-built raw HTTP request and read the full response until the server closes the
    connection. Needed because urllib always sets Content-Length — a MISSING or EMPTY Content-Length
    header can only be exercised at the socket level. Returns (status_code, full_response_bytes)."""
    import socket
    s = socket.create_connection(("127.0.0.1", port), timeout=5)
    try:
        s.sendall(request_bytes)
        s.settimeout(5)
        buf = b""
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            buf += chunk
    finally:
        s.close()
    status = int(buf.split(b" ", 2)[1]) if buf.startswith(b"HTTP/") else 0
    return status, buf


def t_mcp_http_post_parity_with_stdio():
    # E3-S2a: a POST dispatches through the SAME serve_message()/handle() core as stdio, so the JSON-RPC
    # result is identical and the HTTP layer is a framing surface only (never command execution).
    t, port = _http_transport()
    try:
        req = {"jsonrpc": "2.0", "id": 7, "method": "server/discover"}
        status, body, hdrs = _http_post(port, json.dumps(req))
        assert status == 200, status
        assert hdrs.get("content-type") == "application/json", hdrs
        got = json.loads(body)
        assert got == json.loads(mcpsrv.serve_message(json.dumps(req))), got  # identical to the core
        assert got["id"] == 7 and "result" in got, got
    finally:
        t.shutdown()


def t_mcp_http_notification_is_202():
    # A notification (no id) has nothing to return -> 202 Accepted with an empty body (serve_message->None).
    t, port = _http_transport()
    try:
        status, body, _ = _http_post(port, json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}))
        assert status == 202, status
        assert body == b"", body
    finally:
        t.shutdown()


def t_mcp_http_malformed_body_is_parse_error():
    # A malformed body frames as a JSON-RPC -32700 parse error (HTTP 200) and never crashes the listener.
    t, port = _http_transport()
    try:
        status, body, _ = _http_post(port, "not json {{{")
        assert status == 200, status
        err = json.loads(body)
        assert err["error"]["code"] == -32700 and err["id"] is None, err
        status2, body2, _ = _http_post(port, b"\xff\xfe")   # invalid UTF-8 bytes -> parse error, not 500
        assert status2 == 200 and json.loads(body2)["error"]["code"] == -32700, body2
    finally:
        t.shutdown()


def t_mcp_batch_toplevel_array_is_invalid_request():
    # E3-S2d conformance: JSON-RPC batching was removed in MCP 2025-06-18 and not reinstated in
    # 2026-07-28. A top-level JSON array is a single Invalid Request (-32600, id null) at the shared
    # core -- never iterated, never partially executed, never a crash -- so both transports reject it
    # identically by construction (handle() rejects any non-dict before method routing).
    for arr in ([], [{"jsonrpc": "2.0", "id": 1, "method": "tools/list"}],
                [{"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
                 {"jsonrpc": "2.0", "id": 2, "method": "server/discover"}]):
        r = mcpsrv.handle(arr)
        assert r["error"]["code"] == -32600 and r["id"] is None, r
        s = json.loads(mcpsrv.serve_message(json.dumps(arr)))
        assert s["error"]["code"] == -32600 and s["id"] is None, s


def t_mcp_batch_no_element_dispatched_no_side_effect():
    # A top-level array carrying a state-mutating tools/call must NOT execute any element: the array is
    # rejected wholesale (-32600) before dispatch, so no run directory is created. Guards against a
    # future refactor that iterates a batch array.
    repo = fresh_repo()
    cwd0 = os.getcwd()
    try:
        os.chdir(repo)
        arr = [{"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                "params": {"name": "ar_init",
                           "arguments": {"risk": "NORMAL", "dev_providers": ["anthropic"]},
                           "_meta": {"io.modelcontextprotocol/protocolVersion": "2026-07-28",
                                     "io.modelcontextprotocol/clientCapabilities": {}}}}]
        r = json.loads(mcpsrv.serve_message(json.dumps(arr)))
        assert r["error"]["code"] == -32600 and r["id"] is None, r
        assert list((repo / ".adversarial-review").glob("run-*")) == [], "no element may be dispatched"
    finally:
        os.chdir(cwd0)


def t_mcp_http_batch_array_is_invalid_request():
    # Over HTTP a top-level array decodes fine but is an invalid JSON-RPC request: it returns the in-band
    # -32600 (id null) with HTTP 200 -- the SAME convention as the malformed-body -32700 path (in-band
    # JSON-RPC errors ride 200; non-200 is reserved for transport-layer rejections). No element dispatched.
    t, port = _http_transport()
    try:
        for arr in ([], [{"jsonrpc": "2.0", "id": 1, "method": "tools/list"}]):
            status, body, _ = _http_post(port, json.dumps(arr))
            assert status == 200, status
            err = json.loads(body)
            assert err["error"]["code"] == -32600 and err["id"] is None, err
    finally:
        t.shutdown()


def t_mcp_falsy_id_is_request():
    # JSON-RPC (core, both eras): a request with a present-but-falsy id (0 or "") is a REQUEST, not a
    # notification -- notification detection is id PRESENCE (`"id" not in msg`), not truthiness -- so
    # handle() must return a response echoing that id, never None. The HTTP mirror is
    # t_mcp_http_falsy_id_is_response_not_notification; a true notification (no id) still returns None.
    for id_val in (0, ""):
        r = mcpsrv.handle({"jsonrpc": "2.0", "id": id_val, "method": "server/discover"})
        assert r is not None and r["id"] == id_val and "result" in r, r
    assert mcpsrv.handle({"jsonrpc": "2.0", "method": "server/discover"}) is None  # no id => notification


def _http_modern(port, method, params=None, version="2026-07-28", caps=True, id_=1):
    """POST a modern (stateless, 2026-07-28) request over HTTP: declares its version + clientCapabilities
    in params._meta, no MCP-Protocol-Version header (the stateless path). Returns (status, parsed_body, headers)."""
    body = {"jsonrpc": "2.0", "id": id_, "method": method, "params": dict(params or {})}
    meta = {"io.modelcontextprotocol/protocolVersion": version}
    if caps:
        meta["io.modelcontextprotocol/clientCapabilities"] = {}
    body["params"]["_meta"] = meta
    status, raw, hdrs = _http_post(port, json.dumps(body))
    return status, (json.loads(raw) if raw else None), hdrs


def t_mcp_http_modern_ping_is_method_not_found():
    # E3-S2d conformance (MCP 2026-07-28 changelog #5: `ping` removed). A modern ping over HTTP is
    # method-not-found (-32601), NOT a bare {} (which would omit the required resultType) -- CONFORMANT,
    # not a deviation. Legacy ping still returns {} (covered by the stdio parity test).
    t, port = _http_transport()
    try:
        status, resp, _ = _http_modern(port, "ping")
        assert status == 200, status
        assert resp["error"]["code"] == -32601, resp
    finally:
        t.shutdown()


def t_mcp_http_modern_unsupported_version_is_32022():
    # changelog #2/#12: a version mismatch returns UnsupportedProtocolVersionError (-32022). Proven over
    # HTTP in the response BODY (the header-level 400 negotiation is a separate existing test).
    t, port = _http_transport()
    try:
        status, resp, _ = _http_modern(port, "tools/list", version="1900-01-01")
        assert status == 200, status
        assert resp["error"]["code"] == -32022, resp
        assert resp["error"]["data"]["requested"] == "1900-01-01", resp
    finally:
        t.shutdown()


def t_mcp_http_modern_missing_capabilities_is_invalid_params():
    # changelog #2: modern requests carry clientCapabilities in _meta; omitting it is Invalid params (-32602).
    t, port = _http_transport()
    try:
        status, resp, _ = _http_modern(port, "tools/list", caps=False)
        assert status == 200, status
        assert resp["error"]["code"] == -32602, resp
    finally:
        t.shutdown()


def t_mcp_http_modern_result_carries_resulttype():
    # changelog #8: all modern results carry a required resultType. Confirm it survives the HTTP framing.
    t, port = _http_transport()
    try:
        status, resp, hdrs = _http_modern(port, "tools/list")
        assert status == 200 and hdrs.get("content-type") == "application/json", hdrs
        assert resp["result"]["resultType"] == "complete", resp
    finally:
        t.shutdown()


def t_mcp_http_modern_tools_list_is_cacheable():
    # changelog #5 (minor, SEP-2549): tools/list results carry ttlMs + cacheScope (CacheableResult).
    # Confirm both survive the HTTP framing (a client caches off these hints).
    t, port = _http_transport()
    try:
        status, resp, _ = _http_modern(port, "tools/list")
        assert status == 200, status
        assert isinstance(resp["result"]["ttlMs"], int) and resp["result"]["cacheScope"] == "public", resp
    finally:
        t.shutdown()


def t_mcp_http_legacy_tools_list_has_no_modern_fields():
    # Dual-era: a LEGACY tools/list over HTTP (no _meta) must NOT leak modern fields (resultType/ttlMs/
    # cacheScope), matching the stdio parity test. Guards against the HTTP layer stamping modern fields.
    t, port = _http_transport()
    try:
        status, raw, _ = _http_post(port, json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}))
        assert status == 200, status
        tl = json.loads(raw)["result"]
        assert "resultType" not in tl and "ttlMs" not in tl and "cacheScope" not in tl, tl
    finally:
        t.shutdown()


def t_mcp_http_falsy_id_is_response_not_notification():
    # JSON-RPC: a request with a present-but-falsy id (0 or "") is a REQUEST, not a notification -- it must
    # return HTTP 200 echoing that id, never 202. Guards notification detection (id PRESENCE, not truthiness)
    # across the HTTP framing -- the `if not x:` bug class the repo already scarred on for arguments.
    t, port = _http_transport()
    try:
        for id_val in (0, ""):
            status, raw, _ = _http_post(port, json.dumps(
                {"jsonrpc": "2.0", "id": id_val, "method": "server/discover"}))
            assert status == 200, (id_val, status)
            resp = json.loads(raw)
            assert resp["id"] == id_val and "result" in resp, resp
    finally:
        t.shutdown()


# --- E3-S2d conformance manifest + drift guard --------------------------------------------------
# Maps each transport-agnostic DISPATCH conformance behavior to the stdio test that pins it, the HTTP
# parity test that proves it survives the HTTP framing, and the MCP 2026-07-28 clause it satisfies.
# CURATED on purpose (never a name-grep of all t_mcp_*, which would false-positive on the ~80
# pipeline/aggregate tests). The drift guard below fails if any referenced test is missing, so a future
# engineer who adds a dispatch behavior is forced to cover it over HTTP too.
# Clause refs: https://modelcontextprotocol.io/specification/2026-07-28/changelog
_S2D_CONFORMANCE = [
    # (behavior_id, stdio_test, http_test, clause)
    ("batch-rejected", "t_mcp_batch_toplevel_array_is_invalid_request",
     "t_mcp_http_batch_array_is_invalid_request", "JSON-RPC batching removed 2025-06-18; not reinstated"),
    ("modern-ping-removed", "t_mcp_modern_ping_is_method_not_found",
     "t_mcp_http_modern_ping_is_method_not_found", "changelog #5: ping removed"),
    ("unsupported-version", "t_mcp_modern_unsupported_version_rejected",
     "t_mcp_http_modern_unsupported_version_is_32022", "changelog #2/#12: UnsupportedProtocolVersion -32022"),
    ("missing-capabilities", "t_mcp_modern_missing_capabilities_is_invalid_params",
     "t_mcp_http_modern_missing_capabilities_is_invalid_params", "changelog #2: clientCapabilities required"),
    ("resulttype-required", "t_mcp_modern_successful_tool_call",
     "t_mcp_http_modern_result_carries_resulttype", "changelog #8: resultType required on all results"),
    ("cacheable-list", "t_mcp_modern_tools_list_is_cacheable",
     "t_mcp_http_modern_tools_list_is_cacheable", "changelog #5 minor: ttlMs/cacheScope on list results"),
    ("legacy-unchanged", "t_mcp_legacy_responses_unchanged",
     "t_mcp_http_legacy_tools_list_has_no_modern_fields", "dual-era: legacy responses byte-identical"),
    ("falsy-id-is-request", "t_mcp_falsy_id_is_request",
     "t_mcp_http_falsy_id_is_response_not_notification", "JSON-RPC: id present (even 0/'') => a response"),
]


def t_mcp_s2d_conformance_manifest_covers_http():
    # E3-S2d drift guard: every listed dispatch conformance behavior must have BOTH a stdio test and an
    # HTTP parity test DEFINED in this module. Fails if any referenced test is missing -- so adding a
    # dispatch behavior without HTTP coverage breaks CI. Curated (pipeline/aggregate t_mcp_* excluded).
    g = globals()
    missing = [(beh, name) for beh, stdio_t, http_t, _c in _S2D_CONFORMANCE
               for name in (stdio_t, http_t) if not callable(g.get(name))]
    assert not missing, "conformance manifest references missing tests: %r" % (missing,)
    assert len(_S2D_CONFORMANCE) >= 8, "conformance set unexpectedly shrank"


def t_mcp_http_unsupported_verbs_are_405():
    # E3-S2b: GET (SSE stream) and DELETE (terminate a session) are real verbs now — without a session
    # they are 400 (Mcp-Session-Id required), not 405. Every OTHER verb stays 405 (Allow: POST,GET,DELETE).
    t, port = _http_transport()
    try:
        assert _http_get(port)[0] == 400              # GET, no session -> 400 (not 405)
        assert _http_method(port, "DELETE") == 400    # DELETE, no session -> 400 (not 405)
        for method in ("PUT", "PATCH", "OPTIONS"):
            assert _http_method(port, method) == 405, method
    finally:
        t.shutdown()


def t_mcp_http_origin_allowlist():
    # DNS-rebinding defense: a present Origin must be allow-listed; an absent Origin (non-browser client)
    # is allowed. Rejection is 403, before any dispatch.
    t, port = _http_transport(origins=("https://ok.example",))
    try:
        good = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "server/discover"})
        assert _http_post(port, good)[0] == 200                                    # absent Origin -> allowed
        assert _http_post(port, good, {"Origin": "https://ok.example"})[0] == 200   # allow-listed -> allowed
        assert _http_post(port, good, {"Origin": "https://evil.example"})[0] == 403  # disallowed -> 403
    finally:
        t.shutdown()


def t_mcp_http_oversized_body_is_413():
    # DoS bound: a declared body over max_bytes (the test server caps at 4096) is refused with 413.
    t, port = _http_transport()
    try:
        big = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"x": "A" * 5000}})
        assert _http_post(port, big)[0] == 413
    finally:
        t.shutdown()


def t_mcp_http_protocol_version_header():
    # HTTP-level version negotiation: an unsupported MCP-Protocol-Version -> 400 naming supportedVersions;
    # a supported one is echoed on the response.
    t, port = _http_transport()
    try:
        good = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "server/discover"})
        s_bad, b_bad, _ = _http_post(port, good, {"MCP-Protocol-Version": "1999-01-01"})
        assert s_bad == 400 and "2026-07-28" in json.loads(b_bad)["supportedVersions"], b_bad
        s_ok, _, h_ok = _http_post(port, good, {"MCP-Protocol-Version": "2026-07-28"})
        assert s_ok == 200 and h_ok.get("mcp-protocol-version") == "2026-07-28", h_ok
    finally:
        t.shutdown()


def t_mcp_http_transport_selection_defaults_to_stdio():
    # main() picks stdio unless AR_MCP_TRANSPORT=http or --http; pure selector, no server started.
    assert mcpsrv.select_transport(argv=["mcp"], env={}) == "stdio"
    assert mcpsrv.select_transport(argv=["mcp"], env={"AR_MCP_TRANSPORT": "http"}) == "http"
    assert mcpsrv.select_transport(argv=["mcp"], env={"AR_MCP_TRANSPORT": "STDIO"}) == "stdio"
    assert mcpsrv.select_transport(argv=["mcp", "--http"], env={}) == "http"


def t_mcp_http_missing_or_empty_content_length_is_safe():
    # test_quality-1: the Content-Length parse path must fail closed — never hang, never 500.
    #   * zero-length body           -> serve_message(b"") frames a -32700 parse error at HTTP 200
    #   * MISSING Content-Length     -> defaults to 0 -> same graceful -32700 (raw socket; urllib always
    #                                   sets the header, so only a hand-built request reaches this path)
    #   * EMPTY  "Content-Length:"   -> int("") is unparseable -> refused 413, not a crash/hang/500
    t, port = _http_transport()
    try:
        s0, b0, _ = _http_post(port, b"")  # Content-Length: 0
        assert s0 == 200 and json.loads(b0)["error"]["code"] == -32700, (s0, b0)
        sm, rm = _http_raw(port, b"POST / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        assert sm == 200 and b"-32700" in rm, (sm, rm[:120])
        se, _re = _http_raw(port, b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: \r\nConnection: close\r\n\r\n")
        assert se == 413, (se, _re[:120])  # fail-closed on a malformed length, never 200/500
    finally:
        t.shutdown()


def t_mcp_http_non_loopback_bind_is_refused():
    # test_quality-6 / security-1: WITHOUT a token, HttpTransport.bind() must REFUSE any non-loopback host
    # (0.0.0.0 / LAN / hostname / "::") rather than expose an UNAUTHENTICATED tool surface to the network
    # (E3-S2c: a remote bind is permitted only once a token authenticates it — see the token test below).
    # An EMPTY host is refused too: the socket layer binds "" to 0.0.0.0 (all interfaces), so it must NOT
    # count as loopback. Loopback targets still bind normally.
    for host in ("0.0.0.0", "192.168.1.10", "10.0.0.1", "example.com", "::", ""):
        try:
            mcpsrv.HttpTransport(host=host, port=0).bind()
        except ValueError as e:
            assert "non-loopback" in str(e), (host, str(e))
        else:
            raise AssertionError("bind(%r) must refuse a non-loopback host but did not" % host)
    for ok in ("127.0.0.1", "127.0.0.5", "::1", "localhost"):
        assert mcpsrv.is_loopback_host(ok), ok
    for bad in ("0.0.0.0", "192.168.0.1", "8.8.8.8", "example.com", "::", "", "  "):
        assert not mcpsrv.is_loopback_host(bad), bad
    t = mcpsrv.HttpTransport(host="127.0.0.1", port=0)  # a loopback bind still succeeds
    try:
        host, port = t.bind()
        assert host == "127.0.0.1" and port > 0, (host, port)
    finally:
        if t.httpd is not None:
            t.httpd.server_close()


def t_mcp_http_ipv6_loopback_binds():
    # CodeRabbit: is_loopback_host('::1') is accepted, so bind() must actually bind it on an AF_INET6
    # server rather than crash on the default AF_INET socket. Skip only where the runner has no IPv6.
    if not socket.has_ipv6:
        return
    t = mcpsrv.HttpTransport(host="::1", port=0, origins=(), max_bytes=4096)
    try:
        host, port = t.bind()
    except OSError:
        return  # IPv6 stack present but ::1 not bindable in this sandbox — environment, not a code bug
    try:
        assert port > 0 and t.httpd.address_family == socket.AF_INET6, (host, port)
    finally:
        t.httpd.server_close()


def _authbody():
    return json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})


def t_mcp_http_auth_required_when_token_set():
    # E3-S2c: with AR_MCP_HTTP_TOKEN set, a request with NO Authorization -> 401 + a Bearer challenge;
    # the correct Bearer token -> 200.
    tok = "s3cret-token-abcdefghij0123"  # >= HTTP_MIN_TOKEN_LEN
    t, port = _http_transport(token=tok)
    try:
        s_no, _b, h = _http_post(port, _authbody())                         # missing Authorization
        assert s_no == 401, s_no
        assert "bearer" in h.get("www-authenticate", "").lower(), h
        s_ok, _b2, _h2 = _http_post(port, _authbody(), {"Authorization": "Bearer " + tok})
        assert s_ok == 200, s_ok
    finally:
        t.shutdown()


def t_mcp_http_auth_rejects_wrong_token():
    # E3-S2c: a wrong token (same length AND different length), a wrong scheme, and a bare/empty credential
    # all -> 401. Never a 200 on anything but the exact token.
    tok = "correct-token-0123456789abc"
    t, port = _http_transport(token=tok)
    try:
        wrong_same = "x" * len(tok)  # same length, different value
        for hdr in ("Bearer " + wrong_same, "Bearer short", "Basic " + tok, "Bearer", "Bearer ", tok):
            s, _b, _h = _http_post(port, _authbody(), {"Authorization": hdr})
            assert s == 401, (hdr, s)
    finally:
        t.shutdown()


def t_mcp_http_no_auth_when_token_unset():
    # E3-S2c: with no token configured, behavior is unchanged — a request with no Authorization is served.
    t, port = _http_transport()  # token=None -> reads env (unset in tests) -> no auth
    try:
        s, _b, _h = _http_post(port, _authbody())
        assert s == 200, s
    finally:
        t.shutdown()


def t_mcp_http_origin_precedes_auth():
    # E3-S2c: the Origin/rebinding boundary check runs BEFORE auth. A disallowed browser Origin -> 403,
    # not 401 — so attacker bytes never reach the credential comparator for a request already doomed on
    # Origin, and the existing per-verb check order is preserved.
    tok = "order-token-0123456789abcdef"
    t, port = _http_transport(origins=("https://ok.example",), token=tok)
    try:
        s, _b, _h = _http_post(port, _authbody(), {"Origin": "https://evil.example"})  # bad origin, no auth
        assert s == 403, s   # 403 (origin), not 401 (auth)
    finally:
        t.shutdown()


def t_mcp_http_auth_precedes_protocol_version_leak():
    # E3-S2c (Codex, PR #58): auth runs BEFORE the protocol-version check, so an unauthenticated request
    # carrying an UNSUPPORTED MCP-Protocol-Version is 401 (auth) — NOT 400 with the supportedVersions
    # catalog. An unauthenticated caller must learn nothing about supported versions. With a valid token,
    # a bad version returns the 400 negotiation error (with the catalog) as usual.
    tok = "proto-leak-token-0123456789ab"
    t, port = _http_transport(token=tok)
    try:
        s_no, b_no, _h = _http_post(port, _authbody(), {"MCP-Protocol-Version": "1999-01-01"})  # no auth
        assert s_no == 401, s_no
        assert b"supportedVersions" not in b_no, b_no[:160]   # no catalog leak pre-auth
        s_ok, b_ok, _h2 = _http_post(port, _authbody(),
                                     {"Authorization": "Bearer " + tok, "MCP-Protocol-Version": "1999-01-01"})
        assert s_ok == 400 and b"supportedVersions" in b_ok, (s_ok, b_ok[:160])
    finally:
        t.shutdown()


def t_mcp_http_explicit_token_validated():
    # E3-S2c (CodeRabbit, PR #58): an explicit constructor token is validated exactly like the env token,
    # so a remote bind can never be enabled with a blank / too-short / non-string secret.
    for bad in ("", "   ", "short", 12345):
        try:
            mcpsrv.HttpTransport(host="127.0.0.1", port=0, token=bad)
        except ValueError:
            pass
        else:
            raise AssertionError("HttpTransport must reject explicit token %r" % (bad,))
    t = mcpsrv.HttpTransport(host="127.0.0.1", port=0, token="a-valid-explicit-token-12345")
    assert t.token == "a-valid-explicit-token-12345", t.token


def t_mcp_http_discover_gated_when_token_set():
    # E3-S2c: server/discover is gated behind auth too — no pre-auth catalog/version leak. Unauthenticated
    # -> 401; authenticated -> 200 with the supported versions.
    tok = "discover-gate-token-abcdef012"
    t, port = _http_transport(token=tok)
    try:
        body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "server/discover"})
        s_no, _b, _h = _http_post(port, body)
        assert s_no == 401, s_no
        s_ok, b_ok, _h2 = _http_post(port, body, {"Authorization": "Bearer " + tok})
        assert s_ok == 200 and b"supportedVersions" in b_ok, (s_ok, b_ok[:120])
    finally:
        t.shutdown()


def t_mcp_http_auth_no_dispatch_before_auth():
    # E3-S2c: an unauthenticated request must NOT reach serve_message() — no tool dispatch, no side effect.
    tok = "dispatch-guard-token-12345678"
    calls = []
    orig = mcpsrv.serve_message
    mcpsrv.serve_message = lambda raw: (calls.append(1), orig(raw))[1]
    t, port = _http_transport(token=tok)
    try:
        s_no, _b, _h = _http_post(port, _authbody())                       # no auth
        assert s_no == 401 and calls == [], (s_no, len(calls))             # serve_message never called
        s_ok, _b2, _h2 = _http_post(port, _authbody(), {"Authorization": "Bearer " + tok})
        assert s_ok == 200 and len(calls) == 1, (s_ok, len(calls))         # only the authed request dispatched
    finally:
        mcpsrv.serve_message = orig
        t.shutdown()


def t_mcp_http_auth_uses_constant_time_compare():
    # E3-S2c: the token comparison goes through hmac.compare_digest (constant-time), not `==`.
    tok = "ct-compare-token-0123456789ab"
    seen = []
    orig = mcpsrv.hmac.compare_digest
    mcpsrv.hmac.compare_digest = lambda a, b: (seen.append(1), orig(a, b))[1]
    t, port = _http_transport(token=tok)
    try:
        s, _b, _h = _http_post(port, _authbody(), {"Authorization": "Bearer " + tok})
        assert s == 200 and seen, (s, seen)
    finally:
        mcpsrv.hmac.compare_digest = orig
        t.shutdown()


def t_mcp_http_blank_token_fails_closed():
    # E3-S2c: a PRESENT but blank/whitespace or too-short AR_MCP_HTTP_TOKEN fails loudly (never silently
    # disables auth); an UNSET var means no auth (None); a real token resolves. HttpTransport inherits this
    # via http_token() so a blank env token aborts startup rather than binding an open surface.
    import os as _os
    saved = _os.environ.get("AR_MCP_HTTP_TOKEN")
    try:
        for bad in ("", "   ", "short"):
            _os.environ["AR_MCP_HTTP_TOKEN"] = bad
            try:
                mcpsrv.http_token()
            except ValueError:
                pass
            else:
                raise AssertionError("http_token() must reject %r" % bad)
        _os.environ.pop("AR_MCP_HTTP_TOKEN", None)
        assert mcpsrv.http_token() is None
        _os.environ["AR_MCP_HTTP_TOKEN"] = "a-perfectly-fine-token-12345"
        assert mcpsrv.http_token() == "a-perfectly-fine-token-12345"
        # a blank env token must also abort a real startup (token param None -> reads env)
        _os.environ["AR_MCP_HTTP_TOKEN"] = ""
        try:
            mcpsrv.HttpTransport(host="127.0.0.1", port=0)
        except ValueError:
            pass
        else:
            raise AssertionError("HttpTransport must fail closed on a blank AR_MCP_HTTP_TOKEN")
    finally:
        if saved is None:
            _os.environ.pop("AR_MCP_HTTP_TOKEN", None)
        else:
            _os.environ["AR_MCP_HTTP_TOKEN"] = saved


def t_mcp_http_remote_bind_allowed_with_token():
    # E3-S2c: a non-loopback bind IS permitted once a token authenticates it. Bind an ephemeral port on
    # 0.0.0.0 then close immediately (do not serve).
    tok = "remote-bind-token-0123456789a"
    t = mcpsrv.HttpTransport(host="0.0.0.0", port=0, token=tok)
    try:
        host, port = t.bind()
        assert host == "0.0.0.0" and port > 0, (host, port)
    finally:
        if t.httpd is not None:
            t.httpd.server_close()


def t_mcp_http_max_workers_must_exceed_max_streams():
    # E3-S2c: the worker pool must exceed the SSE stream cap or held-open streams starve dispatch; bind()
    # fails fast on the misconfiguration. A valid ratio binds.
    for mw, ms in ((4, 4), (4, 8)):
        t = mcpsrv.HttpTransport(host="127.0.0.1", port=0, max_workers=mw, max_streams=ms)
        try:
            t.bind()
        except ValueError as e:
            assert "MAX_WORKERS" in str(e) or "must exceed" in str(e), str(e)
        else:
            if t.httpd is not None:
                t.httpd.server_close()
            raise AssertionError("bind() must refuse max_workers(%d) <= max_streams(%d)" % (mw, ms))
    t = mcpsrv.HttpTransport(host="127.0.0.1", port=0, max_workers=8, max_streams=4)
    try:
        _h, port = t.bind()
        assert port > 0
    finally:
        if t.httpd is not None:
            t.httpd.server_close()


def t_mcp_http_bounded_worker_pool():
    # E3-S2c: the worker pool caps concurrent connections. With max_workers=2, two in-flight requests hold
    # both workers (one inside serve_message, one blocked on the process-wide dispatch lock — both hold their
    # worker permit); a third connection is refused (socket closed with no HTTP response) rather than served.
    import threading as _th, socket as _sock, time as _time
    release = _th.Event()        # held until the test lets the two in-flight requests finish
    orig = mcpsrv.serve_message

    def blocking(raw):
        release.wait(10)
        return orig(raw)

    mcpsrv.serve_message = blocking
    t, port = _http_transport(max_workers=2, max_streams=1)
    body = _authbody().encode("utf-8")
    req = (b"POST / HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: "
           + str(len(body)).encode() + b"\r\nConnection: close\r\n\r\n" + body)
    held = []
    try:
        for _ in range(2):
            s = _sock.create_connection(("127.0.0.1", port), timeout=5)
            s.sendall(req)
            held.append(s)
        # wait until both worker permits are taken (both connections occupy the bounded pool)
        deadline = _time.time() + 5
        while t.httpd._worker_sem._value != 0 and _time.time() < deadline:
            _time.sleep(0.02)
        assert t.httpd._worker_sem._value == 0, "pool not fully occupied (value=%r)" % t.httpd._worker_sem._value
        third = _sock.create_connection(("127.0.0.1", port), timeout=5)
        try:
            third.sendall(req)
            third.settimeout(5)
            data = b""
            while True:
                try:
                    chunk = third.recv(4096)
                except _sock.timeout as exc:  # a timeout would mean the server left the excess conn open
                    raise AssertionError("third connection was not closed promptly (worker pool full)") from exc
                if not chunk:
                    break
                data += chunk
            assert data == b"", "third connection should get no HTTP response, got %r" % data[:80]
        finally:
            third.close()
    finally:
        release.set()
        for s in held:
            try:
                s.recv(65536)
            except OSError:
                pass
            s.close()
        mcpsrv.serve_message = orig
        t.shutdown()


def t_mcp_http_read_timeout_bounds_slow_loris():
    # E3-S2c: a client that opens a connection and stalls a partial request is dropped within ~the read
    # timeout, not pinned to the worker forever.
    import socket as _sock, time as _time
    t, port = _http_transport(read_timeout=1)
    try:
        s = _sock.create_connection(("127.0.0.1", port), timeout=5)
        try:
            s.sendall(b"POST / HTTP/1.1\r\nHost: x\r\n")  # partial: headers never terminated
            s.settimeout(5)
            start = _time.time()
            while True:
                try:
                    chunk = s.recv(4096)
                except _sock.timeout:
                    chunk = b""
                if not chunk:
                    break
            assert _time.time() - start < 4, "slow-loris connection not dropped promptly"
        finally:
            s.close()
    finally:
        t.shutdown()


def t_mcp_http_transfer_encoding_is_rejected():
    # CodeRabbit: framing is Content-Length only. A chunked body is left unread (length parses as 0) and
    # would desync into the next request on a keep-alive connection (smuggling). Any Transfer-Encoding —
    # alone OR combined with Content-Length — is refused with a closed 400.
    t, port = _http_transport()
    try:
        chunked = (b"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n"
                   b"Connection: close\r\n\r\n4\r\nWiki\r\n0\r\n\r\n")
        s1, r1 = _http_raw(port, chunked)
        head1 = r1.lower().split(b"\r\n\r\n", 1)[0]
        assert s1 == 400 and b"connection: close" in head1, (s1, r1[:200])
        combined = (b"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\nContent-Length: 4\r\n"
                    b"Connection: close\r\n\r\n4\r\nWiki\r\n0\r\n\r\n")
        s2, r2 = _http_raw(port, combined)
        assert s2 == 400, (s2, r2[:200])
    finally:
        t.shutdown()


def t_mcp_http_concurrent_requests_are_correct():
    # CodeRabbit: ThreadingHTTPServer accepts concurrent connections; _HTTP_DISPATCH_LOCK serializes the
    # stateful serve_message() core so runs can't race. Functionally, every concurrent POST must still
    # get its OWN correct JSON-RPC result (id echoed back), never a crossed/dropped response.
    t, port = _http_transport()
    try:
        results = {}
        def hit(i):
            body = json.dumps({"jsonrpc": "2.0", "id": i, "method": "server/discover"})
            st, b, _ = _http_post(port, body)
            results[i] = (st, json.loads(b).get("id"))
        threads = [threading.Thread(target=hit, args=(i,)) for i in range(8)]
        for th in threads:
            th.start()
        for th in threads:
            th.join(15)
        assert len(results) == 8, results
        for i, (st, rid) in results.items():
            assert st == 200 and rid == i, (i, st, rid)
    finally:
        t.shutdown()


def t_mcp_http_config_rejects_invalid_numeric_env():
    # Codex: a typo'd AR_MCP_HTTP_PORT / AR_MCP_HTTP_MAX_BYTES must fail LOUDLY, not silently fall back to
    # the default — a mistyped small cap silently becoming 1 MiB would widen the DoS bound, and a negative
    # cap / out-of-range port would start a broken listener. Range is validated too.
    def with_env(**kv):
        old = {k: os.environ.get(k) for k in kv}
        try:
            for k, v in kv.items():
                os.environ.pop(k, None) if v is None else os.environ.__setitem__(k, v)
            return mcpsrv.http_config()
        finally:
            for k, v in old.items():
                os.environ.pop(k, None) if v is None else os.environ.__setitem__(k, v)
    _h, port, _o, mx = with_env(AR_MCP_HTTP_PORT=None, AR_MCP_HTTP_MAX_BYTES=None)  # unset -> defaults
    assert port == 8730 and mx == 1048576, (port, mx)
    _h, port2, _o, mx2 = with_env(AR_MCP_HTTP_PORT="0", AR_MCP_HTTP_MAX_BYTES="4096")  # valid override
    assert port2 == 0 and mx2 == 4096, (port2, mx2)
    # Each case controls BOTH vars (the untested one reset to unset -> its default), so the only reason
    # http_config can raise is the injected-invalid value — never an ambient env var leaking in.
    for bad in ({"AR_MCP_HTTP_PORT": "80x0"}, {"AR_MCP_HTTP_PORT": "99999"}, {"AR_MCP_HTTP_PORT": "-1"},
                {"AR_MCP_HTTP_MAX_BYTES": "0"}, {"AR_MCP_HTTP_MAX_BYTES": "-5"},
                {"AR_MCP_HTTP_MAX_BYTES": "1O24"}):
        env = {"AR_MCP_HTTP_PORT": None, "AR_MCP_HTTP_MAX_BYTES": None}
        env.update(bad)
        try:
            with_env(**env)
        except ValueError:
            pass
        else:
            raise AssertionError("http_config silently accepted invalid env %r" % bad)


def t_mcp_http_error_paths_close_connection():
    # security-2: rejection paths (Origin / protocol-version / oversized) and non-POST methods do NOT
    # drain the request body, so each MUST close the connection — an undrained body on a keep-alive
    # HTTP/1.1 connection would desync (smuggle into) the next request.
    t, port = _http_transport(origins=("https://ok.example",), max_bytes=64)
    try:
        good = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "server/discover"})
        s403, _b, h403 = _http_post(port, good, {"Origin": "https://evil.example"})
        assert s403 == 403 and h403.get("connection", "").lower() == "close", (s403, h403)
        big = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "x", "params": {"p": "A" * 200}})
        s413, _b2, h413 = _http_post(port, big)
        assert s413 == 413 and h413.get("connection", "").lower() == "close", (s413, h413)
        # GET with no session id -> 400 (Mcp-Session-Id required, E3-S2b), still a closed connection.
        s400, r400 = _http_raw(port, b"GET / HTTP/1.1\r\nHost: x\r\nConnection: keep-alive\r\n\r\n")
        head400 = r400.lower().split(b"\r\n\r\n", 1)[0]
        assert s400 == 400 and b"connection: close" in head400, r400[:200]
    finally:
        t.shutdown()


def _http_initialize(port, headers=None):
    """POST a legacy `initialize` handshake; return (status, minted_session_id_or_None, parsed_response)."""
    req = {"jsonrpc": "2.0", "id": 1, "method": "initialize",
           "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                      "clientInfo": {"name": "t", "version": "0"}}}
    status, body, hdrs = _http_post(port, json.dumps(req), headers)
    return status, hdrs.get("mcp-session-id"), (json.loads(body) if body else None)


def t_mcp_http_session_issued_at_initialize():
    # E3-S2b: a successful `initialize` mints a server session and returns it in the Mcp-Session-Id
    # response header. The id is cryptographically random (long, url-safe) — never a client value — and
    # a subsequent request bearing it is accepted.
    t, port = _http_transport()
    try:
        status, sid, result = _http_initialize(port)
        assert status == 200 and "result" in result, (status, result)
        assert sid and len(sid) >= 40 and re.match(r"^[A-Za-z0-9_-]+$", sid), sid
        s2, _b2, _h2 = _http_post(port, json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}),
                                  {"Mcp-Session-Id": sid})
        assert s2 == 200, s2
    finally:
        t.shutdown()


def t_mcp_http_forged_session_is_404():
    # A client-supplied session id the server never minted is refused with 404 — never silently honored —
    # across POST, GET and DELETE, even for the version-agnostic server/discover probe.
    t, port = _http_transport()
    try:
        body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "server/discover"})
        assert _http_post(port, body, {"Mcp-Session-Id": "forged-not-a-real-session"})[0] == 404
        assert _http_get(port, session_id="forged")[0] == 404
        assert _http_method(port, "DELETE", {"Mcp-Session-Id": "forged"}) == 404
    finally:
        t.shutdown()


def t_mcp_http_session_delete_terminates():
    # DELETE terminates a session (204). The id is then dead: a later request bearing it -> 404, and a
    # repeat DELETE -> 404; a DELETE with no id -> 400.
    t, port = _http_transport()
    try:
        _s, sid, _r = _http_initialize(port)
        assert sid
        assert _http_method(port, "DELETE", {"Mcp-Session-Id": sid}) == 204
        reuse = _http_post(port, json.dumps({"jsonrpc": "2.0", "id": 3, "method": "tools/list"}),
                           {"Mcp-Session-Id": sid})
        assert reuse[0] == 404, reuse[0]
        assert _http_method(port, "DELETE", {"Mcp-Session-Id": sid}) == 404  # repeat
        assert _http_method(port, "DELETE") == 400                            # missing id
    finally:
        t.shutdown()


def t_mcp_http_get_opens_sse_for_valid_session():
    # GET opens the server->client SSE channel for a valid session: 200 text/event-stream + an initial
    # comment. Missing session -> 400; forged -> 404. The initial chunk is read once and the socket is
    # closed, so the live stream never blocks the test.
    t, port = _http_transport()
    try:
        assert _http_get(port)[0] == 400                    # no session
        assert _http_get(port, session_id="nope")[0] == 404  # forged
        _s, sid, _r = _http_initialize(port)
        status, raw = _http_get(port, session_id=sid)
        assert status == 200, (status, raw[:200])
        head = raw.lower().split(b"\r\n\r\n", 1)[0]
        assert b"content-type: text/event-stream" in head, raw[:200]
        assert b": connected" in raw, raw[:200]
    finally:
        t.shutdown()


def t_mcp_http_session_store_bounded_evicts():
    # The session store is bounded with LRU eviction: minting past capacity drops the least-recently-used
    # id (so an `initialize` flood cannot exhaust memory), and the evicted id no longer validates.
    store = mcpsrv._SessionStore(3)
    a, b, c = store.create(), store.create(), store.create()
    assert len(store) == 3 and store.valid(a) and store.valid(b) and store.valid(c)
    store.valid(a)      # touch `a` -> `b` becomes least-recently-used
    d = store.create()  # over capacity -> evict LRU (`b`)
    assert len(store) == 3, len(store)
    assert not store.valid(b), "LRU victim should be evicted"
    assert store.valid(a) and store.valid(c) and store.valid(d)
    assert store.terminate(d) and not store.valid(d)


def t_mcp_http_require_session_flag():
    # AR_MCP_HTTP_REQUIRE_SESSION (strict mode; off by default, on with auth in E3-S2c): a request other
    # than the initialize handshake or the server/discover probe must carry a valid session, else 400.
    t, port = _http_transport(require_session=True)
    try:
        bare = _http_post(port, json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}))
        assert bare[0] == 400, bare[0]                                            # no session -> 400
        disc = _http_post(port, json.dumps({"jsonrpc": "2.0", "id": 2, "method": "server/discover"}))
        assert disc[0] == 200, disc[0]                                            # probe is exempt
        s_init, sid, _r = _http_initialize(port)
        assert s_init == 200 and sid                                             # handshake is exempt
        ok = _http_post(port, json.dumps({"jsonrpc": "2.0", "id": 3, "method": "tools/list"}),
                        {"Mcp-Session-Id": sid})
        assert ok[0] == 200, ok[0]                                                # with session -> 200
    finally:
        t.shutdown()


def t_mcp_http_session_rotates():
    # Rotatable: each initialize mints a FRESH id; both remain independently valid until terminated.
    t, port = _http_transport()
    try:
        _s1, sid1, _r1 = _http_initialize(port)
        _s2, sid2, _r2 = _http_initialize(port)
        assert sid1 and sid2 and sid1 != sid2, (sid1, sid2)
        for sid in (sid1, sid2):
            s = _http_post(port, json.dumps({"jsonrpc": "2.0", "id": 9, "method": "tools/list"}),
                           {"Mcp-Session-Id": sid})
            assert s[0] == 200, (sid, s[0])
    finally:
        t.shutdown()


def t_mcp_http_require_session_rejects_invalid_value():
    # Codex (PR #54): AR_MCP_HTTP_REQUIRE_SESSION is a security toggle. A NON-BLANK value that is neither a
    # documented affirmative nor negative (e.g. the typo "tru") must FAIL LOUDLY, never silently fall back
    # to "off" and quietly accept sessionless requests. Unset/blank stays off; explicit negatives stay off.
    NAME = "AR_MCP_HTTP_REQUIRE_SESSION"

    def val(v):
        old = os.environ.get(NAME)
        try:
            os.environ.pop(NAME, None) if v is None else os.environ.__setitem__(NAME, v)
            return mcpsrv._http_bool_env(NAME)
        finally:
            os.environ.pop(NAME, None) if old is None else os.environ.__setitem__(NAME, old)

    assert val(None) is False and val("") is False and val("   ") is False   # unset/blank -> off
    for aff in ("1", "true", "TRUE", " yes ", "on"):
        assert val(aff) is True, aff                                          # explicit affirmative -> on
    for neg in ("0", "false", "No", "off"):
        assert val(neg) is False, neg                                        # explicit negative -> off
    for bad in ("tru", "flase", "2", "enable", "y", "onn"):
        try:
            val(bad)
        except ValueError:
            pass
        else:
            raise AssertionError("_http_bool_env silently accepted invalid %r (must fail loud)" % bad)
    # End to end: a typo must stop the transport from constructing, not silently disable strict mode.
    old = os.environ.get(NAME)
    try:
        os.environ[NAME] = "tru"
        try:
            mcpsrv.HttpTransport(host="127.0.0.1", port=0)
        except ValueError:
            pass
        else:
            raise AssertionError("HttpTransport accepted AR_MCP_HTTP_REQUIRE_SESSION=tru (must refuse)")
    finally:
        os.environ.pop(NAME, None) if old is None else os.environ.__setitem__(NAME, old)


def t_mcp_http_protocol_version_validated_on_every_verb():
    # Codex (PR #54): the MCP-Protocol-Version check ran only on POST; GET and DELETE skipped it, so a bogus
    # pinned version (1999-01-01) slipped through -> GET 200 / DELETE 204. The check is shared across every
    # verb now: an unsupported version is a closed 400 on POST, GET AND DELETE, before any session work.
    t, port = _http_transport()
    try:
        _s, sid, _r = _http_initialize(port)
        assert sid
        # GET with a valid session but a bogus version -> 400 (was a 200 SSE stream before the fix).
        sg, rg = _http_raw(port, b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n"
                                 b"MCP-Protocol-Version: 1999-01-01\r\n"
                                 b"Mcp-Session-Id: " + sid.encode("ascii") + b"\r\n\r\n")
        assert sg == 400 and b"unsupported MCP-Protocol-Version" in rg, (sg, rg[:200])
        # DELETE with a valid session but a bogus version -> 400 (was 204), and the session is NOT
        # terminated (the version check runs before terminate) — a clean DELETE afterwards still 204s.
        assert _http_method(port, "DELETE", {"MCP-Protocol-Version": "1999-01-01",
                                             "Mcp-Session-Id": sid}) == 400
        assert _http_method(port, "DELETE", {"Mcp-Session-Id": sid}) == 204
        # A supported pinned version is still accepted on GET.
        sok, sid2, _r2 = _http_initialize(port)
        assert sid2
        sg2, rg2 = _http_get(port, session_id=sid2)  # no version header -> allowed (absent is fine)
        assert sg2 == 200 and b": connected" in rg2, (sg2, rg2[:200])
    finally:
        t.shutdown()


def t_mcp_http_sse_streams_are_capped():
    # Codex (PR #54): a valid session does not entitle a client to unbounded parallel SSE streams — each
    # held-open stream pins a server thread + fd, so N concurrent GETs on one valid id = N threads
    # regardless of the session cap. A global BoundedSemaphore caps concurrent streams; the (cap+1)th
    # concurrent GET is refused with a retryable 503, and a slot freed when a stream ends re-admits.
    import time
    old_ka = mcpsrv.SSE_KEEPALIVE_SECONDS
    mcpsrv.SSE_KEEPALIVE_SECONDS = 0.4    # so a closed stream's slot is reclaimed promptly (readmit check)
    t, port = _http_transport(max_streams=1)
    open_socks = []
    try:
        _s, sid, _r = _http_initialize(port)
        assert sid

        def open_stream():
            s = socket.create_connection(("127.0.0.1", port), timeout=5)
            s.sendall(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n"
                      b"Mcp-Session-Id: " + sid.encode("ascii") + b"\r\n\r\n")
            s.settimeout(5)
            buf = b""
            while b": connected" not in buf and b" 503 " not in buf:
                chunk = s.recv(4096)
                if not chunk:
                    break
                buf += chunk
            return s, buf

        # The first stream occupies the single slot and stays open; reading ": connected" proves the
        # handler has acquired the slot (happens-before), so the next GET reliably sees the cap hit.
        s1, b1 = open_stream()
        open_socks.append(s1)
        assert b": connected" in b1, b1[:200]
        # The second concurrent GET is over the cap -> a 503 refusal (retryable), before any second stream
        # opens. Assert on the STATUS: it is the unambiguous cap signal (no other path returns 503), it is
        # read deterministically from the status line, and _http_get stops at the first body byte so it
        # never drains a live stream — so if the cap ever regresses this fails FAST (uncapped -> 200) rather
        # than hanging on an unbounded stream.
        s503, _r503 = _http_get(port, session_id=sid)
        assert s503 == 503, (s503, _r503[:200])
        # Free the slot: close stream 1; within one (shortened) keepalive tick the handler notices the
        # dead socket and releases. A GET then re-admits (bounded retry so the release is observed, not raced).
        s1.close()
        open_socks.remove(s1)
        deadline = time.time() + 4.0
        readmitted = 0
        while time.time() < deadline:
            s2, r2 = _http_get(port, session_id=sid)
            if s2 == 200 and b": connected" in r2:
                readmitted = 200
                break
            time.sleep(0.2)
        assert readmitted == 200, "slot not re-admitted after the stream ended"
    finally:
        for s in open_socks:
            try:
                s.close()
            except OSError:
                pass
        mcpsrv.SSE_KEEPALIVE_SECONDS = old_ka
        t.shutdown()


def t_mcp_http_sse_stops_output_after_delete():
    # Codex (PR #54): terminating a session while its SSE handler is blocked in stop.wait must not yield one
    # more keepalive. The loop rechecks session validity AFTER the wait and BEFORE writing, so a DELETE that
    # lands mid-wait ends the stream with NO further output. Before the fix a keepalive was written after
    # termination (data after DELETE 204). Keepalive cadence is shortened so the test does not wait 15s; the
    # cadence (2.0s) is large relative to the DELETE round-trip, so the DELETE reliably lands mid-wait.
    old_ka = mcpsrv.SSE_KEEPALIVE_SECONDS
    mcpsrv.SSE_KEEPALIVE_SECONDS = 2.0
    t, port = _http_transport()
    try:
        _s, sid, _r = _http_initialize(port)
        assert sid
        s = socket.create_connection(("127.0.0.1", port), timeout=5)
        try:
            s.sendall(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n"
                      b"Mcp-Session-Id: " + sid.encode("ascii") + b"\r\n\r\n")
            s.settimeout(5)
            head = b""
            while b": connected" not in head:                 # read headers + the initial live comment
                chunk = s.recv(4096)
                assert chunk, ("stream closed before ': connected'", head[:200])
                head += chunk
            # Terminate mid-wait (well before the first 2.0s keepalive tick).
            assert _http_method(port, "DELETE", {"Mcp-Session-Id": sid}) == 204
            after = b""
            s.settimeout(5)
            while True:                                       # drain until the server closes the stream
                try:
                    chunk = s.recv(4096)
                except socket.timeout:
                    break                                     # idle without closing -> still no keepalive
                if not chunk:
                    break                                     # server closed the stream (fixed behaviour)
                after += chunk
            assert b"keepalive" not in after, ("keepalive written after DELETE", after[:200])
        finally:
            s.close()
    finally:
        mcpsrv.SSE_KEEPALIVE_SECONDS = old_ka
        t.shutdown()


def t_mcp_http_modern_era_get_is_405():
    # CodeRabbit r3941912010 (era routing): the stateless MCP 2026-07-28 revision removed the HTTP GET
    # stream and Mcp-Session-Id, so a GET pinned to a modern version has no session channel to open and
    # is 405 (Allow: POST) — NOT a 200 SSE stream. Before the fix a modern-pinned GET on a valid session
    # opened a stream (era not enforced). A legacy/absent-version GET is unaffected (still 200).
    t, port = _http_transport()
    try:
        _s, sid, _r = _http_initialize(port)                       # legacy session (2025-06-18)
        assert sid
        st, raw = _http_get(port, session_id=sid, extra={"MCP-Protocol-Version": "2026-07-28"})
        assert st == 405, (st, raw[:200])                          # was 200 (SSE) before era routing
        assert b"text/event-stream" not in raw.split(b"\r\n\r\n", 1)[0].lower(), raw[:200]
        # The legacy path still opens a stream (no version pinned) — the change is era-scoped, not a ban.
        st_ok, raw_ok = _http_get(port, session_id=sid)
        assert st_ok == 200 and b": connected" in raw_ok, (st_ok, raw_ok[:200])
    finally:
        t.shutdown()


def t_mcp_http_modern_era_delete_is_405():
    # CodeRabbit r3941912010 (era routing): 2026-07-28 is stateless with no Mcp-Session-Id to terminate,
    # so a DELETE pinned to a modern version is 405 and does NOT terminate the session. Before the fix a
    # modern-pinned DELETE terminated a legacy session (era not enforced). A legacy DELETE still 204s.
    t, port = _http_transport()
    try:
        _s, sid, _r = _http_initialize(port)
        assert sid
        assert _http_method(port, "DELETE", {"MCP-Protocol-Version": "2026-07-28",
                                             "Mcp-Session-Id": sid}) == 405     # was 204 before the fix
        # Proof it was not torn down by the modern DELETE: a legacy DELETE still terminates it.
        assert _http_method(port, "DELETE", {"Mcp-Session-Id": sid}) == 204
    finally:
        t.shutdown()


def t_mcp_http_post_header_meta_version_mismatch_is_400():
    # CodeRabbit r3941912010 (POST header/_meta consistency): a modern request declares its version in
    # params._meta; when the POST ALSO pins an MCP-Protocol-Version header the two must agree, or the
    # request is contradictory and refused (400). Before the fix the header and _meta could disagree and
    # the request was still served. A matching pair, and a modern header over a version-less body, are OK.
    t, port = _http_transport()
    try:
        body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list",
                           "params": {"_meta": {"io.modelcontextprotocol/protocolVersion": "2026-07-28",
                                                "io.modelcontextprotocol/clientCapabilities": {}}}})
        s_bad, b_bad, _ = _http_post(port, body, {"MCP-Protocol-Version": "2025-06-18"})
        assert s_bad == 400 and b"does not match" in b_bad, (s_bad, b_bad[:200])   # was 200 before the fix
        # A CONSISTENT pair still dispatches (header == _meta).
        s_ok, _b_ok, _h = _http_post(port, body, {"MCP-Protocol-Version": "2026-07-28"})
        assert s_ok == 200, s_ok
    finally:
        t.shutdown()


def t_mcp_http_session_bound_to_negotiated_version():
    # Codex r3941957895 (session bound to its negotiated version): a session negotiated at 2025-06-18 must
    # not be honored for a GET/DELETE pinned to a DIFFERENT version. 2025-03-26 is legacy (not era-405'd),
    # so this isolates the binding from era routing. Before the fix valid()/terminate() ignored the stored
    # version, so a mismatched-version GET opened a stream (200) and DELETE terminated it (204).
    t, port = _http_transport()
    try:
        _s, sid, _r = _http_initialize(port)                       # negotiated 2025-06-18
        assert sid
        st, raw = _http_get(port, session_id=sid, extra={"MCP-Protocol-Version": "2025-03-26"})
        assert st == 404, (st, raw[:200])                          # was 200 (SSE) before binding
        assert _http_method(port, "DELETE", {"MCP-Protocol-Version": "2025-03-26",
                                             "Mcp-Session-Id": sid}) == 404   # was 204 before binding
        # The session is intact (the mismatched DELETE did not terminate it): the matching version works.
        st_ok, raw_ok = _http_get(port, session_id=sid, extra={"MCP-Protocol-Version": "2025-06-18"})
        assert st_ok == 200 and b": connected" in raw_ok, (st_ok, raw_ok[:200])
        assert _http_method(port, "DELETE", {"MCP-Protocol-Version": "2025-06-18",
                                             "Mcp-Session-Id": sid}) == 204
    finally:
        t.shutdown()


def t_mcp_http_get_requires_sse_accept():
    # Codex r3941957888: a GET that does not accept text/event-stream must be refused (406) BEFORE a
    # stream slot is acquired — a client asking only for application/json must not be handed, nor charged
    # a slot for, an SSE body it will not read. Before the fix Accept was ignored and a 200 SSE opened.
    # An absent Accept (accept-anything) still opens the stream.
    t, port = _http_transport()
    try:
        _s, sid, _r = _http_initialize(port)
        assert sid
        st, raw = _http_get(port, session_id=sid, extra={"Accept": "application/json"})
        assert st == 406, (st, raw[:200])                          # was 200 (SSE) before the fix
        # An explicit q=0 rejection of the SSE type is honored too (the finding names this case).
        st_q0, raw_q0 = _http_get(port, session_id=sid, extra={"Accept": "text/event-stream;q=0"})
        assert st_q0 == 406, (st_q0, raw_q0[:200])
        # text/event-stream, a matching wildcard, and absent Accept all still open the stream.
        for acc in ("text/event-stream", "text/*", "*/*", "application/json, text/event-stream"):
            st_ok, raw_ok = _http_get(port, session_id=sid, extra={"Accept": acc})
            assert st_ok == 200 and b": connected" in raw_ok, (acc, st_ok, raw_ok[:200])
    finally:
        t.shutdown()


def t_mcp_http_get_combines_repeated_accept_lines():
    # Codex r3951256116: a client/intermediary may split the list-valued Accept header across MULTIPLE
    # field lines (RFC 9110 5.3). do_GET must combine all of them, not read only the first via
    # get("Accept"). So `Accept: application/json` + `Accept: text/event-stream` (SSE not on the first
    # line) must OPEN the stream (200), in either order. Before the fix only the first line was read -> 406.
    import socket

    def raw_get_two_accepts(port, sid, a1, a2):
        req = (b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n"
               b"Mcp-Session-Id: " + sid.encode("ascii") + b"\r\n"
               b"Accept: " + a1.encode("ascii") + b"\r\n"
               b"Accept: " + a2.encode("ascii") + b"\r\n\r\n")
        s = socket.create_connection(("127.0.0.1", port), timeout=5)
        try:
            s.sendall(req)
            s.settimeout(5)
            data = b""
            for _ in range(10):
                try:
                    chunk = s.recv(4096)
                except socket.timeout:
                    break
                if not chunk:
                    break
                data += chunk
                head, sep, body = data.partition(b"\r\n\r\n")
                if sep and (int(head.split(b" ", 2)[1]) != 200 or body):
                    break
        finally:
            s.close()
        return (int(data.split(b" ", 2)[1]) if data.startswith(b"HTTP/") else 0), data

    t, port = _http_transport()
    try:
        _s, sid, _r = _http_initialize(port)
        assert sid
        # SSE-admitting value on the SECOND line -> must still open (200), in either order.
        st1, raw1 = raw_get_two_accepts(port, sid, "application/json", "text/event-stream")
        assert st1 == 200 and b": connected" in raw1, (st1, raw1[:200])   # was 406 before the fix
        st2, raw2 = raw_get_two_accepts(port, sid, "text/event-stream", "application/json")
        assert st2 == 200 and b": connected" in raw2, (st2, raw2[:200])
        # control: two lines that BOTH exclude SSE -> still 406 (combining must not invent acceptance).
        st3, raw3 = raw_get_two_accepts(port, sid, "application/json", "text/plain")
        assert st3 == 406, (st3, raw3[:200])
    finally:
        t.shutdown()


def t_accepts_event_stream_equal_rank_tie_is_order_independent():
    # Codex (PR #54) r3951751953: with equal-specificity Accept alternatives of differing quality, the
    # strict `r > best_rank` comparison let the FIRST occurrence permanently decide, so
    # `text/event-stream;q=0, text/event-stream;q=1` was 406 while the reverse opened the stream -- an
    # order-dependent result that also arises after combining repeated Accept field lines. Ties are now
    # OR-merged (an acceptable equal-rank alternative wins), so the outcome is order-independent. On the base
    # commit the first-wins comparison returns False for the q=0-first ordering -> this fails there.
    f = mcpsrv._accepts_event_stream
    assert f("text/event-stream;q=0, text/event-stream;q=1") is True   # was False (406) before the fix
    assert f("text/event-stream;q=1, text/event-stream;q=0") is True   # order-independent
    # A MORE specific range still overrides a less specific one: a specific q=0 beats a general q=1 (the
    # tie-merge must not leak across ranks).
    assert f("*/*;q=1, text/event-stream;q=0") is False
    assert f("text/event-stream;q=0, */*;q=1") is False
    # Unchanged baselines: plain accept, absent (accept-anything), and an all-excluding list.
    assert f("text/event-stream") is True
    assert f(None) is True
    assert f("application/json, text/plain") is False


def t_mcp_http_discover_omits_modern_in_strict_mode():
    # Codex (PR #54) r3951751963: in strict mode (AR_MCP_HTTP_REQUIRE_SESSION) the stateless modern revision
    # cannot be served -- it carries no session, every non-initialize/non-discover request without one is
    # 400'd, and a legacy session cannot back it (version-bound) -- so server/discover must not ADVERTISE a
    # version this configuration will reject. Strict-mode discover omits MODERN_PROTOCOLS; normal-mode
    # discover still advertises them. On the base commit strict-mode discover still lists the modern revision
    # -> this fails there.
    req = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "server/discover"})
    t, port = _http_transport(require_session=True)         # strict: modern omitted
    try:
        status, body, _h = _http_post(port, req)            # discover is exempt from the session gate
        assert status == 200, status
        versions = json.loads(body)["result"]["supportedVersions"]
        assert "2026-07-28" not in versions, versions
        assert versions, "legacy (session-bearing) versions must still be advertised"
    finally:
        t.shutdown()
    t2, port2 = _http_transport()                           # normal: modern advertised
    try:
        status, body, _h = _http_post(port2, req)
        versions = json.loads(body)["result"]["supportedVersions"]
        assert "2026-07-28" in versions, versions
    finally:
        t2.shutdown()


def t_mcp_http_rejects_conflicting_protocol_version_headers():
    # Codex (PR #54) r3952163012: MCP-Protocol-Version is a SINGLETON control header, but a client/
    # intermediary may split or repeat it across field lines. self.headers.get() reads only the FIRST, so a
    # contradictory LATER value bypassed _protocol_ok and the downstream session-version binding (Codex
    # reproduced initialize 2025-06-18 then 1999-01-01 getting 200 + a session). _protocol_ok now rejects
    # (400) when the header carries more than one DISTINCT value, on every verb; identical repeats still
    # pass. On the base commit the two-distinct-line requests return 200 -> this fails there.
    import socket

    def raw_post_two_pv(port, pv1, pv2, body):
        b = body.encode("utf-8")
        req = (b"POST / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n"
               b"Content-Type: application/json\r\n"
               b"MCP-Protocol-Version: " + pv1.encode("ascii") + b"\r\n"
               b"MCP-Protocol-Version: " + pv2.encode("ascii") + b"\r\n"
               b"Content-Length: " + str(len(b)).encode("ascii") + b"\r\n\r\n" + b)
        s = socket.create_connection(("127.0.0.1", port), timeout=5)
        try:
            s.sendall(req)
            s.settimeout(5)
            data = b""
            while True:
                try:
                    chunk = s.recv(4096)
                except socket.timeout:
                    break
                if not chunk:
                    break
                data += chunk
        finally:
            s.close()
        return int(data.split(b" ", 2)[1]) if data.startswith(b"HTTP/") else 0

    init = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                       "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                                  "clientInfo": {"name": "t", "version": "0"}}})
    t, port = _http_transport()
    try:
        # two DISTINCT version lines -> 400: the contradictory second value can no longer be smuggled past
        assert raw_post_two_pv(port, "2025-06-18", "1999-01-01", init) == 400, "distinct pv lines must 400"
        # a legacy value then the modern revision is likewise contradictory -> 400
        assert raw_post_two_pv(port, "2025-06-18", "2026-07-28", init) == 400, "legacy+modern pv must 400"
        # identical repeats are harmless (get()'s first == the rest) -> a valid initialize still succeeds
        assert raw_post_two_pv(port, "2025-06-18", "2025-06-18", init) == 200, "identical repeats must pass"
    finally:
        t.shutdown()


def t_mcp_http_get_revalidates_session_before_streaming():
    # Codex r3941957879 (TOCTOU): the window between the session check and committing the 200 lets a
    # concurrent DELETE terminate the session, after which the stream must NOT emit 200 + ": connected".
    # Deterministic reproduction: wrap valid() so the session is terminated as a side effect of the first
    # check (a DELETE landing exactly in the window). Before the fix do_GET checks validity ONCE, so it
    # streams 200 for the now-dead session; the fix revalidates after acquiring the slot -> 404.
    t, port = _http_transport()
    try:
        _s, sid, _r = _http_initialize(port)
        assert sid
        real_valid = t.sessions.valid
        real_terminate = t.sessions.terminate
        state = {"n": 0}

        def racing_valid(s, *a, **k):         # accept both the fix's (sid, version) and the base's (sid)
            state["n"] += 1
            ok = real_valid(s)                # liveness only — this test pins no version, so the base
            if state["n"] == 1:               # streams 200 (the bug) rather than erroring on the arity
                real_terminate(s)             # a concurrent DELETE lands right after the first check
            return ok

        t.sessions.valid = racing_valid
        try:
            st, raw = _http_get(port, session_id=sid)
            assert st == 404, (st, raw[:200])   # was 200 + ": connected" for a dead session before the fix
            assert b": connected" not in raw, raw[:200]
        finally:
            t.sessions.valid = real_valid
    finally:
        t.shutdown()


def t_mcp_http_delete_wakes_stream_slot_promptly():
    # Codex r3941957873: terminating a session must WAKE its open SSE stream so the bounded stream slot is
    # released at once — not held until the next keepalive tick, which would make the 503's Retry-After a
    # lie. With one slot and a long keepalive, an open stream holds the slot; after DELETE, a fresh
    # session's GET must re-admit quickly. Before the fix the stream slept in the keepalive wait and the
    # slot stayed pinned for the full (here, long) interval, so re-admit did NOT happen in the window.
    import time
    old_ka = mcpsrv.SSE_KEEPALIVE_SECONDS
    mcpsrv.SSE_KEEPALIVE_SECONDS = 30       # long: on the base, only a keepalive tick frees the slot
    t, port = _http_transport(max_streams=1)
    open_socks = []
    try:
        _s, sid_a, _r = _http_initialize(port)
        assert sid_a
        s = socket.create_connection(("127.0.0.1", port), timeout=5)
        open_socks.append(s)
        s.sendall(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n"
                  b"Mcp-Session-Id: " + sid_a.encode("ascii") + b"\r\n\r\n")
        s.settimeout(5)
        head = b""
        while b": connected" not in head:                 # the stream holds the single slot (happens-before)
            chunk = s.recv(4096)
            assert chunk, ("stream closed before ': connected'", head[:200])
            head += chunk
        # A second session's GET is over the cap while A holds the slot.
        _s2, sid_b, _r2 = _http_initialize(port)
        assert sid_b
        assert _http_get(port, session_id=sid_b)[0] == 503, "slot should be full while A streams"
        # Terminate A. The fix wakes A's stream immediately -> its slot frees -> B re-admits fast. On the
        # base A sleeps in the 30s keepalive wait, so the slot stays pinned and B keeps getting 503.
        assert _http_method(port, "DELETE", {"Mcp-Session-Id": sid_a}) == 204
        deadline = time.time() + 5.0        # << 30s keepalive: only the wake (not a tick) can free it in time
        readmitted = 0
        while time.time() < deadline:
            st, raw = _http_get(port, session_id=sid_b)
            if st == 200 and b": connected" in raw:
                readmitted = 200
                break
            time.sleep(0.1)
        assert readmitted == 200, "terminating a session did not free its stream slot promptly"
    finally:
        for s in open_socks:
            try:
                s.close()
            except OSError:
                pass
        mcpsrv.SSE_KEEPALIVE_SECONDS = old_ka
        t.shutdown()


def t_mcp_http_modern_pinned_initialize_is_400():
    # CodeRabbit r3943894656 / Codex r3943958158: the 2026-07-28 revision removed the initialize handshake
    # and Mcp-Session-Id, so a POST pinning MCP-Protocol-Version: 2026-07-28 with a legacy initialize body
    # (no _meta, so the header/_meta consistency check does not fire) is contradictory and must be 400 --
    # not dispatched to mint a legacy session while echoing the modern version. Fails on e930dff (200 + id).
    t, port = _http_transport()
    try:
        body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                           "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                                      "clientInfo": {"name": "t", "version": "0"}}})
        s, b, h = _http_post(port, body, {"MCP-Protocol-Version": "2026-07-28"})
        assert s == 400, (s, b[:200])
        assert "mcp-session-id" not in h, h            # no session minted for a modern-pinned initialize
        s_ok, _b, h_ok = _http_post(port, body, {"MCP-Protocol-Version": "2025-06-18"})
        assert s_ok == 200 and h_ok.get("mcp-session-id"), (s_ok, h_ok)   # legacy-pinned initialize still works
    finally:
        t.shutdown()


def t_mcp_http_get_registers_wake_atomically():
    # Codex r3943958149: a DELETE landing at register_wake() (after the prior validity check) must not let
    # the handler still commit 200 + ": connected" for a dead session. register_wake now validates AND
    # registers atomically, returning a pre-set event when the session is gone, which the handler checks
    # before sending. Reproduce by terminating the session as a side effect of registration. Fails on
    # e930dff (streams 200 for the terminated session); passes here (404).
    t, port = _http_transport()
    try:
        _s, sid, _r = _http_initialize(port)
        assert sid
        real_reg = t.sessions.register_wake
        real_term = t.sessions.terminate

        def racing_register(s, *a, **k):
            real_term(s)             # a concurrent DELETE lands exactly at registration
            return real_reg(s)       # now returns a pre-set event (session gone)

        t.sessions.register_wake = racing_register
        try:
            st, raw = _http_get(port, session_id=sid)
            assert st == 404, (st, raw[:200])
            assert b": connected" not in raw, raw[:200]
        finally:
            t.sessions.register_wake = real_reg
    finally:
        t.shutdown()


def t_mcp_http_client_disconnect_releases_stream_slot():
    # Codex r3943958155: a client that closes right after ": connected" must free its stream slot promptly
    # (within the advertised Retry-After), not hold it until the next keepalive write up to
    # SSE_KEEPALIVE_SECONDS later. With max_streams=1 and a long keepalive, closing the sole stream must let
    # a new session's GET re-admit quickly. Fails on e930dff (slot pinned until the keepalive tick).
    import time
    old_ka = mcpsrv.SSE_KEEPALIVE_SECONDS
    mcpsrv.SSE_KEEPALIVE_SECONDS = 30      # long: only prompt disconnect detection (not a tick) frees it
    t, port = _http_transport(max_streams=1)
    try:
        _s, sid_a, _r = _http_initialize(port)
        assert sid_a
        s = socket.create_connection(("127.0.0.1", port), timeout=5)
        s.sendall(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n"
                  b"Mcp-Session-Id: " + sid_a.encode("ascii") + b"\r\n\r\n")
        s.settimeout(5)
        head = b""
        while b": connected" not in head:
            chunk = s.recv(4096)
            assert chunk, ("stream closed before ': connected'", head[:200])
            head += chunk
        _s2, sid_b, _r2 = _http_initialize(port)
        assert sid_b
        assert _http_get(port, session_id=sid_b)[0] == 503, "slot should be full while A streams"
        s.close()                                    # client A disconnects
        deadline = time.time() + 5.0
        readmitted = 0
        while time.time() < deadline:
            st, raw = _http_get(port, session_id=sid_b)
            if st == 200 and b": connected" in raw:
                readmitted = 200
                break
            time.sleep(0.1)
        assert readmitted == 200, "client disconnect did not free the stream slot promptly"
    finally:
        mcpsrv.SSE_KEEPALIVE_SECONDS = old_ka
        t.shutdown()


def t_mcp_http_get_accept_honors_media_params():
    # Codex r3943958164 / CodeRabbit r3943913914: a parameterized exact range (e.g. text/event-stream;level=1)
    # only matches a representation carrying that parameter; this server emits a parameterless
    # text/event-stream, so such a range must not override a plainer acceptable alternative. So
    # `text/event-stream;level=1;q=0, text/event-stream;q=1` must ADMIT the stream (200), not 406. Fails on
    # e930dff, which lets the first parameterized q=0 range reject it.
    t, port = _http_transport()
    try:
        _s, sid, _r = _http_initialize(port)
        assert sid
        st, raw = _http_get(port, session_id=sid,
                            extra={"Accept": "text/event-stream;level=1;q=0, text/event-stream;q=1"})
        assert st == 200 and b": connected" in raw, (st, raw[:200])
        st0, _r0 = _http_get(port, session_id=sid, extra={"Accept": "text/event-stream;q=0"})
        assert st0 == 406, st0                       # a bare q=0 is still an explicit rejection
    finally:
        t.shutdown()


def t_mcp_http_post_revalidates_session_after_dispatch_lock():
    # Codex r3945470134: the session validity check runs BEFORE _HTTP_DISPATCH_LOCK, so a session-bearing
    # POST that queues behind a long handler could have its session terminated meanwhile and then dispatch a
    # (state-mutating) tool anyway. The session is now re-validated after acquiring the lock. Reproduce by
    # terminating the session as a side effect of the pre-lock check; fails on 592212d (tools/list runs, 200).
    t, port = _http_transport()
    try:
        _s, sid, _r = _http_initialize(port)
        assert sid
        real_valid = t.sessions.valid
        real_term = t.sessions.terminate
        state = {"n": 0}

        def racing(s, *a, **k):
            state["n"] += 1
            ok = real_valid(s, *a, **k)
            if state["n"] == 1:               # a concurrent DELETE lands after the pre-lock check
                real_term(s)
            return ok

        t.sessions.valid = racing
        try:
            s2, b2, _h = _http_post(port, json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}),
                                    {"Mcp-Session-Id": sid})
            assert s2 == 404, (s2, b2[:200])
        finally:
            t.sessions.valid = real_valid
    finally:
        t.shutdown()


def t_mcp_http_legacy_initialize_header_must_match_body_version():
    # Codex r3945470135: a legacy initialize whose MCP-Protocol-Version header names a different supported
    # version than its body's protocolVersion is contradictory (the response echoes the header, the session
    # binds the body version) -> 400. Fails on 592212d (200 + a session bound to the body version).
    t, port = _http_transport()
    try:
        body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                           "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                                      "clientInfo": {"name": "t", "version": "0"}}})
        s, b, h = _http_post(port, body, {"MCP-Protocol-Version": "2024-11-05"})
        assert s == 400, (s, b[:200])
        assert "mcp-session-id" not in h, h
        s_ok, _b, h_ok = _http_post(port, body, {"MCP-Protocol-Version": "2025-06-18"})   # matching -> ok
        assert s_ok == 200 and h_ok.get("mcp-session-id"), (s_ok, h_ok)
    finally:
        t.shutdown()


def t_mcp_http_modern_header_requires_modern_body():
    # Codex r3945470142: a modern MCP-Protocol-Version header on a legacy (no-_meta) body -- e.g. tools/list
    # -- is 400; it would otherwise be served under legacy semantics while echoing the modern version and
    # skipping resultType. server/discover (the version probe) stays exempt. Fails on 592212d (200).
    t, port = _http_transport()
    try:
        s, b, _h = _http_post(port, json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}),
                              {"MCP-Protocol-Version": "2026-07-28"})
        assert s == 400, (s, b[:200])
        s_ok, _b, _h2 = _http_post(port, json.dumps({"jsonrpc": "2.0", "id": 2, "method": "server/discover"}),
                                   {"MCP-Protocol-Version": "2026-07-28"})   # version-agnostic probe -> allowed
        assert s_ok == 200, s_ok
        modern = json.dumps({"jsonrpc": "2.0", "id": 3, "method": "tools/list",
                             "params": {"_meta": {"io.modelcontextprotocol/protocolVersion": "2026-07-28",
                                                  "io.modelcontextprotocol/clientCapabilities": {}}}})
        s_m, _b3, _h3 = _http_post(port, modern, {"MCP-Protocol-Version": "2026-07-28"})   # modern body -> ok
        assert s_m == 200, s_m
    finally:
        t.shutdown()


def t_mcp_http_client_disconnect_releases_slot_even_with_unread_byte():
    # Codex r3945470136: a client that sends a stray byte then closes must still free its slot promptly --
    # peeking for EOF alone let the unread byte mask the close until the next keepalive. Any readable input
    # on the server->client SSE stream now ends it. Fails on 592212d (slot pinned by the unread byte).
    import time
    old_ka = mcpsrv.SSE_KEEPALIVE_SECONDS
    mcpsrv.SSE_KEEPALIVE_SECONDS = 30
    t, port = _http_transport(max_streams=1)
    try:
        _s, sid_a, _r = _http_initialize(port)
        assert sid_a
        s = socket.create_connection(("127.0.0.1", port), timeout=5)
        s.sendall(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n"
                  b"Mcp-Session-Id: " + sid_a.encode("ascii") + b"\r\n\r\n")
        s.settimeout(5)
        head = b""
        while b": connected" not in head:
            chunk = s.recv(4096)
            assert chunk, ("stream closed before ': connected'", head[:200])
            head += chunk
        _s2, sid_b, _r2 = _http_initialize(port)
        assert sid_b
        assert _http_get(port, session_id=sid_b)[0] == 503, "slot should be full while A streams"
        s.sendall(b"x")                                  # a stray byte BEFORE closing (masks EOF from MSG_PEEK)
        s.close()
        deadline = time.time() + 5.0
        readmitted = 0
        while time.time() < deadline:
            st, raw = _http_get(port, session_id=sid_b)
            if st == 200 and b": connected" in raw:
                readmitted = 200
                break
            time.sleep(0.1)
        assert readmitted == 200, "an unread client byte masked EOF -> slot not freed promptly"
    finally:
        mcpsrv.SSE_KEEPALIVE_SECONDS = old_ka
        t.shutdown()


def t_mcp_http_accept_ignores_extensions_after_q():
    # Codex r3945470144: an accept-extension after the weight (e.g. text/event-stream;q=1;foo=bar) is NOT a
    # media parameter and must not cause a 406. Fails on 592212d (treats foo as a media param -> skip -> 406).
    t, port = _http_transport()
    try:
        _s, sid, _r = _http_initialize(port)
        assert sid
        st, raw = _http_get(port, session_id=sid, extra={"Accept": "text/event-stream;q=1;foo=bar"})
        assert st == 200 and b": connected" in raw, (st, raw[:200])
        # a media parameter BEFORE q still constrains our parameterless representation -> 406 (unchanged)
        st2, _r2 = _http_get(port, session_id=sid, extra={"Accept": "text/event-stream;level=1"})
        assert st2 == 406, st2
    finally:
        t.shutdown()


def t_mcp_http_initialize_header_matches_negotiated_when_body_omits_version():
    # CodeRabbit r3945516733: a legacy initialize that OMITS params.protocolVersion negotiates
    # SUPPORTED_PROTOCOLS[0] while echoing the header, so a header naming a different supported version is
    # contradictory (the client pins the echoed version and its session id then 404s). The header is now
    # compared to the NEGOTIATED version, so this is 400. Fails on 5f810d4 (the raw-body check skipped a
    # None body -> 200 + a session).
    t, port = _http_transport()
    try:
        body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                           "params": {"capabilities": {}, "clientInfo": {"name": "t", "version": "0"}}})
        supported0 = mcpsrv.SUPPORTED_PROTOCOLS[0]
        other = next(v for v in mcpsrv.SUPPORTED_PROTOCOLS if v != supported0)
        s, b, h = _http_post(port, body, {"MCP-Protocol-Version": other})
        assert s == 400, (s, b[:200])
        assert "mcp-session-id" not in h, h
        s_ok, _b, h_ok = _http_post(port, body, {"MCP-Protocol-Version": supported0})   # matches negotiated
        assert s_ok == 200 and h_ok.get("mcp-session-id"), (s_ok, h_ok)
    finally:
        t.shutdown()


def t_mcp_http_delete_returns_promptly_during_long_dispatch():
    # E3-S2b round 6 (CodeRabbit Major r3945707197): do_POST holds _HTTP_DISPATCH_LOCK across serve_message()
    # for up to ~AR_TIMEOUT_S, so DELETE and the GET stream commit must NOT take that lock or they block for
    # the whole tool call. Round 5 made DELETE take it (for atomic termination); round 6 reverts that --
    # strict termination-vs-dispatch ordering is a multi-client property deferred to E3-S2c. HOLD the dispatch
    # lock (standing in for an in-flight long POST) and show a concurrent DELETE still completes promptly.
    # Fails on 50c7db8 (DELETE takes the lock and blocks until release). Event-coordinated, no sleep race.
    import threading
    t, port = _http_transport()
    try:
        _s, sid, _r = _http_initialize(port)
        assert sid
        done = threading.Event()
        result = {}

        def do_delete():
            result["code"] = _http_method(port, "DELETE", {"Mcp-Session-Id": sid})
            done.set()

        mcpsrv._HTTP_DISPATCH_LOCK.acquire()
        try:
            threading.Thread(target=do_delete, daemon=True).start()
            # On the fix DELETE never touches the dispatch lock -> it completes while we still hold the lock.
            # On 50c7db8 it blocks on the held lock and this wait times out.
            completed = done.wait(5)
        finally:
            mcpsrv._HTTP_DISPATCH_LOCK.release()
        assert completed, "DELETE blocked on _HTTP_DISPATCH_LOCK while a POST would hold it (round-5 regression)"
        assert result.get("code") == 204, result
    finally:
        t.shutdown()


def t_mcp_http_modern_meta_initialize_rejected_no_session():
    # Codex r3949809506: an `initialize` body that DECLARES the modern era (params._meta protocolVersion
    # 2026-07-28) has no handshake in that revision, so it must NOT be served as a legacy handshake -- even
    # with NO MCP-Protocol-Version header (the header-keyed era checks are skipped then, so the body-declared
    # era must be validated in the shared core). handle() now rejects it (-32601), so no legacy session is
    # minted. Fails on 3c0ee23 (200 + negotiated 2025-06-18 result + an Mcp-Session-Id).
    t, port = _http_transport()
    try:
        body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                           "params": {"_meta": {"io.modelcontextprotocol/protocolVersion": "2026-07-28",
                                                "io.modelcontextprotocol/clientCapabilities": {}},
                                      "capabilities": {}, "clientInfo": {"name": "t", "version": "0"}}})
        s, b, h = _http_post(port, body, {})                       # NO MCP-Protocol-Version header
        assert s == 200, (s, b[:200])                              # a JSON-RPC error still rides a 200
        assert "mcp-session-id" not in h, h                        # no legacy session for a modern-declared init
        resp = json.loads(b)
        assert resp.get("error", {}).get("code") == -32601, resp
        assert "result" not in resp, resp
    finally:
        t.shutdown()


# --- ar-mcp #7c review-follow-up regressions (PR #24) ---------------------------

def _patch_run_cli(rc, out="", err="", capture=None):
    """Stub mcp_server._run_cli to return (rc,out,err) and optionally record each call's
    (module, argv, timeout). Returns the original so the caller can restore it."""
    orig = mcpsrv._run_cli

    def fake(module, argv, timeout=120):
        if capture is not None:
            capture.append({"module": module, "argv": list(argv), "timeout": timeout})
        return (rc, out, err)

    mcpsrv._run_cli = fake
    return orig


def t_mcp_init_reports_created_run_not_newest_dir():
    # h_init must report the run it CREATED (parsed from init's stdout), not the
    # lexicographically-newest run-* dir — a decoy or a -9/-10 collision skews that scan.
    repo = fresh_repo()
    (repo / ".adversarial-review" / "run-99999999-999999").mkdir(parents=True)  # sorts newest
    res = _mcp_call(repo, "ar_init",
                    {"risk": "NORMAL", "dev_providers": ["anthropic"], "diff_ref": "main...HEAD"})
    assert not res.get("isError"), res
    run_id = res["structuredContent"]["run_id"]
    assert run_id and run_id != "run-99999999-999999", res
    assert (repo / ".adversarial-review" / run_id).is_dir(), run_id


def t_mcp_run_key_orders_numeric_suffix():
    # run-...-10 sorts after run-...-9 (numeric disambiguator), not lexicographically.
    names = ["run-20260101-000000", "run-20260101-000000-9", "run-20260101-000000-10",
             "run-20260101-000000-2"]
    assert sorted(names, key=mcpsrv._run_key)[-1] == "run-20260101-000000-10", names
    assert sorted(["run-20260101-000000-10", "run-20260102-000000"],
                  key=mcpsrv._run_key)[-1] == "run-20260102-000000"


def t_mcp_check_digest_distinguishes_exit_codes():
    # --check-digest: 0 intact, 1 drifted, 2 (no verdict/attestation) is cannot-verify -> error,
    # not a silent {"intact": false}. A REAL run dir must exist first: h_check_digest confirms the run
    # before mapping exit 1 to drift, so a missing run can never read as {"intact": false}.
    repo = Path(tempfile.mkdtemp(prefix="ar-cd-codes-"))
    (repo / ".adversarial-review" / "run-20260101-010101").mkdir(parents=True)
    cwd0 = os.getcwd()
    os.chdir(repo)
    try:
        orig = _patch_run_cli(0, out="attestation OK")
        try:
            r = mcpsrv.h_check_digest({})
            assert r["structuredContent"] == {"intact": True} and not r["isError"], r
        finally:
            mcpsrv._run_cli = orig
        orig = _patch_run_cli(1, out="attestation MISMATCH")
        try:
            r = mcpsrv.h_check_digest({})
            assert r["structuredContent"] == {"intact": False} and not r["isError"], r
        finally:
            mcpsrv._run_cli = orig
        orig = _patch_run_cli(2, out="no verdict.json in run")
        try:
            r = mcpsrv.h_check_digest({})
            assert r["isError"] and "structuredContent" not in r, r
        finally:
            mcpsrv._run_cli = orig
    finally:
        os.chdir(cwd0)


def t_mcp_no_hardcoded_model_in_tool_schema():
    # No concrete provider/model slug in any served tool schema — models resolve from the live
    # catalog; a hardcoded slug goes stale and steers hosts to pin it.
    blob = json.dumps([mcpsrv._public_tool(t) for t in mcpsrv.TOOLS])
    for bad in ("gemini", "google/gemini-3.6-flash", "gpt-5", "claude-3"):
        assert bad not in blob, f"hardcoded model reference {bad!r} in tool schema"
    assert "<provider>/<model-slug>" in blob


def t_mcp_falsy_arguments_rejected():
    # A falsy non-dict arguments ([], "", 0, false) must be -32602, not silently defaulted to {}.
    for bad in ([], "", 0, False):
        r = mcpsrv.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                           "params": {"name": "ar_get_verdict", "arguments": bad}})
        assert r.get("error", {}).get("code") == -32602, (bad, r)
    # missing/None arguments still dispatches (defaults to {}), it is not a protocol error
    r = mcpsrv.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                       "params": {"name": "ar_get_verdict"}})
    assert "result" in r, r


def t_mcp_aggregate_rejects_stale_verdict():
    # If aggregate does not FRESHLY write verdict.json (e.g. crashes on a malformed artifact),
    # never surface the pre-existing verdict as success.
    repo = Path(tempfile.mkdtemp(prefix="ar-agg-"))
    rundir = repo / ".adversarial-review" / "run-20260101-010101"
    rundir.mkdir(parents=True)
    vf = rundir / "verdict.json"
    vf.write_text(json.dumps({"verdict": "PASS", "run_id": "run-20260101-010101"}))
    cwd0 = os.getcwd()
    os.chdir(repo)
    orig = _patch_run_cli(1, err="Traceback: boom")  # crash, does NOT rewrite verdict.json
    try:
        r = mcpsrv.h_aggregate({"run": "run-20260101-010101"})
        assert r["isError"] and "without an accepted verdict" in r["content"][0]["text"], r
    finally:
        mcpsrv._run_cli = orig
        os.chdir(cwd0)
    # happy path: aggregate writes a NEW verdict.json (h_aggregate moved the prior one aside) +
    # a verdict exit code -> success
    os.chdir(repo)

    def fresh(module, argv, timeout=120):
        (rundir / "verdict.json").write_text(
            json.dumps({"verdict": "FAIL", "run_id": "run-20260101-010101"}))
        return (1, "FAIL", "")

    orig = mcpsrv._run_cli
    mcpsrv._run_cli = fresh
    try:
        r = mcpsrv.h_aggregate({"run": "run-20260101-010101"})
        assert not r["isError"] and r["structuredContent"]["verdict"] == "FAIL", r
    finally:
        mcpsrv._run_cli = orig
        os.chdir(cwd0)


def t_mcp_aggregate_rejects_nonobject_fresh_verdict():
    # aggregate can write a FRESH verdict.json that is valid JSON but NOT an object (e.g. []). It must
    # never be accepted: accepting flips `accepted` true, so the settle step discards the prior, and
    # the return either surfaces a bogus list as structuredContent or crashes at structured.get().
    # A non-object fresh verdict is a rejected outcome — the prior must be restored. (Codex, 52c686f.)
    repo = Path(tempfile.mkdtemp(prefix="ar-agg-nonobj-"))
    rundir = repo / ".adversarial-review" / "run-20260101-010101"
    rundir.mkdir(parents=True)
    vf = rundir / "verdict.json"
    prior = {"verdict": "PASS", "run_id": "run-20260101-010101"}
    vf.write_text(json.dumps(prior))
    cwd0 = os.getcwd()
    os.chdir(repo)

    def writes_nonobject(module, argv, timeout=120):
        # h_aggregate moved the prior aside to .prev; aggregate writes a FRESH but non-object verdict.
        vf.write_text(json.dumps([1, 2, 3]), encoding="utf-8")
        return (0, "PASS", "")

    orig = mcpsrv._run_cli
    mcpsrv._run_cli = writes_nonobject
    try:
        r = mcpsrv.h_aggregate({"run": "run-20260101-010101"})
        assert r["isError"] and "without an accepted verdict" in r["content"][0]["text"], r
        assert json.loads(vf.read_text()) == prior, vf.read_text()   # prior restored, not discarded
    finally:
        mcpsrv._run_cli = orig
        os.chdir(cwd0)


def t_mcp_aggregate_rejects_malformed_fresh_verdict():
    # aggregate can write a FRESH verdict.json that is not even valid JSON (a truncated/corrupt write
    # while still exiting 0/1/2). An unguarded json.loads() would RAISE here and escape h_aggregate
    # PAST the isError return — a crash, not a clean rejected result. It must be handled as a rejected
    # outcome (isError) with the prior restored, like check_digest's read/parse guard. (CodeRabbit,
    # 7da1420.)
    repo = Path(tempfile.mkdtemp(prefix="ar-agg-badjson-"))
    rundir = repo / ".adversarial-review" / "run-20260101-010101"
    rundir.mkdir(parents=True)
    vf = rundir / "verdict.json"
    prior = {"verdict": "PASS", "run_id": "run-20260101-010101"}
    vf.write_text(json.dumps(prior))
    cwd0 = os.getcwd()
    os.chdir(repo)

    def writes_malformed(module, argv, timeout=120):
        # h_aggregate moved the prior aside to .prev; aggregate writes a FRESH but corrupt verdict.
        vf.write_text("{ not valid json", encoding="utf-8")
        return (0, "PASS", "")

    orig = mcpsrv._run_cli
    mcpsrv._run_cli = writes_malformed
    try:
        raised = None
        try:
            r = mcpsrv.h_aggregate({"run": "run-20260101-010101"})
        except Exception as e:  # noqa: BLE001 — must NOT raise; a raise is the very bug under test
            raised = e
        assert raised is None, f"h_aggregate must not raise on malformed fresh verdict JSON: {raised!r}"
        assert r["isError"] and "without an accepted verdict" in r["content"][0]["text"], r
        assert json.loads(vf.read_text()) == prior, vf.read_text()   # prior restored, not discarded
    finally:
        mcpsrv._run_cli = orig
        os.chdir(cwd0)


def t_mcp_aggregate_rejects_foreign_or_unrecognized_fresh_verdict():
    # A fresh verdict.json can be a dict yet NOT be this run's verdict: an empty object, an
    # unsupported verdict value, or another run's run_id. Accepting any of them would surface a stray
    # result as THIS run's and discard the prior. Accept only a recognized PASS/FAIL/BLOCKED whose
    # run_id matches the pinned run. (CodeRabbit, bdccc64.)
    repo = Path(tempfile.mkdtemp(prefix="ar-agg-foreign-"))
    rundir = repo / ".adversarial-review" / "run-20260101-010101"
    rundir.mkdir(parents=True)
    vf = rundir / "verdict.json"
    prior = {"verdict": "PASS", "run_id": "run-20260101-010101"}
    cwd0 = os.getcwd()
    os.chdir(repo)

    def run_with(fresh_obj, rc):
        vf.write_text(json.dumps(prior))                 # reset the prior before each aggregate
        def writes(module, argv, timeout=120):
            vf.write_text(json.dumps(fresh_obj), encoding="utf-8")
            return (rc, str(fresh_obj.get("verdict", "")), "")
        orig = mcpsrv._run_cli
        mcpsrv._run_cli = writes
        try:
            return mcpsrv.h_aggregate({"run": "run-20260101-010101"})
        finally:
            mcpsrv._run_cli = orig

    try:
        for bad in ({},                                                  # empty object
                    {"verdict": "MAYBE", "run_id": "run-20260101-010101"},   # unsupported verdict
                    {"verdict": "PASS", "run_id": "run-99999999-999999"}):   # mismatched run_id
            r = run_with(bad, 0)
            assert r["isError"] and "without an accepted verdict" in r["content"][0]["text"], (bad, r)
            assert json.loads(vf.read_text()) == prior, (bad, vf.read_text())   # prior restored
        # sanity: a recognized verdict for the pinned run IS still accepted (no over-rejection)
        r = run_with({"verdict": "FAIL", "run_id": "run-20260101-010101"}, 1)
        assert not r["isError"] and r["structuredContent"]["verdict"] == "FAIL", r
    finally:
        os.chdir(cwd0)


def t_mcp_aggregate_preserves_prior_when_snapshot_fails():
    # If the prior verdict can be neither moved aside (a stale .prev DIRECTORY blocks vf.replace) NOR
    # byte-snapshotted (it is unreadable), h_aggregate has no way to restore it and running aggregate
    # would overwrite the only copy. It must ABORT (ToolError) before aggregation and leave the prior
    # intact — NOT fall into the settle step's "no prior existed" branch, which unlinks the prior even
    # on a mere aggregate timeout. (Codex, 52c686f.)
    repo = Path(tempfile.mkdtemp(prefix="ar-agg-snap-"))
    rundir = repo / ".adversarial-review" / "run-20260101-010101"
    rundir.mkdir(parents=True)
    vf = rundir / "verdict.json"
    prior = {"verdict": "PASS", "run_id": "run-20260101-010101"}
    vf.write_text(json.dumps(prior))
    (rundir / "verdict.json.prev").mkdir()          # stale .prev DIRECTORY -> vf.replace() raises
    cwd0 = os.getcwd()
    os.chdir(repo)

    def crash_no_write(module, argv, timeout=120):  # like a timeout: does NOT write verdict.json
        return (1, "", "Traceback: timeout")

    RB = type(vf)
    orig_rb = RB.read_bytes

    def unreadable(self):                           # the prior verdict cannot be read either
        if self.name == "verdict.json":
            raise OSError("unreadable prior verdict")
        return orig_rb(self)

    orig_cli = mcpsrv._run_cli
    RB.read_bytes = unreadable
    mcpsrv._run_cli = crash_no_write
    raised = False
    try:
        try:
            mcpsrv.h_aggregate({"run": "run-20260101-010101"})
        except mcpsrv.ToolError as e:
            raised = True
            # CodeRabbit(274b460): the snapshot-failure ToolError must SURFACE the OSError cause — the
            # tools/call handler sends only str(ToolError) to clients. Fails on 274b460 (message omits
            # the cause).
            assert "unreadable prior verdict" in str(e), str(e)
    finally:
        RB.read_bytes = orig_rb
        mcpsrv._run_cli = orig_cli
        os.chdir(cwd0)
    assert raised, "h_aggregate must abort (ToolError) when the prior cannot be snapshotted"
    assert json.loads(vf.read_text()) == prior, vf.read_text()      # prior left intact


def t_mcp_panel_timeout_scales_with_env():
    # The panel-run wrapper timeout scales with AR_TIMEOUT_S AND AR_HIGH_SAMPLES, so a valid slow
    # run — including a multi-sample corroboration sweep — isn't killed before panel.py finishes.
    old_t = os.environ.get("AR_TIMEOUT_S")
    old_h = os.environ.get("AR_HIGH_SAMPLES")
    try:
        os.environ.pop("AR_HIGH_SAMPLES", None)  # hs defaults to 1 -> base 9 request budgets/role
        os.environ["AR_TIMEOUT_S"] = "240"
        assert mcpsrv._panel_timeout() == max(1800, 240 * 9 * 6 + 600) > 300
        os.environ["AR_TIMEOUT_S"] = "garbage"
        assert mcpsrv._panel_timeout() == max(1800, 240 * 9 * 6 + 600)  # bad value -> default
        # Corroboration budget: hs samples add (hs-1) extra samples/role, each a call + retry (x2).
        os.environ["AR_TIMEOUT_S"] = "240"
        os.environ["AR_HIGH_SAMPLES"] = "25"
        assert mcpsrv._panel_timeout() == max(1800, 240 * (9 + 2 * 24) * 6 + 600)
        assert mcpsrv._panel_timeout() > max(1800, 240 * 9 * 6 + 600)  # strictly larger than base
        os.environ["AR_HIGH_SAMPLES"] = "1"
        assert mcpsrv._panel_timeout() == max(1800, 240 * 9 * 6 + 600)  # hs=1 == base
        os.environ["AR_HIGH_SAMPLES"] = "999"  # clamped to the 25 cap, never unbounded
        assert mcpsrv._panel_timeout() == max(1800, 240 * (9 + 2 * 24) * 6 + 600)
    finally:
        for _k, _v in (("AR_TIMEOUT_S", old_t), ("AR_HIGH_SAMPLES", old_h)):
            if _v is None:
                os.environ.pop(_k, None)
            else:
                os.environ[_k] = _v


def t_mcp_panel_timeout_honors_policy_high_samples():
    # high_samples can be set in the repo policy (.adversarial-review.yml), not only via
    # AR_HIGH_SAMPLES. panel.py resolves env > policy > default, so the MCP wrapper timeout must
    # budget for a policy-set value too — otherwise a policy-driven corroboration sweep is killed
    # early. A set env var still wins over the policy.
    repo = Path(tempfile.mkdtemp(prefix="ar-timeout-pol-"))
    (repo / ".adversarial-review.yml").write_text("high_samples: 25\n", encoding="utf-8")
    old_t = os.environ.get("AR_TIMEOUT_S")
    old_h = os.environ.get("AR_HIGH_SAMPLES")
    cwd0 = os.getcwd()
    os.chdir(repo)
    try:
        os.environ["AR_TIMEOUT_S"] = "240"
        os.environ.pop("AR_HIGH_SAMPLES", None)           # env unset -> policy value must be honored
        assert mcpsrv._panel_timeout() == max(1800, 240 * (9 + 2 * 24) * 6 + 600), \
            mcpsrv._panel_timeout()
        os.environ["AR_HIGH_SAMPLES"] = "1"               # env set -> wins over the policy's 25
        assert mcpsrv._panel_timeout() == max(1800, 240 * 9 * 6 + 600), mcpsrv._panel_timeout()
    finally:
        os.chdir(cwd0)
        for _k, _v in (("AR_TIMEOUT_S", old_t), ("AR_HIGH_SAMPLES", old_h)):
            if _v is None:
                os.environ.pop(_k, None)
            else:
                os.environ[_k] = _v


def t_mcp_panel_timeout_reads_policy_racesafe():
    # CodeRabbit r3951172615 (fixing fix-33's stat-then-reopen TOCTOU): _resolved_high_samples() must read
    # the policy through a race-safe descriptor (O_NOFOLLOW rejects a symlink leaf, O_NONBLOCK stops a FIFO
    # from blocking the open, fstat bounds size) and parse a private snapshot -- NEVER reopen the mutable
    # path. An unsafe/oversized policy budgets the clamp MAX (never under-counts); a small regular policy is
    # read as before. On the fix-33 base _resolved_high_samples() used Path.stat() (which FOLLOWS symlinks)
    # then reopened the path, so the symlink case (b) below reads the target and returns 3, not "25" -> the
    # test fails there, pinning the TOCTOU this fix closes.
    orig_cap = mcpsrv._POLICY_MAX_BYTES
    mcpsrv._POLICY_MAX_BYTES = 128
    old_h = os.environ.pop("AR_HIGH_SAMPLES", None)
    old_t = os.environ.get("AR_TIMEOUT_S")
    os.environ["AR_TIMEOUT_S"] = "240"
    cwd0 = os.getcwd()
    MAXB = max(1800, 240 * (9 + 2 * 24) * 6 + 600)   # hs=25 (clamp max) budget
    BASE = max(1800, 240 * 9 * 6 + 600)              # hs=1 budget
    try:
        # (a) oversized REGULAR policy -> refused by size (fstat), budget the MAX (never read whole in-process)
        repo = Path(tempfile.mkdtemp(prefix="ar-pol-big-"))
        os.chdir(repo)
        (repo / ".adversarial-review.yml").write_text("x" * 512, encoding="utf-8")
        assert mcpsrv._resolved_high_samples() == "25"
        assert mcpsrv._panel_timeout() == MAXB, mcpsrv._panel_timeout()
        # (b) a SYMLINK policy leaf is refused (O_NOFOLLOW) even if its target is a small valid policy: never
        #     followed in-process; budget the MAX. panel.py reads the real (symlinked) policy in its subprocess.
        tgt = Path(tempfile.mkdtemp(prefix="ar-pol-tgt-"))
        (tgt / "real.yml").write_text("high_samples: 3\n", encoding="utf-8")
        repo2 = Path(tempfile.mkdtemp(prefix="ar-pol-link-"))
        os.chdir(repo2)
        linked = False
        try:
            (repo2 / ".adversarial-review.yml").symlink_to(tgt / "real.yml")
            linked = True
        except (OSError, NotImplementedError):
            pass
        if linked:
            assert mcpsrv._resolved_high_samples() == "25", "a symlink policy leaf must not be followed in-process"
            assert mcpsrv._panel_timeout() == MAXB, mcpsrv._panel_timeout()
        # (b2) a DANGLING policy symlink (target missing) is PRESENT-but-unsafe, not absent: lexists() keeps it
        #      (exists() would silently drop it), and the O_NOFOLLOW open below then fails closed -> budget the
        #      MAX. On the fix-35 base the presence probe used exists(), which FOLLOWS the link, finds no target,
        #      and reports the policy "absent" -> _resolved_high_samples() returns the non-conservative "1", not
        #      "25" -> this case fails there, pinning exactly what fix-36 closes (CodeRabbit r3951475453).
        repo_dangle = Path(tempfile.mkdtemp(prefix="ar-pol-dangle-"))
        os.chdir(repo_dangle)
        dangled = False
        try:
            (repo_dangle / ".adversarial-review.yml").symlink_to(repo_dangle / "no-such-policy-target.yml")
            dangled = True
        except (OSError, NotImplementedError):
            pass
        if dangled:
            # sanity: this really is a dangling link, and exists()/lexists() diverge on it (the crux of the fix)
            assert not os.path.exists(repo_dangle / ".adversarial-review.yml"), "target must be missing (dangling)"
            assert os.path.lexists(repo_dangle / ".adversarial-review.yml"), "the link itself must be present"
            assert mcpsrv._resolved_high_samples() == "25", "a dangling policy symlink must budget MAX, not read as absent"
            assert mcpsrv._panel_timeout() == MAXB, mcpsrv._panel_timeout()
        # (c) a FIFO policy is refused WITHOUT blocking the open (O_NONBLOCK + fstat non-regular) -> MAX
        if hasattr(os, "mkfifo"):
            repo3 = Path(tempfile.mkdtemp(prefix="ar-pol-fifo-"))
            os.chdir(repo3)
            os.mkfifo(repo3 / ".adversarial-review.yml")
            assert mcpsrv._resolved_high_samples() == "25", "a FIFO policy must be refused, not read"
            assert mcpsrv._panel_timeout() == MAXB, mcpsrv._panel_timeout()
        # (c2) BOTH policy files present -> refused (mirrors load_policy's both-exist rejection) -> MAX budget
        repo_both = Path(tempfile.mkdtemp(prefix="ar-pol-both-"))
        os.chdir(repo_both)
        (repo_both / ".adversarial-review.yml").write_text("high_samples: 3\n", encoding="utf-8")
        (repo_both / ".adversarial-review.json").write_text('{"high_samples": 3}', encoding="utf-8")
        assert mcpsrv._resolved_high_samples() == "25", "both policy files must be refused (CodeRabbit r3951335743)"
        # (c3) when os.O_NOFOLLOW is unavailable (e.g. Windows) the read fails CLOSED -> MAX, never following a
        #      policy symlink (CodeRabbit r3951335750). Simulate by removing the attribute.
        repo_nof = Path(tempfile.mkdtemp(prefix="ar-pol-nof-"))
        os.chdir(repo_nof)
        (repo_nof / ".adversarial-review.yml").write_text("high_samples: 3\n", encoding="utf-8")
        if hasattr(os, "O_NOFOLLOW"):
            saved_nof = os.O_NOFOLLOW
            try:
                del os.O_NOFOLLOW
                assert mcpsrv._resolved_high_samples() == "25", "no O_NOFOLLOW must fail closed, not follow a symlink"
            finally:
                os.O_NOFOLLOW = saved_nof
        # (d) control: a small REGULAR policy is read race-safely and its high_samples honored
        repo4 = Path(tempfile.mkdtemp(prefix="ar-pol-ok-"))
        os.chdir(repo4)
        (repo4 / ".adversarial-review.yml").write_text("high_samples: 3\n", encoding="utf-8")
        assert int(mcpsrv._resolved_high_samples()) == 3, mcpsrv._resolved_high_samples()
        assert mcpsrv._panel_timeout() == max(1800, 240 * (9 + 2 * 2) * 6 + 600), mcpsrv._panel_timeout()
        # ...and a policy with no high_samples -> default hs=1
        (repo4 / ".adversarial-review.yml").write_text("risk: NORMAL\n", encoding="utf-8")
        assert mcpsrv._panel_timeout() == BASE, mcpsrv._panel_timeout()
    finally:
        mcpsrv._POLICY_MAX_BYTES = orig_cap
        os.chdir(cwd0)
        if old_h is not None:
            os.environ["AR_HIGH_SAMPLES"] = old_h
        if old_t is None:
            os.environ.pop("AR_TIMEOUT_S", None)
        else:
            os.environ["AR_TIMEOUT_S"] = old_t


def t_mcp_panel_timeout_budgets_the_substitution_catalog_fetch():
    # The per-role worst case is NINE AR_TIMEOUT_S request budgets, not eight: run_one_role spends 4
    # (two attempts x one corrective retry), then substitution reloads the model catalog LIVE — one
    # /models fetch, bounded by AR_TIMEOUT_S when no --catalog-file is cached (panel.py load_catalog
    # via http_json, whose timeout defaults to AR_TIMEOUT_S) — then run_one_role repeats (4 more):
    # 4 + 1 + 4 = 9. Omitting the catalog fetch (budgeting 8) under-counts the outer deadline by one
    # request width PER ROLE, up to 6 roles, and can kill a legitimately slow but valid run mid-
    # substitution. Assert the base budget is exactly 9 widths and STRICTLY exceeds an 8-width
    # (catalog-fetch-omitting) deadline. (Codex, bdccc64.)
    old_t = os.environ.get("AR_TIMEOUT_S")
    old_h = os.environ.get("AR_HIGH_SAMPLES")
    try:
        os.environ["AR_TIMEOUT_S"] = "240"
        os.environ["AR_HIGH_SAMPLES"] = "1"               # no resampling -> pure base budget
        got = mcpsrv._panel_timeout()
        assert got == max(1800, 240 * 9 * 6 + 600), got    # 9 widths/role x 6 roles + 600 headroom
        assert got > max(1800, 240 * 8 * 6 + 600), got     # strictly more than the pre-fix 8-width budget
        # The per-role width recovered from the deadline is 9 (4 primary + 1 catalog + 4 substitute).
        assert (got - 600) // 6 // 240 == 9, got
    finally:
        for _k, _v in (("AR_TIMEOUT_S", old_t), ("AR_HIGH_SAMPLES", old_h)):
            if _v is None:
                os.environ.pop(_k, None)
            else:
                os.environ[_k] = _v


def t_mcp_panel_run_validates_catalog_before_writing_context():
    # A rejected ar_panel_run (escaping catalog_file) must NOT mutate the run's audit record:
    # catalog_file is validated BEFORE context.md is overwritten, so completed reviewer reports are
    # never left paired with a freshly-written context on a call the host was told failed.
    repo = Path(tempfile.mkdtemp(prefix="ar-panelrun-cat-"))
    rundir = repo / ".adversarial-review" / "run-20260101-010101"
    rundir.mkdir(parents=True)
    ctx = rundir / "context.md"
    ORIGINAL = "ORIGINAL CONTEXT — completed reviewer reports depend on this\n"
    ctx.write_text(ORIGINAL, encoding="utf-8")
    cwd0 = os.getcwd()
    os.chdir(repo)
    try:
        raised = False
        try:
            mcpsrv.h_panel_run({"run": "run-20260101-010101", "context": "NEW REPLACEMENT CONTEXT",
                                "catalog_file": "../../etc/passwd"})
        except mcpsrv.ToolError as e:
            raised = True
            assert "catalog_file" in str(e), e
        assert raised, "an escaping catalog_file must be rejected"
        assert ctx.read_text() == ORIGINAL, "a rejected ar_panel_run must not overwrite context.md"
    finally:
        os.chdir(cwd0)


def t_mcp_panel_run_validates_catalog_loadable_before_writing_context():
    # A catalog_file that is CONFINED but not usable (missing, malformed, or empty after filtering)
    # must be rejected BEFORE context.md is overwritten — panel.py only discovers it when it runs
    # (after the write), which would pair completed reviewer reports with a new context on a call the
    # host was told failed. (Codex, 39ddb1b — the fix-7 reorder only checked confinement.)
    repo = Path(tempfile.mkdtemp(prefix="ar-panelrun-catload-"))
    rundir = repo / ".adversarial-review" / "run-20260101-010101"
    rundir.mkdir(parents=True)
    ctx = rundir / "context.md"
    ORIGINAL = "ORIGINAL CONTEXT — completed reviewer reports depend on this\n"
    bad_catalogs = {
        "missing.json": None,                          # never created -> missing file
        "malformed.json": "{ this is not valid json",  # present but unreadable as JSON
        "empty.json": json.dumps({"data": []}),        # valid JSON but empty after filtering
    }
    cwd0 = os.getcwd()
    os.chdir(repo)
    # If validation is skipped the code reaches the subprocess; make that a loud failure so the ONLY
    # way context.md survives is validating the catalog before the write.
    orig = _patch_run_cli(1, err="panel must not be reached for an unusable catalog")
    try:
        for name, body in bad_catalogs.items():
            ctx.write_text(ORIGINAL, encoding="utf-8")
            if body is not None:
                (repo / name).write_text(body, encoding="utf-8")
            raised = False
            try:
                mcpsrv.h_panel_run({"run": "run-20260101-010101",
                                    "context": "NEW REPLACEMENT CONTEXT", "catalog_file": name})
            except mcpsrv.ToolError as e:
                raised = True
                assert "catalog_file" in str(e), (name, e)
            assert raised, f"a confined but unusable catalog_file must be rejected: {name}"
            assert ctx.read_text() == ORIGINAL, \
                f"a rejected ar_panel_run must not overwrite context.md: {name}"
    finally:
        mcpsrv._run_cli = orig
        os.chdir(cwd0)


def t_mcp_catalog_file_size_capped():
    # fix-32 (Codex r3946169157, now enforced in the snapshot path): _snapshot_confined_catalog rejects an
    # oversized REGULAR catalog by SIZE (fstat on the OPEN descriptor) BEFORE copying it, so a crafted
    # multi-gigabyte catalog is never read into a snapshot. A small file passes the size gate and is
    # snapshotted. On base 947241e the symbol is absent -> the test fails there.
    repo = Path(tempfile.mkdtemp(prefix="ar-bigcat-"))
    cwd0 = os.getcwd()
    orig_cap = mcpsrv._CATALOG_MAX_BYTES        # absent on base -> AttributeError -> fails there
    mcpsrv._CATALOG_MAX_BYTES = 128
    os.chdir(repo)
    snap = None
    try:
        (repo / "big.json").write_text("x" * 512, encoding="utf-8")   # regular, over the (test) cap
        raised = False
        try:
            mcpsrv._snapshot_confined_catalog({"catalog_file": "big.json"}, [])
        except mcpsrv.ToolError as e:
            raised = True
            assert "too large" in str(e), e
        assert raised, "an oversized catalog_file must be rejected by size before snapshotting"
        # a small file passes the size gate and is snapshotted (WHERE/WHAT settled here; loadability separate)
        (repo / "small.json").write_text("not a catalog", encoding="utf-8")
        argv = []
        snap = mcpsrv._snapshot_confined_catalog({"catalog_file": "small.json"}, argv)
        assert snap is not None and snap.is_file(), snap
        assert argv == ["--catalog-file", str(snap)], argv
    finally:
        mcpsrv._cleanup_snapshot(snap)
        mcpsrv._CATALOG_MAX_BYTES = orig_cap
        os.chdir(cwd0)


def t_mcp_catalog_snapshot_decouples_from_source():
    # fix-32 / CodeRabbit r3950684588 + Codex r3950590290: _snapshot_confined_catalog copies the validated
    # catalog to a PRIVATE server-owned snapshot OUTSIDE the tree and forwards THAT, so no consumer reopens
    # the caller's path. This closes the check-to-open race AND removes any need to reject a catalog that
    # aliases a run-written file (context.md, sample_policy.json, ...): a later overwrite of the source can
    # never reach the snapshot. Proves (a) the forwarded path is the snapshot, outside the repo; (b) it is a
    # faithful copy; (c) mutating then deleting the source afterward leaves the snapshot intact. Absent-symbol
    # on base 947241e -> fails there.
    repo = Path(tempfile.mkdtemp(prefix="ar-snap-"))
    (repo / "catalogs").mkdir()
    src = repo / "catalogs" / "cat.json"
    src.write_text(json.dumps({"data": [{"id": "openai/gpt-4o"}]}), encoding="utf-8")
    cwd0 = os.getcwd()
    os.chdir(repo)
    snap = None
    try:
        argv = []
        snap = mcpsrv._snapshot_confined_catalog({"catalog_file": "catalogs/cat.json"}, argv)
        # (a) the forwarded path IS the snapshot, and it lives OUTSIDE the repo tree
        assert "--catalog-file" in argv and argv[argv.index("--catalog-file") + 1] == str(snap), argv
        assert repo.resolve() not in snap.resolve().parents, snap
        # (b) faithful copy of the source bytes
        assert json.loads(snap.read_text(encoding="utf-8")) == {"data": [{"id": "openai/gpt-4o"}]}
        # (c) mutating then deleting the source does not touch the snapshot
        src.write_text("{}", encoding="utf-8")
        src.unlink()
        assert json.loads(snap.read_text(encoding="utf-8"))["data"][0]["id"] == "openai/gpt-4o", snap
    finally:
        mcpsrv._cleanup_snapshot(snap)
        os.chdir(cwd0)


def t_mcp_catalog_snapshot_fails_closed_without_o_nofollow():
    # Codex (PR #55) r3952220749: the catalog snapshot's O_NOFOLLOW is LOAD-BEARING, not defense-in-depth --
    # resolve() canonicalizes the path but does NOT pin the leaf across the reopen, so a concurrent swap of
    # the resolved leaf to an out-of-tree symlink is caught only by O_NOFOLLOW. fix-35 made the sibling
    # policy read fail closed when os.O_NOFOLLOW is unavailable, but the catalog snapshot used
    # getattr(os, "O_NOFOLLOW", 0), silently disabling it on a platform without it (Windows). It now FAILS
    # CLOSED (raises) when os.O_NOFOLLOW is absent, matching the policy read. Simulate by removing the attr.
    # On the base getattr(...,0) lets the open proceed and a snapshot is created -> no raise -> fails there.
    if not hasattr(os, "O_NOFOLLOW"):
        return  # platform genuinely lacks it; the removal-simulation below is what exercises the guard
    repo = Path(tempfile.mkdtemp(prefix="ar-cat-nof-"))
    (repo / "catalogs").mkdir()
    (repo / "catalogs" / "cat.json").write_text(
        json.dumps({"data": [{"id": "openai/gpt-4o"}]}), encoding="utf-8")
    cwd0 = os.getcwd()
    os.chdir(repo)
    saved = os.O_NOFOLLOW
    snap = None
    try:
        del os.O_NOFOLLOW
        raised = False
        try:
            snap = mcpsrv._snapshot_confined_catalog({"catalog_file": "catalogs/cat.json"}, [])
        except mcpsrv.ToolError as e:
            raised = True
            assert "O_NOFOLLOW" in str(e), e
        assert raised, "catalog snapshot must fail closed when os.O_NOFOLLOW is unavailable"
    finally:
        os.O_NOFOLLOW = saved
        mcpsrv._cleanup_snapshot(snap)
        os.chdir(cwd0)


def t_mcp_rebuttal_tool_exposed():
    # The rebuttal round is reachable via MCP: keyless prepare (--prepare) and direct HTTP.
    assert "ar_panel_rebuttal" in mcpsrv.TOOLS_BY_NAME
    cap = []
    orig = _patch_run_cli(0, out="ok", capture=cap)
    try:
        mcpsrv.h_panel_rebuttal({})
        assert cap[-1]["argv"][0] == "rebuttal" and "--prepare" not in cap[-1]["argv"], cap
        assert cap[-1]["timeout"] > 300, cap
        mcpsrv.h_panel_rebuttal({"prepare": True})
        assert "--prepare" in cap[-1]["argv"], cap
    finally:
        mcpsrv._run_cli = orig


def t_mcp_authorized_by_must_be_nonempty_string():
    # A non-string authorized_by (bool/number/list) must be rejected, not stringified into a
    # named authorizer that waives a gate / authorizes a degraded panel.
    for tool in ("ar_gate_plan", "ar_gate_record", "ar_panel_assign"):
        args = {"authorized_by": True}
        if tool == "ar_gate_record":
            args.update({"name": "build", "summary": "x"})
        r = mcpsrv.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                           "params": {"name": tool, "arguments": args}})
        res = r["result"]
        assert res["isError"] and "authorized_by must be a non-empty string" \
            in res["content"][0]["text"], (tool, res)


def t_mcp_catalog_file_confined_cross_platform():
    # catalog_file confinement also rejects Windows-absolute paths (drive letter, backslash,
    # UNC) and NUL, not only POSIX-absolute and traversal.
    for bad in ["/etc/passwd", "../x.json", "C:\\catalog.json", "\\\\srv\\share\\c.json",
                "a\\b.json", "cat\x00.json"]:
        r = mcpsrv.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                           "params": {"name": "ar_panel_assign", "arguments": {"catalog_file": bad}}})
        res = r["result"]
        assert res["isError"] and "catalog_file must be a relative path" \
            in res["content"][0]["text"], (bad, res)
    # control: a real in-tree catalog is snapshotted and the SNAPSHOT (not the source) is forwarded to
    # panel.py assign, then removed after the subprocess returns (fix-32).
    repo = Path(tempfile.mkdtemp(prefix="ar-assign-fwd-"))
    (repo / "catalogs").mkdir()
    body = json.dumps({"data": [{"id": "openai/gpt-4o"}]})
    (repo / "catalogs" / "cat.json").write_text(body, encoding="utf-8")
    cap = {}

    def fake(module, argv, timeout=120):
        cap["argv"] = list(argv)
        p = argv[argv.index("--catalog-file") + 1]
        cap["path"] = p
        cap["content"] = Path(p).read_text(encoding="utf-8")   # the snapshot exists during the call
        return (0, "ok", "")
    orig = mcpsrv._run_cli
    mcpsrv._run_cli = fake
    cwd0 = os.getcwd()
    os.chdir(repo)
    try:
        mcpsrv.h_panel_assign({"catalog_file": "catalogs/cat.json"})
        assert "--catalog-file" in cap["argv"], cap
        assert cap["content"] == body, cap                            # snapshot copied the source faithfully
        assert Path(cap["path"]).name.startswith("ar-catalog-"), cap  # a private snapshot, not the source
        assert cap["path"] != str((repo / "catalogs" / "cat.json").resolve()), cap
        assert not Path(cap["path"]).exists(), cap["path"]            # removed after h_panel_assign returned
    finally:
        os.chdir(cwd0)
        mcpsrv._run_cli = orig


def t_mcp_panel_run_forwards_catalog_file():
    # fix-32: ar_panel_run snapshots the confined catalog_file and forwards the SNAPSHOT (so a reviewer
    # substitution resolves from a stable server-owned copy), then removes it after the subprocess. A bad
    # path is still rejected. The catalog must be LOADABLE (it goes through _require_loadable_snapshot), so
    # point it at a real one on disk.
    repo = Path(tempfile.mkdtemp(prefix="ar-panelrun-fwd-"))
    (repo / "catalogs").mkdir()
    body = json.dumps({"data": [{"id": "openai/gpt-4o"}]})
    (repo / "catalogs" / "cat.json").write_text(body, encoding="utf-8")
    cap = {}

    def fake(module, argv, timeout=120):
        cap["argv"] = list(argv)
        p = argv[argv.index("--catalog-file") + 1]
        cap["path"] = p
        cap["content"] = Path(p).read_text(encoding="utf-8")   # snapshot exists during the subprocess call
        return (0, "ok", "")
    orig_cli = mcpsrv._run_cli
    mcpsrv._run_cli = fake
    orig_ctx = mcpsrv._write_context
    mcpsrv._write_context = lambda run_args, ctx: "context.md"
    cwd0 = os.getcwd()
    os.chdir(repo)
    try:
        mcpsrv.h_panel_run({"context": "diff", "catalog_file": "catalogs/cat.json"})
        assert "--catalog-file" in cap["argv"], cap
        assert cap["content"] == body, cap                            # snapshot copied the source
        assert Path(cap["path"]).name.startswith("ar-catalog-"), cap  # a private snapshot, not the source
        assert cap["path"] != str((repo / "catalogs" / "cat.json").resolve()), cap
        assert not Path(cap["path"]).exists(), cap["path"]            # cleaned up after run returned
        try:
            mcpsrv.h_panel_run({"context": "diff", "catalog_file": "C:\\x.json"})
            assert False, "expected ToolError for a Windows-absolute catalog path"
        except mcpsrv.ToolError:
            pass
    finally:
        os.chdir(cwd0)
        mcpsrv._run_cli = orig_cli
        mcpsrv._write_context = orig_ctx


def t_mcp_catalog_file_rejects_symlink_escape():
    # A relative catalog_file that passes the string checks but is a SYMLINK whose target lives
    # outside the tree must still be rejected — resolving it escapes the repo, so it is never opened
    # or snapshotted. A real in-tree file is still accepted (control: snapshotted, snapshot forwarded).
    outside = Path(tempfile.mkdtemp(prefix="ar-outside-"))
    (outside / "secret.json").write_text("{}")
    repo = Path(tempfile.mkdtemp(prefix="ar-repo-"))
    link = repo / "evil.json"
    try:
        link.symlink_to(outside / "secret.json")
    except (OSError, NotImplementedError):
        return  # platform/user without symlink privilege -> nothing to assert here
    cwd0 = os.getcwd()
    os.chdir(repo)
    snap = None
    try:
        argv = []
        raised = False
        try:
            mcpsrv._snapshot_confined_catalog({"catalog_file": "evil.json"}, argv)
        except mcpsrv.ToolError as e:
            raised = True
            assert "escapes the working tree" in str(e), e
        assert raised and argv == [], "symlink-escaping catalog_file must be rejected"
        # control: a real in-tree file is snapshotted; the forwarded path is the private snapshot (outside
        # the repo), not the in-tree source.
        (repo / "ok.json").write_text("{}")
        argv2 = []
        snap = mcpsrv._snapshot_confined_catalog({"catalog_file": "ok.json"}, argv2)
        assert argv2 == ["--catalog-file", str(snap)], argv2
        assert snap.is_file() and repo.resolve() not in snap.resolve().parents, snap
    finally:
        mcpsrv._cleanup_snapshot(snap)
        os.chdir(cwd0)


def t_mcp_catalog_snapshot_survives_symlink_swap():
    # fix-32 / CodeRabbit r3950684588 (supersedes the fix-31 canonical-forwarding regression): the snapshot
    # is copied from a race-safe descriptor, so a symlink swapped at the source to an EXTERNAL target AFTER
    # validation cannot redirect any consumer — they read the snapshot, taken before the swap. An in-tree
    # symlink is a valid source (resolved, then snapshotted). On base 947241e _snapshot_confined_catalog is
    # absent -> this test fails there.
    outside = Path(tempfile.mkdtemp(prefix="ar-toctou-out-"))
    (outside / "secret.json").write_text(json.dumps({"data": [{"id": "external/model"}]}), encoding="utf-8")
    repo = Path(tempfile.mkdtemp(prefix="ar-toctou-repo-"))
    (repo / "catalogs").mkdir()
    (repo / "catalogs" / "real.json").write_text(
        json.dumps({"data": [{"id": "openai/gpt-4o"}]}), encoding="utf-8")
    link = repo / "link.json"
    try:
        link.symlink_to(repo / "catalogs" / "real.json")   # in-tree at validation time
    except (OSError, NotImplementedError):
        return  # no symlink privilege -> nothing to assert
    cwd0 = os.getcwd()
    os.chdir(repo)
    snap = None
    try:
        argv = []
        snap = mcpsrv._snapshot_confined_catalog({"catalog_file": "link.json"}, argv)
        # swap the symlink to point OUTSIDE the tree, simulating the post-validation race
        link.unlink()
        link.symlink_to(outside / "secret.json")
        # the snapshot still holds the IN-TREE bytes; the external target is never read
        got = json.loads(snap.read_text(encoding="utf-8"))
        assert got == {"data": [{"id": "openai/gpt-4o"}]}, got
        assert got != json.loads((outside / "secret.json").read_text(encoding="utf-8"))
    finally:
        mcpsrv._cleanup_snapshot(snap)
        os.chdir(cwd0)


def t_mcp_aggregate_pins_run_against_concurrent_init():
    # h_aggregate must resolve the newest run ONCE and pin --run <id> before invoking
    # aggregate.py, so a concurrent ar_init creating a newer run mid-call cannot make the child
    # aggregate a different run than the one whose freshness is verified here (TOCTOU).
    repo = Path(tempfile.mkdtemp(prefix="ar-agg-toctou-"))
    arroot = repo / ".adversarial-review"
    older = arroot / "run-20260101-010101"
    older.mkdir(parents=True)
    (older / "verdict.json").write_text(
        json.dumps({"verdict": "PASS", "run_id": "run-20260101-010101"}))
    cwd0 = os.getcwd()
    os.chdir(repo)
    cap = []

    def fake(module, argv, timeout=120):
        cap.append({"module": module, "argv": list(argv), "timeout": timeout})
        # simulate a concurrent ar_init creating a NEWER run between resolution and child exec
        newer = arroot / "run-20260101-020202"
        newer.mkdir(parents=True, exist_ok=True)
        (newer / "verdict.json").write_text(
            json.dumps({"verdict": "BLOCKED", "run_id": "run-20260101-020202"}))
        # write a fresh verdict into the PINNED (older) run (h_aggregate moved the prior one aside)
        (older / "verdict.json").write_text(
            json.dumps({"verdict": "FAIL", "run_id": "run-20260101-010101"}))
        return (1, "FAIL", "")

    orig = mcpsrv._run_cli
    mcpsrv._run_cli = fake
    try:
        r = mcpsrv.h_aggregate({})  # no explicit run -> must pin the newest-at-entry (older)
        # --run <id> is pinned (the TOCTOU concern here). The aggregate child's re-entrancy token rides in
        # the ENV now (fix-38), not argv, so argv stays exactly the pinned run.
        assert cap and cap[0]["argv"][:2] == ["--run", "run-20260101-010101"], cap
        assert not r["isError"], r
        assert r["structuredContent"]["run_id"] == "run-20260101-010101", r
        assert r["structuredContent"]["verdict"] == "FAIL", r
    finally:
        mcpsrv._run_cli = orig
        os.chdir(cwd0)


def t_mcp_panel_run_pins_newest_run():
    # With 'run' omitted, the numeric-newest run (run-...-10) must be pinned as --run to the
    # subprocess AND used for context.md, so panel.py's lexicographic newest-sort (which would
    # pick run-...-9) cannot split the context file and the reviewer artifacts across two runs.
    repo = Path(tempfile.mkdtemp(prefix="ar-pin-run-"))
    arroot = repo / ".adversarial-review"
    for name in ("run-20260101-010101-9", "run-20260101-010101-10"):
        (arroot / name).mkdir(parents=True)
    cwd0 = os.getcwd()
    os.chdir(repo)
    cap = []
    orig = _patch_run_cli(0, out="ok", capture=cap)
    try:
        mcpsrv.h_panel_run({"context": "the diff"})
        argv = cap[-1]["argv"]
        assert argv[:3] == ["run", "--run", "run-20260101-010101-10"], argv
        assert (arroot / "run-20260101-010101-10" / "context.md").is_file(), "context in pinned run"
        assert not (arroot / "run-20260101-010101-9" / "context.md").exists(), "not lexicographic run"
    finally:
        mcpsrv._run_cli = orig
        os.chdir(cwd0)


def t_mcp_init_run_id_parsed_from_path_basename():
    # h_init takes the run id from the BASENAME of the path init printed ("initialized <path>"),
    # not the first run-... substring in stdout — an ancestor dir (e.g. AR_RUN_DIR) can itself
    # contain a run-YYYYMMDD-HHMMSS segment that an unanchored search would wrongly return.
    orig = _patch_run_cli(
        0, out="initialized /tmp/run-20000101-000000/runs/run-20260829-120000  (risk=NORMAL)\n")
    try:
        r = mcpsrv.h_init({"risk": "NORMAL", "dev_providers": ["anthropic"],
                           "diff_ref": "main...HEAD"})
        assert r["structuredContent"]["run_id"] == "run-20260829-120000", r
    finally:
        mcpsrv._run_cli = orig


def t_mcp_aggregate_fresh_verdict_independent_of_mtime():
    # Freshness must not depend on mtime changing: on a coarse-mtime filesystem a same-quantum
    # rewrite leaves st_mtime_ns unchanged. h_aggregate moves the old verdict aside and proves
    # freshness by the NEW verdict.json's existence, so an unchanged mtime is still 'fresh'.
    repo = Path(tempfile.mkdtemp(prefix="ar-agg-mtime-"))
    rundir = repo / ".adversarial-review" / "run-20260101-010101"
    rundir.mkdir(parents=True)
    vf = rundir / "verdict.json"
    vf.write_text(json.dumps({"verdict": "PASS", "run_id": "run-20260101-010101"}))
    frozen = vf.stat().st_mtime_ns
    cwd0 = os.getcwd()
    os.chdir(repo)

    def fake(module, argv, timeout=120):
        p = rundir / "verdict.json"
        p.write_text(json.dumps({"verdict": "FAIL", "run_id": "run-20260101-010101"}))
        os.utime(p, ns=(frozen, frozen))  # coarse FS: mtime identical to the prior verdict
        return (1, "FAIL", "")

    orig = mcpsrv._run_cli
    mcpsrv._run_cli = fake
    try:
        r = mcpsrv.h_aggregate({"run": "run-20260101-010101"})
        assert not r["isError"], r
        assert r["structuredContent"]["verdict"] == "FAIL", r
    finally:
        mcpsrv._run_cli = orig
        os.chdir(cwd0)


def t_mcp_aggregate_restores_prior_verdict_on_rejected_write():
    # If aggregate WRITES a new verdict.json but exits with an unrecognized code (rc 3), the
    # result is rejected AND the prior verdict must be restored: the rejected output must not be
    # left active, and the prior must not be stranded in verdict.json.prev.
    repo = Path(tempfile.mkdtemp(prefix="ar-agg-reject-"))
    rundir = repo / ".adversarial-review" / "run-20260101-010101"
    rundir.mkdir(parents=True)
    (rundir / "verdict.json").write_text(
        json.dumps({"verdict": "PASS", "run_id": "run-20260101-010101"}))
    cwd0 = os.getcwd()
    os.chdir(repo)

    def fake(module, argv, timeout=120):
        # aggregate writes a NEW (to-be-rejected) verdict but exits with an unrecognized code
        (rundir / "verdict.json").write_text(json.dumps({"verdict": "PASS", "run_id": "REJECTED"}))
        return (3, "", "boom: unrecognized exit")

    orig = mcpsrv._run_cli
    mcpsrv._run_cli = fake
    try:
        r = mcpsrv.h_aggregate({"run": "run-20260101-010101"})
        assert r["isError"] and "without an accepted verdict" in r["content"][0]["text"], r
        restored = json.loads((rundir / "verdict.json").read_text())
        assert restored["run_id"] == "run-20260101-010101" and restored["verdict"] == "PASS", restored
        assert not (rundir / "verdict.json.prev").exists(), "prior verdict must not be stranded in .prev"
    finally:
        mcpsrv._run_cli = orig
        os.chdir(cwd0)


def t_mcp_aggregate_refuses_symlink_swapped_prev_stash():
    # Codex (PR #55) r3952220753: a concurrent process with write access to the untrusted run dir can replace
    # the PREDICTABLE .prev with a symlink AFTER h_aggregate's move-aside but before the settle. os.replace
    # renames the link itself, so it would PROMOTE that symlink to verdict.json and ar_get_verdict would then
    # follow it OUT of the run dir (Codex reproduced reading an external file's secret). The settle now
    # refuses to promote a symlinked stash (lstat) and never leaves verdict.json a symlink. Simulate the swap
    # inside the _run_cli stub (which runs AFTER the move-aside), then reject: verdict.json must NOT become a
    # symlink and must not carry the external content. On the base the symlink is promoted -> verdict.json is
    # a symlink to the external file -> this fails there.
    repo = Path(tempfile.mkdtemp(prefix="ar-agg-prevswap-"))
    rundir = repo / ".adversarial-review" / "run-20260101-010101"
    rundir.mkdir(parents=True)
    (rundir / "verdict.json").write_text(
        json.dumps({"verdict": "PASS", "run_id": "run-20260101-010101"}))
    external = repo / "external-secret.json"
    external.write_text(json.dumps(
        {"verdict": "PASS", "run_id": "run-20260101-010101", "secret": "leaked"}), encoding="utf-8")
    cwd0 = os.getcwd()
    os.chdir(repo)
    swapped = {"ok": False}

    def fake(module, argv, timeout=120):
        # runs after the move-aside: verdict.json has been renamed to .prev. Swap .prev -> symlink to external.
        prev = rundir / "verdict.json.prev"
        try:
            if prev.is_file():
                prev.unlink()
            prev.symlink_to(external)
            swapped["ok"] = True
        except (OSError, NotImplementedError):
            pass
        return (3, "", "boom: rejected")   # rejected -> settle tries to restore from the (swapped) .prev

    orig = mcpsrv._run_cli
    mcpsrv._run_cli = fake
    try:
        # The settle refuses to promote the swapped symlink and fails closed. Because the rejected aggregate
        # ALSO cannot restore the prior (the attacker destroyed it), h_aggregate surfaces that as a ToolError
        # (never silently) -- expected here. On the base it instead promotes the symlink and returns without
        # raising, leaving verdict.json a symlink (caught by the assertion below).
        try:
            mcpsrv.h_aggregate({"run": "run-20260101-010101"})
        except mcpsrv.ToolError:
            pass
    finally:
        mcpsrv._run_cli = orig
        os.chdir(cwd0)
    if not swapped["ok"]:
        return  # platform without symlink support; nothing to assert
    vf = rundir / "verdict.json"
    assert not vf.is_symlink(), "settle must never leave verdict.json as a symlink to an external file"
    if vf.exists():
        assert "leaked" not in vf.read_text(encoding="utf-8"), "verdict.json must not carry external content"


def t_mcp_aggregate_surfaces_failed_prior_restore():
    # If the run is rejected and restoring the prior from .prev FAILS (a transient OSError — a
    # Windows lock, a vanished parent), the failure must be SURFACED, not swallowed: otherwise the
    # accepted prior is stranded at .prev while ar_get_verdict sees no or a rejected verdict, with no
    # signal. h_aggregate raises ToolError (-> isError at the server) naming .prev so the stranded
    # prior can be recovered, AND the prior is never lost. (Codex, 13d473f.)
    repo = Path(tempfile.mkdtemp(prefix="ar-agg-restorefail-"))
    rundir = repo / ".adversarial-review" / "run-20260101-010101"
    rundir.mkdir(parents=True)
    prior = {"verdict": "PASS", "run_id": "run-20260101-010101"}
    (rundir / "verdict.json").write_text(json.dumps(prior))
    cwd0 = os.getcwd()
    os.chdir(repo)

    def fake(module, argv, timeout=120):
        # h_aggregate has already moved the prior aside to verdict.json.prev. Simulate aggregate by
        # replacing verdict.json with a DIRECTORY: it is not a fresh FILE (so the run is rejected),
        # and the settle step's stash.replace(verdict.json) then raises OSError (renaming .prev onto
        # a directory -> IsADirectoryError). rc 0 proves even a PASS-looking exit is rejected once no
        # fresh verdict FILE exists. This deterministically forces the restore to fail.
        (rundir / "verdict.json").mkdir()
        return (0, "", "")

    orig = mcpsrv._run_cli
    mcpsrv._run_cli = fake
    raised = False
    try:
        try:
            mcpsrv.h_aggregate({"run": "run-20260101-010101"})
        except mcpsrv.ToolError as e:
            raised = True
            assert ".prev" in str(e) and "could not be restored" in str(e), str(e)
    finally:
        mcpsrv._run_cli = orig
        os.chdir(cwd0)
    assert raised, "h_aggregate must SURFACE (ToolError) a failed prior-verdict restore, not swallow it"
    # The prior must still be recoverable at .prev — never lost, even though the restore failed.
    assert json.loads((rundir / "verdict.json.prev").read_text()) == prior, "prior must survive at .prev"


def t_mcp_run_selection_ignores_non_minted_dirs():
    # Implicit newest-run selection must ignore directories that are not minted run ids, so a
    # stray 'run-zombie' (which sorts lexicographically after a real run) cannot hijack selection
    # and pin an invalid --run on every subprocess.
    repo = Path(tempfile.mkdtemp(prefix="ar-runsel-"))
    arroot = repo / ".adversarial-review"
    (arroot / "run-20260101-010101").mkdir(parents=True)
    (arroot / "run-zombie").mkdir(parents=True)
    cwd0 = os.getcwd()
    os.chdir(repo)
    try:
        assert mcpsrv._run_dir([]).name == "run-20260101-010101", mcpsrv._run_dir([]).name
        assert mcpsrv._safe_run({}) == ["--run", "run-20260101-010101"], mcpsrv._safe_run({})
    finally:
        os.chdir(cwd0)


def t_mcp_aggregate_removes_rejected_output_when_no_prior_verdict():
    # With NO prior verdict.json (stash is None), if aggregate writes a verdict but exits with an
    # unrecognized code (rc 3), that rejected output must be REMOVED — never left active on disk.
    repo = Path(tempfile.mkdtemp(prefix="ar-agg-noprior-"))
    rundir = repo / ".adversarial-review" / "run-20260101-010101"
    rundir.mkdir(parents=True)  # deliberately no verdict.json — no prior verdict
    cwd0 = os.getcwd()
    os.chdir(repo)

    def fake(module, argv, timeout=120):
        (rundir / "verdict.json").write_text(json.dumps({"verdict": "PASS", "run_id": "REJECTED"}))
        return (3, "", "boom: unrecognized exit")

    orig = mcpsrv._run_cli
    mcpsrv._run_cli = fake
    try:
        r = mcpsrv.h_aggregate({"run": "run-20260101-010101"})
        assert r["isError"] and "without an accepted verdict" in r["content"][0]["text"], r
        assert not (rundir / "verdict.json").exists(), "rejected verdict must be removed when no prior existed"
    finally:
        mcpsrv._run_cli = orig
        os.chdir(cwd0)


def t_mcp_init_run_id_parsed_from_path_with_spaces():
    # A run path containing a space (a Windows "C:\\Users\\Jane Doe\\..." checkout, or a spaced
    # AR_RUN_DIR) must still parse. \S+ truncated it at the first space, so an otherwise-successful
    # init returned run_id=null; the parse now captures the full path up to the "  (risk=" suffix.
    orig = _patch_run_cli(
        0, out="initialized /tmp/review runs/.adversarial-review/run-20260830-131400  (risk=NORMAL)\n")
    try:
        r = mcpsrv.h_init({"risk": "NORMAL", "dev_providers": ["anthropic"],
                           "diff_ref": "main...HEAD"})
        assert r["structuredContent"]["run_id"] == "run-20260830-131400", r
    finally:
        mcpsrv._run_cli = orig


def t_mcp_aggregate_restores_prior_verdict_when_invocation_raises():
    # If the aggregate INVOCATION raises (e.g. _run_cli's 120s subprocess timeout -> ToolError) after
    # the prior verdict was moved aside, the prior must be restored — not stranded in
    # verdict.json.prev — and the error must propagate, so ar_get_verdict keeps returning the last
    # accepted verdict.
    repo = Path(tempfile.mkdtemp(prefix="ar-agg-raise-"))
    rundir = repo / ".adversarial-review" / "run-20260101-010101"
    rundir.mkdir(parents=True)
    (rundir / "verdict.json").write_text(
        json.dumps({"verdict": "PASS", "run_id": "run-20260101-010101"}))
    cwd0 = os.getcwd()
    os.chdir(repo)

    def fake(module, argv, timeout=120):
        raise mcpsrv.ToolError("aggregate timed out after 120s")

    orig = mcpsrv._run_cli
    mcpsrv._run_cli = fake
    try:
        raised = False
        try:
            mcpsrv.h_aggregate({"run": "run-20260101-010101"})
        except mcpsrv.ToolError:
            raised = True
        assert raised, "a raised aggregate invocation must propagate as ToolError"
        restored = json.loads((rundir / "verdict.json").read_text())
        assert restored["run_id"] == "run-20260101-010101" and restored["verdict"] == "PASS", restored
        assert not (rundir / "verdict.json.prev").exists(), "prior verdict must not be stranded in .prev"
    finally:
        mcpsrv._run_cli = orig
        os.chdir(cwd0)


def t_mcp_instructions_include_rebuttal_step():
    # A host that follows _INSTRUCTIONS verbatim must be told to run ar_panel_rebuttal before
    # ar_aggregate; omitting it deterministically BLOCKs runs whose rebuttal policy requires it.
    instr = mcpsrv._INSTRUCTIONS
    assert "ar_panel_rebuttal" in instr, instr
    assert instr.index("ar_panel_rebuttal") < instr.index("ar_aggregate"), instr
    # server/discover advertises the same instructions
    assert mcpsrv._discover_result()["instructions"] == instr


def t_mcp_aggregate_stash_invariant_across_exit_paths():
    # Broader invariant over the WHOLE h_aggregate stash/restore path: after h_aggregate returns OR
    # raises, verdict.json holds either the freshly accepted verdict (success) or the prior verdict
    # (any rejection/raise), and verdict.json.prev is NEVER left on disk. Exercising the full matrix
    # {prior, no-prior} x {accept, reject, raise} means every past AND future variant of the
    # "some exit path forgot to reconcile the stash" bug lives in one cell of this test.
    PRIOR = {"verdict": "PASS", "run_id": "run-20260101-010101"}
    for has_prior in (True, False):
        for outcome in ("accept", "reject", "raise"):
            repo = Path(tempfile.mkdtemp(prefix="ar-agg-inv-"))
            rundir = repo / ".adversarial-review" / "run-20260101-010101"
            rundir.mkdir(parents=True)
            vf = rundir / "verdict.json"
            if has_prior:
                vf.write_text(json.dumps(PRIOR))
            cwd0 = os.getcwd()
            os.chdir(repo)

            def fake(module, argv, timeout=120, _o=outcome, _vf=vf):
                if _o == "raise":
                    raise mcpsrv.ToolError("aggregate timed out after 120s")
                # accept and reject both WRITE a fresh verdict.json; only the exit code differs
                _vf.write_text(json.dumps(
                    {"verdict": "FAIL", "run_id": "run-20260101-010101"} if _o == "accept"
                    else {"verdict": "PASS", "run_id": "REJECTED"}))
                return (1, "FAIL", "") if _o == "accept" else (3, "", "boom")

            orig = mcpsrv._run_cli
            mcpsrv._run_cli = fake
            try:
                raised = False
                r = None
                try:
                    r = mcpsrv.h_aggregate({"run": "run-20260101-010101"})
                except mcpsrv.ToolError:
                    raised = True
                case = (has_prior, outcome)
                assert not (rundir / "verdict.json.prev").exists(), (case, "stray .prev")
                if outcome == "accept":
                    assert not raised and not r["isError"], (case, r)
                    assert json.loads(vf.read_text())["run_id"] == "run-20260101-010101", case
                elif outcome == "reject":
                    assert not raised and r["isError"], (case, r)
                    if has_prior:
                        assert json.loads(vf.read_text()) == PRIOR, (case, "prior not restored")
                    else:
                        assert not vf.exists(), (case, "rejected output not removed")
                else:  # raise
                    assert raised, (case, "must propagate")
                    if has_prior:
                        assert json.loads(vf.read_text()) == PRIOR, (case, "prior not restored")
                    else:
                        assert not vf.exists(), (case, "no verdict should exist")
            finally:
                mcpsrv._run_cli = orig
                os.chdir(cwd0)


def t_mcp_aggregate_preserves_prior_when_stash_move_fails():
    # The stash-FAILED cell the invariant test can't reach: when verdict.json -> .prev raises OSError
    # (here .prev is a directory), h_aggregate falls back to mtime tracking with stash=None and the
    # prior verdict LEFT IN PLACE at vf. A rejected exit or a raised invocation must NOT delete that
    # untouched prior — there is no stash to restore it, so ar_get_verdict would lose the last
    # accepted verdict.
    PRIOR = {"verdict": "PASS", "run_id": "run-20260101-010101"}
    for outcome in ("reject", "raise"):
        repo = Path(tempfile.mkdtemp(prefix="ar-agg-nostash-"))
        rundir = repo / ".adversarial-review" / "run-20260101-010101"
        rundir.mkdir(parents=True)
        vf = rundir / "verdict.json"
        vf.write_text(json.dumps(PRIOR))
        (rundir / "verdict.json.prev").mkdir()  # force vf.replace(.prev) to raise OSError
        cwd0 = os.getcwd()
        os.chdir(repo)

        def fake(module, argv, timeout=120, _o=outcome):
            if _o == "raise":
                raise mcpsrv.ToolError("aggregate timed out after 120s")
            return (3, "", "boom")  # rejected WITHOUT writing verdict.json — prior stays untouched

        orig = mcpsrv._run_cli
        mcpsrv._run_cli = fake
        try:
            raised = False
            try:
                mcpsrv.h_aggregate({"run": "run-20260101-010101"})
            except mcpsrv.ToolError:
                raised = True
            assert raised == (outcome == "raise"), (outcome, raised)
            assert vf.is_file(), (outcome, "prior verdict must survive a failed stash move")
            assert json.loads(vf.read_text()) == PRIOR, (outcome, "prior verdict must be intact")
        finally:
            mcpsrv._run_cli = orig
            os.chdir(cwd0)


def t_mcp_aggregate_restores_prior_over_same_mtime_rejected_overwrite():
    # Coarse-mtime-filesystem trap in the stash-FAILED fallback: aggregate overwrites verdict.json
    # with a REJECTED verdict, but the new mtime lands in the same quantum as the prior (unchanged
    # st_mtime_ns). An mtime check would treat that rejected output as the untouched prior and let
    # ar_get_verdict surface it. The restore must snapshot the prior's BYTES and rewrite them.
    repo = Path(tempfile.mkdtemp(prefix="ar-agg-samemtime-"))
    rundir = repo / ".adversarial-review" / "run-20260101-010101"
    rundir.mkdir(parents=True)
    vf = rundir / "verdict.json"
    PRIOR = {"verdict": "PASS", "run_id": "run-20260101-010101"}
    vf.write_text(json.dumps(PRIOR))
    prior_mtime_ns = vf.stat().st_mtime_ns
    (rundir / "verdict.json.prev").mkdir()  # force vf.replace(.prev) to raise OSError -> fallback
    cwd0 = os.getcwd()
    os.chdir(repo)

    def fake(module, argv, timeout=120):
        # aggregate overwrites with a rejected verdict, then the mtime lands unchanged (coarse FS)
        vf.write_text(json.dumps({"verdict": "PASS", "run_id": "REJECTED"}))
        os.utime(vf, ns=(prior_mtime_ns, prior_mtime_ns))
        return (3, "", "boom")

    orig = mcpsrv._run_cli
    mcpsrv._run_cli = fake
    try:
        r = mcpsrv.h_aggregate({"run": "run-20260101-010101"})
        assert r["isError"], r
        restored = json.loads(vf.read_text())
        assert restored == PRIOR, ("rejected output with an unchanged mtime must not survive", restored)
    finally:
        mcpsrv._run_cli = orig
        os.chdir(cwd0)


def t_mcp_check_digest_missing_run_is_error_not_drift():
    # A nonexistent/typo'd run makes aggregate.py's resolve_run die() with exit 1 — the SAME code
    # --check-digest uses for a real attestation MISMATCH. Reporting "no run to verify" as
    # {"intact": false} (drift) would flag a typo as tampering. h_check_digest must raise ToolError
    # (-> isError, no structuredContent at the server), never a silent drift. (Fable, 60cb2c3.)
    repo = Path(tempfile.mkdtemp(prefix="ar-cd-missing-"))
    (repo / ".adversarial-review").mkdir(parents=True)   # root exists, but holds no runs
    cwd0 = os.getcwd()
    os.chdir(repo)
    try:
        for args in ({"run": "run-20990909-090909"}, {}):  # explicit typo, then implicit-newest, no runs
            raised = False
            try:
                mcpsrv.h_check_digest(args)
            except mcpsrv.ToolError:
                raised = True
            assert raised, ("missing run must raise ToolError, not return a drift verdict", args)
    finally:
        os.chdir(cwd0)


def t_mcp_inprocess_helpers_resolve_under_console_script():
    # mcp_server's in-process helpers do `from panel import ...` / `from _common import ...`. Under the
    # documented `ar-mcp` console script the package imports as adversarial_review.mcp_server, where
    # those BARE imports resolve ONLY if mcp_server puts its own dir on sys.path (as panel.py /
    # aggregate.py do). Without it, catalog validation always fails and policy `high_samples` is
    # silently ignored (timeout under-budgeted). Emulate the console-script sys.path in a subprocess
    # and assert the policy value is honored. (Fable, 60cb2c3.)
    site = Path(tempfile.mkdtemp(prefix="ar-site-")) / "adversarial_review"
    site.mkdir(parents=True)
    scripts = Path(mcpsrv.__file__).resolve().parent
    for py in scripts.glob("*.py"):
        (site / py.name).write_bytes(py.read_bytes())
    work = Path(tempfile.mkdtemp(prefix="ar-work-"))
    (work / ".adversarial-review.yml").write_text("risk: SENSITIVE\nhigh_samples: 7\n")
    env = {**os.environ, "PYTHONPATH": str(site.parent)}
    env.pop("AR_HIGH_SAMPLES", None)   # so policy (not env) drives the value
    r = subprocess.run(
        [sys.executable, "-c",
         "from adversarial_review import mcp_server as m; print(m._resolved_high_samples())"],
        cwd=str(work), env=env, capture_output=True, text=True)
    assert r.returncode == 0, (r.stdout, r.stderr)
    assert r.stdout.strip() == "7", ("policy high_samples must be honored under the console script",
                                     r.stdout, r.stderr)


def t_mcp_aggregate_fallback_snapshot_is_durable_before_aggregation():
    # CodeRabbit(60cb2c3): when verdict.json cannot be moved aside to .prev, the prior was kept ONLY
    # in memory; if aggregate then overwrote verdict.json and the in-memory rewrite ALSO failed, the
    # prior was lost — and the error misnamed .prev, never created in that path. The fallback must
    # persist a DURABLE snapshot (verdict.json.bak) BEFORE aggregating, restore from it, and name it.
    repo = Path(tempfile.mkdtemp(prefix="ar-agg-durablebak-"))
    rundir = repo / ".adversarial-review" / "run-20260101-010101"
    rundir.mkdir(parents=True)
    vf = rundir / "verdict.json"
    prior = {"verdict": "PASS", "run_id": "run-20260101-010101"}
    vf.write_text(json.dumps(prior))
    cwd0 = os.getcwd()
    os.chdir(repo)

    RB = type(vf)
    orig_replace = RB.replace

    def blocked_move(self, target):            # rename-hostile FS: the .prev move fails, but a fresh
        if str(target).endswith(".prev"):      # write (the .bak backup) still succeeds
            raise OSError("simulated: cannot rename verdict.json -> .prev")
        return orig_replace(self, target)

    def fake(module, argv, timeout=120):
        # aggregate leaves verdict.json as a DIRECTORY: not a fresh FILE (rejected) AND the write-back
        # restore (vf.write_bytes) then fails, forcing the reconcile-failure path. The fallback now removes
        # the original after snapshotting to .bak (freshness by existence, Codex r3942166702), so
        # verdict.json may already be gone here — create the directory either way.
        p = rundir / "verdict.json"
        if p.is_file():
            p.unlink()
        p.mkdir()
        return (0, "", "")

    orig_cli = mcpsrv._run_cli
    RB.replace = blocked_move
    mcpsrv._run_cli = fake
    raised = False
    try:
        try:
            mcpsrv.h_aggregate({"run": "run-20260101-010101"})
        except mcpsrv.ToolError as e:
            raised = True
            assert ".bak" in str(e) and "could not be restored" in str(e), str(e)
    finally:
        RB.replace = orig_replace
        mcpsrv._run_cli = orig_cli
        os.chdir(cwd0)
    assert raised, "h_aggregate must SURFACE a failed fallback restore, not swallow it"
    # THE durability guarantee: the prior survives on disk at verdict.json.bak (in memory alone it
    # would be gone once aggregate overwrote verdict.json). Fails on base (no .bak written).
    bak = rundir / "verdict.json.bak"
    assert bak.is_file() and json.loads(bak.read_text()) == prior, "prior must be durable at .bak"


def t_mcp_aggregate_surfaces_restore_failure_during_unwind():
    # Codex(60cb2c3): when _run_cli RAISES (e.g. a subprocess timeout) AND restoring the prior also
    # fails, the settle step must not drop the restore failure — a client told only "aggregate timed
    # out" would never learn its accepted verdict is stranded and ar_get_verdict can no longer return
    # it. The restore failure is folded INTO the in-flight ToolError, and the prior survives at .prev.
    repo = Path(tempfile.mkdtemp(prefix="ar-agg-unwind-"))
    rundir = repo / ".adversarial-review" / "run-20260101-010101"
    rundir.mkdir(parents=True)
    prior = {"verdict": "PASS", "run_id": "run-20260101-010101"}
    (rundir / "verdict.json").write_text(json.dumps(prior))
    cwd0 = os.getcwd()
    os.chdir(repo)

    def fake(module, argv, timeout=120):
        # h_aggregate moved the prior aside to .prev. Replace verdict.json with a DIRECTORY so the
        # settle step's stash.replace(verdict.json) raises, THEN raise like a subprocess timeout so the
        # restore failure must be reconciled WHILE that exception unwinds.
        (rundir / "verdict.json").mkdir()
        raise mcpsrv.ToolError("aggregate timed out after 120s")

    orig = mcpsrv._run_cli
    mcpsrv._run_cli = fake
    raised = False
    try:
        try:
            mcpsrv.h_aggregate({"run": "run-20260101-010101"})
        except mcpsrv.ToolError as e:
            raised = True
            msg = str(e)
            assert "timed out" in msg, msg                                  # original error preserved
            assert "could not be restored" in msg and ".prev" in msg, msg   # restore failure surfaced
    finally:
        mcpsrv._run_cli = orig
        os.chdir(cwd0)
    assert raised, "h_aggregate must surface (not swallow) a restore failure during an unwind"
    # The prior is never lost — it survives at .prev.
    assert json.loads((rundir / "verdict.json.prev").read_text()) == prior, "prior must survive at .prev"


def t_check_digest_deeply_nested_verdict_is_cannot_verify():
    # Codex(60cb2c3): a valid but pathologically deep verdict.json makes json.loads raise
    # RecursionError (NOT ValueError), which escaped check_digest's (OSError, ValueError) guard —
    # aggregate.py --check-digest then crashed with exit 1, which the MCP wrapper maps to
    # {"intact": false}, misreporting a parser failure as tampering. It must be cannot-verify (exit 2).
    repo = Path(tempfile.mkdtemp(prefix="ar-cd-deep-"))
    run = repo / ".adversarial-review" / "run-20260101-010101"
    run.mkdir(parents=True)
    (run / "verdict.json").write_text("[" * 100000 + "]" * 100000)  # deep nesting -> RecursionError
    r = sh(["aggregate.py", "--check-digest", "--run", "run-20260101-010101"], repo, expect=2)
    assert "cannot read verdict.json" in (r.stdout + r.stderr), (r.stdout, r.stderr)


def t_attestation_recursionerror_artifact_is_raw_hashed_not_crash():
    # Codex(60cb2c3): a recorded .json artifact nested deeply enough to raise RecursionError in
    # json.loads must be hashed over its RAW bytes (like bad-UTF8 / bad-JSON), never crash
    # compute_attestation — so aggregation and --check-digest both stay robust and a legitimately deep
    # but unchanged artifact remains verifiable.
    import aggregate as agg
    run = Path(tempfile.mkdtemp(prefix="ar-att-deep-")) / "run"
    run.mkdir(parents=True)
    (run / "plan.json").write_text("[" * 100000 + "]" * 100000)  # deep artifact
    att = agg.compute_attestation(run)                           # must NOT raise RecursionError
    assert att["files"].get("plan.json", "").startswith("raw:"), att["files"]


def t_mcp_run_dir_rejects_trailing_newline_dir_name():
    # Codex(fc4a701): RUN_RE used `$`, which matches just before a trailing newline, so RUN_RE.match
    # admitted a directory named "run-…\n". iterdir() is untrusted repo content; a crafted
    # run-99999999-999999\n dir sorts newest and would pin every tool to that non-minted directory.
    # RUN_RE now anchors with \Z, so _run_dir selects only genuinely-minted names.
    repo = Path(tempfile.mkdtemp(prefix="ar-nlrun-"))
    arroot = repo / ".adversarial-review"
    (arroot / "run-20260101-010101").mkdir(parents=True)
    try:
        (arroot / "run-99999999-999999\n").mkdir()  # trailing-newline decoy (POSIX allows newlines)
    except OSError:
        return  # platform disallows a newline in a filename (Windows) -> nothing to assert here
    cwd0 = os.getcwd()
    os.chdir(repo)
    try:
        assert mcpsrv._run_dir([]).name == "run-20260101-010101", mcpsrv._run_dir([]).name
        assert mcpsrv._safe_run({}) == ["--run", "run-20260101-010101"], mcpsrv._safe_run({})
    finally:
        os.chdir(cwd0)


def t_mcp_require_loadable_catalog_rejects_fifo():
    # Codex(fc4a701), now enforced in the snapshot path: a catalog_file that is a FIFO must be rejected
    # WITHOUT blocking. _snapshot_confined_catalog opens the resolved path O_NONBLOCK (so the FIFO open
    # returns immediately instead of waiting for a writer) and fstat-rejects a non-regular file before any
    # read. Run in a SUBPROCESS with a timeout so a regression that blocks is caught as a failure, not a
    # hung suite.
    if not hasattr(os, "mkfifo"):
        return  # no FIFOs on this platform (Windows) -> nothing to assert here
    repo = Path(tempfile.mkdtemp(prefix="ar-fifo-"))
    os.mkfifo(repo / "catalog.json")
    script = (
        "import sys; sys.path.insert(0, %r); import mcp_server as m\n"
        "try:\n"
        "    m._snapshot_confined_catalog({'catalog_file': 'catalog.json'}, []); print('NO_RAISE')\n"
        "except m.ToolError as e:\n"
        "    print('REJECTED' if 'regular file' in str(e) else 'OTHER:' + str(e))\n"
        % str(SKILL / "scripts"))
    try:
        r = subprocess.run([sys.executable, "-c", script], cwd=str(repo),
                           capture_output=True, text=True, timeout=8)
    except subprocess.TimeoutExpired:
        raise AssertionError("_snapshot_confined_catalog hung on a FIFO catalog_file — it must open "
                             "non-blocking and reject a non-regular file before reading it")
    assert "REJECTED" in r.stdout, (r.stdout, r.stderr)


def t_mcp_opt_authorizer_strips_whitespace():
    # Fable(fc4a701): a valid authorized_by must not carry incidental surrounding whitespace into the
    # audit record; _opt_authorizer now strips it. (None / empty / non-string is still rejected.)
    assert mcpsrv._opt_authorizer({"authorized_by": "  alice  "}) == "alice"
    assert mcpsrv._opt_authorizer({"authorized_by": "bob"}) == "bob"
    assert mcpsrv._opt_authorizer({}) is None


def t_mcp_init_errors_when_run_id_unparseable_rather_than_guessing():
    # Codex(9b93b4c): a SUCCESSFUL ar_init whose stdout can't be parsed for the run id must NOT guess it
    # from a directory scan — a concurrent init would make _run_dir([]) return a DIFFERENT caller's run,
    # a valid-looking WRONG id. It surfaces a tool error instead, even with a decoy newest run present.
    repo = Path(tempfile.mkdtemp(prefix="ar-init-unparseable-"))
    (repo / ".adversarial-review" / "run-29990101-010101").mkdir(parents=True)  # decoy "newest" run
    cwd0 = os.getcwd()
    os.chdir(repo)

    def fake(module, argv, timeout=120):
        return (0, "some unparseable init output without the expected line", "")

    orig = mcpsrv._run_cli
    mcpsrv._run_cli = fake
    try:
        r = mcpsrv.h_init({"risk": "NORMAL", "dev_providers": ["anthropic"]})
        assert r["isError"], r                                        # not a success with a guessed id
        assert "could not be parsed" in r["content"][0]["text"], r
        assert r.get("structuredContent", {}).get("run_id") != "run-29990101-010101", r
    finally:
        mcpsrv._run_cli = orig
        os.chdir(cwd0)


def t_mcp_init_error_names_actual_run_root():
    # CodeRabbit(274b460): when init succeeds but its stdout can't be parsed for the run id, the
    # recovery hint must name the ACTUAL run root — AR_RUN_DIR when set — not the hardcoded
    # .adversarial-review default, which would send the operator to an empty directory. Fails on
    # 274b460 (message hardcodes .adversarial-review/).
    repo = Path(tempfile.mkdtemp(prefix="ar-init-root-"))
    cwd0 = os.getcwd()
    os.chdir(repo)
    custom = "custom-run-root"
    orig_cli = mcpsrv._run_cli
    orig_env = os.environ.get("AR_RUN_DIR")

    def fake(module, argv, timeout=120):
        return (0, "some init output with no parseable initialized line", "")   # rc 0, unparseable

    mcpsrv._run_cli = fake
    os.environ["AR_RUN_DIR"] = custom
    try:
        r = mcpsrv.h_init({"risk": "NORMAL", "dev_providers": ["anthropic"]})
        assert r["isError"], r
        text = r["content"][0]["text"]
        assert custom in text, text                     # names the ACTUAL (AR_RUN_DIR) root
        assert ".adversarial-review" not in text, text  # not the hardcoded default
    finally:
        mcpsrv._run_cli = orig_cli
        if orig_env is None:
            os.environ.pop("AR_RUN_DIR", None)
        else:
            os.environ["AR_RUN_DIR"] = orig_env
        os.chdir(cwd0)


def t_mcp_aggregate_refuses_when_no_run_exists():
    # CodeRabbit merge-risk (9b93b4c): ar_aggregate invoked with no run and none at entry must NOT
    # invoke aggregate.py unpinned — an unpinned aggregate resolves the newest run ITSELF, so a run a
    # concurrent external init creates in the meantime would be aggregated and its verdict.json mutated
    # by this call. h_aggregate refuses (call ar_init first) and never shells out.
    repo = Path(tempfile.mkdtemp(prefix="ar-agg-norun-"))
    (repo / ".adversarial-review").mkdir(parents=True)  # exists but holds NO runs -> _safe_run({}) == []
    cwd0 = os.getcwd()
    os.chdir(repo)
    called = []

    def fake(module, argv, timeout=120):
        called.append((module, list(argv)))
        return (0, "", "")

    orig = mcpsrv._run_cli
    mcpsrv._run_cli = fake
    raised = False
    try:
        try:
            mcpsrv.h_aggregate({})  # run omitted; none at entry -> run_args == []
        except mcpsrv.ToolError as e:
            raised = True
            assert "call ar_init first" in str(e), str(e)
    finally:
        mcpsrv._run_cli = orig
        os.chdir(cwd0)
    assert raised, "h_aggregate must refuse (ToolError) when no run exists"
    assert called == [], "aggregate.py must NOT be invoked when there is no run to aggregate"


def t_mcp_aggregate_stranded_prev_not_auto_promoted():
    # PR #55 fix-25 (CodeRabbit r3942141283 / Codex r3942166700): recovery is FAIL-CLOSED. When verdict.json
    # is absent and a verdict is stranded at verdict.json.prev, ar_aggregate must NOT adopt/promote it -- a
    # rejected retry leaves verdict.json absent (RECOVERY_PENDING), and the .prev is left intact for an
    # explicit, gated recovery. fix-24 adopted the .prev and promoted it on a rejected retry; because the run
    # dir is attacker-writable and its input-digest is freely recomputable, that surfaced un-vetted bytes as
    # a verdict. Fails on e67c330 (fix-24), which restores the .prev to verdict.json.
    repo = _complete_sensitive_repo()
    run = latest_run(repo)
    write(run / "validation" / "idor.json", {
        "finding_ids": ["security-1"], "classification": "confirmed", "severity": "high",
        "evidence": "reproduced", "reproduced": True, "regression_test": "t",
        "resolution": {"fixed": True, "gates_rerun": ["unit"]}})
    sh(["aggregate.py"], repo, expect=0)                        # mint a genuine verdict.json (with attestation)
    (run / "verdict.json").rename(run / "verdict.json.prev")    # crash-stranded: aside-move done, settle never ran
    cwd0 = os.getcwd()
    os.chdir(repo)

    def fake(module, argv, timeout=120):
        return (3, "", "boom")  # rejected WITHOUT writing a fresh verdict.json

    orig = mcpsrv._run_cli
    mcpsrv._run_cli = fake
    try:
        r = mcpsrv.h_aggregate({"run": run.name})
        assert r["isError"], r
    finally:
        mcpsrv._run_cli = orig
        os.chdir(cwd0)
    # Fail-closed: the stranded sidecar is NOT promoted; verdict.json stays absent and .prev is left intact.
    assert not (run / "verdict.json").exists(), "stranded .prev must NOT be auto-promoted on a rejected retry"
    assert (run / "verdict.json.prev").is_file(), "the stranded .prev must be left intact for gated recovery"
    # ar_get_verdict reports RECOVERY_PENDING rather than returning the un-vetted sidecar as a verdict
    # (run resolution is relative to cwd, so this check runs from inside the repo).
    os.chdir(repo)
    try:
        mcpsrv.h_get_verdict({"run": run.name})
        assert False, "ar_get_verdict must not return a stranded sidecar as a verdict"
    except mcpsrv.ToolError as e:
        assert "recovery sidecar" in str(e), str(e)
    finally:
        os.chdir(cwd0)


def t_mcp_aggregate_rejection_states_reason():
    # Fable(fc4a701): a rejected aggregate now names WHY (stale / malformed / unrecognized / wrong-run),
    # not just "without an accepted verdict". Here aggregate writes a fresh but UNRECOGNIZED verdict.
    repo = Path(tempfile.mkdtemp(prefix="ar-agg-reason-"))
    rundir = repo / ".adversarial-review" / "run-20260101-010101"
    rundir.mkdir(parents=True)
    (rundir / "verdict.json").write_text(json.dumps({"verdict": "PASS", "run_id": "run-20260101-010101"}))
    cwd0 = os.getcwd()
    os.chdir(repo)

    def fake(module, argv, timeout=120):
        (rundir / "verdict.json").write_text(json.dumps({"verdict": "MAYBE", "run_id": "run-20260101-010101"}))
        return (0, "", "")

    orig = mcpsrv._run_cli
    mcpsrv._run_cli = fake
    try:
        r = mcpsrv.h_aggregate({"run": "run-20260101-010101"})
        assert r["isError"], r
        assert "unrecognized verdict value" in r["content"][0]["text"], r["content"][0]["text"]
    finally:
        mcpsrv._run_cli = orig
        os.chdir(cwd0)


def t_mcp_aggregate_refuses_ambiguous_prev_sidecar():
    # Codex(274b460): a verdict.json.prev FILE present alongside verdict.json is AMBIGUOUS — it is
    # EITHER a crash-mid-settle (the .prev is the last accepted verdict and verdict.json the crashed
    # output) OR a SUCCESSFUL aggregate whose best-effort .prev cleanup failed (verdict.json is the
    # NEWER accepted verdict and .prev is obsolete). fix-16 assumed the former and restored .prev on a
    # rejected re-aggregate — which, in the latter case, ROLLS a newer accepted verdict BACK to an
    # older one (a newer FAIL reverted to an older PASS). Refuse instead: never guess, never roll
    # back, never touch the run. This supersedes fix-16's preserve-and-track of an existing .prev, and
    # still keeps a crash-stranded good .prev intact (it is never overwritten). Fails on 274b460 (which
    # restores the older .prev over the newer verdict and does not refuse).
    repo = Path(tempfile.mkdtemp(prefix="ar-agg-ambigprev-"))
    rundir = repo / ".adversarial-review" / "run-20260101-010101"
    rundir.mkdir(parents=True)
    newer = {"verdict": "FAIL", "run_id": "run-20260101-010101"}    # current accepted verdict
    older = {"verdict": "PASS", "run_id": "run-20260101-010101"}    # obsolete .prev from a failed cleanup
    (rundir / "verdict.json").write_text(json.dumps(newer))
    (rundir / "verdict.json.prev").write_text(json.dumps(older))
    cwd0 = os.getcwd()
    os.chdir(repo)

    called = []

    def fake(module, argv, timeout=120):
        called.append(list(argv))
        return (3, "", "boom")

    orig = mcpsrv._run_cli
    mcpsrv._run_cli = fake
    raised = False
    try:
        try:
            mcpsrv.h_aggregate({"run": "run-20260101-010101"})
        except mcpsrv.ToolError as e:
            raised = True
            assert "recovery sidecar" in str(e) and "ambiguous" in str(e), str(e)
    finally:
        mcpsrv._run_cli = orig
        os.chdir(cwd0)
    assert raised, "must refuse (ToolError) when a .prev sidecar is present alongside verdict.json"
    assert called == [], "must refuse BEFORE invoking aggregate — never touch the run"
    # neither file is rolled back or lost: the newer accepted verdict stays, the obsolete .prev is left
    # for the operator (fix-16 would have restored the older .prev over the newer verdict).
    assert json.loads((rundir / "verdict.json").read_text()) == newer, "newer verdict must not be rolled back"
    assert json.loads((rundir / "verdict.json.prev").read_text()) == older, ".prev must be left intact"


def t_mcp_aggregate_refuses_and_preserves_existing_bak():
    # Codex(274b460): the rename-fallback used to blindly overwrite verdict.json.bak. If a PRIOR
    # fallback had already written a good .bak and then crashed (leaving verdict.json as the crashed
    # output), a second fallback overwrote that good .bak with the crashed bytes, and a rejected
    # aggregate then restored them — destroying the last accepted verdict. The refuse-guard now stops
    # at entry when a .bak FILE is present, so the good backup is never touched. Fails on 274b460
    # (which overwrites .bak with the crashed bytes and then unlinks it on restore).
    repo = Path(tempfile.mkdtemp(prefix="ar-agg-existingbak-"))
    rundir = repo / ".adversarial-review" / "run-20260101-010101"
    rundir.mkdir(parents=True)
    good = {"verdict": "PASS", "run_id": "run-20260101-010101"}
    (rundir / "verdict.json").write_text("{ crashed/partial output")   # crashed run's output
    (rundir / "verdict.json.bak").write_text(json.dumps(good))         # last accepted, from a prior fallback
    (rundir / "verdict.json.prev").mkdir()                             # a prior fallback's blocking .prev dir
    cwd0 = os.getcwd()
    os.chdir(repo)

    called = []

    def fake(module, argv, timeout=120):
        called.append(list(argv))
        return (3, "", "boom")

    orig = mcpsrv._run_cli
    mcpsrv._run_cli = fake
    raised = False
    try:
        try:
            mcpsrv.h_aggregate({"run": "run-20260101-010101"})
        except mcpsrv.ToolError:
            raised = True
    finally:
        mcpsrv._run_cli = orig
        os.chdir(cwd0)
    assert raised, "must refuse (ToolError) when a .bak sidecar is present"
    assert called == [], "must refuse BEFORE invoking aggregate"
    # the good backup is never overwritten or unlinked — the last accepted verdict survives at .bak
    bak = rundir / "verdict.json.bak"
    assert bak.is_file() and json.loads(bak.read_text()) == good, "existing good .bak must be preserved"


def t_mcp_aggregate_rejects_symlinked_prev_recovery():
    # Codex P1 r3930666147 (fix-21) + CodeRabbit r3941598640 (fix-22): the crash-recovery path handles a
    # stranded verdict.json.prev when verdict.json is ABSENT. `is_file()` FOLLOWS symlinks, so a .prev that
    # is a SYMLINK into an untrusted run dir would be adopted as the stash and then moved to verdict.json by
    # the settle -- after which ar_get_verdict follows it and returns an arbitrary external file. fix-21
    # stopped ADOPTING a symlinked .prev; fix-22 makes this branch REFUSE a symlinked sidecar outright (as
    # the entry guard already does), so the vector is surfaced rather than silently ignored, aggregate is
    # never invoked, and the symlink is never followed/moved. Fails on the pre-fix (fix-21) source, which
    # does NOT refuse (it proceeds to aggregate with no stash) -- so `raised`/`called==[]` fail there.
    secret_dir = Path(tempfile.mkdtemp(prefix="ar-secret-"))
    secret = secret_dir / "secret.txt"
    secret.write_text("TOP-SECRET out-of-run contents")
    repo = Path(tempfile.mkdtemp(prefix="ar-agg-symprev-"))
    rundir = repo / ".adversarial-review" / "run-20260101-010101"
    rundir.mkdir(parents=True)
    cand = rundir / "verdict.json.prev"
    try:
        cand.symlink_to(secret)                  # stranded .prev is a SYMLINK -> out-of-run secret
    except (OSError, NotImplementedError):
        return  # platform/user without symlink privilege -> nothing to assert here
    # verdict.json is ABSENT -> the crash-recovery branch is taken
    cwd0 = os.getcwd()
    os.chdir(repo)
    called = []

    def fake(module, argv, timeout=120):
        called.append(list(argv))
        return (3, "", "boom")

    orig = mcpsrv._run_cli
    mcpsrv._run_cli = fake
    raised = False
    try:
        try:
            mcpsrv.h_aggregate({"run": "run-20260101-010101"})
        except mcpsrv.ToolError as e:
            raised = True
            assert "symlink" in str(e), str(e)
    finally:
        mcpsrv._run_cli = orig
        os.chdir(cwd0)
    assert raised, "a symlinked .prev with absent verdict.json must be REFUSED (ToolError)"
    assert called == [], "must refuse BEFORE invoking aggregate"
    vj = rundir / "verdict.json"
    # the symlinked .prev must NEVER be adopted/exposed via verdict.json (arbitrary-read vector)
    assert not (vj.exists() and vj.read_text() == secret.read_text()), \
        "symlinked .prev was adopted and exposed an out-of-run file via verdict.json"
    assert cand.is_symlink(), "the symlinked .prev must be left untouched, not adopted as the stash"


def t_mcp_aggregate_stranded_bak_not_promoted_but_superseded_on_success():
    # PR #55 fix-25 (CodeRabbit r3942141283 / Codex r3942166700): recovery is FAIL-CLOSED for a .bak too.
    # When verdict.json is absent and a verdict is stranded at verdict.json.bak (the rename-fallback path),
    # ar_aggregate must NOT promote it on a rejected retry (fix-24 restored it -> un-vetted bytes surfaced as
    # a verdict), and it must SUPERSEDE it on a successful retry (so a stranded .bak is not left for the entry
    # guard to trip over next call). Part (1) fails on e67c330 (fix-24), which restores the .bak to verdict.json.
    def _mint_and_strand_bak():
        repo = _complete_sensitive_repo()
        run = latest_run(repo)
        write(run / "validation" / "idor.json", {
            "finding_ids": ["security-1"], "classification": "confirmed", "severity": "high",
            "evidence": "reproduced", "reproduced": True, "regression_test": "t",
            "resolution": {"fixed": True, "gates_rerun": ["unit"]}})
        sh(["aggregate.py"], repo, expect=0)                    # genuine verdict.json (with attestation)
        (run / "verdict.json").rename(run / "verdict.json.bak")  # durable .bak stranded; verdict.json ABSENT
        return repo, run

    orig = mcpsrv._run_cli
    cwd0 = os.getcwd()

    # (1) rejected retry -> the stranded .bak is NOT promoted; verdict.json stays absent (RECOVERY_PENDING)
    repo, run = _mint_and_strand_bak()
    os.chdir(repo)

    def reject(module, argv, timeout=120):
        return (3, "", "boom")   # rejected WITHOUT writing a fresh verdict.json

    mcpsrv._run_cli = reject
    try:
        r = mcpsrv.h_aggregate({"run": run.name})
        assert r["isError"], r
    finally:
        mcpsrv._run_cli = orig
        os.chdir(cwd0)
    assert not (run / "verdict.json").exists(), "stranded .bak must NOT be auto-promoted on a rejected retry"
    assert (run / "verdict.json.bak").is_file(), "the stranded .bak must be left intact for gated recovery"

    # (2) successful retry -> a fresh verdict is written and the stranded .bak is superseded (cleaned up)
    repo2, run2 = _mint_and_strand_bak()
    os.chdir(repo2)

    def fresh(module, argv, timeout=120):
        write(run2 / "verdict.json", {"verdict": "FAIL", "run_id": run2.name})
        return (1, "FAIL", "")

    mcpsrv._run_cli = fresh
    try:
        r2 = mcpsrv.h_aggregate({"run": run2.name})
        assert not r2.get("isError") and r2["structuredContent"]["verdict"] == "FAIL", r2
    finally:
        mcpsrv._run_cli = orig
        os.chdir(cwd0)
    assert not (run2 / "verdict.json.bak").exists(), "successful retry must supersede the stranded .bak"


def t_mcp_aggregate_refuses_ambiguous_prev_and_bak_when_absent():
    # CodeRabbit r3941598640: when verdict.json is ABSENT and BOTH a regular verdict.json.prev and a
    # regular verdict.json.bak are present, which holds the last accepted verdict is ambiguous -- adopting
    # one could restore a stale verdict over a newer one -- so h_aggregate must REFUSE (as the entry guard
    # does), never invoke aggregate, and leave both sidecars intact. Fails on the pre-fix source (fix-21),
    # which adopts .prev, ignores .bak, and proceeds to aggregate (no refusal).
    repo = Path(tempfile.mkdtemp(prefix="ar-agg-ambigbak-"))
    rundir = repo / ".adversarial-review" / "run-20260101-010101"
    rundir.mkdir(parents=True)
    aprev = {"verdict": "PASS", "run_id": "run-20260101-010101"}
    abak = {"verdict": "FAIL", "run_id": "run-20260101-010101"}
    (rundir / "verdict.json.prev").write_text(json.dumps(aprev))
    (rundir / "verdict.json.bak").write_text(json.dumps(abak))     # both present; verdict.json ABSENT
    cwd0 = os.getcwd()
    os.chdir(repo)
    called = []

    def fake(module, argv, timeout=120):
        called.append(list(argv))
        return (3, "", "boom")

    orig = mcpsrv._run_cli
    mcpsrv._run_cli = fake
    raised = False
    try:
        try:
            mcpsrv.h_aggregate({"run": "run-20260101-010101"})
        except mcpsrv.ToolError as e:
            raised = True
            assert "ambiguous" in str(e), str(e)
    finally:
        mcpsrv._run_cli = orig
        os.chdir(cwd0)
    assert raised, "both .prev and .bak present with absent verdict.json must be refused (ToolError)"
    assert called == [], "must refuse BEFORE invoking aggregate"
    assert json.loads((rundir / "verdict.json.prev").read_text()) == aprev, ".prev must be left intact"
    assert json.loads((rundir / "verdict.json.bak").read_text()) == abak, ".bak must be left intact"


def t_check_digest_unrecognized_algorithm_id_matching_digest_is_cannot_verify():
    # Codex r3941637877: the algorithm-id whitelist must run BEFORE the digest-equality check. A verdict
    # whose attestation.algorithm was changed to an unrecognized value but whose digest still equals the
    # recompute (only the id changed) must be cannot-verify (exit 2) -- this version cannot interpret that
    # representation -- NOT "attestation OK" (exit 0). Fails on the pre-fix source (fix-21), where the
    # digest-match exit-0 runs first and reports OK before the id is validated.
    repo = _complete_sensitive_repo()
    run = latest_run(repo)
    write(run / "validation" / "idor.json", {
        "finding_ids": ["security-1"], "classification": "confirmed",
        "severity": "high", "evidence": "reproduced", "reproduced": True,
        "regression_test": "t", "resolution": {"fixed": True, "gates_rerun": ["unit"]}})
    sh(["aggregate.py"], repo, expect=0)
    base = read(run / "verdict.json")
    assert base["attestation"]["algorithm"] == "sha256-canonical-json-v2", base["attestation"]["algorithm"]
    # Change ONLY the algorithm id (unknown string, then malformed non-string); leave files + digest exactly
    # as written so the recompute still equals the stored digest -- the digest-match path would exit 0.
    for algo in ("sha256-canonical-json-v3", 2):
        base["attestation"]["algorithm"] = algo
        (run / "verdict.json").write_text(json.dumps(base))
        r = sh(["aggregate.py", "--check-digest"], repo, expect=2)
        blob = r.stdout + r.stderr
        assert "CANNOT BE VERIFIED" in blob, blob
        assert "attestation OK" not in r.stdout, \
            "an unrecognized algorithm id must be cannot-verify even when the digest matches"


def t_mcp_aggregate_rejects_exit_code_verdict_mismatch():
    # Codex r3941637886: aggregate.py maps verdict->exit code (PASS=0/FAIL=1/BLOCKED=2) and writes
    # verdict.json BEFORE the human-readable verdict.md; a crash AFTER that write (e.g. verdict.md is a
    # directory) exits nonzero with a fresh, well-formed PASS verdict.json on disk. h_aggregate must REJECT
    # when the exit code does not match the written verdict -- not return isError:false with a PASS carrying
    # a traceback. Fails on the pre-fix source (fix-21), which accepts any rc in {0,1,2}.
    repo = Path(tempfile.mkdtemp(prefix="ar-agg-rcmismatch-"))
    rundir = repo / ".adversarial-review" / "run-20260101-010101"
    rundir.mkdir(parents=True)
    cwd0 = os.getcwd()
    os.chdir(repo)

    def crash_after_pass(module, argv, timeout=120):
        (rundir / "verdict.json").write_text(                       # fresh, well-formed PASS verdict.json
            json.dumps({"verdict": "PASS", "run_id": "run-20260101-010101"}))
        return (1, "PASS", "Traceback (most recent call last): IsADirectoryError")  # but exit 1 (post-write crash)

    orig = mcpsrv._run_cli
    mcpsrv._run_cli = crash_after_pass
    try:
        r = mcpsrv.h_aggregate({"run": "run-20260101-010101"})
    finally:
        mcpsrv._run_cli = orig
        os.chdir(cwd0)
    assert r["isError"], "a PASS verdict.json with exit 1 (crash after write) must be rejected, not accepted"
    assert "does not match" in r["content"][0]["text"], r["content"][0]["text"]


def t_mcp_aggregate_refuses_dangling_bak_symlink():
    # Codex P1 r3930666146: the entry guard refuses when a recovery sidecar is present next to an existing
    # verdict.json, but used only `is_file()` -- which is False for a DANGLING symlink (target absent). A
    # verdict.json.bak that is a dangling symlink therefore slipped past the guard, and the durable-snapshot
    # write below would follow it and CREATE the attacker-chosen target out-of-run. The guard now also trips
    # on `is_symlink()` (an lstat, which catches a dangling link too) and refuses BEFORE invoking aggregate.
    # Fails on the pre-fix source, which does not refuse (is_file() is False for the dangling link).
    target_dir = Path(tempfile.mkdtemp(prefix="ar-bak-target-"))
    target = target_dir / "attacker-chosen.json"     # does NOT exist -> the .bak symlink is dangling
    repo = Path(tempfile.mkdtemp(prefix="ar-agg-danglingbak-"))
    rundir = repo / ".adversarial-review" / "run-20260101-010101"
    rundir.mkdir(parents=True)
    (rundir / "verdict.json").write_text(
        json.dumps({"verdict": "PASS", "run_id": "run-20260101-010101"}))
    cand_bak = rundir / "verdict.json.bak"
    try:
        cand_bak.symlink_to(target)              # DANGLING: target does not exist
    except (OSError, NotImplementedError):
        return  # platform/user without symlink privilege -> nothing to assert here
    assert cand_bak.is_symlink() and not cand_bak.is_file(), "precondition: .bak is a dangling symlink"
    cwd0 = os.getcwd()
    os.chdir(repo)
    called = []

    def fake(module, argv, timeout=120):
        called.append(list(argv))
        return (0, "PASS", "")

    orig = mcpsrv._run_cli
    mcpsrv._run_cli = fake
    raised = False
    try:
        try:
            mcpsrv.h_aggregate({"run": "run-20260101-010101"})
        except mcpsrv.ToolError as e:
            raised = True
            assert "recovery sidecar" in str(e) and "symlink" in str(e), str(e)
    finally:
        mcpsrv._run_cli = orig
        os.chdir(cwd0)
    assert raised, "must refuse (ToolError) when a dangling .bak symlink is present"
    assert called == [], "must refuse BEFORE invoking aggregate -- never follow/create through the symlink"
    assert not target.exists(), "the dangling symlink's target must never be created (write-through vector)"


def t_aggregate_post_write_crash_exits_3():
    # CodeRabbit (PR #55) r3941710394: aggregate.py writes verdict.json BEFORE verdict.md, so an uncaught
    # exception AFTER that write must exit 3 -- a code OUTSIDE the verdict set {0,1,2} -- rather than Python's
    # default 1, which is identical to FAIL. Force the post-write crash by making verdict.md a directory (the
    # markdown write raises IsADirectoryError); verdict.json (FAIL) is still written first. Fails on the base
    # commit, where the uncaught-exception exit is 1.
    repo = _complete_sensitive_repo()
    sh(["gate.py", "record", "--name", "unit", "--exit-code", "1", "--summary", "boom"], repo)
    run = latest_run(repo)
    (run / "verdict.md").mkdir()                     # the post-verdict.json markdown write will raise
    sh(["aggregate.py"], repo, expect=3)             # uncaught error -> exit 3 (base: 1, == FAIL)
    v = read(run / "verdict.json")                   # verdict.json was written BEFORE the crash ...
    assert v["verdict"] == "FAIL", v                 # ... and it is the FAIL the base would exit 1 for


def t_mcp_aggregate_rejects_post_write_fail_crash():
    # CodeRabbit (PR #55) r3941710394: the fix-22 exit-code/verdict match is necessary but not sufficient --
    # a crash after writing a FAIL verdict.json exits 1, which EQUALS verdict_exit["FAIL"], so h_aggregate
    # accepted a crashed FAIL as a completed verdict. With aggregate.py now exiting 3 on an uncaught error,
    # h_aggregate (running the REAL aggregate via _run_cli, not a mock) REJECTS it. Fails on the base commit,
    # where the real aggregate exits 1 and the crashed FAIL is accepted.
    repo = _complete_sensitive_repo()
    sh(["gate.py", "record", "--name", "unit", "--exit-code", "1", "--summary", "boom"], repo)
    run = latest_run(repo)
    (run / "verdict.md").mkdir()                     # post-verdict.json markdown write raises -> aggregate crash
    cwd0 = os.getcwd()
    os.chdir(repo)
    try:
        r = mcpsrv.h_aggregate({"run": run.name})    # real aggregate via _run_cli (NOT mocked)
    finally:
        os.chdir(cwd0)
    assert r.get("isError"), ("a crash after writing a FAIL verdict.json must be rejected, not accepted", r)
    assert "exited 3" in r["content"][0]["text"], r["content"][0]["text"]


def t_mcp_aggregate_refuses_fifo_bak_sidecar():
    # Codex (PR #55) r3941758239 + CodeRabbit r3941991607: with verdict.json present, .prev a DIRECTORY (so
    # the move-aside rename fails), and .bak a FIFO, the rename-fallback's write_bytes() opened the FIFO and
    # BLOCKED forever waiting for a reader. The backup is now created with os.open O_CREAT|O_EXCL|O_WRONLY,
    # which FAILS (FileExistsError -> ToolError "already exists") on ANY pre-existing path — a FIFO included —
    # without opening or blocking on it, and closes the earlier lstat TOCTOU. Run in a daemon thread with a
    # join timeout so a full regression (raw write_bytes) fails FAST here instead of hanging the suite.
    if not hasattr(os, "mkfifo"):
        return  # POSIX-only (CI is Linux); no FIFO on this platform
    import threading
    repo = Path(tempfile.mkdtemp(prefix="ar-agg-fifobak-"))
    rundir = repo / ".adversarial-review" / "run-20260101-010101"
    rundir.mkdir(parents=True)
    (rundir / "verdict.json").write_text(json.dumps({"verdict": "PASS", "run_id": "run-20260101-010101"}))
    (rundir / "verdict.json.prev").mkdir()           # .prev is a directory -> vf.replace(.prev) fails
    os.mkfifo(str(rundir / "verdict.json.bak"))      # .bak is a FIFO -> write_bytes would block forever
    cwd0 = os.getcwd()
    os.chdir(repo)
    called = []

    def fake(module, argv, timeout=120):
        called.append(list(argv))
        return (3, "", "boom")

    out = {}

    def call():
        try:
            mcpsrv.h_aggregate({"run": "run-20260101-010101"})
            out["ret"] = True
        except mcpsrv.ToolError as e:
            out["err"] = str(e)
        except BaseException as e:  # pragma: no cover
            out["other"] = repr(e)

    orig = mcpsrv._run_cli
    mcpsrv._run_cli = fake
    th = threading.Thread(target=call, daemon=True)
    th.start()
    th.join(10)   # the fixed handler raises in ms; only a regression (the blocking write) reaches the timeout
    try:
        assert not th.is_alive(), \
            "h_aggregate blocked on a FIFO .bak (regression: no O_EXCL guard before writing the backup)"
        assert "err" in out and "already exists" in out["err"], out
        assert called == [], "must refuse BEFORE invoking aggregate"
    finally:
        mcpsrv._run_cli = orig
        os.chdir(cwd0)


def t_mcp_aggregate_forged_stranded_sidecar_never_promoted():
    # PR #55 fix-25 (CodeRabbit r3942141283 / Codex r3942166700): the ACTUAL forgery fix-24 missed. fix-24
    # adopted a stranded sidecar when its attestation DIGEST re-verified -- but compute_attestation() hashes
    # the run's PUBLIC *.json artifacts (all attacker-writable) and never binds the verdict VALUE, so an
    # attacker recomputes the correct digest and flips the verdict. Here the forged .prev reuses the genuine
    # (recomputable) attestation and flips the decision to PASS -- exactly the sidecar fix-24's digest check
    # accepts. Recovery is now fail-closed: a stranded sidecar is NEVER promoted by ar_aggregate. Fails on
    # e67c330 (fix-24), which adopts the forged PASS and promotes it to verdict.json on the rejected retry.
    repo = _complete_sensitive_repo()
    run = latest_run(repo)
    write(run / "validation" / "idor.json", {
        "finding_ids": ["security-1"], "classification": "confirmed", "severity": "high",
        "evidence": "reproduced", "reproduced": True, "regression_test": "t",
        "resolution": {"fixed": True, "gates_rerun": ["unit"]}})
    sh(["aggregate.py"], repo, expect=0)                        # mint a genuine verdict WITH a real attestation
    genuine = read(run / "verdict.json")
    # Reuse the genuine attestation (its digest recomputes from the unchanged *.json artifacts -- removing
    # verdict.json and adding a non-*.json .prev does not change it), but FLIP the decision to PASS.
    forged = {**genuine, "verdict": "PASS", "forged_marker": True}
    (run / "verdict.json").unlink()
    (run / "verdict.json.prev").write_text(json.dumps(forged))   # planted; verdict.json ABSENT
    cwd0 = os.getcwd()
    os.chdir(repo)

    def fake(module, argv, timeout=120):
        return (3, "", "boom")   # rejected retry -> fix-24 PROMOTES the forged .prev; fix-25 does not

    orig = mcpsrv._run_cli
    mcpsrv._run_cli = fake
    try:
        r = mcpsrv.h_aggregate({"run": run.name})
        assert r["isError"], r
    finally:
        mcpsrv._run_cli = orig
        os.chdir(cwd0)
    vj = run / "verdict.json"
    assert not vj.exists(), "a stranded forged sidecar must NEVER be promoted to verdict.json (fail-closed)"
    # and ar_get_verdict never surfaces it as a verdict (run resolution is relative to cwd)
    os.chdir(repo)
    try:
        mcpsrv.h_get_verdict({"run": run.name})
        assert False, "ar_get_verdict must not return the forged sidecar"
    except mcpsrv.ToolError as e:
        assert "recovery sidecar" in str(e), str(e)
    finally:
        os.chdir(cwd0)


def t_mcp_aggregate_fallback_freshness_is_mtime_independent():
    # PR #55 fix-25 (Codex r3942166702): in the rename-FALLBACK path (the .prev move failed, so the prior is
    # snapshotted to .bak), fix-24 proved a fresh verdict by comparing st_mtime_ns. A coarse-granularity
    # filesystem can leave the mtime UNCHANGED on a same-quantum rewrite, so a genuinely fresh verdict is
    # mislabeled stale and rolled back to .bak. fix-25 removes the original after snapshotting, so freshness
    # is by EXISTENCE (mtime-independent). This forces the coarse-FS case by writing the fresh verdict with
    # the prior's exact mtime; fails on e67c330 (rejects the fresh verdict, rolls back to the prior).
    repo = Path(tempfile.mkdtemp(prefix="ar-agg-mtime-"))
    rundir = repo / ".adversarial-review" / "run-20260101-010101"
    rundir.mkdir(parents=True)
    vf = rundir / "verdict.json"
    vf.write_text(json.dumps({"verdict": "PASS", "run_id": "run-20260101-010101"}))
    prior_mtime = vf.stat().st_mtime_ns
    cwd0 = os.getcwd()
    os.chdir(repo)

    RB = type(vf)
    orig_replace = RB.replace

    def blocked_move(self, target):            # force the rename-fallback: the .prev move fails, .bak succeeds
        if str(target).endswith(".prev"):
            raise OSError("simulated: cannot rename verdict.json -> .prev")
        return orig_replace(self, target)

    def fake(module, argv, timeout=120):
        # a genuine FRESH verdict, but written within the SAME coarse mtime quantum as the prior
        p = rundir / "verdict.json"
        p.write_text(json.dumps({"verdict": "FAIL", "run_id": "run-20260101-010101"}))
        os.utime(p, ns=(prior_mtime, prior_mtime))
        return (1, "FAIL", "")

    orig_cli = mcpsrv._run_cli
    RB.replace = blocked_move
    mcpsrv._run_cli = fake
    try:
        r = mcpsrv.h_aggregate({"run": "run-20260101-010101"})
    finally:
        RB.replace = orig_replace
        mcpsrv._run_cli = orig_cli
        os.chdir(cwd0)
    assert not r.get("isError"), ("a fresh verdict in the same mtime quantum must be ACCEPTED, not rolled back", r)
    assert r["structuredContent"]["verdict"] == "FAIL", r
    assert json.loads(vf.read_text())["verdict"] == "FAIL", "the fresh verdict must be on disk, not the prior"


def t_mcp_aggregate_aborts_when_prior_verdict_cannot_be_unlinked():
    # PR #55 fix-29 (Codex r3945727346): in the rename-FALLBACK path (the .prev move failed, so the prior is
    # snapshotted to .bak), fix-25 removes the original so freshness is proven by EXISTENCE. If that unlink
    # ALSO fails — e.g. a Windows handle that shares writes but not deletes — the code swallowed the error and
    # fell back to the mtime check, which a coarse-granularity filesystem defeats: a fresh FAIL rewritten in
    # the prior's mtime quantum is mislabeled stale and ROLLED BACK to the prior PASS. h_aggregate now fails
    # closed — it refuses (ToolError) before running aggregate, leaving verdict.json intact and no .bak
    # stranded. Fails on e51160c (the except swallowed the unlink error; aggregate ran and the fresh FAIL was
    # rolled back to PASS, isError with verdict.json restored to PASS — no ToolError raised).
    repo = Path(tempfile.mkdtemp(prefix="ar-agg-unlinkfail-"))
    rundir = repo / ".adversarial-review" / "run-20260101-010101"
    rundir.mkdir(parents=True)
    vf = rundir / "verdict.json"
    vf.write_text(json.dumps({"verdict": "PASS", "run_id": "run-20260101-010101"}))
    prior_mtime = vf.stat().st_mtime_ns
    cwd0 = os.getcwd()
    os.chdir(repo)

    RB = type(vf)
    orig_replace = RB.replace
    orig_unlink = RB.unlink

    def blocked_move(self, target):            # force the rename-fallback: the .prev move fails, .bak succeeds
        if str(target).endswith(".prev"):
            raise OSError("simulated: cannot rename verdict.json -> .prev")
        return orig_replace(self, target)

    def blocked_unlink(self, *a, **k):         # the prior verdict.json shares writes but not deletes
        if self.name == "verdict.json":
            raise OSError("simulated: cannot unlink verdict.json")
        return orig_unlink(self, *a, **k)

    def fake(module, argv, timeout=120):
        # a genuine FRESH verdict, written in the SAME coarse mtime quantum as the prior (the rollback trap)
        p = rundir / "verdict.json"
        p.write_text(json.dumps({"verdict": "FAIL", "run_id": "run-20260101-010101"}))
        os.utime(p, ns=(prior_mtime, prior_mtime))
        return (1, "FAIL", "")

    orig_cli = mcpsrv._run_cli
    RB.replace = blocked_move
    RB.unlink = blocked_unlink
    mcpsrv._run_cli = fake
    raised = None
    try:
        try:
            mcpsrv.h_aggregate({"run": "run-20260101-010101"})
        except mcpsrv.ToolError as e:
            raised = e
    finally:
        RB.replace = orig_replace
        RB.unlink = orig_unlink
        mcpsrv._run_cli = orig_cli
        os.chdir(cwd0)
    assert raised is not None, "h_aggregate must FAIL CLOSED (ToolError) when the prior verdict cannot be unlinked"
    assert "refusing to aggregate" in str(raised) or "rolled back" in str(raised), str(raised)
    # the prior verdict.json is left intact (never rolled back to a stale value) and no .bak is stranded
    assert json.loads(vf.read_text())["verdict"] == "PASS", "prior verdict.json must be left intact on the abort"
    assert not (rundir / "verdict.json.bak").exists(), "the redundant .bak must be cleaned up on the fail-closed abort"


def t_aggregate_console_entry_crash_exits_3():
    # Codex (PR #55) r3942035551: the post-write-crash exit-3 mapping must apply to the INSTALLED console
    # entry (ar-aggregate = adversarial_review.aggregate:main), which calls main() directly and never runs
    # the __main__ block. Invoke main() the way the console script does (not via __main__) with a run whose
    # verdict.md is a directory, and assert exit 3. Fails on base 2d8cfe3, where the wrapper lived in
    # __main__ so the callable entry exits 1.
    repo = _complete_sensitive_repo()
    sh(["gate.py", "record", "--name", "unit", "--exit-code", "1", "--summary", "boom"], repo)
    run = latest_run(repo)
    (run / "verdict.md").mkdir()                                # post-verdict.json markdown write raises
    code = ("import sys; sys.path.insert(0, %r); import aggregate; "
            "sys.argv = ['aggregate', '--run', %r]; aggregate.main()"
            % (str(SKILL / "scripts"), str(run)))
    r = subprocess.run([sys.executable, "-c", code], cwd=str(repo), capture_output=True, text=True)
    assert r.returncode == 3, (r.returncode, r.stderr[-300:])
    assert (run / "verdict.json").is_file(), "verdict.json must have been written before the crash"


def t_mcp_rebuttal_tool_description_covers_any_policy():
    # Codex (PR #55) r3942035552: the ar_panel_rebuttal tool description said rebuttal is required only for
    # SENSITIVE/CRITICAL runs, but a NORMAL run with rebuttal_policy=any and high/critical findings also
    # requires it -- MCP hosts relying on the metadata would skip it and hit an avoidable BLOCKED. The
    # description now frames the requirement by policy (critical / contention / any), explicitly incl. NORMAL.
    tl = mcpsrv.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    reb = next(t for t in tl["result"]["tools"] if t["name"] == "ar_panel_rebuttal")
    desc = reb["description"]
    assert "any" in desc and "NORMAL" in desc and "contention" in desc, desc
    assert "SENSITIVE/CRITICAL run" not in desc, desc   # the old, misleading phrasing is gone


def t_check_digest_unrecognized_algorithm_id_is_cannot_verify():
    # CodeRabbit r3930631485: --check-digest must validate the stored `algorithm` id BEFORE any legacy
    # handling. Only the current sha256-canonical-json-v2 and recognized predecessors (...-v1) are
    # interpretable; a NEWER, unknown, or malformed (non-string) id means this version cannot interpret the
    # representation, so a digest mismatch is cannot-verify (exit 2) -- never the legacy canonical->raw path
    # and never DRIFT (exit 1). Fails on the pre-fix source, which had no id whitelist: an unknown id whose
    # drift is not a canonical->raw transition fell through to DRIFT (exit 1).
    repo = _complete_sensitive_repo()
    run = latest_run(repo)
    write(run / "validation" / "idor.json", {                       # triage the high finding -> PASS
        "finding_ids": ["security-1"], "classification": "confirmed",
        "severity": "high", "evidence": "reproduced", "reproduced": True,
        "regression_test": "t", "resolution": {"fixed": True, "gates_rerun": ["unit"]}})
    sh(["aggregate.py"], repo, expect=0)
    v = read(run / "verdict.json")
    att = v["attestation"]
    assert att["algorithm"] == "sha256-canonical-json-v2", att["algorithm"]
    some = sorted(att["files"])[0]                                  # any recorded artifact
    assert not att["files"][some].startswith("raw:"), \
        "the tampered file's recompute must be a PLAIN hash so the drift is not a canonical->raw transition"

    def forge(algo):
        files = dict(att["files"])
        files[some] = "b" * 64                                     # a PLAIN (non-"raw:") modification -> drift
        forged = dict(att); forged["files"] = files; forged["algorithm"] = algo
        manifest = "\n".join(f"{sha}  {rel}" for rel, sha in sorted(files.items()))
        forged["digest"] = hashlib.sha256(manifest.encode("utf-8")).hexdigest()
        doc = dict(v); doc["attestation"] = forged
        (run / "verdict.json").write_text(json.dumps(doc))

    # (a) a NEWER/unknown string id this version does not know
    forge("sha256-canonical-json-v3")
    r = sh(["aggregate.py", "--check-digest"], repo, expect=2)
    blob = r.stdout + r.stderr
    assert "CANNOT BE VERIFIED" in blob, blob
    assert "sha256-canonical-json-v3" in blob, "message must name the unrecognized id"
    assert "recognize" in blob, blob
    assert "MISMATCH" not in r.stdout and "DRIFT" not in r.stdout, \
        "an unrecognized id is cannot-verify, never DRIFT"
    assert "LEGACY" not in r.stdout, "an unrecognized id must not be routed through the legacy path"
    # (b) a MALFORMED, non-string id
    forge(2)
    r = sh(["aggregate.py", "--check-digest"], repo, expect=2)
    blob = r.stdout + r.stderr
    assert "CANNOT BE VERIFIED" in blob, blob
    assert "MISMATCH" not in r.stdout and "DRIFT" not in r.stdout, blob


def t_check_digest_legacy_message_says_unverifiable_not_unchanged():
    # Codex r3930666148 / CodeRabbit r3930631493: fix-20's LEGACY cannot-verify message overstated the
    # guarantee -- it said a digest match is impossible "even though the run is unchanged," asserting the
    # content IS unchanged. From a stored canonical hash and a recomputed "raw:" hash alone the tool cannot
    # tell a benign representation change from a real modification that stayed beyond the cap, so the message
    # now says the transition is UNVERIFIABLE (re-aggregate), not proven-unchanged. The classification is
    # unchanged: recognized-predecessor id + all-canonical->raw -> exit 2 (a tool error, never DRIFT). This
    # pins BOTH: still exit 2 (not drift -- the alternative Codex raised) AND no false "unchanged" claim.
    repo = _complete_sensitive_repo()
    run = latest_run(repo)
    write(run / "validation" / "idor.json", {
        "finding_ids": ["security-1"], "classification": "confirmed",
        "severity": "high", "evidence": "reproduced", "reproduced": True,
        "regression_test": "t", "resolution": {"fixed": True, "gates_rerun": ["unit"]}})
    (run / "wide.json").write_bytes(b'{"n": ' + b'9' * 300 + b'}')  # 300-digit int > _MAX_INT_DIGITS -> "raw:"
    sh(["aggregate.py"], repo, expect=0)
    att = read(run / "verdict.json")["attestation"]
    assert att["files"]["wide.json"].startswith("raw:"), att["files"]["wide.json"]
    # forge a v1 (recognized predecessor) verdict that stored a PLAIN canonical hash for wide.json
    v = read(run / "verdict.json")
    files = dict(att["files"]); files["wide.json"] = "a" * 64       # plain canonical -> canonical->raw transition
    legacy = dict(att); legacy["files"] = files; legacy["algorithm"] = "sha256-canonical-json-v1"
    manifest = "\n".join(f"{sha}  {rel}" for rel, sha in sorted(files.items()))
    legacy["digest"] = hashlib.sha256(manifest.encode("utf-8")).hexdigest()
    v["attestation"] = legacy
    (run / "verdict.json").write_text(json.dumps(v))
    r = sh(["aggregate.py", "--check-digest"], repo, expect=2)      # recognized-predecessor legacy transition
    blob = r.stdout + r.stderr
    assert "CANNOT BE VERIFIED" in blob, blob
    assert "MISMATCH" not in r.stdout and "DRIFT" not in r.stdout, \
        "a legacy transition stays cannot-verify, never DRIFT (the alternative Codex raised)"
    assert "even though the run is unchanged" not in blob, \
        "must not falsely assert the run is unchanged (fix-20 overstatement)"
    assert ("cannot establish whether" in blob or "cannot tell them apart" in blob), \
        "message must convey the transition is unverifiable, not proven-unchanged"


def t_mcp_rebuttal_prepare_must_be_boolean():
    # Codex r3894216938: the server does not auto-validate tool arguments against the schema, so a truthy
    # non-boolean `prepare` (e.g. the string "false") must be REJECTED, not treated as enabled and routed
    # to the keyless prepare path. Fails on 561122f (which forwards `panel rebuttal --prepare`).
    repo = _complete_sensitive_repo()
    run = latest_run(repo)
    cwd0 = os.getcwd()
    os.chdir(repo)
    called = []

    def fake(module, argv, timeout=120):
        called.append(list(argv))
        return (0, "ok", "")

    orig = mcpsrv._run_cli
    mcpsrv._run_cli = fake
    outcome = "returned"
    msg = ""
    try:
        try:
            mcpsrv.h_panel_rebuttal({"run": run.name, "prepare": "false"})
        except mcpsrv.ToolError as e:
            outcome, msg = "toolerror", str(e)
        # a real boolean still dispatches (via the fake), proving only the non-boolean is rejected
        called.clear()
        mcpsrv.h_panel_rebuttal({"run": run.name, "prepare": True})
        forwarded = called and "--prepare" in called[0]
    finally:
        mcpsrv._run_cli = orig
        os.chdir(cwd0)
    assert outcome == "toolerror" and "prepare must be a boolean" in msg, (outcome, msg)
    assert forwarded, "prepare=True must still forward --prepare"


def t_mcp_aggregate_unremovable_rejected_verdict_is_not_readable():
    # Codex r3944027644: when no prior verdict exists and aggregation writes verdict.json but is rejected
    # (an exit-3 post-write crash), a cleanup unlink that fails (transient OSError / Windows lock) must NOT
    # be swallowed -- the rejected verdict.json would then be returned by a later ar_get_verdict as an
    # accepted verdict. It is now moved aside to a non-verdict name (.rejected), unreadable as a verdict;
    # only if that also fails is the failure surfaced. Fails on 561122f (ar_get_verdict returns the rejected PASS).
    repo = Path(tempfile.mkdtemp(prefix="ar-agg-rejclean-"))
    rundir = repo / ".adversarial-review" / "run-20260101-010101"
    rundir.mkdir(parents=True)
    cwd0 = os.getcwd()
    os.chdir(repo)

    RB = type(rundir)
    orig_unlink = RB.unlink

    def blocked_unlink(self, *a, **k):
        if self.name == "verdict.json":                 # simulate a locked verdict.json (unlink fails)
            raise OSError("simulated: verdict.json is locked")
        return orig_unlink(self, *a, **k)

    def fake(module, argv, timeout=120):
        # aggregate writes a fresh PASS verdict.json, then "crashes" post-write -> exit 3 (rejected)
        (rundir / "verdict.json").write_text(json.dumps({"verdict": "PASS", "run_id": "run-20260101-010101"}))
        return (3, "", "boom")

    orig_cli = mcpsrv._run_cli
    RB.unlink = blocked_unlink
    mcpsrv._run_cli = fake
    try:
        r = mcpsrv.h_aggregate({"run": "run-20260101-010101"})
        assert r["isError"], r                          # exit 3 -> rejected
    finally:
        RB.unlink = orig_unlink
        mcpsrv._run_cli = orig_cli
        os.chdir(cwd0)
    # The rejected verdict must not be readable as an accepted verdict: moved aside, not left in place.
    assert not (rundir / "verdict.json").is_file(), "the rejected verdict.json must be moved aside, not left readable"
    assert (rundir / "verdict.json.rejected").is_file(), "the rejected verdict must be preserved under .rejected"
    os.chdir(repo)
    try:
        v = mcpsrv.h_get_verdict({"run": "run-20260101-010101"})
        assert False, ("ar_get_verdict must not return the rejected verdict", v)
    except mcpsrv.ToolError:
        pass
    finally:
        os.chdir(cwd0)


def t_mcp_aggregate_reconcile_failure_does_not_mask_original_error():
    # CodeRabbit r3945458785: when a rejected verdict can be neither removed NOR moved aside AND a
    # non-ToolError is already unwinding, the cleanup log referenced `where`, which the rejected_unremoved
    # branch never assigns -> UnboundLocalError, masking the original exception. It now logs `detail`
    # (assigned in both branches). Fails on 778b087 (raises UnboundLocalError instead of the original error).
    repo = Path(tempfile.mkdtemp(prefix="ar-agg-reclog-"))
    rundir = repo / ".adversarial-review" / "run-20260101-010101"
    rundir.mkdir(parents=True)
    cwd0 = os.getcwd()
    os.chdir(repo)

    RB = type(rundir)
    orig_unlink = RB.unlink
    orig_replace = RB.replace

    def blocked_unlink(self, *a, **k):
        if self.name == "verdict.json":
            raise OSError("simulated: verdict.json is locked")
        return orig_unlink(self, *a, **k)

    def blocked_replace(self, target, *a, **k):
        if str(target).endswith("verdict.json.rejected"):
            raise OSError("simulated: cannot move the rejected verdict aside")
        return orig_replace(self, target, *a, **k)

    class Boom(RuntimeError):
        pass

    def fake(module, argv, timeout=120):
        (rundir / "verdict.json").write_text(json.dumps({"verdict": "PASS", "run_id": "run-20260101-010101"}))
        raise Boom("subprocess exploded")            # a NON-ToolError unwinds while cleanup fails

    orig_cli = mcpsrv._run_cli
    RB.unlink = blocked_unlink
    RB.replace = blocked_replace
    mcpsrv._run_cli = fake
    got = None
    try:
        try:
            mcpsrv.h_aggregate({"run": "run-20260101-010101"})
        except BaseException as e:
            got = e
    finally:
        RB.unlink = orig_unlink
        RB.replace = orig_replace
        mcpsrv._run_cli = orig_cli
        os.chdir(cwd0)
    # The original error must propagate, not be masked by an UnboundLocalError from the cleanup log.
    assert isinstance(got, Boom), ("expected the original error to propagate, got", type(got).__name__, repr(got)[:150])


# ---------------------------------------------------------------- ai-defects gate
# Wrapper (scripts/ai_defects_verify.py) + gate.py --exit-map status mapping. Fixtures
# under tests/fixtures/ai_defects/ are mock "verifiers"; NONE is the real pinned binary
# (the verifier is adopted by command and never committed/redistributed). Covers the
# TRD Section 9 IDs that apply to Adversarial Review: T-P1/P3/P4, T-N1..N6, T-E1/E3/E4/
# E7/E8/E9/E10, plus gate mapping, plan inclusion, and fail-closed extras.

AIDEF_FIX = SKILL / "tests" / "fixtures" / "ai_defects"
AIDEF_WRAPPER = SKILL / "scripts" / "ai_defects_verify.py"


def _aidef_fix(name):
    p = AIDEF_FIX / name
    try:
        os.chmod(p, 0o755)  # exec bit may be lost in transit; tests must not depend on it
    except OSError:
        pass
    return p


def _sha256_file(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def _aidef_env(binpath, digest=None, version="1.0.0", timeout=None):
    e = dict(ENV)
    e["AI_DEFECTS_BIN"] = str(binpath)
    e["AI_DEFECTS_PIN_VERSION"] = version
    e["AI_DEFECTS_PIN_DIGEST"] = digest if digest is not None else _sha256_file(binpath)
    if timeout is not None:
        e["AI_DEFECTS_TIMEOUT_S"] = str(timeout)
    return e


def _aidef_rundir(paths=("scripts/x.py",)):
    d = Path(tempfile.mkdtemp(prefix="ar-aidef-"))
    (d / "changed_paths.txt").write_text("\n".join(paths) + ("\n" if paths else ""))
    return d


def _aidef_wrap(run, env, expect, extra=None):
    args = ["ai_defects_verify.py", "--run-dir", str(run),
            "--diff-file", str(Path(run) / "changed_paths.txt")]
    if extra:
        args += extra
    return sh(args, cwd=str(run), expect=expect, env=env)


def _silence(root):
    return subprocess.run(
        ["sh", str(SKILL / "scripts" / "check_ai_defects_public_silence.sh"), str(root)],
        capture_output=True, text=True)


def t_ai_defects_exit0_pass():                       # T-P1
    run = _aidef_rundir()
    r = _aidef_wrap(run, _aidef_env(_aidef_fix("exit0_clean.py")), expect=0)
    assert "PASS" in r.stdout


def t_ai_defects_empty_diff_pass():                  # T-P3 / T-E2 (A12)
    run = _aidef_rundir(paths=())  # zero paths -> an empty changed_paths.txt
    r = _aidef_wrap(run, _aidef_env(_aidef_fix("exit0_clean.py"), digest=""), expect=0)
    assert "empty-diff" in r.stdout  # PASS reached BEFORE the (absent) pin is needed
    # NB: a whitespace-only line is a real (space-named) file, NOT empty -- see
    # t_ai_defects_whitespace_filename_scanned.


def t_ai_defects_exit1_fail():                       # T-N1
    run = _aidef_rundir()
    r = _aidef_wrap(run, _aidef_env(_aidef_fix("exit1_defects.py")), expect=1)
    assert "FAIL" in r.stdout


def t_ai_defects_exit2_blocked():                    # T-N2
    run = _aidef_rundir()
    r = _aidef_wrap(run, _aidef_env(_aidef_fix("exit2_incomplete.py")), expect=2)
    assert "BLOCKED" in r.stdout


def t_ai_defects_missing_pin_blocked():              # T-N3
    run = _aidef_rundir()
    r = _aidef_wrap(run, _aidef_env(_aidef_fix("exit0_clean.py"), digest=""), expect=2)
    assert "AI_DEFECTS_PIN_DIGEST" in r.stdout


def t_ai_defects_extra_argv_blocked():               # T-N4
    run = _aidef_rundir()
    r = _aidef_wrap(run, _aidef_env(_aidef_fix("exit0_clean.py")), expect=2,
                    extra=["--evil"])
    assert "unexpected argument" in r.stdout


def t_ai_defects_wildcard_rejected():                # T-N5
    run = _aidef_rundir()
    r = _aidef_wrap(run, _aidef_env(_aidef_fix("exit0_clean.py")), expect=2, extra=[":*"])
    assert "unexpected argument" in r.stdout  # no wildcard/passthrough accepted


def t_ai_defects_timeout_blocked():                  # T-E1
    run = _aidef_rundir()
    env = _aidef_env(_aidef_fix("sleep_timeout.py"), timeout=1)
    r = _aidef_wrap(run, env, expect=2)
    assert "timed out" in r.stdout


def t_ai_defects_exec_error_blocked():               # T-E4 (wrong arch / not an image)
    run = _aidef_rundir()
    r = _aidef_wrap(run, _aidef_env(_aidef_fix("not_a_binary.bin")), expect=2)
    assert "execute" in r.stdout


def t_ai_defects_incomplete_json_blocked():          # T-E7
    run = _aidef_rundir()
    r = _aidef_wrap(run, _aidef_env(_aidef_fix("exit0_incomplete_json.py")), expect=2)
    assert "incomplete" in r.stdout


def t_ai_defects_bad_summary_json_blocked():         # fail-closed: present-but-corrupt summary
    run = _aidef_rundir()
    (run / "ai-defects.json").write_text("{ not valid json")
    r = _aidef_wrap(run, _aidef_env(_aidef_fix("exit0_clean.py")), expect=2)
    assert "unreadable" in r.stdout


def t_ai_defects_unknown_exit_blocked():             # T-E8
    run = _aidef_rundir()
    r = _aidef_wrap(run, _aidef_env(_aidef_fix("exit99_unknown.py")), expect=2)
    assert "fail-closed" in r.stdout


def t_ai_defects_digest_mismatch_blocked():          # T-E9
    run = _aidef_rundir()
    env = _aidef_env(_aidef_fix("exit0_clean.py"), digest="0" * 64)
    r = _aidef_wrap(run, env, expect=2)
    assert "digest mismatch" in r.stdout


def t_ai_defects_unset_rundir_blocked():             # T-E10
    r = sh(["ai_defects_verify.py", "--run-dir", "", "--diff-file", "x"],
           cwd=str(SKILL), expect=2)
    assert "--run-dir" in r.stdout


def t_ai_defects_missing_binary_blocked():           # T-E3
    run = _aidef_rundir()
    r = _aidef_wrap(run, _aidef_env("/no/such/verifier", digest="0" * 64), expect=2)
    assert "not found" in r.stdout


def t_ai_defects_gate_maps_exit_taxonomy():          # WP-AR-4: gate ledger PASS/FAIL/BLOCKED
    for fixture, want in [("exit0_clean.py", "PASS"), ("exit1_defects.py", "FAIL"),
                          ("exit2_incomplete.py", "BLOCKED")]:
        run = _aidef_rundir()
        env = _aidef_env(_aidef_fix(fixture))
        sh(["gate.py", "run", "--run", str(run), "--name", "ai-defects",
            "--exit-map", "1=FAIL,2=BLOCKED,*=BLOCKED", "--",
            sys.executable, str(AIDEF_WRAPPER),
            "--run-dir", str(run), "--diff-file", str(run / "changed_paths.txt")],
           cwd=str(run), expect=None, env=env)
        rec = read(run / "gates" / "ai-defects.json")
        assert rec["status"] == want, (fixture, rec["status"], want)
        assert rec["gate"] == "ai-defects"


def t_ai_defects_gate_exit_map_rejects_bad_spec():   # malformed --exit-map dies, no bogus record
    run = _aidef_rundir()
    sh(["gate.py", "run", "--run", str(run), "--name", "ai-defects",
        "--exit-map", "2=NOPE", "--", "true"], cwd=str(run), expect=1)
    assert not (run / "gates" / "ai-defects.json").exists()


def t_ai_defects_plan_includes_gate():               # WP-AR-4: NORMAL+ plan can include ai-defects
    repo = fresh_repo()
    sh(["panel.py", "init", "--risk", "NORMAL", "--dev-providers", "anthropic",
        "--diff-ref", "main...HEAD"], repo)
    run = latest_run(repo)
    sh(["gate.py", "plan", "--run", str(run), "--require", "ai-defects"], repo)
    req = read(run / "gates" / "_required.json")
    assert "ai-defects" in req["required"], req["required"]


def t_ai_defects_public_silence_clean_tree():        # T-P4 / T-R3: real public surfaces are clean
    r = _silence(SKILL)
    assert r.returncode == 0, r.stdout + r.stderr


def t_ai_defects_public_silence_detects_vendor():    # T-N6: planted vendor/brand fails the check
    d = Path(tempfile.mkdtemp(prefix="ar-silence-"))
    (d / "README.md").write_text("We run skylos under the hood.\n")
    r = _silence(d)
    assert r.returncode != 0 and "README.md" in r.stdout
    d2 = Path(tempfile.mkdtemp(prefix="ar-silence-"))
    (d2 / "references").mkdir()
    (d2 / "references" / "x.md").write_text("we built this engine ourselves\n")
    assert _silence(d2).returncode != 0


def t_ai_defects_gate_exit_map_rejects_nonzero_pass():  # exit-map must never weaken a failing check
    run = _aidef_rundir()
    for spec in ("1=PASS", "*=PASS"):
        sh(["gate.py", "run", "--run", str(run), "--name", "ai-defects",
            "--exit-map", spec, "--", "true"], cwd=str(run), expect=1)
    assert not (run / "gates" / "ai-defects.json").exists()


def t_ai_defects_undecodable_diff_blocked():            # non-UTF-8 scope input -> BLOCKED, not FAIL
    run = _aidef_rundir()
    (run / "changed_paths.txt").write_bytes(b"\xff\xfe\x00 not utf8\n")
    r = _aidef_wrap(run, _aidef_env(_aidef_fix("exit0_clean.py")), expect=2)
    assert "diff file" in r.stdout


def t_ai_defects_nonfinite_timeout_blocked():           # nan/inf watchdog is no watchdog -> BLOCKED
    run = _aidef_rundir()
    env = _aidef_env(_aidef_fix("exit0_clean.py"), timeout="inf")
    r = _aidef_wrap(run, env, expect=2)
    assert "finite" in r.stdout


def t_ai_defects_public_silence_readme_variant_and_your_sast():
    # Every root README* variant is in scope (not just README.md)...
    d = Path(tempfile.mkdtemp(prefix="ar-silence-"))
    (d / "README.rst").write_text("Powered by skylos.\n")
    assert _silence(d).returncode != 0
    # ...but ordinary second-person guidance ("your SAST") is NOT a first-party claim.
    d2 = Path(tempfile.mkdtemp(prefix="ar-silence-"))
    (d2 / "README.md").write_text("Configure your SAST policy before merging.\n")
    r2 = _silence(d2)
    assert r2.returncode == 0, r2.stdout


def t_ai_defects_relative_binpath_blocked():           # exec exactly the digest-verified file
    run = _aidef_rundir()
    e = dict(ENV)
    e["AI_DEFECTS_BIN"] = "verifier-bare-name"  # relative -> hashed file != PATH-exec'd file
    e["AI_DEFECTS_PIN_VERSION"] = "1.0.0"
    e["AI_DEFECTS_PIN_DIGEST"] = "0" * 64
    r = _aidef_wrap(run, e, expect=2)
    assert "absolute" in r.stdout


def t_ai_defects_whitespace_filename_scanned():        # a space-named Git file is NOT empty-diff
    run = _aidef_rundir()
    (run / "changed_paths.txt").write_text("   \n")  # a file literally named three spaces
    r = _aidef_wrap(run, _aidef_env(_aidef_fix("exit0_clean.py")), expect=0)
    assert "empty-diff" not in r.stdout and "completed" in r.stdout


def t_ai_defects_binary_output_pass():                 # non-UTF-8 child output must not crash->FAIL
    run = _aidef_rundir()
    r = _aidef_wrap(run, _aidef_env(_aidef_fix("exit0_binary_output.py")), expect=0)
    assert "PASS" in r.stdout


def t_ai_defects_timeout_kills_child_tree():           # timeout kills the whole process group
    run = _aidef_rundir()
    env = _aidef_env(_aidef_fix("spawn_child_timeout.py"), timeout=1)
    r = _aidef_wrap(run, env, expect=2)
    assert "timed out" in r.stdout
    import time as _time
    _time.sleep(5)  # past the worker's 3s write window
    assert not (run / "child-marker").exists(), "spawned worker survived the timeout tree-kill"


def t_ai_defects_summary_nonobject_blocked():          # summary must be a JSON object
    run = _aidef_rundir()
    (run / "ai-defects.json").write_text("[]")
    r = _aidef_wrap(run, _aidef_env(_aidef_fix("exit0_clean.py")), expect=2)
    assert "not a JSON object" in r.stdout


def t_ai_defects_summary_nonbool_incomplete_blocked():  # 'incomplete' must be a boolean
    run = _aidef_rundir()
    (run / "ai-defects.json").write_text('{"incomplete": []}')
    r = _aidef_wrap(run, _aidef_env(_aidef_fix("exit0_clean.py")), expect=2)
    assert "non-boolean" in r.stdout


def t_ai_defects_public_silence_bad_root_blocked():    # a bad scan root fails closed (exit 2)
    r = _silence("/nonexistent/ar-root-does-not-exist")
    assert r.returncode == 2, (r.returncode, r.stdout, r.stderr)


# --- diff-ref scope resolver (scripts/ai_defects_diffscope.py) ------------------------
# The ai-defects CI job resolves the scan scope from a git diff-ref. That logic used to be
# inline in the workflow_dispatch job, which CI never runs -- so "a bad diff-ref must not
# become an empty-diff PASS" was untested. These exercise the extracted, CI-run resolver.

def _aidef_git_repo():
    d = Path(tempfile.mkdtemp(prefix="ar-aidef-git-"))

    def g(*a):
        r = subprocess.run(["git", *a], cwd=str(d), capture_output=True, text=True)
        assert r.returncode == 0, "git %s failed: %s" % (" ".join(a), r.stderr)

    g("init", "-q")
    g("config", "user.email", "t@ar.local")
    g("config", "user.name", "ar-test")
    g("config", "commit.gpgsign", "false")
    (d / "a.txt").write_text("one\n")
    g("add", "a.txt")
    g("commit", "-qm", "c1")
    (d / "a.txt").write_text("one\ntwo\n")
    g("commit", "-qam", "c2")
    return d


def _aidef_emptydir():
    return Path(tempfile.mkdtemp(prefix="ar-aidef-run-"))  # a run dir with NO changed_paths.txt


def _diffscope(repo, run_dir, ref, expect):
    return sh(["ai_defects_diffscope.py", "--run-dir", str(run_dir), "--diff-ref", ref],
              cwd=str(repo), expect=expect)


def t_ai_defects_diffscope_valid_range():              # valid range -> writes the changed list
    repo = _aidef_git_repo(); run = _aidef_emptydir()
    _diffscope(repo, run, "HEAD~1...HEAD", expect=0)
    cp = run / "changed_paths.txt"
    assert cp.is_file() and "a.txt" in cp.read_text()
    assert not (run / "changed_paths.txt.tmp").exists()  # atomic publish left no temp behind


def t_ai_defects_diffscope_valid_empty_range_pass():   # valid range, no changes -> legit empty-diff
    repo = _aidef_git_repo(); run = _aidef_emptydir()
    _diffscope(repo, run, "HEAD...HEAD", expect=0)
    cp = run / "changed_paths.txt"
    assert cp.is_file() and cp.read_text().strip() == ""


def t_ai_defects_diffscope_invalid_ref_blocked():      # bad ref -> BLOCKED, no changed_paths.txt
    repo = _aidef_git_repo(); run = _aidef_emptydir()
    r = _diffscope(repo, run, "bogus...HEAD", expect=2)
    assert "BLOCKED" in r.stdout and not (run / "changed_paths.txt").exists()


def t_ai_defects_diffscope_pathspec_blocked():         # a bare tracked filename is not a revision
    repo = _aidef_git_repo(); run = _aidef_emptydir()
    _diffscope(repo, run, "a.txt", expect=2)
    assert not (run / "changed_paths.txt").exists()


def t_ai_defects_diffscope_option_prefixed_blocked():  # -x is rejected before touching git
    repo = _aidef_git_repo(); run = _aidef_emptydir()
    r = _diffscope(repo, run, "-x", expect=2)
    assert "option-prefixed" in r.stdout and not (run / "changed_paths.txt").exists()


def t_ai_defects_diffscope_empty_ref_blocked():        # missing/empty diff-ref -> BLOCKED
    repo = _aidef_git_repo(); run = _aidef_emptydir()
    _diffscope(repo, run, "", expect=2)
    assert not (run / "changed_paths.txt").exists()


def t_ai_defects_diffscope_clears_stale_changed_paths():  # a failed resolution leaves no leftover
    repo = _aidef_git_repo(); run = _aidef_emptydir()
    (run / "changed_paths.txt").write_text("stale/leftover.py\n")
    _diffscope(repo, run, "bogus...HEAD", expect=2)
    assert not (run / "changed_paths.txt").exists(), "stale changed_paths survived a failed resolution"


def t_ai_defects_invalid_diffref_never_empty_diff_pass():
    # End-to-end: a bad diff-ref must NOT become an empty-diff PASS. The resolver fails closed
    # (no changed_paths.txt), and the verify wrapper handed that absent file BLOCKS -- it does
    # not read an empty file and record empty-diff PASS.
    repo = _aidef_git_repo(); run = _aidef_emptydir()
    _diffscope(repo, run, "not-a-ref", expect=2)
    assert not (run / "changed_paths.txt").exists()
    r = _aidef_wrap(run, _aidef_env(_aidef_fix("exit0_clean.py")), expect=2)
    assert "cannot read diff file" in r.stdout and "empty-diff" not in r.stdout


def main():
    srv = mock_router.start(PORT)
    tests = [(k, v) for k, v in sorted(globals().items()) if k.startswith("t_")]
    print(f"running {len(tests)} scenarios against mock router on :{PORT}\n")
    for name, fn in tests:
        check(name, fn)
    srv.shutdown()
    print(f"\n{len(PASSED)} passed, {len(FAILED)} failed")
    sys.exit(1 if FAILED else 0)


if __name__ == "__main__":
    main()
