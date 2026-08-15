#!/usr/bin/env python3
"""End-to-end tests for the adversarial-review skill scripts against a mock router."""
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
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
    assert att1["algorithm"] == "sha256-canonical-json-v1"
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
    repo = fresh_repo()
    cwd0 = os.getcwd()
    try:
        os.chdir(repo)
        note = {"jsonrpc": "2.0", "method": "tools/call",
                "params": {"name": "ar_init",
                           "arguments": {"risk": "NORMAL", "dev_providers": ["anthropic"]}}}
        assert mcpsrv.handle(note) is None
        assert list((repo / ".adversarial-review").glob("run-*")) == []
    finally:
        os.chdir(cwd0)


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
