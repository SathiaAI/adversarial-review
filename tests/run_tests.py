#!/usr/bin/env python3
"""End-to-end tests for the adversarial-review skill scripts against a mock router."""
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
SKILL = Path(os.environ.get("SKILL_DIR", HERE.parent))  # repo root = skill root
sys.path.insert(0, str(HERE))
import mock_router  # noqa: E402

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
    assert len(plan["roles"]) == 3, f"expected 3 roles, got {len(plan['roles'])}"
    assert len(set(fams)) == 3, f"family collision: {fams}"
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
    assert len(plan["roles"]) == 5 and len(set(fams)) == 5, f"collision: {fams}"
    assert not {"anthropic", "openai"} & set(fams)


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
    assert len(cov["panel"]["roles_filled"]) == 5
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
    assert len(cov["panel"]["roles_filled"]) == 3
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
    assert len(pcov["roles_required"]) == 4 and len(pcov["roles_filled"]) == 3


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
    att1 = read(run / "verdict.json")["attestation"]
    assert att1["algorithm"] == "sha256-canonical-json-v1"
    assert att1["inputs"] == len(att1["files"]) > 0
    assert "verdict.json" not in att1["files"]
    assert "run.json" in att1["files"] and "gates/unit.json" in att1["files"]
    sh(["aggregate.py"], repo, expect=0)   # re-aggregate the untouched run
    att2 = read(run / "verdict.json")["attestation"]
    assert att1["digest"] == att2["digest"], "digest not reproducible"
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
        req = urllib.request.Request(
            f"http://127.0.0.1:{PORT}/v1/chat/completions",
            data=json.dumps(body).encode(),
            headers={"Content-Type": "application/json"})
        resp = urllib.request.urlopen(req, timeout=10).read().decode()
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
