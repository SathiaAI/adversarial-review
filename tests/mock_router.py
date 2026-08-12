"""In-process mock of an OpenAI-compatible router (OpenRouter shape) for tests."""
import json
import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

CATALOG = {"data": [
    {"id": "anthropic/claude-opus-5", "created": 300, "context_length": 400000,
     "supported_parameters": ["structured_outputs", "temperature"]},
    {"id": "openai/gpt-5.6-luna-pro", "created": 310, "context_length": 300000,
     "supported_parameters": ["structured_outputs"]},
    {"id": "openai/gpt-5.6-sol", "created": 305, "context_length": 300000,
     "supported_parameters": ["structured_outputs"]},
    {"id": "google/gemini-3.6-flash", "created": 290, "context_length": 1000000,
     "supported_parameters": ["structured_outputs"]},
    {"id": "x-ai/grok-4.5", "created": 280, "context_length": 256000,
     "supported_parameters": ["structured_outputs"]},
    {"id": "qwen/qwen3.8-max", "created": 270, "context_length": 128000,
     "supported_parameters": ["structured_outputs"]},
    {"id": "mistralai/mistral-large-3", "created": 260, "context_length": 128000,
     "supported_parameters": ["temperature"]},          # no structured outputs
    {"id": "deepseek/deepseek-v4-flash-0731", "created": 250, "context_length": 128000,
     "supported_parameters": ["structured_outputs"]},
    {"id": "moonshotai/kimi-k3", "created": 240, "context_length": 200000,
     "supported_parameters": ["structured_outputs"]},
    {"id": "z-ai/glm-5.2", "created": 230, "context_length": 128000,
     "supported_parameters": ["structured_outputs"]},
    {"id": "cohere/command-b", "created": 220, "context_length": 128000,
     "supported_parameters": []},
    # Must all be filtered out by the assign step:
    {"id": "qwen/qwen3.8-max:free", "created": 271, "context_length": 128000},
    {"id": "x-ai/grok-latest", "created": 999, "context_length": 256000},
    {"id": "google/gemini-3.6-flash-preview", "created": 999, "context_length": 100},
    {"id": "openai/gpt-image-2", "created": 999, "context_length": 100},
    {"id": "openrouter/auto", "created": 999, "context_length": 100},
]}

STATE = {"fail_models": set(), "malformed_once": set(), "calls": {}, "concur_agrees": True}


def _report(role, model):
    findings = []
    if role == "security":
        findings = [{
            "id": "security-1", "title": "IDOR on invoice endpoint",
            "severity": "high", "confidence": 0.8, "file": "api/invoices.py",
            "line": 42, "evidence": "no owner check before fetch",
            "scenario": "user A requests user B's invoice id and receives it",
            "reproduction": ["login as A", "GET /invoices/<B's id>"],
            "fix": "filter by authenticated principal",
            "regression_test": "test_invoice_cross_tenant_denied",
            "release_blocking": True}]
    return {"role": role, "model_id": model, "summary": f"{role} review complete",
            "findings": findings, "assumptions": [], "additional_tests": [],
            "areas_reviewed": ["diff"], "areas_not_reviewed": ["infra"],
            "top_residual_risks": ["auth middleware unreviewed"],
            "injection_suspected": False,
            "output_statements_checked": [
                {"rendered": "sample rendered user-facing line",
                 "states_truth": True, "note": "consistent with the state it describes"}]}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):  # quiet
        pass

    def _send(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path.endswith("/models"):
            return self._send(200, CATALOG)
        return self._send(404, {"error": "not found"})

    def do_POST(self):
        if not self.path.endswith("/chat/completions"):
            return self._send(404, {"error": "not found"})
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        model = body["model"]
        STATE["calls"][model] = STATE["calls"].get(model, 0) + 1
        if model in STATE["fail_models"]:
            return self._send(500, {"error": {"message": "provider unavailable"}})

        text = json.dumps(body["messages"])
        if "rebuttal round" in text:
            user = json.loads(body["messages"][-1]["content"])
            content = {"role": re.search(r"the (\w+) reviewer", text).group(1),
                       "model_id": model,
                       "responses": [{"finding_id": f["id"], "position": "corroborate",
                                      "evidence": "reproduced the cross-tenant read"}
                                     for f in user["findings_to_contest"]]}
        elif "arbiter" in text:
            content = {"agrees_false_positive": STATE["concur_agrees"],
                       "reasoning": "evidence conclusive" if STATE["concur_agrees"]
                       else "evidence does not refute the finding"}
        else:
            role = re.search(r"Your role: (\w+)", text).group(1)
            content = _report(role, model)

        if model in STATE["malformed_once"] and STATE["calls"][model] == 1:
            payload = "here you go: {broken json"
        else:
            payload = json.dumps(content)
        self._send(200, {"choices": [{"message": {"content": payload}}],
                         "usage": {"prompt_tokens": 1200, "completion_tokens": 300},
                         "provider": "MockServe"})


def start(port=8811):
    srv = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv
