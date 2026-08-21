#!/usr/bin/env python3
"""Publish an adversarial-review run to a GitHub pull request (E5-S1).

Reads a completed run dir (as written by ``aggregate.py``) and mirrors it onto a PR:

  * one **verdict summary** comment (created once, then updated in place on every re-run),
  * one **inline review comment** per deduped finding, anchored to its file/line, and
  * a **commit status** whose state maps from the verdict (PASS/FAIL/BLOCKED).

It is **idempotent**: every comment it writes carries a hidden ``<!-- ar-managed -->`` marker plus
a stable per-item key, so a re-run *updates* the comment for a finding that is still present,
*creates* one for a new finding, and *deletes* the comment for a finding that is gone — it never
duplicates and never touches a human's comment. Findings whose cited line is not part of the PR
diff (GitHub rejects an inline anchor there) fall back into the summary comment rather than being
dropped.

It is **token-gated**: with no token available it runs as a **dry run** — it computes the exact
plan and returns the same exit code, but performs no network writes. It is a **no-op** in that
mode, which is also how the offline tests drive it (a fake client records the intended calls).

It **never writes a secret** into a comment: bodies are rendered only from run artifacts and static
text, and a final scrub replaces any token-looking value before anything is sent.

This is *tooling*, not pipeline runtime: it lives in ``integrations/`` and is never imported by
``scripts/*.py``. It is kept stdlib-only and Python 3.9-safe for portability.

Usage (typically from CI, where the GITHUB_* vars are already set):
    python integrations/pr_publish.py RUN_DIR --repo owner/name --pr 42 [--sha SHA] \\
        [--fail-on fail|blocked] [--dry-run]

Auth/context env fallbacks: ``GITHUB_TOKEN``/``GH_TOKEN`` (token; absent → dry run),
``GITHUB_REPOSITORY`` (owner/name), ``GITHUB_API_URL`` (default ``https://api.github.com``),
``GITHUB_SHA`` (head commit), ``GITHUB_STEP_SUMMARY`` (if set, the verdict markdown is also
appended there).
"""
import argparse
import hashlib
import http.client
import json
import os
import re
import sys
import urllib.parse

VERDICTS = ("PASS", "FAIL", "BLOCKED")
# commit-status state per verdict — BLOCKED is "could not determine", which is `error`, not a
# clean failure, so a reader can tell "we proved it's broken" from "we could not check".
_STATUS_STATE = {"PASS": "success", "FAIL": "failure", "BLOCKED": "error"}
_SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}
MANAGED = "<!-- ar-managed -->"
VERDICT_MARKER = "<!-- ar-verdict -->"
_STATUS_CONTEXT = "adversarial-review"
_MAX_PAGES = 20  # pagination backstop; a PR with >2000 managed comments is not a real scenario

# ``repo`` and ``sha`` are interpolated straight into request paths, so constrain them to their real
# character sets before use — and do it at the point of use (the client), not only at the CLI, so a
# caller of the programmatic API is guarded too (panel finding correctness-1). Without this a value
# containing ``?``, ``#``, ``..`` or ``%`` would alter the target path or query instead of failing
# loudly. The char class excludes ``%``, so percent-encoded traversal (``%2e%2e``) is rejected too.
_REPO_RE = re.compile(r"^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$")
_SHA_RE = re.compile(r"^[0-9a-fA-F]{7,64}$")


def _check_repo(repo):
    # The char class permits ``.`` (repo names may contain dots), so also reject a ``.``/``..``
    # *segment* explicitly — otherwise "../x" or "o/.." would pass and traverse the request path.
    if (not isinstance(repo, str) or not _REPO_RE.match(repo)
            or any(part in (".", "..") for part in repo.split("/"))):
        raise ValueError("repo must be 'owner/name' with no path/query characters (got %r)" % (repo,))
    return repo


def _check_sha(sha):
    sha = (sha or "").strip()
    if sha and not _SHA_RE.match(sha):
        raise ValueError("sha must be 7-64 hex characters (got %r)" % (sha,))
    return sha


# --------------------------------------------------------------------------- artifact loading

def _read_json(path):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def _text(value):
    """A UTF-8-encodable ``str`` — round-trip through UTF-8 with replacement so a lone surrogate
    from ``json.load`` degrades to a placeholder instead of crashing a later request encode."""
    return str(value).encode("utf-8", "replace").decode("utf-8")


def _severity(value):
    # A malformed artifact can carry a non-string severity (e.g. ``[]`` or ``{}``); guard the
    # membership test so an unhashable value degrades to "low" instead of raising ``TypeError``
    # and aborting the whole publish.
    return value if isinstance(value, str) and value in _SEV_RANK else "low"


def load_run(run_dir):
    """Load the artifacts ``publish`` needs from a run dir, tolerating partial/old runs.

    Returns a dict with the verdict mapping, the per-role reports, and the validation records
    (keyed by the finding ids each covers). Raises ``FileNotFoundError``/``ValueError`` only when
    ``verdict.json`` itself is missing or unparseable — without a verdict there is nothing to post.
    """
    verdict = _read_json(os.path.join(run_dir, "verdict.json"))
    if not isinstance(verdict, dict):
        raise ValueError("verdict.json is not an object")

    plan_path = os.path.join(run_dir, "panel", "plan.json")
    plan = {}
    if os.path.isfile(plan_path):
        # A malformed plan.json must not abort the publish — only verdict.json can (see docstring).
        # The role fallback below already handles a missing/empty plan.
        try:
            loaded = _read_json(plan_path)
            if isinstance(loaded, dict):
                plan = loaded
        except (ValueError, OSError):
            plan = {}
    roles = list(plan.get("roles", {})) if isinstance(plan.get("roles"), dict) else []

    reports = {}
    panel_dir = os.path.join(run_dir, "panel")
    if os.path.isdir(panel_dir):
        # Prefer the plan's role order; fall back to any panel/<role>.json present.
        names = roles or sorted(
            f[:-5] for f in os.listdir(panel_dir)
            if f.endswith(".json") and os.path.isfile(os.path.join(panel_dir, f)))
        for role in names:
            p = os.path.join(panel_dir, role + ".json")
            if not os.path.isfile(p):
                continue
            try:
                rep = _read_json(p)
            except (ValueError, OSError):
                continue
            if isinstance(rep, dict):
                reports[role] = rep

    validations = []
    vdir = os.path.join(run_dir, "validation")
    if os.path.isdir(vdir):
        for name in sorted(os.listdir(vdir)):
            if not name.endswith(".json"):
                continue
            try:
                rec = _read_json(os.path.join(vdir, name))
            except (ValueError, OSError):
                continue
            if isinstance(rec, dict):
                validations.append(rec)
    return {"run_dir": run_dir, "verdict": verdict, "plan": plan,
            "reports": reports, "validations": validations}


def _triage_index(validations):
    """Map every covered finding id to its triage record (classification + resolution)."""
    idx = {}
    for rec in validations:
        ids = rec.get("finding_ids")
        if not isinstance(ids, list):
            continue
        for fid in ids:
            if isinstance(fid, str):
                idx[fid] = rec
    return idx


def _finding_key(file, title):
    """Stable identity for a finding across re-runs: file + normalized title. Line numbers drift
    between pushes, so they are deliberately excluded from the key (the anchor still uses the live
    line). A reworded title is treated as a new finding — the old comment is retired, the new one
    posted, which is the honest outcome."""
    basis = "%s\n%s" % (_text(file).strip(), " ".join(_text(title).lower().split()))
    # sha256, truncated: this is a stable *identity* key for idempotent comment matching, not a
    # cryptographic signature — but there is no reason to reach for a weaker digest.
    return hashlib.sha256(basis.encode("utf-8")).hexdigest()[:12]


def collect_findings(run):
    """Dedupe findings across roles into one record per issue, most-severe first.

    Two reviewers reporting the same ``(file, title)`` collapse into a single record whose
    ``roles``/``ids`` list both sources. Each record carries the triage decision from the matching
    validation record when one exists, else ``"untriaged"``.
    """
    triage = _triage_index(run["validations"])
    by_key = {}
    for role, rep in run["reports"].items():
        findings = rep.get("findings")
        if not isinstance(findings, list):
            continue
        for f in findings:
            if not isinstance(f, dict):
                continue
            file = _text(f.get("file") or "")
            title = _text(f.get("title") or "(untitled finding)")
            key = _finding_key(file, title)
            line = f.get("line")
            line = line if isinstance(line, int) and not isinstance(line, bool) and line > 0 else None
            fid = _text(f.get("id") or "")
            rec = triage.get(fid, {}) if fid else {}
            cls = rec.get("classification") if isinstance(rec, dict) else None
            entry = by_key.get(key)
            if entry is None:
                entry = {
                    "key": key, "file": file, "line": line,
                    "title": title, "severity": _severity(f.get("severity")),
                    "evidence": _text(f.get("evidence") or ""),
                    "scenario": _text(f.get("scenario") or ""),
                    "fix": _text(f.get("fix") or ""),
                    "release_blocking": bool(f.get("release_blocking")),
                    "roles": set(), "ids": set(), "classification": cls,
                    "resolution": rec.get("resolution") if isinstance(rec, dict) else None,
                }
                by_key[key] = entry
            else:
                # keep the most-severe label and the first concrete line/classification we saw
                if _SEV_RANK[_severity(f.get("severity"))] < _SEV_RANK[entry["severity"]]:
                    entry["severity"] = _severity(f.get("severity"))
                entry["release_blocking"] = entry["release_blocking"] or bool(f.get("release_blocking"))
                if entry["line"] is None and line is not None:
                    entry["line"] = line
                if entry["classification"] is None and cls:
                    entry["classification"] = cls
                    entry["resolution"] = rec.get("resolution") if isinstance(rec, dict) else None
            if role:
                entry["roles"].add(role)
            if fid:
                entry["ids"].add(fid)
    out = list(by_key.values())
    out.sort(key=lambda e: (_SEV_RANK[e["severity"]], e["file"], e["title"]))
    return out


# --------------------------------------------------------------------------- rendering

def _triage_label(entry):
    cls = entry.get("classification")
    if not cls:
        return "untriaged"
    res = entry.get("resolution") if isinstance(entry.get("resolution"), dict) else {}
    if cls == "confirmed" and res.get("fixed") is True:
        return "confirmed · fixed"
    return _text(cls).replace("_", " ")


def _clean(value):
    """Neutralize a finding's untrusted text before it enters a comment body. Finding titles and
    evidence are derived from the (untrusted) diff, so they must not be able to inject an HTML
    comment — which is how our managed/finding markers are written, and how GitHub hides content.
    Escaping the comment-forming ``<`` renders any ``<!-- … -->`` as visible literal text instead of
    an active comment, so a crafted finding can neither forge a managed marker nor smuggle hidden
    content into a comment this tool owns (panel findings security-2 / correctness-3)."""
    return _text(value).replace("<!--", "&lt;!--").replace("-->", "--&gt;")


def render_finding_body(run_id, entry):
    """Markdown for one inline finding comment, carrying its managed + per-finding markers.
    The single trusted marker line is appended last, after all untrusted text has been neutralized."""
    roles = ", ".join(sorted(entry["roles"])) or "panel"
    ids = ", ".join(sorted(entry["ids"]))
    head = "**%s** · %s%s" % (
        entry["severity"].upper(), _clean(entry["title"]),
        " · release-blocking" if entry["release_blocking"] else "")
    lines = [head, ""]
    lines.append("_Reviewer(s): %s_  ·  _Triage: %s_%s"
                 % (roles, _triage_label(entry), ("  ·  `%s`" % ids if ids else "")))
    if entry["evidence"]:
        lines += ["", "**Evidence** — %s" % _clean(entry["evidence"])]
    if entry["scenario"]:
        lines += ["", "**Scenario** — %s" % _clean(entry["scenario"])]
    if entry["fix"]:
        lines += ["", "**Suggested fix** — %s" % _clean(entry["fix"])]
    lines += ["", "%s\n<!-- ar-finding:%s -->" % (MANAGED, entry["key"])]
    return "\n".join(lines)


def _verdict_of(run):
    v = run["verdict"].get("verdict")
    return v if v in VERDICTS else "BLOCKED"


def render_verdict_summary(run, repo, pr, unanchored):
    """Markdown for the single, updatable verdict summary comment on the PR."""
    v = run["verdict"]
    verdict = _verdict_of(run)
    counts = v.get("counts") if isinstance(v.get("counts"), dict) else {}
    cov = v.get("coverage") if isinstance(v.get("coverage"), dict) else {}
    gates = cov.get("gates") if isinstance(cov.get("gates"), dict) else {}
    panel = cov.get("panel") if isinstance(cov.get("panel"), dict) else {}
    findings_cov = cov.get("findings") if isinstance(cov.get("findings"), dict) else {}
    att = v.get("attestation") if isinstance(v.get("attestation"), dict) else {}

    def _n(seq):
        return len(seq) if isinstance(seq, list) else 0

    emoji = {"PASS": "✅", "FAIL": "❌", "BLOCKED": "⛔"}[verdict]
    out = ["## %s Adversarial Review verdict: **%s**" % (emoji, verdict), ""]
    out.append("Run `%s` · risk **%s** · the verdict is computed by `aggregate.py`, not authored."
               % (_text(v.get("run_id") or "?"), _text(v.get("risk") or cov.get("risk") or "?")))
    reasons = v.get("reasons")
    if isinstance(reasons, list) and reasons:
        out += ["", "**Blocking reasons:**"] + ["- %s" % _text(r) for r in reasons[:20]]
    out += ["", "**Gates** %d/%d passed · **Panel** %d/%d roles · **Findings** %d raised, %d triaged"
            % (_n(gates.get("passed")), _n(gates.get("required")),
               _n(panel.get("roles_filled")), _n(panel.get("roles_required")),
               _int0(findings_cov.get("raised")), _int0(findings_cov.get("triaged")))]

    findings = collect_findings(run)
    if findings:
        out += ["", "| severity | finding | file:line | triage |", "|---|---|---|---|"]
        for e in findings:
            # e["file"] is untrusted artifact text: neutralize marker/pipe/newline so it cannot forge
            # a managed marker or break the row (panel finding correctness-3, re-review).
            efile = _md_cell(e["file"])
            loc = "%s:%s" % (efile, e["line"]) if e["line"] else (efile or "—")
            out.append("| %s%s | %s | `%s` | %s |" % (
                e["severity"], " \U0001f6a9" if e["release_blocking"] else "",
                _md_cell(e["title"]), loc, _triage_label(e)))
    else:
        out += ["", "_No findings._"]

    if unanchored:
        out += ["", "<details><summary>%d finding(s) not anchorable to the diff</summary>" % len(unanchored), ""]
        for e in unanchored:
            out.append("- **%s** %s (`%s:%s`) — %s"
                       % (e["severity"].upper(), _md_cell(e["title"]), _md_cell(e["file"]),
                          e["line"] if e["line"] else "?", _triage_label(e)))
        out += ["", "</details>"]

    cost = cov.get("cost_usd")
    tail = []
    if isinstance(cost, (int, float)) and not isinstance(cost, bool):
        tail.append("cost $%.4f" % cost)
    if att.get("digest"):
        tail.append("attestation `sha256:%s…`" % _text(att["digest"])[:12])
    if tail:
        out += ["", "<sub>%s · %s</sub>" % (" · ".join(tail), "posted by adversarial-review")]
    out += ["", "%s\n%s" % (MANAGED, VERDICT_MARKER)]
    return "\n".join(out)


def _int0(value):
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else 0


def _md_cell(text):
    """Neutralize an untrusted title for a one-line markdown table cell: strip newlines, escape
    pipes, and neutralize comment markers (so it cannot forge a managed marker in the summary)."""
    return _clean(text).replace("\n", " ").replace("|", "\\|").strip()


# --------------------------------------------------------------------------- github client

class GitHubError(Exception):
    def __init__(self, status, message):
        super().__init__("github %s: %s" % (status, message))
        self.status = status


class GitHubClient:
    """Minimal GitHub REST client over ``urllib`` (no third-party deps)."""

    def __init__(self, token, repo, api_url="https://api.github.com"):
        # Parse the API base once. Using http.client (not urllib) keeps this an HTTP(S)-only client
        # by construction — it cannot be steered into a `file://`/`ftp://` read the way a urllib
        # opener can — while a configurable host is still supported for GitHub Enterprise.
        parts = urllib.parse.urlsplit(api_url)
        host = parts.hostname
        if parts.scheme not in ("http", "https") or not host:
            raise ValueError("api_url must be an http(s) URL with a host, got %r" % api_url)
        # The bearer token must not travel in cleartext. Require https except for an explicit
        # loopback host (self-hosted/testing), so a plaintext base URL can never leak the token
        # (panel finding security-3).
        if parts.scheme == "http" and host not in ("localhost", "127.0.0.1", "::1"):
            raise ValueError("api_url must be https (refusing to send the token over cleartext http "
                             "to %r); http is allowed only for localhost" % host)
        self.token = token
        self.repo = _check_repo(repo)  # validate here so the programmatic API is guarded, not just the CLI
        self._scheme = parts.scheme
        self._host = host
        self._port = parts.port
        self._base = parts.path.rstrip("/")  # GHE mounts the API under a path prefix (e.g. /api/v3)
        self._login = None
        self._login_resolved = False

    def whoami(self):
        """The authenticated account's login, or ``None`` if it cannot be determined. Cached. Used
        to prove ownership of a managed comment by author, not by a public marker alone."""
        if not self._login_resolved:
            self._login_resolved = True
            try:
                me = self._request("GET", "/user")
                self._login = me.get("login") if isinstance(me, dict) else None
            except GitHubError:
                self._login = None
        return self._login

    def _request(self, method, path, body=None):
        data = json.dumps(body).encode("utf-8") if body is not None else None
        headers = {"Authorization": "Bearer %s" % self.token,
                   "Accept": "application/vnd.github+json",
                   "X-GitHub-Api-Version": "2022-11-28",
                   "User-Agent": "adversarial-review-pr-publish"}
        if data is not None:
            headers["Content-Type"] = "application/json"
        conn = (http.client.HTTPSConnection if self._scheme == "https"
                else http.client.HTTPConnection)(self._host, self._port, timeout=30)
        try:
            conn.request(method, self._base + path, body=data, headers=headers)
            resp = conn.getresponse()
            raw = resp.read().decode("utf-8")
            if resp.status >= 400:
                raise GitHubError(resp.status, (raw[:300] or resp.reason))
            return json.loads(raw) if raw else {}
        finally:
            conn.close()

    def _paged(self, path):
        items = []
        sep = "&" if "?" in path else "?"
        for page in range(1, _MAX_PAGES + 1):
            batch = self._request("GET", "%s%sper_page=100&page=%d" % (path, sep, page))
            if not isinstance(batch, list) or not batch:
                break
            items.extend(batch)
            if len(batch) < 100:
                break
        return items

    # issue (summary) comments
    def list_issue_comments(self, pr):
        return self._paged("/repos/%s/issues/%d/comments" % (self.repo, pr))

    def create_issue_comment(self, pr, body):
        return self._request("POST", "/repos/%s/issues/%d/comments" % (self.repo, pr), {"body": body})

    def update_issue_comment(self, comment_id, body):
        return self._request("PATCH", "/repos/%s/issues/comments/%d" % (self.repo, comment_id), {"body": body})

    def delete_issue_comment(self, comment_id):
        return self._request("DELETE", "/repos/%s/issues/comments/%d" % (self.repo, comment_id))

    # pull request (used to bind publication to the reviewed head sha)
    def get_pull(self, pr):
        return self._request("GET", "/repos/%s/pulls/%d" % (self.repo, pr))

    # inline review comments
    def list_review_comments(self, pr):
        return self._paged("/repos/%s/pulls/%d/comments" % (self.repo, pr))

    def create_review_comment(self, pr, commit_sha, path, line, body):
        return self._request("POST", "/repos/%s/pulls/%d/comments" % (self.repo, pr),
                             {"body": body, "commit_id": commit_sha, "path": path,
                              "line": line, "side": "RIGHT"})

    def update_review_comment(self, comment_id, body):
        return self._request("PATCH", "/repos/%s/pulls/comments/%d" % (self.repo, comment_id), {"body": body})

    def delete_review_comment(self, comment_id):
        return self._request("DELETE", "/repos/%s/pulls/comments/%d" % (self.repo, comment_id))

    # commit status
    def set_status(self, sha, state, description, target_url=None):
        _check_sha(sha)  # sha is interpolated into the request path — validate before use
        body = {"state": state, "context": _STATUS_CONTEXT, "description": description[:140]}
        if target_url:
            body["target_url"] = target_url
        return self._request("POST", "/repos/%s/statuses/%s" % (self.repo, sha), body)


class DryRunClient:
    """Records intended writes without performing any; list calls return nothing. Used when there
    is no token (a genuine no-op) and by the offline tests."""

    def __init__(self):
        self.calls = []

    def whoami(self):
        return None  # unknown identity → reconcile falls back to marker-only (a dry run mutates nothing)

    def get_pull(self, pr):
        return {}  # a dry run performs no head-sha binding (it mutates nothing)

    def list_issue_comments(self, pr):
        return []

    def list_review_comments(self, pr):
        return []

    def create_issue_comment(self, pr, body):
        self.calls.append(("create_issue_comment", pr, body))
        return {"id": 0}

    def update_issue_comment(self, cid, body):
        self.calls.append(("update_issue_comment", cid, body))
        return {"id": cid}

    def delete_issue_comment(self, cid):
        self.calls.append(("delete_issue_comment", cid))
        return {}

    def create_review_comment(self, pr, sha, path, line, body):
        self.calls.append(("create_review_comment", pr, path, line, body))
        return {"id": 0}

    def update_review_comment(self, cid, body):
        self.calls.append(("update_review_comment", cid, body))
        return {"id": cid}

    def delete_review_comment(self, cid):
        self.calls.append(("delete_review_comment", cid))
        return {}

    def set_status(self, sha, state, description, target_url=None):
        self.calls.append(("set_status", sha, state, description))
        return {}


# --------------------------------------------------------------------------- reconciliation

def _managed_index(comments, marker_prefix, owner_login=None):
    """Map an item key -> ``{"id", "line"}`` for the comments this tool owns that carry
    ``marker_prefix``.

    Ownership requires **both** the ``MANAGED`` sentinel **and**, when ``owner_login`` is known,
    that the comment was authored by that account. Relying on the public marker alone would let a
    human (or a malicious PR author) paste the marker into their own comment and have this tool
    update or delete it; the author check closes that (panel findings security-1 / correctness-3).
    When ``owner_login`` is ``None`` (identity unknown, e.g. a dry run that mutates nothing) the
    marker alone is used.
    """
    idx = {}
    for c in comments:
        if not isinstance(c, dict):
            continue
        body = c.get("body") or ""
        if MANAGED not in body or marker_prefix not in body:
            continue
        if owner_login is not None:
            author = (c.get("user") or {}).get("login") if isinstance(c.get("user"), dict) else None
            if author != owner_login:
                continue  # marker present but not authored by us — a human/spoofed comment
        start = body.find(marker_prefix)
        rest = body[start + len(marker_prefix):]
        end = rest.find("-->")
        key = rest[:end].strip() if end != -1 else ""
        cid = c.get("id")
        if isinstance(cid, int):
            line = c.get("line")
            line = line if isinstance(line, int) and not isinstance(line, bool) else None
            idx[key or "_"] = {"id": cid, "line": line}
    return idx


def _scrub(body, secrets):
    """Replace any secret value that leaked into a body with a redaction. Defense in depth — bodies
    are built only from artifacts, but a run dir could in principle echo a key."""
    for s in secrets:
        if s and len(s) >= 8 and s in body:
            body = body.replace(s, "***redacted***")
    return body


def _verify_attestation(run_dir, verdict):
    """Recompute the run's attestation and compare it to the digest stored in ``verdict.json`` —
    **before any network write**. If a gate, report, or validation artifact was modified after
    ``aggregate.py`` wrote the verdict (e.g. artifacts from two runs accidentally combined in CI),
    the recomputed digest will not match and we refuse to publish: a PASS status must never be
    attached to inputs that were not the ones the verdict was computed over (Codex P1, PR #43).

    Mirrors ``aggregate.py:compute_attestation`` exactly (``sha256-canonical-json-v1``), kept
    self-contained so this tool stays stdlib-only. A run with no stored attestation (aggregated
    before attestation existed) cannot be checked, so it is allowed through with the check skipped."""
    att = verdict.get("attestation") if isinstance(verdict, dict) else None
    if not isinstance(att, dict) or not att.get("digest"):
        return  # nothing to verify against — an older run without an attestation
    files = {}
    for root, _dirs, names in os.walk(run_dir):
        for name in names:
            if not name.endswith(".json"):
                continue
            path = os.path.join(root, name)
            rel = os.path.relpath(path, run_dir).replace(os.sep, "/")
            if rel == "verdict.json":  # the output is never one of its own inputs
                continue
            with open(path, "rb") as fh:
                raw = fh.read()
            try:
                canon = json.dumps(json.loads(raw.decode("utf-8")), sort_keys=True,
                                   separators=(",", ":"), ensure_ascii=False)
                files[rel] = hashlib.sha256(canon.encode("utf-8")).hexdigest()
            except (ValueError, UnicodeDecodeError):
                files[rel] = "raw:" + hashlib.sha256(raw).hexdigest()
    manifest = "\n".join("%s  %s" % (sha, rel) for rel, sha in sorted(files.items()))
    digest = hashlib.sha256(manifest.encode("utf-8")).hexdigest()
    if digest != att.get("digest"):
        stored = att.get("files") if isinstance(att.get("files"), dict) else {}
        drift = sorted(rel for rel in set(stored) | set(files) if stored.get(rel) != files.get(rel))
        raise ValueError("run attestation mismatch: stored digest %s, recomputed %s — artifacts "
                         "changed after aggregate.py wrote the verdict; refusing to publish "
                         "(drifted: %s). Re-run aggregate.py or verify with --check-digest."
                         % (att.get("digest"), digest, ", ".join(drift[:10]) or "?"))


def _sha_matches(a, b):
    """True when two commit SHAs identify the same commit, tolerating short vs full form: compare
    case-insensitively and accept when one is a hex prefix of the other (a 7-char ``--sha`` against
    a 40-char PR head)."""
    a, b = (a or "").lower(), (b or "").lower()
    return bool(a) and bool(b) and (a == b or a.startswith(b) or b.startswith(a))


def publish(run_dir, ctx, client, secrets=()):
    """Reconcile the PR to reflect ``run_dir``. Returns a plan dict; ``client`` performs (or, for
    ``DryRunClient``, records) the writes. ``ctx`` = {pr, commit_sha, target_url, fail_on}.

    Exit-code intent is in the returned ``exit_code`` (mirrors the gate's fail-on semantics); the
    commit status state always reflects the true verdict.
    """
    run = load_run(run_dir)
    # Integrity gate: never publish a verdict whose inputs drifted after it was computed.
    _verify_attestation(run_dir, run["verdict"])
    verdict = _verdict_of(run)
    run_id = _text(run["verdict"].get("run_id") or os.path.basename(run_dir.rstrip("/")))
    repo = ctx.get("repo", "")
    pr = ctx["pr"]
    sha = ctx.get("commit_sha")
    write_capable = not isinstance(client, DryRunClient)

    # Bind publication to the reviewed PR head. In a `pull_request` workflow $GITHUB_SHA is GitHub's
    # synthetic merge commit, not the head that was reviewed; attaching a PASS to it (or to any
    # `--sha` that is not the PR head) would mark bytes the run never saw. Fetch the PR head and refuse
    # to publish to a different commit (Codex P1, PR #43). We fail only on a *confirmed* mismatch — if
    # the head cannot be resolved we do not block, so the tool never becomes unavailable when the PR
    # read is denied. A DryRunClient mutates nothing, so it is not bound.
    if sha and write_capable and hasattr(client, "get_pull"):
        try:
            pull = client.get_pull(pr)
        except GitHubError:
            pull = None
        head = (pull or {}).get("head") if isinstance(pull, dict) else None
        head_sha = head.get("sha") if isinstance(head, dict) else None
        if isinstance(head_sha, str) and head_sha and not _sha_matches(sha, head_sha):
            raise GitHubError(0, "refusing to publish: --sha %s is not the head of PR #%d (%s). In a "
                                 "pull_request workflow pass github.event.pull_request.head.sha, not "
                                 "github.sha (the merge commit)." % (sha, pr, head_sha))

    findings = collect_findings(run)

    # split findings into anchorable (have file+line) and not
    anchorable = [e for e in findings if e["file"] and e["line"]]
    unanchored = [e for e in findings if not (e["file"] and e["line"])]

    plan = {"verdict": verdict, "created": 0, "updated": 0, "deleted": 0,
            "summary_retired": 0, "unanchored": len(unanchored),
            "status_state": _STATUS_STATE[verdict]}

    # Ownership is proven by comment *author*, not the public marker alone, so this tool never edits
    # or deletes a human's comment that merely quotes a marker (panel findings security-1 /
    # correctness-3). ``whoami`` (GET /user) resolves that author — but a *write-capable* token can be
    # denied /user (a default GitHub Actions ``GITHUB_TOKEN`` 403s it), which would leave the identity
    # unknown and silently collapse ownership back to marker-only. When that happens, bootstrap our
    # identity from a write we control: author the verdict summary first and read our own login back
    # from the response, then reconcile everything else by that author. A ``DryRunClient`` mutates
    # nothing, so it stays on the harmless marker-only path and is never bootstrapped.
    owner_login = client.whoami() if hasattr(client, "whoami") else None
    summary_cid = None
    if owner_login is None and write_capable:
        bootstrap = client.create_issue_comment(
            pr, _scrub(render_verdict_summary(run, repo, pr, unanchored), secrets))
        owner_login = (bootstrap.get("user") or {}).get("login") if isinstance(bootstrap, dict) else None
        bootstrap_cid = bootstrap.get("id") if isinstance(bootstrap, dict) else None
        if owner_login is None:
            raise GitHubError(0, "cannot resolve the authenticated identity (GET /user denied and the "
                                 "created comment carried no author); refusing to reconcile comments by "
                                 "marker alone, which could touch a human's comment")
        # Keep a *stable* summary comment id across re-runs rather than creating a fresh one each time
        # (which would re-notify subscribers and lose the discussion anchor — CodeRabbit, PR #43).
        # Enumerate the raw list (not _managed_index, which collapses every verdict-marker comment
        # onto one key); of our prior summaries (excluding the throwaway bootstrap), keep the OLDEST as
        # the anchor and update it in place below, deleting the bootstrap and any extra older summaries
        # so exactly one stable id survives. Comments authored by anyone else are untouched.
        owned = []
        for c in client.list_issue_comments(pr):
            if not isinstance(c, dict):
                continue
            body = c.get("body") or ""
            author = (c.get("user") or {}).get("login") if isinstance(c.get("user"), dict) else None
            cid = c.get("id")
            if (MANAGED in body and VERDICT_MARKER in body and author == owner_login
                    and isinstance(cid, int) and cid != bootstrap_cid):
                owned.append(cid)
        if owned:
            owned.sort()  # GitHub comment ids increase monotonically → the smallest is the oldest
            summary_cid = owned[0]
            for cid in owned[1:] + [bootstrap_cid]:  # retire extras + the throwaway bootstrap comment
                if isinstance(cid, int):
                    client.delete_issue_comment(cid)
                    plan["summary_retired"] += 1  # issue-comment retirement, not an inline deletion
            plan["summary"] = "updated"
        else:
            summary_cid = bootstrap_cid  # first run on this PR: the bootstrap comment IS the summary
            plan["summary"] = "created"

    def _create_inline(e):
        """Create one inline comment; a 422 (line not in the diff) falls back to the summary."""
        try:
            client.create_review_comment(pr, sha, e["file"], e["line"],
                                          _scrub(render_finding_body(run_id, e), secrets))
            plan["created"] += 1
        except GitHubError as exc:
            if exc.status == 422:
                unanchored.append(e)
            else:
                raise

    # 1) inline finding comments (reconcile by key = file+title; ours only, by author)
    existing = _managed_index(client.list_review_comments(pr), "<!-- ar-finding:", owner_login)
    desired = {}
    for e in anchorable:
        prev = existing.get(e["key"])
        if prev is not None:
            # An inline comment's anchor line cannot be changed by PATCH. If the cited line drifted
            # across pushes — or the API returned the existing comment with ``line: null`` (outdated,
            # no longer in the diff) — refreshing the body in place would leave it pointing at the old
            # or unknown line; delete and re-anchor instead. ``e["line"]`` is always a real int here
            # (``e`` is anchorable), so ``prev["line"] != e["line"]`` also catches ``prev["line"] is
            # None`` (panel findings correctness-1 / correctness-2, re-review).
            if sha and prev["line"] != e["line"]:
                client.delete_review_comment(prev["id"])
                plan["deleted"] += 1
                _create_inline(e)
            else:
                client.update_review_comment(prev["id"],
                                             _scrub(render_finding_body(run_id, e), secrets))
                plan["updated"] += 1
        elif sha:
            _create_inline(e)
        else:
            unanchored.append(e)
        desired[e["key"]] = True
    # Retire managed finding comments whose finding is gone — but only when this run's panel actually
    # completed. If reviewer reports are missing (a transport/cost abort left the panel partial),
    # collect_findings sees fewer findings than a prior complete run did; missing panel output is not
    # proof an issue was fixed, so deleting those comments would erase still-valid warnings. Preserve
    # them when coverage does not prove completion, and record that reconciliation was held (Codex P1,
    # PR #43).
    cov = run["verdict"].get("coverage") if isinstance(run["verdict"].get("coverage"), dict) else {}
    pcov = cov.get("panel") if isinstance(cov.get("panel"), dict) else {}
    req = pcov.get("roles_required") if isinstance(pcov.get("roles_required"), list) else []
    filled = pcov.get("roles_filled") if isinstance(pcov.get("roles_filled"), list) else []
    panel_complete = bool(req) and set(req).issubset(set(filled))
    stale = [meta["id"] for key, meta in existing.items() if key not in desired]
    if panel_complete:
        for cid in stale:
            client.delete_review_comment(cid)
            plan["deleted"] += 1
    elif stale:
        plan["reconcile_held"] = len(stale)  # prior finding comments preserved (panel incomplete)

    # 2) verdict summary comment. If we already created it above to bootstrap our identity, finalize
    #    that same comment now that ``unanchored`` is complete (inline 422s may have appended to it);
    #    otherwise upsert by the single verdict marker in the normal way.
    summary_body = _scrub(render_verdict_summary(run, repo, pr, unanchored), secrets)
    if summary_cid is not None:
        client.update_issue_comment(summary_cid, summary_body)
    else:
        sidx = _managed_index(client.list_issue_comments(pr), VERDICT_MARKER, owner_login)
        scid = sidx.get("_", {}).get("id")  # verdict marker has no per-item key
        if scid is not None:
            client.update_issue_comment(scid, summary_body)
            plan["summary"] = "updated"
        else:
            client.create_issue_comment(pr, summary_body)
            plan["summary"] = "created"

    # 3) commit status — state reflects the true verdict; the description states only what the
    #    verdict is (not a specific unverified cause), pointing readers at the summary for detail. A
    #    PASS can still carry non-blocking findings shown in the summary, so it must not claim the
    #    review was "clear" — it says only what a PASS proves (panel finding correctness-4, re-review).
    if sha:
        desc = {"PASS": "Verdict PASS — required gates passed; see the review summary.",
                "FAIL": "Verdict FAIL — required checks did not pass; see the review summary.",
                "BLOCKED": "Verdict BLOCKED — verification incomplete; see the review summary."}[verdict]
        client.set_status(sha, _STATUS_STATE[verdict], desc, ctx.get("target_url"))
        plan["status_set"] = True
    else:
        # No head SHA → a commit status cannot be set. Surface it (not silently) so a caller knows
        # the verdict reached the PR only via the summary comment (panel finding correctness-4).
        plan["status_set"] = False
        plan["status_skipped_reason"] = "no commit sha (pass --sha or set $GITHUB_SHA)"

    plan["unanchored"] = len(unanchored)
    plan["unanchored_entries"] = unanchored  # so the caller (job summary) can render them too
    plan["exit_code"] = verdict_exit_code(verdict, ctx.get("fail_on", "blocked"))
    return plan


def verdict_exit_code(verdict, fail_on):
    """Exit code mirroring the gate: PASS=0. ``fail_on='blocked'`` (default) fails on FAIL and
    BLOCKED; ``fail_on='fail'`` tolerates BLOCKED (exit 0) but still fails on FAIL."""
    if verdict == "PASS":
        return 0
    if verdict == "FAIL":
        return 1
    return 0 if fail_on == "fail" else 2  # BLOCKED


# --------------------------------------------------------------------------- cli

def _resolve_repo(arg):
    # Shared validation lives in _check_repo (also enforced inside GitHubClient); this adds the
    # CLI-specific source resolution and error hint.
    repo = arg or os.environ.get("GITHUB_REPOSITORY", "")
    try:
        return _check_repo(repo)
    except ValueError:
        raise ValueError("repo must be 'owner/name' with no path/query characters (got %r); "
                         "set --repo or $GITHUB_REPOSITORY" % (repo,)) from None


def _resolve_sha(arg):
    try:
        return _check_sha(arg)
    except ValueError:
        raise ValueError("--sha must be 7-64 hex characters (got %r); set --sha or $GITHUB_SHA"
                         % ((arg or "").strip(),)) from None


def main(argv=None):
    ap = argparse.ArgumentParser(description="Publish an adversarial-review run to a GitHub PR.")
    ap.add_argument("run_dir", help="the run dir written by aggregate.py (holds verdict.json)")
    ap.add_argument("--repo", default=None, help="owner/name (default: $GITHUB_REPOSITORY)")
    ap.add_argument("--pr", type=int, required=True, help="pull request number")
    ap.add_argument("--sha", default=os.environ.get("GITHUB_SHA", ""),
                    help="head commit SHA for inline anchors + status (default: $GITHUB_SHA)")
    ap.add_argument("--fail-on", choices=["fail", "blocked"], default="blocked",
                    help="exit non-zero on FAIL only, or on FAIL and BLOCKED (default)")
    ap.add_argument("--api-url", default=os.environ.get("GITHUB_API_URL", "https://api.github.com"))
    ap.add_argument("--target-url", default="", help="optional URL for the commit status")
    ap.add_argument("--dry-run", action="store_true", help="compute the plan but perform no writes")
    args = ap.parse_args(argv)

    try:
        repo = _resolve_repo(args.repo)
        sha = _resolve_sha(args.sha)
    except ValueError as exc:
        print("pr_publish: %s" % exc, file=sys.stderr)
        return 2

    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN") or ""
    dry = args.dry_run or not token
    client = DryRunClient() if dry else GitHubClient(token, repo, args.api_url)
    # scrub any credential-looking env value out of every body, defensively. The name allowlist
    # covers password/credential-style variables too — a `DB_PASSWORD` is as much a secret as an
    # API token and must not survive into a comment or the job summary. Markers are matched
    # case-insensitively; `KEY` already subsumes `APIKEY`/`PRIVATE_KEY`. Deliberately narrow (no bare
    # `PWD`/`AUTH`/`PASS`) so common non-secrets like `$PWD` or `AUTHOR` are not needlessly redacted.
    _SECRET_NAME_MARKERS = ("TOKEN", "KEY", "SECRET", "PASSWORD", "PASSWD", "CREDENTIAL", "PASSPHRASE")
    secrets = [v for k, v in os.environ.items()
               if v and any(m in k.upper() for m in _SECRET_NAME_MARKERS)]

    ctx = {"repo": repo, "pr": args.pr, "commit_sha": sha or None,
           "target_url": args.target_url or None, "fail_on": args.fail_on}
    try:
        plan = publish(args.run_dir, ctx, client, secrets=secrets)
    except (FileNotFoundError, ValueError) as exc:
        print("pr_publish: cannot read run: %s" % exc, file=sys.stderr)
        return 2
    except GitHubError as exc:
        print("pr_publish: %s" % exc, file=sys.stderr)
        return 2

    # optional: also append the verdict markdown to the Actions job summary — through the SAME
    # secret scrub as every posted body, so a leaked credential cannot reach the summary either
    # (panel findings security-4 / correctness-5).
    step_summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if step_summary and not dry:
        try:
            run = load_run(args.run_dir)
            # reuse the unanchored findings publish() already computed so the job summary shows the
            # same "not anchorable to the diff" section the PR comment does (not an empty one)
            unanchored = plan.get("unanchored_entries", [])
            with open(step_summary, "a", encoding="utf-8") as fh:
                fh.write(_scrub(render_verdict_summary(run, repo, args.pr, unanchored), secrets) + "\n")
        except OSError:
            pass

    mode = "DRY-RUN" if dry else "published"
    note = "" if plan.get("status_set") else " [status skipped: %s]" % plan.get(
        "status_skipped_reason", "n/a")
    print("pr_publish: %s %s#%d verdict=%s (summary %s, +%d/~%d/-%d inline, -%d summary, "
          "%d unanchored)%s"
          % (mode, repo, args.pr, plan["verdict"], plan.get("summary", "?"),
             plan["created"], plan["updated"], plan["deleted"],
             plan.get("summary_retired", 0), plan["unanchored"], note))
    return plan["exit_code"]


if __name__ == "__main__":
    sys.exit(main())
