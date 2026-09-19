# Jev triage layer (`scripts/jev_triage.py`)

TypeSafe Jev (`typesafe/jev-1.13`) is a fast, cheap **structured-decision** model served by
OpenRouter at a bespoke endpoint (`POST https://openrouter.ai/api/alpha/decisions`) — **not**
a chat model; it does not speak `/chat/completions`. A call takes a `state` (the material to
decide over) and a `questions` map (each question typed `noul` — a 0.0–1.0 likelihood —
`choice`, or `score`) and returns one typed answer per question, typically in well under a
second and at roughly $0.00003/call.

`jev_triage.py` uses Jev to cut the *volume* of what you, the operator, have to look at
between panel stages — never to decide anything. Read this alongside `SKILL.md` Step 3/4;
it assumes you already know the pipeline's non-negotiable rule:

> **`aggregate.py` still computes PASS/FAIL/BLOCKED from recorded artifacts alone. No Jev
> output ever reaches that computation directly, and no Jev output can dismiss a finding.**

Three independent guarantees make this true regardless of what Jev says:

1. **Jev priors never feed `aggregate.py`'s fail/blocked logic.** `verdict.md` displays them
   (see *Jev triage priors in verdict.md* below) strictly for the operator's convenience —
   `collect_jev_priors()` reads `triage/<id>.json` and writes into the markdown only, never
   into `counts`, `blocked`, or `notes` that affect the verdict.
2. **Jev never closes a finding.** `triage` only prioritizes a worklist; `patch-check` only
   *proposes* a finding as resolved — Claude still inspects the patch and still updates the
   `validation/<slug>.json` record by hand. The existing rule that a high/critical
   `false_positive` requires a written concurrence from an uninvolved panel model is
   untouched — Jev is not that model and its output cannot substitute for it.
3. **Every command is fail-closed.** Any Jev error — no key, a transport failure, a
   malformed response, an out-of-range or missing answer — is treated as the *more cautious*
   outcome: `is_real=1.0`, `needs_human=1.0`, `fix_is_obvious=0.0` for `triage`; `contested=1.0`,
   `rebuttal_would_change_outcome=1.0` for `rebuttal-gate` (so the finding stays in the
   rebuttal round); `resolved_by_patch=0.0`, `patch_introduces_new_risk=1.0` for
   `patch-check` (so the finding stays open and is flagged risky). A broken or unreachable
   Jev degrades every command to "do the old, more thorough thing" — never to a silent pass.

## Credentials — independently configurable, and fully optional

adversarial-review is a portable OSS skill, not built only around one operator's
OpenRouter account — not every adopter has (or wants) an OpenRouter key, so Jev's
credentials are resolved independently of the reviewer panel's, with three tiers
(`jev_available()`/`_jev_credentials()` in `jev_triage.py`):

1. **`AR_JEV_API_KEY`** (or **`AR_JEV_KEY_FILE`**, read the same way `AR_KEY_FILE` is for
   the panel) — a dedicated Jev key, valid against whatever `AR_JEV_BASE_URL` /
   `AR_JEV_ENDPOINT` points at.
2. **No dedicated key**: fall back to the reviewer panel's own key
   (`panel.api_config()`) — but **only** when Jev's resolved endpoint is the **same host**
   the panel itself is configured against (`AR_BASE_URL`). A key an operator configured
   for one host (default OpenRouter, or a private/self-hosted proxy) is never silently
   forwarded to a different host just because Jev's own base URL happens to differ or was
   left at its default. When this tier is used, a one-line notice is printed to stderr
   (once per process) so it's never silent.
3. **Neither applies** (including `AR_JEV_DISABLE=1`, an explicit off switch): Jev is
   simply **unavailable** — this is not an error. Every command here refuses cleanly
   (`require_jev_key()` exits 2, no partial triage, no Jev call, no file write), and
   nothing else in the pipeline requires Jev at all — `SKILL.md` documents Jev triage as
   optional, skippable by going straight to Step 4 by hand.

`jev_available()` is the mandatory, side-effect-free (no network) preflight: it returns
`{"available": bool, "mode": "dedicated"|"panel_fallback"|"disabled"|"unavailable",
"reason": str|None}` and never carries a key, so it's safe to call, print, or log before
deciding whether to run any Jev command at all.

**Endpoint.** `AR_JEV_BASE_URL` (default OpenRouter, `https://openrouter.ai/api`) selects
the endpoint by the same base+`/alpha/decisions`-path convention the credential tiers
above assume. `AR_JEV_ENDPOINT` is a full-URL override for a decisions-capable relay that
doesn't follow that convention — for example TypeSafe's own direct API
(`https://api.typesafe.ai/v1/systemone`, `docs.typesafe.ai/api`), a separate product from
OpenRouter's beta integration of Jev, with its own (currently waitlisted, batch-issued, no
published free tier) signup — set both `AR_JEV_API_KEY` and `AR_JEV_ENDPOINT` to use it;
`AR_JEV_BASE_URL` is ignored whenever `AR_JEV_ENDPOINT` is set.

State sent to Jev is capped at roughly 25k tokens (approximated in characters, at a
deliberately low chars-per-token estimate so the char cap stays conservative even when the
approximation is off — stdlib has no tokenizer). Shrinkable fields (the diff excerpt, a
patch, the context summary, evidence text) are truncated head+tail, never the finding's
identity fields (id/title/severity). The diff a finding cites is narrowed to just the
unified-diff hunk covering the reported line — see *Cited-hunk extraction* below — so Jev
sees the relevant few dozen lines, not the whole diff.

## (a) `jev_triage.py triage [<run-dir>] [--context-file context.md]`

Run after `panel.py run`, before Step 4 (Validate findings). One Jev call per finding
across every recorded `panel/<role>.json`. For each finding, Jev answers:

- **`is_real`** (noul) — genuine defect, not a false positive or style nit.
- **`severity`** (score, `low|medium|high|critical`) — Jev's own severity estimate.
- **`duplicate_of`** (choice, over the ids of earlier findings **in the same file**, plus
  `"none"`) — same underlying issue as an earlier finding. Findings are processed
  role-then-order so grouping is deterministic; "earlier" means earlier in that fixed
  iteration order, not earlier in wall-clock time.
- **`needs_human`** (noul) — resolving this requires product/business judgment a reviewer
  can't make.
- **`fix_is_obvious`** (noul) — the fix is small, mechanical, no design choice involved.

Writes one `triage/<finding-id>.json` per finding:

```json
{
  "finding_id": "security-1", "role": "security", "component": "api/invoices.py",
  "reviewer_severity": "high", "title": "IDOR on invoice endpoint",
  "release_blocking": true,
  "jev": {
    "model": "typesafe/jev-1.13", "called_at": "ISO-8601", "error": null, "cost": 0.00003,
    "is_real": 0.92, "severity": {"score": 2.4, "label": "high", "legend": {"0": "low", "1": "medium", "2": "high", "3": "critical"}},
    "duplicate_of": {"choice": "none", "confidence": 0.95, "probabilities": {"none": 0.95}},
    "needs_human": 0.1, "fix_is_obvious": 0.3
  }
}
```

`jev.error` is non-null whenever the fail-closed defaults above were applied (either no
answer came back, or an answer had the wrong shape) — check it before trusting a record's
numbers. `triage/_summary.json` records the run's model, finding count, error count, and
total Jev spend.

Prints a ranked worklist to prioritize Step 4, not to replace it:

- **High/critical, likely real** (`reviewer_severity` high/critical **and** `is_real ≥ 0.6`),
  sorted by `is_real` descending — validate these first.
- **Possible duplicate clusters** — findings sharing a non-`"none"` `duplicate_of.choice`.
- **Candidate false positives** (`reviewer_severity` medium/low **and** `is_real < 0.25`) —
  labeled explicitly as *"still need a validation record; never auto-dismissed"*. A
  candidate false positive still gets a `validation/<slug>.json` like any other finding;
  Jev only moves it to the bottom of the pile, it never removes the requirement.
- A count of findings that hit a Jev error and got fail-closed defaults, pointing at the
  `triage/<id>.json` files for detail.

## (b) `jev_triage.py rebuttal-gate [<run-dir>] [--context-file context.md]`

Replaces the old *"contest every high/critical finding"* blanket rule with a per-finding
decision, over the exact same digest `panel.py rebuttal` would otherwise contest
(`panel.high_critical_digest()`). For each high/critical finding, Jev answers:

- **`contested`** (noul) — reviewers from other roles would materially disagree.
- **`rebuttal_would_change_outcome`** (noul) — a rebuttal round could plausibly change
  whether the finding is confirmed, dismissed, or its severity.

A finding runs through the rebuttal round when `contested ≥ 0.5` **or**
`rebuttal_would_change_outcome ≥ 0.5` — **or on any Jev error** (fail-closed: an error
forces both values to `1.0`, so the finding is never silently skipped). Writes
`rebuttal/plan.json`:

```json
{
  "generated_at": "ISO-8601", "model": "typesafe/jev-1.13",
  "decisions": {"security-1": {"contested": 0.8, "would_change": 0.6, "error": null, "decision": "run"}},
  "required_finding_ids": ["security-1"], "skipped_finding_ids": [],
  "jev_cost_usd": 0.00006
}
```

and `rebuttal/digest.json` — the same digest shape as `panel.high_critical_digest()`,
filtered to `required_finding_ids` only. Feed it straight to `panel.py rebuttal
--digest-file rebuttal/digest.json` to contest only the gated subset; without
`--digest-file`, `panel.py rebuttal` is unchanged and contests every high/critical finding
as before.

**This is the piece `aggregate.py`'s `check_rebuttal()` actually reads** (via
`_rebuttal_jev_gate()`, which loads `rebuttal/plan.json` and validates its shape):

- No `rebuttal/plan.json`, one that isn't a well-formed object with list-of-strings
  `required_finding_ids`/`skipped_finding_ids`, **or one whose `required_finding_ids` ∪
  `skipped_finding_ids` doesn't name every real high/critical finding id in this run's own
  `panel/<role>.json` reports** → **treated as absent** → `check_rebuttal()` falls back to
  the pre-Jev rule (rebuttal required whenever *any* high/critical finding exists) — byte-
  identical behavior to a run that never used Jev triage at all.
- A present, well-formed, fully-covering `rebuttal/plan.json` → rebuttal is required only
  when `required_finding_ids` is non-empty.

The coverage check closes a real bypass: `required_finding_ids=[]` alone used to satisfy
the shape check regardless of whether it reflected anything Jev actually decided — a
fabricated or stale `rebuttal/plan.json` claiming "nothing needs contest" could otherwise
suppress a required rebuttal round entirely, with no Jev call ever having evaluated the
findings it silently waived. Requiring every real high/critical id to appear in one of the
two lists closes that without any signature or hash — the file already has to name every
finding to "win" either way. Because a malformed, missing, or incomplete gate file falls
back to the *strictly more demanding* blanket rule, and because `rebuttal-gate` itself only
ever adds findings to `required_finding_ids` on error, a corrupted or adversarial gate file
can only ever require **more** verification, never less.

**`panel.py rebuttal --digest-file` never trusts the file's content, only its selection.**
Every entry is cross-checked against this run's own current `panel.high_critical_digest()`
(freshly recomputed from `panel/<role>.json`, not from the file): an id that isn't a real
current high/critical finding, a duplicate id, or an entry whose `title`/`severity`/`file`/
`line`/`evidence`/`scenario`/`author_role` doesn't match the real finding's own content
dies loudly (`--digest-file references finding id ... not a current high/critical
finding`, or `... does not match this run's current panel/<role>.json content`) rather than
silently contesting a fabricated finding or substituting altered content into the rebuttal
round. A legitimate `rebuttal/digest.json` — the one `rebuttal-gate` itself writes — is
always a straight subset of the real digest, so this never rejects normal use.

If there are no high/critical findings at all, `rebuttal-gate` writes an empty plan/digest
and makes no Jev calls — nothing to gate.

## (c) `jev_triage.py patch-check <run-dir> <patch>`

Run before the next round, once you have a patch/diff addressing this round's `confirmed`
findings. One Jev call per `confirmed` `validation/<slug>.json` record (skips
`concur-request.json` and anything not classified `confirmed`), checking the given patch
against that record's `evidence`/`resolution`. Jev answers:

- **`resolved_by_patch`** (noul) — this patch fixes the confirmed finding.
- **`patch_introduces_new_risk`** (noul) — this patch introduces a new defect/risk not
  present before.

Writes `patch_check/round-N.json` (`N` auto-increments per run directory), bound to the
exact bytes checked: `patch_sha256` is the sha256 of the patch file as read, and each
item's `validation_sha256` is the sha256 of that `validation/<slug>.json` record as it
stood at check time. Nothing in the pipeline reads these back automatically today
(`patch_check/` is informational, read by a human/Claude, same as `triage/` and
`rebuttal/plan.json`) — but they let a later "does this round still describe the patch I'm
about to apply / the validation record as it stands now" question be answered by
recomputing and comparing, instead of trusting the round file on faith:

```json
{
  "generated_at": "ISO-8601", "round": 1, "patch": "fix.diff",
  "patch_sha256": "…", "model": "typesafe/jev-1.13",
  "jev_cost_usd": 0.00003,
  "items": [
    {"slug": "security-1", "finding_ids": ["security-1"],
     "resolved_by_patch": 0.91, "patch_introduces_new_risk": 0.1,
     "status": "resolved (operator must confirm)", "error": null,
     "validation_sha256": "…"}
  ]
}
```

`status` buckets `resolved_by_patch` for the human-readable summary:
`≥ 0.8` → *"resolved (operator must confirm)"* — a **proposal**, not a closed finding; `< 0.4`
→ *"still open"*; in between → *"still open (ambiguous — verify by hand)"*. The label says
"operator", not "Claude" specifically, because this skill is portable across supported
agents (Codex, Cursor, Copilot, etc. — see the credentials section above); whichever agent
is running the skill is the one that must confirm.
`patch_introduces_new_risk ≥ 0.5` flags an item for the panel regardless of its resolution
status.

Prints a one-screen round summary a non-coder can read: how many findings Jev proposes as
resolved (the operator still confirms each and still updates its `validation/<slug>.json`), how
many are still open (with the one-line reason), and how many carry a new-risk flag that
should go back to the panel. No confirmed findings on record → prints "nothing to check"
and writes an empty round record; no Jev calls made.

## Jev triage priors in `verdict.md`

When `triage/` has recorded records for this run, `aggregate.py` adds a **"## Jev triage
priors"** section to `verdict.md`, one line per triaged finding:
`` `<finding_id>`: is_real=0.92, jev_severity=high, duplicate_of=security-1, jev_error ``
(the last two segments only appear when applicable). This is read-only display, assembled
by `collect_jev_priors()` directly from `triage/<id>.json` — it is never consulted by the
functions that decide PASS/FAIL/BLOCKED, and its absence (no `triage/` directory, or a run
that never used Jev) simply omits the section — `verdict.md` for a Jev-free run is
unaffected.

## Cited-hunk extraction (`extract_cited_hunk`)

Best-effort: locates the unified-diff hunk for a finding's `file` that covers its `line` in
the new-file numbering (falling back to the file's first hunk if the line isn't inside any
hunk header's declared range, and to `""` if the file isn't found in the diff at all). A
miss here only makes the state Jev sees *less scoped* — it never fabricates or misattributes
content — so this one helper fails **open** by design, unlike every Jev call itself, which
fails **closed**.

## Design notes / non-goals

- **No retries.** A Jev call that errors is recorded as an error and defaulted, not retried
  — Jev calls are cheap and fast enough that a retry loop would add complexity without a
  clear benefit; if Jev is down, every command degrades to its fail-closed default and keeps
  working correctly, just without the triage speedup.
- **Not a substitute for the reviewer panel or Step 4.** Jev never reviews code itself — it
  only classifies/prioritizes findings the panel already raised, using the same evidence the
  panel produced. It has no visibility into the repo beyond what `_triage_one`,
  `rebuttal-gate`, and `patch-check` explicitly hand it in `state`.
- **Stdlib only, Python 3.9+**, matching the rest of the skill (CONTRIBUTING.md rule #1).
- **Cost is tiny and tracked.** Each command sums its own Jev spend (`jev_cost_usd`) into
  its summary/plan/round artifact; at ~$0.00003/call even a large panel's full triage costs
  a fraction of a cent. This is separate from, and far smaller than, the reviewer panel's
  cost cap (`AR_MAX_COST_USD`, `references/config.md`) — Jev calls are not currently metered
  against that cap.
- **Privacy/ZDR parity with the reviewer panel.** Every Jev call for a SENSITIVE/CRITICAL
  run sends the same `provider` data-handling preferences (`data_collection: deny`, plus
  `zdr: true` for CRITICAL) the reviewer panel sends for its own calls
  (`panel.privacy_provider_prefs`) — the run's risk tier is never a lower-privacy path just
  because it went through Jev instead of the panel.
- **Finding ids are sanitized before touching the filesystem.** A finding's `id` comes from
  reviewer-model output, not trusted input, and `triage` writes one file per finding named
  after it — `_safe_finding_id()` rejects anything outside a conservative charset, any
  reserved name (`_summary`), and any id already used this run, falling back to a
  disambiguated `<role>-unnamed-N` name instead. The finding's own record still stores the
  literal, unsanitized id in `finding_id` — only the filename is constrained.
