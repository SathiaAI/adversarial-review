# Final release report template

Write `report.md` in the run directory using exactly this structure. The Verdict section
embeds `verdict.json` verbatim — the report never states a verdict the aggregator did
not compute. Plain English throughout; the audience may not be the person who ran this.

```markdown
# Adversarial Review Report — <product> — <date>

## Verdict

<verdict.json, verbatim, in a code block>

<One paragraph of prose context. If you disagree with the computed verdict, say so here
and why — the verdict above still stands until artifacts change.>

## Change reviewed

<What the change does, diff ref, size, acceptance criteria. Risk tier and why.>

## Independence

Development models/providers (excluded): <list>
Panel: <role — exact model slug — provider family>, per panel/plan.json.
Substitutions or degraded-mode authorization, if any, and who authorized.
Transport and privacy routing used (direct/proxy/MCP; default/deny/zdr).

## Deterministic gates

<Table: gate — required-at-tier — result (exit code) — one-line summary. Include
mutation score vs threshold and DAST result when applicable. Note gates ingested from
CI rather than run here.>

## Findings

<High/critical first. For each deduped issue: title, severity, finding IDs, authors,
classification, evidence one-liner, fix + regression test if confirmed, concurrence if
dismissed. Then medium/low triage: kept-as-is / fix-later / fixed, one line each.>

## Rebuttal round (CRITICAL only)

<Per contested finding: who refuted/corroborated/extended, and what reproduction settled.>

## Suppressions and accepted risks

<Each suppression: finding ID, evidence, owner, expiry. "None" if none.>

## Enforcement

<Branch protection verification result, or the exact missing configuration/access.>

## Residual risks and attestations

<Union of reviewers' top_residual_risks and areas_not_reviewed — what this review did
NOT establish.>

## Cost

<Per-reviewer tokens (and cost when the router reports it), total.>
```
