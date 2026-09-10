# The `ai-defects` gate — fail-closed by construction

The `ai-defects` gate runs a **deeper AI-code verifier** over a change and records a gate
result. It is a **category, not a vendor**: it runs a **pinned CLI adopted by command** in CI
behind a fixed, closed argument list. This page documents its fail-closed contract for
operators. (Landed across SAT-1103 and its follow-up; see the `CHANGELOG`.)

## The tri-state exit
The port wrapper (`scripts/ai_defects_verify.py`) collapses the whole outcome space to three
states — there is no fourth, and no silent skip:

| Exit | Status | When |
|---|---|---|
| `0` | **PASS** | The verifier ran and reported a complete, clean result. An empty diff also records PASS (reason `empty-diff`). |
| `1` | **FAIL** | The verifier ran and found a defect. |
| `2` | **BLOCKED** | Anything that prevents a trustworthy PASS/FAIL. |

**BLOCKED covers**, among others: a missing or empty pin (`AI_DEFECTS_PIN_VERSION` /
`AI_DEFECTS_PIN_DIGEST`), a digest mismatch, a missing or non-executable binary, an
`incomplete: true` summary *even on exit 0*, a timeout, an unreadable input, bad argv, an
unset run dir, or any unrecognized exit code. A BLOCKED gate is **unknown, not wrong** — it is
never rounded up to PASS.

## Why closed argv
The wrapper invokes the pinned binary with exactly `--run-dir <dir> --diff-file <file>` — no
shell, no wildcards, no `$*` passthrough. The verifier is a program run by command, not a
string interpolated into a shell, so shell metacharacters in a path or filename cannot create extra
`argv` entries or a shell command (the values are still passed as the two fixed arguments). A relative
or wildcard binary path is refused.

## Diff-ref scope resolution is fail-closed too
Resolving the git `diff-ref` into a changed-paths list lives in `scripts/ai_defects_diffscope.py`
(a CI-tested helper, not inline workflow shell that CI never runs). A **bad, missing, empty,
option-prefixed (`-x`), or bare-pathspec (`README.md`)** diff-ref exits **BLOCKED and writes no
`changed_paths.txt`** — so an unresolvable ref can **never** become an empty-diff PASS. A valid
range writes the list; a valid no-change range writes an empty list (a legitimate PASS).

## How it records without touching the verdict authority
`gate.py run` takes an opt-in, backward-compatible `--exit-map` (`CODE=STATUS`, `*` =
catch-all for unmapped nonzero), so the tri-state wrapper records BLOCKED with **no change to
`aggregate.py` or `panel.py`** — the verdict is still computed solely by `aggregate.py`, and
the default gate mapping (exit 0 = PASS, nonzero = FAIL) is unchanged for every existing gate.

## Public-silence
The gate is documented in **port language only** — "ai-defects", "deeper verifier", "port
wrapper", "pinned CLI in CI". A CI job (`scripts/check_ai_defects_public_silence.sh`) fails the
build if a scanner/brand string or a first-party-authorship claim reaches a public surface
(`README*`, `references/**`, `SKILL.md`, workflow names). The pinned binary is installed to the
CI runner only — digest-verified, never committed, never a release asset.

## Operator checklist
- Set the pin (`AI_DEFECTS_PIN_VERSION` + `AI_DEFECTS_PIN_DIGEST`) in CI secrets; an unset pin
  is BLOCKED, by design.
- Treat a BLOCKED result as a real gate outcome to investigate (a missing pin, a bad digest, a
  timeout) — not as a flake to retry until green.
- Keep public docs in port language; extend the brand denylist in the private operator runbook,
  never in public docs.
