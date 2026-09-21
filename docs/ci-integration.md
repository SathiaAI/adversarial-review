# CI integration — GitHub Action & GitLab CI

Wire the computed verdict into your pipeline so a merge is gated by evidence, not by a
human's optimism. The same deterministic gates, the same independent panel, and the same
`aggregate.py` verdict run on **GitHub** and **GitLab** — the only thing that differs is the
YAML around them. On both platforms the rule is identical:

> **The verdict is exactly what `aggregate.py` computes — `0` PASS, `1` FAIL, `2` BLOCKED — exposed
> verbatim as the Action's `exit-code` output and as the GitLab job's exit status.** Whether that
> verdict *fails the job* is a separate, explicit policy: `fail-on` (GitHub) and `allow_failure`
> (GitLab) decide whether a **BLOCKED** blocks the merge or is tolerated during adoption. Without a
> reviewer key the panel is skipped and the verdict is **BLOCKED** — the honest result for an
> un-reviewed change, not a soft pass — unless a deterministic gate already **FAILED**, which takes
> precedence and yields **FAIL**.

- **GitHub** → the composite [`action.yml`](https://github.com/SathiaAI/adversarial-review/blob/main/action.yml), used via [`examples/adversarial-review.yml`](https://github.com/SathiaAI/adversarial-review/blob/main/examples/adversarial-review.yml).
- **GitLab** → the [`examples/.gitlab-ci.yml`](https://github.com/SathiaAI/adversarial-review/blob/main/examples/.gitlab-ci.yml) template.

Both call the same zero-dependency scripts — `panel.py init/assign/run`, `gate.py plan/run/record`,
and `aggregate.py` — so the verdict is computed the same way whichever platform you are on.

---

## GitHub Action

Add a workflow that runs the action on every pull request. Copy
[`examples/adversarial-review.yml`](https://github.com/SathiaAI/adversarial-review/blob/main/examples/adversarial-review.yml)
into `.github/workflows/`:

```yaml
name: adversarial-review
on:
  pull_request:
permissions:
  contents: read
jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0            # the panel reviews a real git range
      - uses: actions/setup-python@v5
        with:
          python-version: '3.12'
      - uses: SathiaAI/adversarial-review@v0   # moving major (auto patch/minor); or pin @v0.2.0 / a full SHA for an immutable ref — see "Version & tag scheme" below
        with:
          risk: NORMAL              # or leave empty to resolve from .adversarial-review.yml
          dev-providers: anthropic  # families that wrote/advised the change — barred from the panel
          gates: |                  # the NORMAL floor is build, unit, secrets, deps, sast — provide all five (adjust commands to your stack)
            build=python -m py_compile $(git ls-files '*.py')
            unit=python -m pytest -q
            secrets=gitleaks detect --no-banner --redact --source .
            deps=pip-audit
            sast=bandit -ll -q -r .
          fail-on: blocked          # gate the merge on FAIL or BLOCKED; use 'fail' to tolerate BLOCKED while adopting
          openrouter-api-key: ${{ secrets.OPENROUTER_API_KEY }}
```

### Inputs

These mirror `action.yml` exactly — do not pass anything not listed here.

| Input | Purpose | Default |
|---|---|---|
| `risk` | Risk tier `NORMAL` \| `SENSITIVE` \| `CRITICAL`. Empty resolves from the repo's `.adversarial-review.yml` policy or `AR_RISK`. | `''` |
| `dev-providers` | Comma list of provider families that **wrote/advised** the change; those families are barred from the reviewer panel. Empty resolves from the policy file or `AR_DEV_PROVIDERS`. | `''` |
| `gates` | Newline-separated `name=command` pairs (e.g. `unit=npm test`). Each runs through `gate.py` so its exit code is recorded; the gate **names** also form the `--require` list. Empty falls back to the policy's `required_gates`. | `''` |
| `fail-on` | `blocked` fails the job on FAIL **or** BLOCKED; `fail` fails only on FAIL and reports BLOCKED as a warning (incremental-adoption mode). | `blocked` |
| `diff-ref` | Git range the panel reviews (needs `fetch-depth: 0`). | `origin/main...HEAD` |
| `product` | Product/change label recorded in `run.json`. | `''` |
| `openrouter-api-key` | OpenRouter key (pass a **secret**). Set → the panel runs. Empty → only gates are recorded and the verdict is **BLOCKED** for missing panel coverage. | `''` |

### Outputs

| Output | Value |
|---|---|
| `verdict` | `PASS`, `FAIL`, or `BLOCKED` — exactly what `aggregate.py` computed. |
| `exit-code` | The `aggregate.py` exit code: `0` PASS, `1` FAIL, `2` BLOCKED. |

### Behavior

- **Verdict → job result.** The action runs `aggregate.py` and maps its exit through `fail-on`.
  `fail-on: blocked` (default) fails the job on FAIL or BLOCKED; `fail-on: fail` lets a BLOCKED
  verdict pass as a warning so you can wire things up before you have a reviewer key.
- **Keyless path needs no secret.** With no `openrouter-api-key`, the reviewer panel step is
  skipped and the verdict is BLOCKED for missing panel coverage. The gate-only path needs no
  network — good for a first, honest signal.
- **The diff is transmitted only after a passing secrets scan.** The reviewer-panel step refuses to
  send the diff to the panel unless this run's `secrets` gate is recorded PASS, so a
  correctly-configured secrets scanner catches a committed credential before the diff is transmitted.
  Include a `secrets=…` gate (the example does); the NORMAL floor requires it anyway. This is a
  single-job precondition, not a hard isolation boundary — for untrusted/fork PRs prefer the GitLab
  two-job template, which re-runs the scan in the keyed job so repository-controlled code cannot
  influence the transmission decision.
- **The verdict is written to the job summary** (`verdict.md`), and `verdict` / `exit-code` are
  exposed as step outputs you can branch on.

### Secure adoption (required checks)

The workflow above is the fastest path to wired-up. It is **not** the secure-by-default posture
for a **required** check, because of two structural traps that catch every adopter who makes a
plain `pull_request` workflow required on merge (issue #61):

1. **Hollow green.** `fail-on: fail` reports a BLOCKED verdict (missing gates, no panel
   coverage — see "Behavior" above) as a passing job. Correct while you're wiring things up;
   wrong once the check gates a merge, since a green that never actually reviewed anything is
   worse than an honest red. Use `fail-on: blocked` for a required check.
2. **Self-mutating required check.** A plain `pull_request` workflow runs from the PR's own
   branch. This repo's own transmit-only-after-secrets-pass precondition (above) is a
   single-job mitigation, not a hard isolation boundary — for a same-repo PR (not just forks),
   an author can still edit the workflow file itself in their branch: shrink `gates:`, drop
   `fail-on: blocked` back to `fail`, or remove the `openrouter-api-key` line entirely, and the
   check still reports whatever that edited job produces. `OPENROUTER_API_KEY` is live in that
   same run regardless.

The fix for both is the same shape already used above for GitLab (**GitLab CI template**,
below): split gates (untrusted, no secret) from verdict (trusted, keyed, re-computes its own
secrets authorization). GitHub's `pull_request` trigger doesn't give you that isolation for
free the way GitLab's protected CI/CD variables do, so the trusted half needs a different
mechanism — `workflow_run`, which GitHub always executes from the **default branch's** copy of
the workflow file, never the triggering PR's, even for a same-repo PR that edits that exact
file in its own branch.

**[`examples/trusted/`](../examples/trusted/)** — `ar-classify.yml` (untrusted: records
deterministic gates, uploads them as an artifact, carries no secret) and `ar-verify.yml`
(trusted: `workflow_run`-triggered, downloads that artifact, re-runs the secrets gate itself,
runs the panel and `aggregate.py`, and posts the actual required check — `adversarial-review/verify`
— on the PR's head SHA). Copy both files into `.github/workflows/`; the two-workflow split is
the point, don't merge them back into one.

Also add, once you adopt the required-check posture:

- A `CODEOWNERS` entry for `.github/workflows/` and `.adversarial-review.yml`, so changes to the
  check itself (not just changes it's checking) need a second reviewer — this repo's own
  [`.github/CODEOWNERS`](../.github/CODEOWNERS) is a working example. **Include the
  `CODEOWNERS` file itself** in its own rules — otherwise a contributor can edit it to remove
  every other rule without needing code-owner approval to do that edit.
- Branch protection requiring the `adversarial-review/verify` check (not `adversarial-review` —
  that's `ar-classify`'s own, still-advisory job name) before merge.

**Stronger, optional variant.** `ar-verify.yml`'s default posts the check with the workflow's
own `GITHUB_TOKEN`, scoped by its `permissions:` block — sufficient for both traps above. A
GitHub App-authenticated variant additionally pins the required check to a specific App
identity, so it can only be satisfied by that App's installation token, not by anyone who can
trigger a workflow with `checks: write`. Live-tested end-to-end (normal-tier and manually-gated
critical-tier waiver flows, a genuine fork-originated PR, and rapid re-signs on the same commit)
in `SathiaAI/Sandbox`, tag `reference-v1-tested` — see the comment block at the end of
`ar-verify.yml` for how to adopt it. Not required for the baseline #61 guarantees.

---

## GitLab CI template

[`examples/.gitlab-ci.yml`](https://github.com/SathiaAI/adversarial-review/blob/main/examples/.gitlab-ci.yml)
gives GitLab the same recorded gates and the same machine-computed verdict. Copy it into your
repo's `.gitlab-ci.yml`, or `include:` it. It is deliberately **two jobs** so that
repository-controlled code never runs in the same job as the reviewer key:

- **`ar-gates`** (stage `gates`) runs your build/test/deps/sast commands — untrusted code — with
  **no key present**, and saves the recorded gates as an artifact.
- **`ar-panel`** (stage `review`) has the key and a **fresh, pinned** copy of the tooling. It
  runs the secrets scan (which authorizes transmitting the diff), the independent panel, and
  `aggregate.py`. It executes no repository-provided commands and re-runs the secrets scan itself
  with a pinned, off-repo scanner, so a malicious change cannot read `OPENROUTER_API_KEY` or forge
  the secrets gate that authorizes transmission. (Pin `risk`/`dev-providers` via protected CI/CD
  variables or a protected `.adversarial-review.yml`, so an MR author cannot weaken the panel
  through the policy the gates job resolves.) **`aggregate.py` is the job's last command, so the job
  result is its verdict: `0` PASS / `1` FAIL / `2` BLOCKED.**

### CI/CD variables (Settings → CI/CD → Variables)

| Variable | Role |
|---|---|
| `OPENROUTER_API_KEY` | Mark **masked and protected**. Set → the panel runs. Empty → verdict is BLOCKED (no panel coverage). Protected so it is never exposed to a fork MR. |
| `AR_BUILD_CMD` / `AR_UNIT_CMD` / `AR_DEPS_CMD` / `AR_SAST_CMD` | The commands behind each gate. A gate with **no command** is recorded BLOCKED (unknown is not pass), so the template can never fabricate a PASS. |
| `AR_SECRETS_CMD` | The secrets scanner (e.g. `gitleaks`). Runs in the **keyed `ar-panel` job**, not `ar-gates`, because it authorizes transmitting the diff. Pin its config **outside** the repo so a committed allowlist can't hide a planted secret. |
| `AR_REQUIRE` | Required gates for `gate.py plan`. Set to `""` to honor your policy file's `required_gates`; a non-empty value overrides it. The tier floor is always enforced. |
| `AR_RISK` / `AR_DEV_PROVIDERS` | Optional. Leave unset so `.adversarial-review.yml` resolves the tier and developer families; setting them here overrides consumer policy. |
| `AR_REF` | The tooling version to run. **Pin** to a tag or a full 40-char commit SHA (never a moving branch). |

### Keyless vs keyed, and the `fail-on` equivalent

- **Keyless** (no `OPENROUTER_API_KEY`): gates are recorded, the panel is skipped, and the
  verdict is BLOCKED — identical honesty to the Action's keyless path. No secret required.
- **Keyed**: with the key set *and* the secrets scan passing in `ar-panel`, the diff goes to the
  independent panel before `aggregate.py` computes the verdict.
- **`fail-on: fail` equivalent.** By default a BLOCKED verdict (exit `2`) fails the pipeline,
  matching `fail-on: blocked`. For incremental adoption, add `allow_failure: { exit_codes: 2 }`
  to `ar-panel` so BLOCKED becomes a warning while a FAIL (exit `1`) still fails the pipeline —
  the GitLab equivalent of `fail-on: fail`.

### How the Action inputs map to the GitLab template

| GitHub Action input | GitLab template equivalent |
|---|---|
| `gates` (`name=command` pairs) | `AR_BUILD_CMD` / `AR_UNIT_CMD` / `AR_DEPS_CMD` / `AR_SAST_CMD` / `AR_SECRETS_CMD` + `AR_REQUIRE` (the gate names) |
| `fail-on` | default pipeline fail = `blocked`; `allow_failure: { exit_codes: 2 }` = `fail` |
| `openrouter-api-key` | `OPENROUTER_API_KEY` CI/CD variable (masked + protected) |
| `diff-ref` | `AR_DIFF`, computed from GitLab's predefined variables (`CI_MERGE_REQUEST_DIFF_BASE_SHA` / `CI_DEFAULT_BRANCH`) |
| `risk` / `dev-providers` | `AR_RISK` / `AR_DEV_PROVIDERS` (or, preferably, `.adversarial-review.yml`) |
| _the action ref_ `@v0` / `@<sha>` | `AR_REF` (pin to a tag or full SHA) |
| `product` | recorded via the policy file / `run.json`; no separate variable in the template |

> **Supported GitLab gate names.** The template runs exactly **`build`, `unit`, `deps`, `sast`, and
> `secrets`**. A gate with any other name (e.g. `lint`) has no step in the template — add a matching
> `run_gate` line and CI/CD variable, or run it as its own job — otherwise it stays unrecorded and,
> if required, the verdict is BLOCKED.

---

## Publishing to the GitHub Marketplace (maintainer steps)

Listing the action on the GitHub Marketplace is a **manual action on github.com** — it involves
branding, category choices, and the Marketplace Developer Agreement that only a repo maintainer
can complete. It is **not** automated by this repository's release workflow (which publishes the
PyPI package on a full-semver `vX.Y.Z` tag — see "Version & tag scheme" below). The code side is already in place: `action.yml` declares
`name`, `description`, and `branding` (icon `shield`, color `red`). What remains for a maintainer:

1. **Confirm the prerequisites.** The repo is public, `action.yml` sits at the repo root, its
   `name` is unique across the Marketplace, and `branding.icon` / `branding.color` are set
   (they are). The README is the listing body, so keep it current.
2. **Draft a release.** On the repo's **Releases → Draft a new release** page, GitHub detects
   `action.yml` and shows a **"Publish this Action to the GitHub Marketplace"** checkbox. Check it.
3. **Accept the Marketplace Developer Agreement** (first publish only).
4. **Choose categories.** Pick a primary category and an optional secondary one
   (e.g. *Continuous integration*, *Code quality*, *Code review*, or *Security*). The icon and
   color come from `action.yml`'s `branding`; the category is chosen here, in the UI.
5. **Publish at the current release.** Publish the listing from the existing **`v0.2.0`** release
   (it already exists). The action then appears on the Marketplace and is installable as
   `SathiaAI/adversarial-review@v0.2.0`. There is **no need to cut a `v1.0.0`** to list on the
   Marketplace — the listing publishes from any release tag.
6. **Adopt a moving major tag now: `v0`.** So consumers can pin `@v0` and receive patch/minor
   updates within the current 0.x line, maintain a `v0` tag that always points at the latest
   `v0.x.y` release. **Bootstrap it once**, onto a commit that carries the narrowed release trigger:

   ```bash
   # Point v0 at a commit that CONTAINS the narrowed release trigger — i.e. main AFTER the PR that
   # narrows it merges, NOT the older v0.2.0 tag. A tag-push event runs the workflows present AT
   # THE PUSHED REF: if v0 pointed at the pre-change v0.2.0 commit (still `tags: ["v*"]`), pushing
   # v0 would start the OLD release workflow and fail its version guard (package 0.2.0 vs tag "0")
   # — the exact red pipeline the narrowing removes. On a commit with the narrowed trigger, `v0`
   # matches nothing, so the push fires no workflow.
   git fetch origin
   git tag -f v0 origin/main      # main HEAD (carries the narrowed full-semver trigger)
   git push -f origin v0
   ```

   **After each subsequent release, move `v0` to that release's full-semver tag — not
   `origin/main`, which may carry commits that were merged but not yet released** (pointing `v0`
   at `origin/main` would expose that unreleased code through `@v0`):

   ```bash
   git fetch origin --tags
   git tag -f v0 v0.3.0      # the tag of the release you just published (e.g. v0.3.0)
   git push -f origin v0
   ```

   The moving alias is force-pushed **by a maintainer, by hand** — the release workflow never
   creates or moves it (its trigger matches full `vX.Y.Z` only, so moving `v0`/`v1` fires nothing).

### Version & tag scheme

This repo publishes the same release as **two distribution surfaces from one tree** — a GitHub
Action and a PyPI package. They share one version line (the `pyproject` version); what differs is
the **pinning form**, not an independent version number:

| Surface | How to pin | Meaning |
|---|---|---|
| The **GitHub Action** | `@<full-sha>` (immutable) · `@v0.2.0` (a specific release) · `@v0` (moving major) | Action **interface** compatibility. A **full commit SHA is the only inherently immutable pin** — the recommended default for security-sensitive consumers. `@v0.2.0` is a bare git tag: stable *only if* the tag-protection ruleset below is enforced (an unprotected tag can be force-moved or deleted). `@v0` is a moving alias that auto-receives patch/minor fixes within 0.x. |
| The **PyPI package** `adversarial-review` | `adversarial-review==0.2.0` (or a range) | The same release, installed as a CLI. |

The Action major alias tracks the **package major**: Action compatibility is **not** advanced
independently of the package release — both come from the same `vX.Y.Z` tag. What differs is only
how each surface is pinned. Full `vX.Y.Z` tags drive the PyPI release (protect them as immutable —
see below); `v0`/`v1` are **moving aliases** for Action consumers and are never attached to a PyPI
publish. **Why the ref is the reproducibility boundary:**
the composite action runs **its own** committed scripts via `${{ github.action_path }}/scripts` and
never `pip install`s the package at run time, so `@v0.2.0` / `@<sha>` pins the *exact* code that
executes — the Action ref, not a mutable PyPI "latest", is the reproducibility boundary.

A `v1` moving tag is deliberately **not** cut yet: `v1.0.0` is reserved for the real 1.0 release
(after the remaining PR-comment integration and signed-attestation work land), at which point that
tag both drives the PyPI 1.0.0 publish and becomes the new moving `v1` for the Action. Cutting a
`1.0.0` early would be a stability claim the project is not ready to make.

**Tag hygiene (recommended repo ruleset):** protect `v[0-9]*.[0-9]*.[0-9]*` as immutable
(no force-push, no delete); allow force-push on the `v0` alias only, for narrowly-scoped
maintainers. This keeps the immutable release history honest while letting the major alias move.

Marketplace publication and the moving-alias discipline above are the only parts of this
integration a maintainer performs by hand; everything else — the template, the workflow, and the
verdict wiring — is in the repository.

---

*See also the full per-platform guide, [using-on-your-platform.md](using-on-your-platform.md),
for wiring the same pipeline into coding agents rather than CI.*
