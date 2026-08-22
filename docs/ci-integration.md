# CI integration — GitHub Action & GitLab CI

Wire the computed verdict into your pipeline so a merge is gated by evidence, not by a
human's optimism. The same deterministic gates, the same independent panel, and the same
`aggregate.py` verdict run on **GitHub** and **GitLab** — the only thing that differs is the
YAML around them. On both platforms the rule is identical:

> **The job's exit code is exactly what `aggregate.py` computed: `0` PASS, `1` FAIL, `2` BLOCKED.**
> No wrapper reinterprets it. Without a reviewer key the panel is skipped and the verdict is
> **BLOCKED** — the honest result for an un-reviewed change, not a soft pass.

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
      - uses: SathiaAI/adversarial-review@v1   # moving major tag; or pin a full SHA
        with:
          gates: |
            build=python -m py_compile $(git ls-files '*.py')
            unit=python -m pytest -q
          fail-on: fail             # tolerate BLOCKED while adopting; tighten to 'blocked'
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
- **The verdict is written to the job summary** (`verdict.md`), and `verdict` / `exit-code` are
  exposed as step outputs you can branch on.

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
  `aggregate.py`. It executes no repository-provided commands, so a malicious change cannot
  tamper with the panel or read `OPENROUTER_API_KEY`. **`aggregate.py` is the job's last command,
  so the job result is its verdict: `0` PASS / `1` FAIL / `2` BLOCKED.**

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
| _the action ref_ `@v1` / `@<sha>` | `AR_REF` (pin to a tag or full SHA) |
| `product` | recorded via the policy file / `run.json`; no separate variable in the template |

---

## Publishing to the GitHub Marketplace (maintainer steps)

Listing the action on the GitHub Marketplace is a **manual action on github.com** — it involves
branding, category choices, and the Marketplace Developer Agreement that only a repo maintainer
can complete. It is **not** automated by this repository's release workflow (which publishes the
PyPI package on a `v*` tag). The code side is already in place: `action.yml` declares
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
5. **Tag and publish.** Publish the release at a semver tag such as `v1.0.0`. The action then
   appears on the Marketplace and is installable as `SathiaAI/adversarial-review@v1.0.0`.
6. **Adopt a moving `v1` major tag.** So consumers can pin `@v1` and receive patch/minor updates,
   maintain a `v1` tag that always points at the latest `v1.x.y` release. After each release,
   move it and force-push:

   ```bash
   git tag -f v1 v1.2.3      # point v1 at the new release commit
   git push -f origin v1
   ```

   Document both options for consumers: **`@v1`** (moving major — auto-receives patches) or a
   **full commit SHA** (immutable — reproducible, opt into updates deliberately). The examples in
   this repo use `@main` for early adopters; switch them to `@v1` once the first major tag exists.

Marketplace publication and the moving-tag discipline above are the only parts of this
integration a maintainer performs by hand; everything else — the template, the workflow, and the
verdict wiring — is in the repository.

---

*See also the full per-platform guide, [using-on-your-platform.md](using-on-your-platform.md),
for wiring the same pipeline into coding agents rather than CI.*
