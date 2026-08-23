# CI: OpenAI-assisted PR code review

An advisory, repository-owned CI check that posts an AI-generated code
review comment on pull requests. It never blocks merging, never commits or
approves anything, and is not a required status check. This document is
the operational reference for administrators; the design rationale and
every trust/security decision below was worked through in detail before
any of this was built -- see the git history of this document's own PR
for that record if you need the "why", not just the "what".

## What it does, and does not do

- Reads only the changed files/patches of a pull request via the GitHub
  API. It never checks out or executes any code from the pull request
  itself, at any stage, under any trigger.
- Sends those patches to the OpenAI API (Responses API, strict structured
  output) and asks for a bounded set of findings (`blocking` / `advisory`
  / `nit`), each citing a file, line, the specific evidence, and a
  suggested fix.
- Posts (or updates, on a later push) a single PR comment containing those
  findings, always prefaced with a notice that the findings are
  AI-generated, unverified, and require human judgement.
- Does **not** post inline/per-line review comments (deferred to a later
  phase, pending evaluation of the single-comment format's accuracy).
- Does **not** review pull requests from forked repositories. This is a
  deliberate consequence of the trust model below, not an oversight --
  see "Why fork PRs aren't reviewed."

## Architecture: two workflows, untrusted then trusted

- **`.github/workflows/openai-review-collect.yml`** ("Stage 1", untrusted):
  runs on every `pull_request` event, including forks. No secrets, no
  elevated permissions, no OpenAI credentials in scope. Its only output is
  an artifact recording the PR number -- nothing else.
- **`.github/workflows/openai-review-comment.yml`** ("Stage 2", trusted):
  runs on `workflow_run`, triggered after Stage 1 completes. This is the
  only job with OpenAI credentials and a comment-writing GitHub token. It
  always executes the default branch's own copy of this workflow and its
  scripts, regardless of what triggered Stage 1.

This split exists because `pull_request`-triggered workflows from forks
never receive repository secrets (GitHub's own default), and because
`pull_request_target` -- the alternative that *would* get secrets on a
fork PR -- is exactly the pattern that leads to secret exfiltration and
RCE via "pwn requests" when combined with checking out PR content. Stage 2
never checks out PR content, and gets its facts about "what changed"
entirely from its own, independent, trusted API calls -- never from
anything Stage 1 produced. See `.github/scripts/openai-review/src/trust.mjs`
for the exact validation sequence, and its test suite
(`.github/scripts/openai-review/test/trust.test.mjs`) for the specific
attack scenarios it's proven to reject (a fork-originated run, a forged
artifact pointing at an unrelated PR, a stale run whose commit has moved
on, and a same-SHA/branch scenario from a different repository).

### Why fork PRs aren't reviewed

Stage 2 requires the PR number to appear in GitHub's own trusted
`workflow_run.pull_requests` association -- this is what prevents an
attacker-controlled Stage 1 artifact from pointing the review at an
unrelated PR. GitHub does not populate that association for
fork-originated runs at all (this is documented GitHub behaviour, not a
gap in our own code). The design's answer to that gap is to fail open --
skip the review entirely, log why, post nothing -- rather than fall back
to trusting the artifact alone for exactly the case where trusting it
would matter most. The practical result: only pull requests from
branches within this repository get an automated review; external
contributions do not, until GitHub offers some other verifiable
association for fork-originated `workflow_run` events.

## Authentication: workload identity federation, API key fallback

Preferred: [OpenAI workload identity federation](https://developers.openai.com/api/docs/guides/workload-identity-federation/github-actions)
-- Stage 2 exchanges a short-lived GitHub Actions OIDC token for OpenAI
credentials on every run. No long-lived `OPENAI_API_KEY` needs to exist at
all if this is configured.

**One-time setup, in order:**

1. Temporarily set the repository variable `OPENAI_WIF_CLAIMS_DEBUG` to
   `true`, then trigger Stage 2 once (open or update any PR from a branch
   in this repository). The "Setup only: print observed OIDC claims" step
   will print this exact job's real claims (`repository`, `ref`,
   `workflow_ref`, `aud`, `sub`, etc.) to the workflow log -- **use those
   observed values, not an assumption**, when configuring the mapping
   below. In particular, do not assume `ref` is `refs/heads/main` without
   checking it here first for this specific `workflow_run` job shape.
2. In the OpenAI dashboard, create a Workload Identity Provider for
   GitHub's OIDC issuer, and a service account mapping restricted to the
   observed claims from step 1 -- at minimum, exact-match on `repository`
   and `workflow_ref` (not organisation-wide, not a wildcard).
3. Set the repository **variables** (not secrets -- this configuration
   isn't a credential): `OPENAI_IDENTITY_PROVIDER_ID`,
   `OPENAI_SERVICE_ACCOUNT_ID`, `OPENAI_WIF_AUDIENCE`.
4. Set `OPENAI_WIF_CLAIMS_DEBUG` back to `false` (or delete it) -- it is a
   setup diagnostic, not something that should run on every review.

**Fallback**, if federation is not yet configured: set the repository
**secret** `OPENAI_API_KEY` to a key created under its own dedicated
OpenAI Project (not the org's default project) -- never a repository
Variable, which is plaintext and readable by anyone with repository read
access. See "Cost controls" below for the project-side spend limit this
key should also have configured.

## Model selection

Configurable via the `OPENAI_REVIEW_MODEL` repository variable (defaults
to `gpt-5-mini` if unset). The model was not selected on price alone --
before changing it, run the comparison described in the design proposal:
build a small set of this repository's own past pull requests with
already-known, previously-documented findings (the DNS provider batch
review corrections are a natural source), and measure valid findings /
false positives / missed known findings / latency / cost per candidate
model before changing the default.

## Cost controls

Layered, so no single control failing is catastrophic:

1. **Per-run diff ceiling**: `OPENAI_REVIEW_MAX_DIFF_BYTES` (default
   200,000) and `OPENAI_REVIEW_MAX_DIFF_FILES` (default 60) repository
   variables. A PR exceeding either gets a "too large for automated
   review" notice instead of an OpenAI call.
2. **Per-call output cap**: `OPENAI_REVIEW_MAX_OUTPUT_TOKENS` (default
   4,000) repository variable, passed as `max_output_tokens`.
3. **Per-call timeout**: `OPENAI_REVIEW_TIMEOUT_MS` (default 60,000)
   repository variable.
4. **Project hard spend limit**: configured in the OpenAI dashboard on the
   dedicated project this pipeline uses, independent of anything in this
   repository. This is the ultimate backstop -- once reached, the OpenAI
   API itself returns HTTP 429 with `project_spend_limit_exceeded` (or
   `organization_spend_limit_exceeded`/`insufficient_quota`), which the
   pipeline recognises and treats as a normal fail-open condition (see
   below), never a build failure.

## Data handling

- Every OpenAI call sets `store: false` -- this opts out of OpenAI's
  server-side conversation-state retention for these calls specifically.
  It does **not** mean zero data retention in any broader sense: OpenAI's
  API data-processing and abuse-monitoring policies still apply
  independently of this flag.
- Source diffs for reviewed PRs leave GitHub and are transmitted to, and
  processed by, the OpenAI API (subject to OpenAI's API data-usage
  policies, distinct from consumer ChatGPT product policies).
- This repository is public, so private-repository eligibility was not a
  design question that needed resolving here. If this pipeline is ever
  proposed for a private repository, that needs its own separate review
  of what OpenAI's terms and this org's data-handling obligations permit
  -- do not assume the same design choices carry over automatically.
- A best-effort regex sweep (`.github/scripts/openai-review/src/redact.mjs`)
  excludes any file whose diff matches a known credential shape (AWS keys,
  GitHub tokens, PEM blocks, etc.) from what's sent, rather than
  redacting and sending it. This is explicitly **not a guarantee** -- it
  will miss anything that doesn't match a known pattern, and is not a
  substitute for never committing secrets in the first place.

## Review scope

In scope: production PHP, tests, GitHub Actions workflow files, build/CI
scripts, configuration, and documentation where it makes a behaviour or
security claim. Out of scope, and only this: generated files, bundled or
minified assets, vendored third-party code, binary files, and dependency
lockfiles (`composer.lock`, `package-lock.json`, etc.) -- see the
`DEFAULT_EXCLUDE_PATTERNS` list in
`.github/scripts/openai-review/src/diff.mjs`. Tests and CI workflow files
are deliberately **not** excluded, even though they're excluded from this
project's own PHPCS scope -- that exclusion exists to keep a style linter
focused, which is a different purpose from code review.

## Failure behaviour

Every failure mode -- quota/spend-limit exhaustion, a model refusal, an
incomplete response, a transport error, an unexpected exception -- results
in the workflow exiting successfully (never failing the build) while
writing a plain-language reason (never account figures, tokens, or raw API
error bodies) to the GitHub Actions job summary, the workflow logs, and,
where a PR has already been validated as the right target, an update to
the existing review comment noting the review didn't complete and why in
general terms.

## Rollout

Ships advisory-only (not a required check). Suggested evaluation window:
2-4 weeks or roughly 20-30 real pull requests, whichever comes first at
this repository's current PR volume, before considering any change to
that status. Track informally: false-positive rate, whether it surfaces
anything a human reviewer would have wanted to know about, and actual
monthly OpenAI spend against the estimate in the original design proposal.

## Rollback

Disable or delete `.github/workflows/openai-review-collect.yml` and
`.github/workflows/openai-review-comment.yml`. Nothing else in this
repository depends on their output -- no schema migrations, no other
workflow references either one. If discontinuing entirely, also revoke or
rotate the dedicated OpenAI project's credentials (the WIF service account
mapping, and/or the fallback API key).
