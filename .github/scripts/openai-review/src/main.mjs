/**
 * Stage 2 (trusted): orchestrates the full trust-validation -> diff
 * retrieval -> OpenAI review -> comment-publish sequence. This is the
 * only file with `id-token: write`-derived OpenAI credentials and a
 * writable GitHub token in scope; it never checks out or executes PR
 * content.
 *
 * Top-level guarantee: whatever happens, this process exits 0. The
 * review is advisory -- it must never fail the build. Every failure mode
 * writes a plain-language (never account/token-detail) reason to the job
 * summary and workflow logs, and to the PR comment where a validated PR
 * is already known.
 */
import { readFileSync, appendFileSync } from 'node:fs';
import { makeGitHubClient } from './github.mjs';
import { validatePreConditions, validatePrAssociation, validateResolvedPr } from './trust.mjs';
import { collectDiff } from './diff.mjs';
import { detectSecretShape } from './redact.mjs';
import { requestReview, createOpenAIClient } from './review.mjs';
import { MARKER, findExistingMarkedComment, buildReviewCommentBody, buildUnavailableCommentBody } from './comment.mjs';

const STAGE1_WORKFLOW_NAME = 'OpenAI review: collect';
const EXPECTED_BOT_LOGIN = 'github-actions[bot]';

function writeSummary(text) {
  console.log(text); // eslint-disable-line no-console
  if (process.env.GITHUB_STEP_SUMMARY) {
    appendFileSync(process.env.GITHUB_STEP_SUMMARY, `${text}\n`, 'utf8');
  }
}

function classifyApiError(err) {
  const message = String(err?.message ?? err);
  if (/project_spend_limit_exceeded|organization_spend_limit_exceeded|insufficient_quota/i.test(message)) {
    return 'the configured OpenAI spend limit has been reached for this billing period';
  }
  if (/429/.test(message)) {
    return 'the OpenAI API rate limit was hit for this request';
  }
  if (/timeout/i.test(message)) {
    return 'the OpenAI API call timed out';
  }
  return 'the OpenAI API call failed';
}

async function publishOrUpdate(gh, prNumber, body) {
  const comments = await gh.listAllComments(prNumber);
  const existing = findExistingMarkedComment(comments, EXPECTED_BOT_LOGIN);
  if (existing) {
    await gh.updateComment(existing.id, body);
  } else {
    await gh.createComment(prNumber, body);
  }
}

async function run() {
  // `||`, not `??`, throughout: an unset GitHub Actions `vars.*`/`secrets.*`
  // reference resolves to an empty string, not `undefined` -- `??` would
  // silently let "" through instead of falling back to these defaults
  // (e.g. maxBytes would become 0, flagging every PR as "too large").
  const repoFullName = process.env.GITHUB_REPOSITORY;
  const token = process.env.GITHUB_TOKEN;
  const artifactPath = process.env.ARTIFACT_PATH || 'openai-review-artifact/pr.json';
  const model = process.env.OPENAI_MODEL || 'gpt-5-mini';
  const maxBytes = Number(process.env.MAX_DIFF_BYTES || 200_000);
  const maxFiles = Number(process.env.MAX_DIFF_FILES || 60);
  const maxOutputTokens = Number(process.env.MAX_OUTPUT_TOKENS || 4000);
  const timeoutMs = Number(process.env.OPENAI_TIMEOUT_MS || 60_000);

  if (!repoFullName || !token) {
    writeSummary('OpenAI review: GITHUB_REPOSITORY or GITHUB_TOKEN missing -- cannot proceed. This is a workflow configuration problem, not a PR-specific one.');
    return;
  }

  const eventPath = process.env.GITHUB_EVENT_PATH;
  const event = JSON.parse(readFileSync(eventPath, 'utf8'));
  const workflowRun = event.workflow_run;

  const gh = makeGitHubClient(token, repoFullName);

  // --- Trust validation, phase 1: the event itself, and the artifact's PR
  //     number against GitHub's own trusted association. ---
  const preConditions = validatePreConditions(workflowRun, repoFullName, STAGE1_WORKFLOW_NAME);
  if (!preConditions.ok) {
    writeSummary(`OpenAI review: skipped -- ${preConditions.reason}`);
    return;
  }

  let artifactPrNumber;
  try {
    artifactPrNumber = JSON.parse(readFileSync(artifactPath, 'utf8')).pr_number;
  } catch (err) {
    writeSummary(`OpenAI review: skipped -- could not read Stage 1 artifact at ${artifactPath}: ${err.message}`);
    return;
  }

  const association = validatePrAssociation(workflowRun, artifactPrNumber);
  if (!association.ok) {
    // Explicitly: no OpenAI call, no comment posted anywhere, including
    // whenever workflow_run.pull_requests comes back empty (observed for
    // a simulated fork-originated event; real fork-PR behaviour is not
    // yet independently confirmed -- see docs/ci-openai-review.md).
    writeSummary(`OpenAI review: skipped -- ${association.reason}`);
    return;
  }
  const prNumber = association.prNumber;

  // --- Trust validation, phase 2: independently resolve the PR and
  //     cross-check it against the trusted workflow_run fields. ---
  let resolvedPr;
  try {
    resolvedPr = await gh.getPullRequest(prNumber);
  } catch (err) {
    writeSummary(`OpenAI review: skipped -- could not resolve PR #${prNumber}: ${err.message}`);
    return;
  }

  const preCheck = validateResolvedPr(resolvedPr, workflowRun, repoFullName);
  if (!preCheck.ok) {
    // No trusted PR to post to at this point -- log only, per the same
    // reasoning as the association-failure case above.
    writeSummary(`OpenAI review: skipped -- ${preCheck.reason}`);
    return;
  }

  // From here on, prNumber is a validated, trusted target -- a "review
  // unavailable" notice may legitimately be posted to it on any later
  // failure, since we know this is the right PR.

  let diffResult;
  try {
    diffResult = await collectDiff(gh.fetchFilesPage(prNumber), { maxBytes, maxFiles });
  } catch (err) {
    writeSummary(`OpenAI review: could not fetch diff for PR #${prNumber}: ${err.message}`);
    await publishOrUpdate(gh, prNumber, buildUnavailableCommentBody('the diff could not be retrieved')).catch(() => {});
    return;
  }

  if (diffResult.status === 'too_large') {
    writeSummary(`OpenAI review: PR #${prNumber} diff too large -- ${diffResult.reason}`);
    await publishOrUpdate(gh, prNumber, buildUnavailableCommentBody(`the diff is too large for automated review (${diffResult.reason})`)).catch(() => {});
    return;
  }

  // Best-effort secret-shape exclusion: a match removes the file from what
  // is sent, and is reported the same way any other exclusion is.
  const excludedFiles = [...diffResult.excluded];
  const filesToSend = [];
  for (const file of diffResult.included) {
    const secretShape = detectSecretShape(file.patch);
    if (secretShape) {
      excludedFiles.push({ filename: file.filename, reason: `excluded: possible credential detected (${secretShape}-shaped content)` });
    } else {
      filesToSend.push({ filename: file.filename, patch: file.patch });
    }
  }

  if (filesToSend.length === 0) {
    writeSummary(`OpenAI review: PR #${prNumber} has no reviewable files after exclusions.`);
    await publishOrUpdate(gh, prNumber, buildUnavailableCommentBody('no files remained reviewable after applying exclusion rules')).catch(() => {});
    return;
  }

  let reviewResult;
  try {
    const client = createOpenAIClient(process.env);
    reviewResult = await requestReview(client, model, filesToSend, { maxOutputTokens, timeoutMs });
  } catch (err) {
    // Deliberately never includes err.message here: some API client
    // errors echo back partial request/credential detail in their own
    // message text (e.g. "Incorrect API key provided: sk-***"), and this
    // reason is written to a job summary/log visible to anyone with
    // repository read access. classifyApiError()'s output is a fixed,
    // safe, generic phrase -- nothing derived from the raw error is ever
    // surfaced.
    const reason = classifyApiError(err);
    writeSummary(`OpenAI review: PR #${prNumber} -- ${reason}.`);
    await publishOrUpdate(gh, prNumber, buildUnavailableCommentBody(reason)).catch(() => {});
    return;
  }

  // --- Freshness recheck immediately before publishing. ---
  let freshPr;
  try {
    freshPr = await gh.getPullRequest(prNumber);
  } catch (err) {
    writeSummary(`OpenAI review: PR #${prNumber} -- could not re-resolve PR before publishing, discarding result: ${err.message}`);
    return;
  }
  const freshnessCheck = validateResolvedPr(freshPr, workflowRun, repoFullName);
  if (!freshnessCheck.ok) {
    writeSummary(`OpenAI review: PR #${prNumber} changed since review started, discarding result -- ${freshnessCheck.reason}`);
    return;
  }

  if (reviewResult.status !== 'completed') {
    const reason =
      reviewResult.status === 'refused'
        ? 'the model declined to produce a review for this diff'
        : reviewResult.status === 'incomplete'
          ? 'the response did not complete (likely the output-token limit was reached)'
          : 'the response did not match the expected format';
    writeSummary(`OpenAI review: PR #${prNumber} -- ${reason} (${reviewResult.reason}).`);
    await publishOrUpdate(gh, prNumber, buildUnavailableCommentBody(reason)).catch(() => {});
    return;
  }

  const body = buildReviewCommentBody(reviewResult.findings, excludedFiles);
  await publishOrUpdate(gh, prNumber, body);
  writeSummary(`OpenAI review: posted ${Math.min(reviewResult.findings.length, 20)} finding(s) for PR #${prNumber} (marker: ${MARKER}).`);
}

run().catch((err) => {
  // Absolute last-resort backstop: never let an uncaught error fail the
  // build. Log plainly; no account/token detail.
  writeSummary(`OpenAI review: unexpected error, review skipped for this run. (${err?.message ?? err})`);
});
