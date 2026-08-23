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
 *
 * Every comment write -- success, or any "review unavailable" notice --
 * goes through publishIfFresh(), which re-validates the PR's current
 * state immediately before writing, every time. A comment is never
 * published against a stale understanding of the PR just because the
 * failure that triggered it happened early (before any freshness-sensitive
 * work) rather than late.
 */
import { readFileSync, appendFileSync } from 'node:fs';
import { makeGitHubClient } from './github.mjs';
import { validatePreConditions, validatePrAssociation, validateResolvedPr } from './trust.mjs';
import { collectDiff } from './diff.mjs';
import { detectSecretShape } from './redact.mjs';
import { requestReview, createOpenAIClient } from './review.mjs';
import { validateFindings } from './validate-findings.mjs';
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

/**
 * The single, trusted publication path -- every comment write, success or
 * "unavailable" notice alike, goes through this. Re-fetches the PR and
 * re-validates it against the trusted workflow_run event immediately
 * before writing, every time, regardless of how early or late in the
 * pipeline the caller is. A PR that has moved on (new commit, closed)
 * since trust was last confirmed is never published to -- the result is
 * silently discarded (logged, not published) rather than risk overwriting
 * a newer review with a stale one.
 *
 * @returns {Promise<boolean>} whether the comment was actually published
 */
async function publishIfFresh(gh, prNumber, workflowRun, repoFullName, body) {
  let freshPr;
  try {
    freshPr = await gh.getPullRequest(prNumber);
  } catch {
    writeSummary(`OpenAI review: PR #${prNumber} -- could not re-resolve PR immediately before publishing, discarding result.`);
    return false;
  }

  const freshnessCheck = validateResolvedPr(freshPr, workflowRun, repoFullName);
  if (!freshnessCheck.ok) {
    writeSummary(`OpenAI review: PR #${prNumber} changed since validation, discarding result -- ${freshnessCheck.reason}`);
    return false;
  }

  const comments = await gh.listAllComments(prNumber);
  const existing = findExistingMarkedComment(comments, EXPECTED_BOT_LOGIN);
  if (existing) {
    await gh.updateComment(existing.id, body);
  } else {
    await gh.createComment(prNumber, body);
  }
  return true;
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
  } catch {
    writeSummary('OpenAI review: skipped -- could not read or parse the Stage 1 artifact.');
    return;
  }

  const association = validatePrAssociation(workflowRun, artifactPrNumber);
  if (!association.ok) {
    // Explicitly: no OpenAI call, no comment published anywhere, including
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
  } catch {
    writeSummary(`OpenAI review: skipped -- could not resolve PR #${prNumber}.`);
    return;
  }

  const preCheck = validateResolvedPr(resolvedPr, workflowRun, repoFullName);
  if (!preCheck.ok) {
    // No trusted PR to publish to at this point -- log only, per the same
    // reasoning as the association-failure case above.
    writeSummary(`OpenAI review: skipped -- ${preCheck.reason}`);
    return;
  }

  // From here on, prNumber is a validated target as of this moment -- but
  // every actual publish below still re-validates freshness itself via
  // publishIfFresh(), rather than relying on this one-time check staying
  // true for the rest of the run.

  let diffResult;
  try {
    diffResult = await collectDiff(gh.fetchFilesPage(prNumber), { maxBytes, maxFiles });
  } catch {
    writeSummary(`OpenAI review: PR #${prNumber} -- could not fetch the diff.`);
    await publishIfFresh(gh, prNumber, workflowRun, repoFullName, buildUnavailableCommentBody('the diff could not be retrieved'));
    return;
  }

  if (diffResult.status === 'too_large') {
    writeSummary(`OpenAI review: PR #${prNumber} diff too large -- ${diffResult.reason}`);
    await publishIfFresh(gh, prNumber, workflowRun, repoFullName, buildUnavailableCommentBody(`the diff is too large for automated review (${diffResult.reason})`));
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
    await publishIfFresh(gh, prNumber, workflowRun, repoFullName, buildUnavailableCommentBody('no files remained reviewable after applying exclusion rules'));
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
    await publishIfFresh(gh, prNumber, workflowRun, repoFullName, buildUnavailableCommentBody(reason));
    return;
  }

  if (reviewResult.status !== 'completed') {
    const reason =
      reviewResult.status === 'refused'
        ? 'the model declined to produce a review for this diff'
        : reviewResult.status === 'incomplete'
          ? 'the response did not complete (likely the output-token limit was reached)'
          : 'the response did not match the expected format';
    // Deliberately never includes reviewResult.reason here: for a refusal,
    // that string originates from the model's own response and is
    // therefore untrusted -- it could contain active Markdown or
    // attacker/prompt-influenced text. `reason` above is a fixed,
    // pre-written classification, not anything derived from model output.
    writeSummary(`OpenAI review: PR #${prNumber} -- ${reason}.`);
    await publishIfFresh(gh, prNumber, workflowRun, repoFullName, buildUnavailableCommentBody(reason));
    return;
  }

  // Deterministic validation after parsing: strict schema enforcement
  // guarantees shape, not that a finding's file/line genuinely correspond
  // to something in the diff that was actually sent, or that its fields
  // are sanely bounded. Invalid findings are rejected individually; the
  // discarded count is reported, not silently absorbed.
  const { accepted, rejectedCount } = validateFindings(reviewResult.findings, filesToSend);

  const body = buildReviewCommentBody(accepted, excludedFiles);
  const published = await publishIfFresh(gh, prNumber, workflowRun, repoFullName, body);
  if (published) {
    writeSummary(
      `OpenAI review: posted ${accepted.length} finding(s) for PR #${prNumber}` +
        (rejectedCount > 0 ? ` (${rejectedCount} discarded by validation)` : '') +
        ` (marker: ${MARKER}).`
    );
  }
}

run().catch(() => {
  // Absolute last-resort backstop: never let an uncaught error fail the
  // build, and never surface its message -- this exists specifically to
  // catch whatever wasn't anticipated by the specific handling above, so
  // by definition its content is not something this code can vouch for.
  writeSummary('OpenAI review: unexpected error, review skipped for this run.');
});
