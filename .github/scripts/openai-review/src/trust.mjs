/**
 * Trust-validation for Stage 2 (the reviewer job). Every function here is
 * pure -- no network calls, no GitHub/OpenAI SDK use -- so the full
 * decision logic can be unit-tested with plain fixture objects (see
 * test/trust.test.mjs) without needing a real workflow_run event or a
 * real PR.
 *
 * The `workflow_run` event is the only trusted source of "what actually
 * happened": which repository/branch/commit triggered Stage 1, and which
 * pull request(s) GitHub itself associates with that run. Stage 1's own
 * artifact is never trusted beyond being a hint of which PR *number* to
 * look up -- every fact used to decide whether to review or publish is
 * re-derived from the workflow_run event and a fresh PR lookup, and the
 * artifact's PR number must independently agree with GitHub's own
 * pull_requests association before anything proceeds.
 */

/**
 * @typedef {{ ok: true, prNumber: number }} TrustOk
 * @typedef {{ ok: false, reason: string }} TrustFail
 * @typedef {TrustOk | TrustFail} TrustResult
 */

/**
 * Step 1: does the workflow_run event itself describe a run worth acting on.
 *
 * @param {object} workflowRun - github.event.workflow_run
 * @param {string} expectedRepoFullName - "<owner>/<repo>" of this repository
 * @param {string} expectedWorkflowName - the Stage 1 workflow's `name:` field
 * @returns {TrustResult}
 */
export function validatePreConditions(workflowRun, expectedRepoFullName, expectedWorkflowName) {
  if (!workflowRun) {
    return { ok: false, reason: 'no workflow_run payload present' };
  }
  if (workflowRun.event !== 'pull_request') {
    return { ok: false, reason: `workflow_run.event is "${workflowRun.event}", expected "pull_request"` };
  }
  if (workflowRun.conclusion !== 'success') {
    return { ok: false, reason: `workflow_run.conclusion is "${workflowRun.conclusion}", expected "success"` };
  }
  if (workflowRun.repository?.full_name !== expectedRepoFullName) {
    return { ok: false, reason: `workflow_run.repository.full_name is "${workflowRun.repository?.full_name}", expected "${expectedRepoFullName}"` };
  }
  // Defense in depth: the on.workflow_run.workflows filter in the YAML
  // already restricts which workflow can trigger Stage 2 at all -- this
  // re-check costs nothing and catches a misconfigured filter.
  if (workflowRun.name !== expectedWorkflowName) {
    return { ok: false, reason: `workflow_run.name is "${workflowRun.name}", expected "${expectedWorkflowName}"` };
  }
  return { ok: true, prNumber: -1 }; // prNumber not yet known at this step; caller ignores it here.
}

/**
 * Step 2: the artifact's PR number is only a hint -- it must appear in
 * GitHub's own trusted association for this exact workflow_run. If
 * workflow_run.pull_requests is empty (always true for fork-originated
 * runs) or does not contain the artifact's number, this fails closed.
 * There is no fallback to trusting the artifact alone.
 *
 * @param {object} workflowRun - github.event.workflow_run
 * @param {number} artifactPrNumber - the PR number Stage 1's artifact claims
 * @returns {TrustResult}
 */
export function validatePrAssociation(workflowRun, artifactPrNumber) {
  const pullRequests = workflowRun?.pull_requests;
  if (!Array.isArray(pullRequests) || pullRequests.length === 0) {
    return {
      ok: false,
      reason: 'workflow_run.pull_requests is empty -- this is always the case for fork-originated runs, and GitHub provides no other verifiable PR association for them, so this pipeline does not review fork-originated pull requests by design',
    };
  }
  const matches = pullRequests.some((pr) => pr.number === artifactPrNumber);
  if (!matches) {
    return {
      ok: false,
      reason: `artifact PR number ${artifactPrNumber} does not appear in workflow_run.pull_requests (${pullRequests.map((pr) => pr.number).join(', ')})`,
    };
  }
  return { ok: true, prNumber: artifactPrNumber };
}

/**
 * Step 3: cross-check a freshly-resolved PR (from Stage 2's own
 * GET /repos/{owner}/{repo}/pulls/{number} call) against what the trusted
 * workflow_run event says. Called both before the OpenAI call and again,
 * with a freshly re-resolved PR, immediately before publishing -- the
 * second call catches a PR that moved (new commit, closed) while the
 * OpenAI call was in flight.
 *
 * @param {object} resolvedPr - the PR object from the GitHub API
 * @param {object} workflowRun - github.event.workflow_run
 * @param {string} expectedRepoFullName - "<owner>/<repo>" of this repository
 * @returns {TrustResult}
 */
export function validateResolvedPr(resolvedPr, workflowRun, expectedRepoFullName) {
  if (!resolvedPr) {
    return { ok: false, reason: 'PR lookup returned no result' };
  }
  if (resolvedPr.state !== 'open') {
    return { ok: false, reason: `PR #${resolvedPr.number} state is "${resolvedPr.state}", expected "open"` };
  }
  if (resolvedPr.base?.repo?.full_name !== expectedRepoFullName) {
    return { ok: false, reason: `PR #${resolvedPr.number} base repo is "${resolvedPr.base?.repo?.full_name}", expected "${expectedRepoFullName}"` };
  }
  if (resolvedPr.head?.sha !== workflowRun.head_sha) {
    return { ok: false, reason: `PR #${resolvedPr.number} head SHA is "${resolvedPr.head?.sha}", workflow_run.head_sha is "${workflowRun.head_sha}"` };
  }
  if (resolvedPr.head?.repo?.full_name !== workflowRun.head_repository?.full_name) {
    return { ok: false, reason: `PR #${resolvedPr.number} head repo is "${resolvedPr.head?.repo?.full_name}", workflow_run.head_repository.full_name is "${workflowRun.head_repository?.full_name}"` };
  }
  if (resolvedPr.head?.ref !== workflowRun.head_branch) {
    return { ok: false, reason: `PR #${resolvedPr.number} head ref is "${resolvedPr.head?.ref}", workflow_run.head_branch is "${workflowRun.head_branch}"` };
  }
  return { ok: true, prNumber: resolvedPr.number };
}

/**
 * Runs the full pre-OpenAI-call trust sequence (steps 1-3) in order,
 * short-circuiting on the first failure.
 *
 * @param {{workflowRun: object, expectedRepoFullName: string, expectedWorkflowName: string, artifactPrNumber: number, resolvedPr: object}} input
 * @returns {TrustResult}
 */
export function validateTrust({ workflowRun, expectedRepoFullName, expectedWorkflowName, artifactPrNumber, resolvedPr }) {
  const preConditions = validatePreConditions(workflowRun, expectedRepoFullName, expectedWorkflowName);
  if (!preConditions.ok) {
    return preConditions;
  }

  const association = validatePrAssociation(workflowRun, artifactPrNumber);
  if (!association.ok) {
    return association;
  }

  return validateResolvedPr(resolvedPr, workflowRun, expectedRepoFullName);
}
