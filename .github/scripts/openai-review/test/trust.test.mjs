import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { validatePreConditions, validatePrAssociation, validateResolvedPr, validateTrust } from '../src/trust.mjs';

const REPO = 'vcns/security-automation-manager';
const STAGE1_NAME = 'OpenAI review: collect';

function fakeWorkflowRun(overrides = {}) {
  return {
    event: 'pull_request',
    conclusion: 'success',
    repository: { full_name: REPO },
    name: STAGE1_NAME,
    head_sha: 'abc123',
    head_branch: 'feature/x',
    head_repository: { full_name: REPO },
    pull_requests: [{ number: 42 }],
    ...overrides,
  };
}

function fakeResolvedPr(overrides = {}) {
  return {
    number: 42,
    state: 'open',
    base: { repo: { full_name: REPO } },
    head: { sha: 'abc123', ref: 'feature/x', repo: { full_name: REPO } },
    ...overrides,
  };
}

describe('validatePreConditions', () => {
  test('accepts a well-formed same-repo workflow_run', () => {
    const result = validatePreConditions(fakeWorkflowRun(), REPO, STAGE1_NAME);
    assert.equal(result.ok, true);
  });

  test('rejects an event that is not pull_request', () => {
    const result = validatePreConditions(fakeWorkflowRun({ event: 'push' }), REPO, STAGE1_NAME);
    assert.equal(result.ok, false);
    assert.match(result.reason, /event/);
  });

  test('rejects a non-successful conclusion', () => {
    const result = validatePreConditions(fakeWorkflowRun({ conclusion: 'failure' }), REPO, STAGE1_NAME);
    assert.equal(result.ok, false);
  });

  test('rejects a workflow_run from a different repository (e.g. a fork\'s own copy)', () => {
    const result = validatePreConditions(fakeWorkflowRun({ repository: { full_name: 'attacker/security-automation-manager' } }), REPO, STAGE1_NAME);
    assert.equal(result.ok, false);
    assert.match(result.reason, /repository/);
  });

  test('rejects an unexpected workflow name', () => {
    const result = validatePreConditions(fakeWorkflowRun({ name: 'Something else' }), REPO, STAGE1_NAME);
    assert.equal(result.ok, false);
  });
});

describe('validatePrAssociation', () => {
  test('accepts when the artifact PR number appears in the trusted array', () => {
    const result = validatePrAssociation(fakeWorkflowRun(), 42);
    assert.equal(result.ok, true);
    assert.equal(result.prNumber, 42);
  });

  test('fails closed when pull_requests is empty (fork-originated run) -- does not fall back to trusting the artifact', () => {
    const result = validatePrAssociation(fakeWorkflowRun({ pull_requests: [] }), 42);
    assert.equal(result.ok, false);
    assert.match(result.reason, /fork/);
  });

  test('fails when the artifact PR number does not appear in the trusted array (forged/mismatched artifact)', () => {
    const result = validatePrAssociation(fakeWorkflowRun({ pull_requests: [{ number: 999 }] }), 42);
    assert.equal(result.ok, false);
    assert.match(result.reason, /does not appear/);
  });

  test('accepts when the correct number is present among multiple associated PRs', () => {
    const result = validatePrAssociation(fakeWorkflowRun({ pull_requests: [{ number: 1 }, { number: 42 }, { number: 7 }] }), 42);
    assert.equal(result.ok, true);
  });
});

describe('validateResolvedPr', () => {
  test('accepts a fresh, matching, open PR', () => {
    const result = validateResolvedPr(fakeResolvedPr(), fakeWorkflowRun(), REPO);
    assert.equal(result.ok, true);
    assert.equal(result.prNumber, 42);
  });

  test('rejects a closed PR', () => {
    const result = validateResolvedPr(fakeResolvedPr({ state: 'closed' }), fakeWorkflowRun(), REPO);
    assert.equal(result.ok, false);
    assert.match(result.reason, /state/);
  });

  test('rejects a PR whose base repo is not this repository', () => {
    const result = validateResolvedPr(fakeResolvedPr({ base: { repo: { full_name: 'someone-else/fork' } } }), fakeWorkflowRun(), REPO);
    assert.equal(result.ok, false);
    assert.match(result.reason, /base repo/);
  });

  test('rejects a stale run: PR head SHA no longer matches workflow_run.head_sha', () => {
    const staleWorkflowRun = fakeWorkflowRun({ head_sha: 'old-commit-sha' });
    const result = validateResolvedPr(fakeResolvedPr({ head: { sha: 'new-commit-sha', ref: 'feature/x', repo: { full_name: REPO } } }), staleWorkflowRun, REPO);
    assert.equal(result.ok, false);
    assert.match(result.reason, /head SHA/);
  });

  test('rejects a forged-artifact scenario: same head SHA/branch but a different head repository', () => {
    // Simulates the exact attack this correction closes: an attacker-controlled
    // PR happening to share a head SHA/branch name with another PR's context,
    // but originating from a different repository.
    const result = validateResolvedPr(
      fakeResolvedPr({ head: { sha: 'abc123', ref: 'feature/x', repo: { full_name: 'attacker/fork' } } }),
      fakeWorkflowRun(),
      REPO
    );
    assert.equal(result.ok, false);
    assert.match(result.reason, /head repo/);
  });

  test('rejects a mismatched head branch', () => {
    const result = validateResolvedPr(
      fakeResolvedPr({ head: { sha: 'abc123', ref: 'different-branch', repo: { full_name: REPO } } }),
      fakeWorkflowRun(),
      REPO
    );
    assert.equal(result.ok, false);
    assert.match(result.reason, /head ref/);
  });
});

describe('validateTrust (full sequence)', () => {
  test('a completely well-formed, same-repo PR passes every check', () => {
    const result = validateTrust({
      workflowRun: fakeWorkflowRun(),
      expectedRepoFullName: REPO,
      expectedWorkflowName: STAGE1_NAME,
      artifactPrNumber: 42,
      resolvedPr: fakeResolvedPr(),
    });
    assert.equal(result.ok, true);
    assert.equal(result.prNumber, 42);
  });

  test('a fork-originated run (empty pull_requests) is rejected before any PR resolution would matter', () => {
    const result = validateTrust({
      workflowRun: fakeWorkflowRun({ pull_requests: [] }),
      expectedRepoFullName: REPO,
      expectedWorkflowName: STAGE1_NAME,
      artifactPrNumber: 42,
      resolvedPr: fakeResolvedPr(), // even a perfectly valid PR object must not rescue this
    });
    assert.equal(result.ok, false);
    assert.match(result.reason, /fork/);
  });

  test('an artifact claiming an unrelated, otherwise-valid open PR is rejected', () => {
    // The artifact says PR #999; #999 is a real, open, same-repo PR -- but
    // the trusted workflow_run association never mentions it.
    const result = validateTrust({
      workflowRun: fakeWorkflowRun(), // only associates PR #42
      expectedRepoFullName: REPO,
      expectedWorkflowName: STAGE1_NAME,
      artifactPrNumber: 999,
      resolvedPr: fakeResolvedPr({ number: 999 }),
    });
    assert.equal(result.ok, false);
    assert.match(result.reason, /does not appear/);
  });
});
