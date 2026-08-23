import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { MARKER, MAX_PUBLISHED_FINDINGS, findExistingMarkedComment, buildReviewCommentBody, buildUnavailableCommentBody } from '../src/comment.mjs';

describe('findExistingMarkedComment', () => {
  test('finds the marked comment authored by the expected bot', () => {
    const comments = [
      { id: 1, body: 'unrelated comment', user: { login: 'someone', type: 'User' } },
      { id: 2, body: `## AI-assisted code review\n\n${MARKER}`, user: { login: 'github-actions[bot]', type: 'Bot' } },
    ];
    const result = findExistingMarkedComment(comments, 'github-actions[bot]');
    assert.equal(result.id, 2);
  });

  test('ignores a marker string placed in a contributor-authored comment', () => {
    const comments = [
      { id: 1, body: `nice try ${MARKER}`, user: { login: 'a-contributor', type: 'User' } },
    ];
    const result = findExistingMarkedComment(comments, 'github-actions[bot]');
    assert.equal(result, null);
  });

  test('ignores a comment from a different bot identity even if marked', () => {
    const comments = [
      { id: 1, body: MARKER, user: { login: 'some-other-bot[bot]', type: 'Bot' } },
    ];
    const result = findExistingMarkedComment(comments, 'github-actions[bot]');
    assert.equal(result, null);
  });

  test('returns null when no comments exist', () => {
    assert.equal(findExistingMarkedComment([], 'github-actions[bot]'), null);
  });
});

describe('buildReviewCommentBody', () => {
  function finding(overrides = {}) {
    return { file: 'foo.php', line: 1, severity: 'advisory', evidence: 'evidence text', remediation: 'fix it', ...overrides };
  }

  test('includes the standing human-review notice', () => {
    const body = buildReviewCommentBody([], []);
    assert.match(body, /AI-generated and unverified/);
  });

  test('always ends with the marker', () => {
    const body = buildReviewCommentBody([finding()], []);
    assert.ok(body.trimEnd().endsWith(MARKER));
  });

  test('sorts findings blocking-first', () => {
    const findings = [finding({ severity: 'nit', file: 'a.php' }), finding({ severity: 'blocking', file: 'b.php' })];
    const body = buildReviewCommentBody(findings, []);
    assert.ok(body.indexOf('b.php') < body.indexOf('a.php'));
  });

  test('caps published findings and notes the omitted count', () => {
    const many = Array.from({ length: MAX_PUBLISHED_FINDINGS + 5 }, (_, i) => finding({ file: `f${i}.php`, line: i }));
    const body = buildReviewCommentBody(many, []);
    assert.match(body, /5 further finding\(s\)/);
    // Only the first MAX_PUBLISHED_FINDINGS filenames should appear.
    assert.doesNotMatch(body, /f24\.php/);
  });

  test('lists excluded files with their reasons', () => {
    const body = buildReviewCommentBody([], [{ filename: 'vendor/x.php', reason: 'excluded by file-type/path rule' }]);
    assert.match(body, /vendor\/x\.php/);
    assert.match(body, /excluded by file-type\/path rule/);
  });
});

describe('buildUnavailableCommentBody', () => {
  test('includes the reason and the marker, and never fails the build language', () => {
    const body = buildUnavailableCommentBody('the OpenAI API call failed');
    assert.match(body, /the OpenAI API call failed/);
    assert.match(body, /does not block merging/);
    assert.ok(body.trimEnd().endsWith(MARKER));
  });
});
