import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { extractValidLineNumbers, validateFindings } from '../src/validate-findings.mjs';

describe('extractValidLineNumbers', () => {
  test('includes added and context lines, excludes deleted-only lines', () => {
    const patch = ['@@ -10,3 +10,4 @@', ' context at 10', '-deleted at 11 (old)', '+added at 11', ' context at 12'].join('\n');
    // new-file numbering starts at 10: 10=context, 11=added (deleted line
    // consumes no new-file number), 12=context.
    assert.deepEqual([...extractValidLineNumbers(patch)].sort((a, b) => a - b), [10, 11, 12]);
  });

  test('handles multiple hunks independently', () => {
    const patch = ['@@ -1,1 +1,1 @@', '+first hunk line', '@@ -50,1 +51,1 @@', '+second hunk line'].join('\n');
    assert.deepEqual([...extractValidLineNumbers(patch)].sort((a, b) => a - b), [1, 51]);
  });

  test('a pure-deletion hunk yields no valid new-file lines', () => {
    const patch = ['@@ -5,2 +5,0 @@', '-removed one', '-removed two'].join('\n');
    assert.deepEqual([...extractValidLineNumbers(patch)], []);
  });
});

describe('validateFindings', () => {
  function file(filename, patch) {
    return { filename, patch };
  }

  function finding(overrides = {}) {
    return { file: 'a.php', line: 1, severity: 'advisory', evidence: 'some evidence', remediation: 'do this instead', ...overrides };
  }

  const files = [file('a.php', '@@ -1,1 +1,2 @@\n unchanged\n+added at line 2')];
  // new-file lines: 1 (context), 2 (added).

  test('accepts a finding whose file and line are both genuinely in the diff', () => {
    const result = validateFindings([finding({ line: 2 })], files);
    assert.equal(result.accepted.length, 1);
    assert.equal(result.rejectedCount, 0);
  });

  test('rejects a finding citing a file that was never sent (hallucinated or prompt-influenced)', () => {
    const result = validateFindings([finding({ file: 'never-sent.php', line: 2 })], files);
    assert.equal(result.accepted.length, 0);
    assert.equal(result.rejectedCount, 1);
  });

  test('rejects a finding citing a line number absent from that file\'s diff', () => {
    const result = validateFindings([finding({ line: 999 })], files);
    assert.equal(result.accepted.length, 0);
    assert.equal(result.rejectedCount, 1);
  });

  test('rejects a finding citing a deleted-only line (never existed in the new file)', () => {
    const deletionFiles = [file('b.php', '@@ -1,1 +0,0 @@\n-removed line')];
    const result = validateFindings([finding({ file: 'b.php', line: 1 })], deletionFiles);
    assert.equal(result.accepted.length, 0);
    assert.equal(result.rejectedCount, 1);
  });

  test('rejects an invalid severity even though the schema should already prevent it (defence in depth)', () => {
    const result = validateFindings([finding({ line: 2, severity: 'critical' })], files);
    assert.equal(result.accepted.length, 0);
    assert.equal(result.rejectedCount, 1);
  });

  test('rejects evidence exceeding the length bound', () => {
    const result = validateFindings([finding({ line: 2, evidence: 'x'.repeat(3000) })], files);
    assert.equal(result.accepted.length, 0);
    assert.equal(result.rejectedCount, 1);
  });

  test('rejects remediation exceeding the length bound', () => {
    const result = validateFindings([finding({ line: 2, remediation: 'x'.repeat(2000) })], files);
    assert.equal(result.accepted.length, 0);
    assert.equal(result.rejectedCount, 1);
  });

  test('rejects individually, not the whole batch: one bad finding does not discard a good one', () => {
    const result = validateFindings(
      [finding({ line: 2 }), finding({ file: 'never-sent.php', line: 2 })],
      files
    );
    assert.equal(result.accepted.length, 1);
    assert.equal(result.rejectedCount, 1);
  });

  test('handles a non-array findings input safely', () => {
    const result = validateFindings(null, files);
    assert.equal(result.accepted.length, 0);
    assert.equal(result.rejectedCount, 0);
  });
});
