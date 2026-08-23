import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { globMatch, isExcludedByPattern, countPatchLines, classifyFile, collectDiff } from '../src/diff.mjs';

describe('globMatch / isExcludedByPattern', () => {
  test('matches a vendor/** pattern', () => {
    assert.equal(globMatch('vendor/**', 'vendor/squizlabs/phpcs/foo.php'), true);
  });

  test('matches a **/*.min.js pattern at any depth', () => {
    assert.equal(globMatch('**/*.min.js', 'assets/js/app.min.js'), true);
    assert.equal(globMatch('**/*.min.js', 'app.min.js'), true);
  });

  test('does not match unrelated paths', () => {
    assert.equal(globMatch('vendor/**', 'includes/class-foo.php'), false);
  });

  test('isExcludedByPattern excludes composer.lock by default', () => {
    assert.equal(isExcludedByPattern('composer.lock'), true);
  });

  test('isExcludedByPattern does not exclude ordinary PHP or test files', () => {
    assert.equal(isExcludedByPattern('includes/certificates/class-dns-provider.php'), false);
    assert.equal(isExcludedByPattern('test/unit/ProviderContractOvhTest.php'), false);
    assert.equal(isExcludedByPattern('.github/workflows/ci.yml'), false);
  });
});

describe('countPatchLines', () => {
  test('counts additions and deletions in a realistic GitHub-shaped patch (no --- a/ / +++ b/ preamble)', () => {
    const patch = [
      '@@ -1,3 +1,4 @@',
      ' unchanged line',
      '-removed line',
      '+added line 1',
      '+added line 2',
      ' another unchanged line',
    ].join('\n');
    const result = countPatchLines(patch);
    assert.deepEqual(result, { additions: 2, deletions: 1 });
  });

  test('regression: a content line whose own text begins with "+++" or "---" is counted, not mistaken for a file header', () => {
    // GitHub's per-file `patch` field never includes a --- a/ / +++ b/
    // preamble (the filename is already given elsewhere in the same API
    // response), so a line starting with that literal sequence here is
    // always genuine added/removed content, e.g. an added YAML document
    // separator or a removed line of code that itself starts with "--".
    const patch = [
      '@@ -1,2 +1,2 @@',
      '-----old marker line',
      '+++new marker line',
    ].join('\n');
    const result = countPatchLines(patch);
    assert.deepEqual(result, { additions: 1, deletions: 1 });
  });

  test('a patch containing only a hunk header (no body lines) counts zero', () => {
    const patch = '@@ -1,1 +1,1 @@';
    assert.deepEqual(countPatchLines(patch), { additions: 0, deletions: 0 });
  });
});

describe('classifyFile', () => {
  test('includes a normal modified PHP file whose counts match', () => {
    const file = {
      filename: 'includes/foo.php',
      status: 'modified',
      additions: 1,
      deletions: 0,
      patch: '@@ -1,1 +1,2 @@\n unchanged\n+added',
    };
    const result = classifyFile(file);
    assert.equal(result.included, true);
  });

  test('includes a removed file with a real patch -- "changed files only" is not narrower than GitHub\'s own diff, and a security-relevant removal must not be silently skipped', () => {
    const file = { filename: 'foo.php', status: 'removed', additions: 0, deletions: 5, patch: '@@ -1,5 +0,0 @@\n-line one\n-line two\n-line three\n-line four\n-line five' };
    const result = classifyFile(file);
    assert.equal(result.included, true);
  });

  test('excludes a file whose status is genuinely content-free ("unchanged")', () => {
    const result = classifyFile({ filename: 'foo.php', status: 'unchanged', additions: 0, deletions: 0, patch: '' });
    assert.equal(result.included, false);
    assert.match(result.reason, /status/);
  });

  test('includes a renamed file with a real patch', () => {
    const file = { filename: 'new-name.php', status: 'renamed', previous_filename: 'old-name.php', additions: 1, deletions: 0, patch: '@@ -1,1 +1,2 @@\n unchanged\n+added' };
    const result = classifyFile(file);
    assert.equal(result.included, true);
  });

  test('excludes a file matching a default pattern', () => {
    const result = classifyFile({ filename: 'package-lock.json', status: 'modified', additions: 100, deletions: 5, patch: '+huge diff' });
    assert.equal(result.included, false);
    assert.match(result.reason, /excluded by file-type/);
  });

  test('excludes a file with no patch at all (binary or too large)', () => {
    // Deliberately not an image/asset extension -- isolates the
    // missing-patch code path from the pattern-exclusion path, which a
    // "photo.png"-style filename would also trigger for an unrelated reason.
    const result = classifyFile({ filename: 'includes/certificates/oversized-file.php', status: 'modified', additions: 0, deletions: 0 });
    assert.equal(result.included, false);
    assert.match(result.reason, /no diff available/);
  });

  test('excludes a file whose parsed patch counts disagree with GitHub-reported stats (incomplete patch)', () => {
    const file = {
      filename: 'includes/foo.php',
      status: 'modified',
      additions: 50, // GitHub says 50 lines were added...
      deletions: 0,
      patch: '@@ -1,1 +1,2 @@\n unchanged\n+added', // ...but the patch text only shows 1
    };
    const result = classifyFile(file);
    assert.equal(result.included, false);
    assert.match(result.reason, /incomplete/);
  });
});

describe('collectDiff', () => {
  function pageFetcher(pages) {
    return async (page) => pages[page - 1] ?? [];
  }

  test('paginates across multiple pages and includes files from all of them', async () => {
    const page1 = Array.from({ length: 100 }, (_, i) => ({
      filename: `file-${i}.php`,
      status: 'modified',
      additions: 1,
      deletions: 0,
      patch: '@@ -1,1 +1,2 @@\n unchanged\n+added',
    }));
    const page2 = [{ filename: 'file-100.php', status: 'added', additions: 1, deletions: 0, patch: '@@ -0,0 +1,1 @@\n+added' }];
    const result = await collectDiff(pageFetcher([page1, page2]), { maxBytes: 1_000_000, maxFiles: 200 });
    assert.equal(result.status, 'ok');
    assert.equal(result.included.length, 101);
  });

  test('flags too_large by file count', async () => {
    const page1 = Array.from({ length: 5 }, (_, i) => ({
      filename: `file-${i}.php`,
      status: 'modified',
      additions: 1,
      deletions: 0,
      patch: '@@ -1,1 +1,2 @@\n unchanged\n+added',
    }));
    const result = await collectDiff(pageFetcher([page1]), { maxBytes: 1_000_000, maxFiles: 2 });
    assert.equal(result.status, 'too_large');
    assert.match(result.reason, /file ceiling/);
  });

  test('flags too_large by total bytes', async () => {
    const bigPatch = '@@ -1,1 +1,2 @@\n unchanged\n+' + 'a'.repeat(1000);
    const page1 = [{ filename: 'big.php', status: 'modified', additions: 1, deletions: 0, patch: bigPatch }];
    const result = await collectDiff(pageFetcher([page1]), { maxBytes: 100, maxFiles: 200 });
    assert.equal(result.status, 'too_large');
    assert.match(result.reason, /byte ceiling/);
  });

  test('reports excluded files with reasons rather than dropping them silently', async () => {
    const page1 = [
      { filename: 'vendor/lib.php', status: 'modified', additions: 5, deletions: 0, patch: '+x' },
      { filename: 'assets/img.png', status: 'modified', additions: 0, deletions: 0 },
    ];
    const result = await collectDiff(pageFetcher([page1]), { maxBytes: 1_000_000, maxFiles: 200 });
    assert.equal(result.status, 'ok');
    assert.equal(result.included.length, 0);
    assert.equal(result.excluded.length, 2);
    assert.ok(result.excluded.some((e) => e.filename === 'vendor/lib.php'));
    assert.ok(result.excluded.some((e) => e.filename === 'assets/img.png'));
  });
});
