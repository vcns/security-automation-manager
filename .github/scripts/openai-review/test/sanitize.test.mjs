import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { sanitizeModelText, sanitizeFilePath } from '../src/sanitize.mjs';

describe('sanitizeModelText', () => {
  test('neutralises an @mention so it cannot notify anyone', () => {
    const result = sanitizeModelText('cc @someone please review');
    assert.doesNotMatch(result, /@someone/); // the exact notifying sequence must not survive intact
    assert.match(result, /someone/); // but the visible text is preserved
  });

  test('escapes raw HTML so no tag can render', () => {
    const result = sanitizeModelText('<img src=x onerror=alert(1)>');
    assert.doesNotMatch(result, /<img/);
    assert.match(result, /&lt;img/);
  });

  test('escapes a hidden HTML comment so it cannot smuggle content or collide with the dedup marker', () => {
    const result = sanitizeModelText('normal text <!-- openai-review:v1 --> more text');
    assert.doesNotMatch(result, /<!--/);
  });

  test('neutralises markdown image syntax so nothing external is embedded', () => {
    const result = sanitizeModelText('see ![evidence](https://attacker.example/track.png)');
    // The bracket is escaped (\[), so "![evidence](" no longer appears as
    // valid, unescaped link/image syntax -- assert the escape is present
    // rather than searching for the substring's mere presence, since the
    // substring itself still legitimately appears (now inert) either way.
    assert.match(result, /!\\\[evidence\]\(/);
    assert.doesNotMatch(result, /(?<!\\)!\[evidence\]\(/);
  });

  test('neutralises markdown link syntax so nothing external is linked', () => {
    const result = sanitizeModelText('see [details](https://attacker.example/phish)');
    assert.match(result, /\\\[details\]\(/);
    assert.doesNotMatch(result, /(?<!\\)\[details\]\(/);
  });

  test('bounds length and marks truncation', () => {
    const result = sanitizeModelText('a'.repeat(10000));
    assert.ok(result.length < 10000);
    assert.match(result, /…$/);
  });

  test('leaves ordinary prose and inline code spans untouched in substance', () => {
    const result = sanitizeModelText('Use `array_map()` instead of a manual loop.');
    assert.match(result, /`array_map\(\)`/);
  });
});

describe('sanitizeFilePath', () => {
  test('neutralises a backtick so it cannot break out of a code span', () => {
    const result = sanitizeFilePath('weird`file.php');
    assert.doesNotMatch(result, /`/);
  });

  test('neutralises an @ in a filename', () => {
    const result = sanitizeFilePath('@scope/weird-file.php');
    assert.doesNotMatch(result, /@scope/);
  });

  test('leaves an ordinary path unchanged in substance', () => {
    const result = sanitizeFilePath('includes/certificates/class-dns-provider.php');
    assert.match(result, /includes\/certificates\/class-dns-provider\.php/);
  });
});
