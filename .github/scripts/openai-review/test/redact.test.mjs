import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { detectSecretShape } from '../src/redact.mjs';

describe('detectSecretShape', () => {
  test('detects an AWS access key ID shape', () => {
    assert.equal(detectSecretShape('const key = "AKIAABCDEFGHIJKLMNOP";'), 'AWS access key ID');
  });

  test('detects a GitHub token shape', () => {
    assert.equal(detectSecretShape('token: ghp_' + 'a'.repeat(36)), 'GitHub token');
  });

  test('detects a PEM private key block', () => {
    assert.equal(detectSecretShape('-----BEGIN RSA PRIVATE KEY-----\nMIIB...'), 'PEM private key block');
  });

  test('returns null for ordinary code with no secret-shaped content', () => {
    assert.equal(detectSecretShape('+function create_txt_record( string $fqdn, string $value ): void {'), null);
  });

  test('this is best-effort, not exhaustive -- an opaque unmatched token format is not detected', () => {
    // Documented limitation, asserted explicitly so it can't silently
    // start passing (and be mistaken for a guarantee) without review.
    assert.equal(detectSecretShape('const internalToken = "xyz-not-a-known-shape-12345";'), null);
  });
});
