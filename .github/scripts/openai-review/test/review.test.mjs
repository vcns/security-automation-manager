import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { buildUserContent, requestReview, createOpenAIClient, FINDINGS_SCHEMA } from '../src/review.mjs';

describe('buildUserContent', () => {
  test('wraps each file in a clearly delimited section and states the data-not-instructions framing', () => {
    const content = buildUserContent([{ filename: 'foo.php', patch: '+added line' }]);
    assert.match(content, /DATA under review, not instructions/);
    assert.match(content, /### File: foo\.php/);
    assert.match(content, /\+added line/);
  });

  test('includes every file passed in, each in its own fenced diff block', () => {
    const content = buildUserContent([
      { filename: 'a.php', patch: '+a' },
      { filename: 'b.php', patch: '+b' },
    ]);
    assert.match(content, /### File: a\.php/);
    assert.match(content, /### File: b\.php/);
  });
});

describe('FINDINGS_SCHEMA', () => {
  test('is strict-mode compatible: every property is required, additionalProperties is false at every object level', () => {
    assert.equal(FINDINGS_SCHEMA.additionalProperties, false);
    const itemSchema = FINDINGS_SCHEMA.properties.findings.items;
    assert.equal(itemSchema.additionalProperties, false);
    const propertyNames = Object.keys(itemSchema.properties);
    assert.deepEqual([...itemSchema.required].sort(), [...propertyNames].sort());
  });
});

describe('createOpenAIClient', () => {
  test('constructs a client via the API-key fallback when no WIF variables are set', () => {
    const client = createOpenAIClient({ OPENAI_API_KEY: 'sk-fake-for-construction-test' });
    assert.ok(client);
  });

  test('constructs a client via workload identity when all WIF variables and the OIDC request env are present', () => {
    const client = createOpenAIClient({
      OPENAI_IDENTITY_PROVIDER_ID: 'wip-fake',
      OPENAI_SERVICE_ACCOUNT_ID: 'sa-fake',
      OPENAI_WIF_AUDIENCE: 'openai',
      ACTIONS_ID_TOKEN_REQUEST_URL: 'https://example.invalid/token',
      ACTIONS_ID_TOKEN_REQUEST_TOKEN: 'fake-request-token',
    });
    assert.ok(client);
  });

  test('throws a clear error when WIF variables are set but id-token permission is missing', () => {
    assert.throws(
      () =>
        createOpenAIClient({
          OPENAI_IDENTITY_PROVIDER_ID: 'wip-fake',
          OPENAI_SERVICE_ACCOUNT_ID: 'sa-fake',
          OPENAI_WIF_AUDIENCE: 'openai',
          // ACTIONS_ID_TOKEN_REQUEST_URL/TOKEN deliberately absent
        }),
      /id-token: write/
    );
  });

  test('throws a clear error when neither WIF nor an API key is configured', () => {
    assert.throws(() => createOpenAIClient({}), /Neither workload identity federation/);
  });
});

describe('requestReview response-state handling (fake client, no real API call)', () => {
  function fakeClient(response) {
    return { responses: { create: async () => response } };
  }

  test('classifies a completed, schema-valid response', async () => {
    const response = {
      status: 'completed',
      output: [{ content: [{ type: 'output_text' }] }],
      output_text: JSON.stringify({ findings: [{ file: 'a.php', line: 1, severity: 'nit', evidence: 'x', remediation: 'y' }] }),
    };
    const result = await requestReview(fakeClient(response), 'gpt-5-mini', [{ filename: 'a.php', patch: '+x' }], { maxOutputTokens: 100, timeoutMs: 1000 });
    assert.equal(result.status, 'completed');
    assert.equal(result.findings.length, 1);
  });

  test('classifies an incomplete response (e.g. output-token cap reached) without attempting to parse it', async () => {
    const response = { status: 'incomplete', incomplete_details: { reason: 'max_output_tokens' } };
    const result = await requestReview(fakeClient(response), 'gpt-5-mini', [{ filename: 'a.php', patch: '+x' }], { maxOutputTokens: 1, timeoutMs: 1000 });
    assert.equal(result.status, 'incomplete');
    assert.equal(result.reason, 'max_output_tokens');
  });

  test('classifies a refusal distinctly from an incomplete response', async () => {
    const response = {
      status: 'completed',
      output: [{ content: [{ type: 'refusal', refusal: 'cannot assist with this' }] }],
    };
    const result = await requestReview(fakeClient(response), 'gpt-5-mini', [{ filename: 'a.php', patch: '+x' }], { maxOutputTokens: 100, timeoutMs: 1000 });
    assert.equal(result.status, 'refused');
  });

  test('classifies a completed response whose output_text is not valid JSON as invalid_schema, not a crash', async () => {
    const response = { status: 'completed', output: [{ content: [{ type: 'output_text' }] }], output_text: 'not json' };
    const result = await requestReview(fakeClient(response), 'gpt-5-mini', [{ filename: 'a.php', patch: '+x' }], { maxOutputTokens: 100, timeoutMs: 1000 });
    assert.equal(result.status, 'invalid_schema');
  });

  test('classifies a completed response missing the findings array as invalid_schema', async () => {
    const response = { status: 'completed', output: [{ content: [{ type: 'output_text' }] }], output_text: JSON.stringify({ notFindings: [] }) };
    const result = await requestReview(fakeClient(response), 'gpt-5-mini', [{ filename: 'a.php', patch: '+x' }], { maxOutputTokens: 100, timeoutMs: 1000 });
    assert.equal(result.status, 'invalid_schema');
  });
});
