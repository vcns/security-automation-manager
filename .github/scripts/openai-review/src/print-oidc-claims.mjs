/**
 * One-time setup diagnostic, NOT part of the review pipeline itself.
 *
 * Requests a GitHub Actions OIDC token exactly as review.mjs's WIF path
 * would, in this exact job/trigger context, decodes its claims locally
 * (JWT payload only -- base64url decode, no signature verification, no
 * exchange with OpenAI), and prints them so an operator can configure the
 * OpenAI Workload Identity Provider mapping from what this specific
 * workflow_run job actually emits -- per OpenAI's own guidance, claim
 * values (particularly `ref` and `workflow_ref`) should be observed, not
 * assumed, since they depend on the triggering event shape.
 *
 * The raw token is never printed or logged, only its decoded claims.
 * Invoked as a gated, temporary step in openai-review-comment.yml (see
 * docs/ci-openai-review.md) -- turn the gate on, run once, note the
 * claims, turn it back off.
 */

const audience = process.env.OPENAI_WIF_AUDIENCE || 'openai';
const requestUrl = process.env.ACTIONS_ID_TOKEN_REQUEST_URL;
const requestToken = process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN;

if (!requestUrl || !requestToken) {
  throw new Error('ACTIONS_ID_TOKEN_REQUEST_URL/ACTIONS_ID_TOKEN_REQUEST_TOKEN are not set -- this job is missing `id-token: write`.');
}

const url = new URL(requestUrl);
url.searchParams.set('audience', audience);

const response = await fetch(url, { headers: { Authorization: `bearer ${requestToken}` } });
if (!response.ok) {
  throw new Error(`Failed to request GitHub OIDC token: ${response.status} ${response.statusText}`);
}

const { value: jwt } = await response.json();
if (!jwt) {
  throw new Error('GitHub OIDC token response did not include a value.');
}

const [, payloadSegment] = jwt.split('.');
const payload = JSON.parse(Buffer.from(payloadSegment, 'base64url').toString('utf8'));

const relevantClaims = {
  iss: payload.iss,
  aud: payload.aud,
  sub: payload.sub,
  repository: payload.repository,
  repository_owner: payload.repository_owner,
  event_name: payload.event_name,
  ref: payload.ref,
  ref_type: payload.ref_type,
  workflow_ref: payload.workflow_ref,
  job_workflow_ref: payload.job_workflow_ref,
  run_id: payload.run_id,
};

console.log('Observed OIDC claims for this job (raw token not printed):'); // eslint-disable-line no-console
console.log(JSON.stringify(relevantClaims, null, 2)); // eslint-disable-line no-console
console.log('\nConfigure the OpenAI Workload Identity Provider mapping from the values above -- do not assume `ref` is `refs/heads/main` without checking it here first.'); // eslint-disable-line no-console
