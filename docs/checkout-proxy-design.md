# VCNS Checkout & Entitlement Proxy — Design Proposal

**Status: proposed, awaiting sign-off. Nothing in this document is implemented.**

## Problem

The commercial build's checkout flow currently requires VCNS's own
account-wide Stripe secret key to be entered into the plugin's admin UI and
stored as a plaintext WordPress option on whichever site runs checkout (see
`SECURITY.md` and the "Entitlements and commercial control plane" section of
`docs/threat-model.md`). That key can create charges and issue refunds
against VCNS's entire Stripe account. Any compromise of that one WordPress
install — a different plugin's vulnerability, a leaked backup, a malicious
co-admin, a compromised host — exposes it.

This is a regression: an earlier architecture (a Cloudflare Worker holding
the same key as a Worker secret) had this property correctly and was removed
in PR #143 to make checkout "configurable without leaving wp-admin."

**Design goal, stated directly by the product owner:** customers using the
WordPress plugin must never see, hold, or be able to extract a Stripe secret,
under any circumstance — not in the wp-admin UI, not in the database, not in
the shipped plugin code. The plugin must be able to sell entitlements and
verify them without ever possessing a credential capable of acting on VCNS's
Stripe account.

## Why "bake it into the release ZIP" doesn't solve this

Worth stating explicitly since it was the first option considered: a secret
embedded in the plugin package via CI/CD (a PHP constant defined at build
time from a GitHub Actions secret) is still present on every server that
installs the plugin. It's invisible in the wp-admin UI, but it's still
extractable by anyone with filesystem or process access on any one customer
site — the same blast radius as the current option-based storage, just a
different storage location. GitHub Actions secrets protect the build
pipeline; they say nothing about what happens to a value once it's compiled
into an artifact that ships to thousands of untrusted servers. **The only
architecture that satisfies "customers never see it" is one where the secret
never leaves VCNS-controlled infrastructure in the first place.**

## Goals

1. The Stripe secret key and webhook signing secret exist only on
   VCNS-controlled infrastructure, never on a customer's WordPress install.
2. The plugin can still offer a self-service "buy now" flow inside wp-admin —
   no degradation of the current customer experience.
3. Entitlement grants are cryptographically verifiable by the plugin without
   a network call on every page load (reuse the existing
   `sam_entitlements` local-state-first model — see `docs/stripe-operations.md`
   "no per-request remote licence check during normal plugin runtime").
4. Reuse the signing pattern already specified in
   `docs/remote-config-and-signing.md` (Ed25519, detached signature, embedded
   public key) rather than inventing a new one.
5. The proxy's own attack surface is small, reviewable, and its secrets have
   documented rotation/revocation/incident-response procedures from day one
   (closing the gap noted in `docs/security-privacy-checklist.md`).

## Non-goals (for this iteration)

- Subscription billing — the commercial model is one-time purchase
  (`docs/stripe-operations.md`); this proposal doesn't change that.
- Multi-tenant fleet billing (#188/#189) — out of scope until fleet
  management itself is designed.
- Replacing `Feature_Gate`'s local-decision model — the proxy changes how
  entitlements are *granted*, not how they're *checked* at runtime.

## Proposed architecture

```
┌─────────────────────────┐         ┌──────────────────────────┐         ┌────────────┐
│  WordPress install      │         │  VCNS Checkout Proxy      │         │   Stripe   │
│  (Checkout_Service,      │         │  (new repo, Cloudflare    │         │            │
│   Entitlement_Store)     │         │   Worker)                 │         │            │
│                          │         │                            │         │            │
│  Holds:                  │  (1)    │  Holds:                    │  (2)    │            │
│  - site_identity hash    │ ──────► │  - Stripe secret key       │ ──────► │  Creates   │
│  - product_key            │        │  - Stripe webhook secret   │         │  Checkout  │
│  - Ed25519 PUBLIC key      │        │  - Ed25519 PRIVATE key     │         │  Session   │
│  (all safe to ship)       │        │  (all secret, in Worker    │         │            │
│                          │         │   Secrets, never in git)   │         │            │
│                          │ ◄────── │                            │ ◄────── │  Webhook   │
│                          │  (4)    │                            │  (3)    │  event     │
└─────────────────────────┘         └──────────────────────────┘         └────────────┘
```

1. Admin clicks "Buy" in wp-admin. Plugin POSTs `{site_identity, product_key,
   plugin_version}` to the proxy — no secret involved, nothing here is
   sensitive if intercepted.
2. Proxy creates a Stripe Checkout Session using its own (never-shipped)
   secret key, embeds `site_identity` and `product_key` in Checkout Session
   metadata, and returns the Checkout Session URL. The plugin redirects the
   admin's browser there. Payment happens entirely on Stripe's hosted page —
   the plugin never touches card data (unchanged from today).
3. Stripe sends the webhook event to the proxy's endpoint, not the WordPress
   site. The proxy verifies Stripe's HMAC signature using its own webhook
   secret (never shipped) and the existing 5-minute timestamp tolerance
   pattern already used by `Webhook_Controller` today.
4. The proxy looks up which site the `site_identity` in the event metadata
   belongs to, builds a small JSON payload (`site_identity`, `product_key`,
   `tier`, `granted_at`, a nonce), and signs it with its Ed25519 private key.
   The plugin polls `GET /entitlement/{site_identity}` once, shortly after
   the checkout redirect returns to wp-admin, and verifies the signature
   against its embedded public key (decided — see "Decided" below; a
   callback model was considered and rejected).

The plugin's local `sam_entitlements` table is written only after signature
verification succeeds, exactly as `Webhook_Controller` does today for direct
webhook events — this preserves the existing "entitlements from webhooks
only" invariant (`docs/threat-model.md` invariant #1), just moved one hop
further from Stripe.

## What moves and what stays

| Component | Today | After this change |
|---|---|---|
| Stripe secret key, webhook secret | WordPress option, this repo | Cloudflare Worker Secret, new repo — **never in this repo, never in any customer database** |
| Checkout Session creation | `Checkout_Service`, direct Stripe API call | Proxy, direct Stripe API call |
| Webhook receipt | `Webhook_Controller`, this repo's REST route | Proxy's own endpoint |
| Entitlement grant → local DB write | `Webhook_Controller` writes `sam_entitlements` directly | Plugin writes `sam_entitlements` after verifying the proxy's signed payload |
| Entitlement *checking* at runtime (`Feature_Gate`) | Local DB only, no network call | **Unchanged** — still local DB only, no network call |
| Ed25519 keypair | Specified in `docs/remote-config-and-signing.md`, never implemented | Implemented, reused for this purpose (and available for the originally-intended remote product-config use case too) |

## New repo proposal

A new, separate repository — **not merged into
`vcns/security-automation-manager`** — holding:

- `worker.js` / TypeScript Worker source (Stripe Checkout Session creation,
  webhook verification, Ed25519 signing)
- `wrangler.toml` (the `wp-sam.vcns.tech` custom domain route this project
  already used before — per PR #122's changelog entry)
- Its own CI (lint, unit tests for the signing/verification logic, a secret
  scan identical in spirit to this repo's `secret-scan` CI job)
- Its own `SECURITY.md` and threat model, scoped to this proxy specifically
- Its own deployment workflow (`wrangler deploy`, authenticated via a
  Cloudflare API token stored as a GitHub Actions secret **on that repo
  only** — this repo's CI/CD should never hold Cloudflare or Stripe
  credentials)

Suggested name: `vcns/wp-sam-checkout-proxy` (matching the naming convention
already visible in `vcns/wp-updates`, the sibling repo referenced by PR #206).
Left for your decision — not creating it as part of this proposal.

## Threat model for the proxy itself

The proxy becomes the highest-value target in this system once it exists — it
holds the one credential that used to be scattered across every commercial
install and will now be concentrated in one place. That's the right trade
(one hardened, reviewable, access-controlled target beats N uncontrolled
ones), but it means the proxy's own security posture matters more than any
single WordPress install's.

| Threat | Mitigation |
|---|---|
| Compromise of the Worker's source/deploy pipeline | Deploy only via CI from the new repo's protected `main` branch; Cloudflare API token scoped to this Worker only, not account-wide; branch protection + required review on the new repo |
| Compromise of Worker Secrets at rest | Cloudflare Worker Secrets are encrypted at rest and not readable via the Workers API once set (write-only) — this is a real, load-bearing security property of the chosen platform, not just convenience |
| Forged checkout-initiation requests (fake `site_identity`) | Low severity by design — initiation requests carry no secret and can only result in a Checkout Session being created (a real payment must still occur on Stripe's hosted page for any entitlement to be granted); rate-limit per `site_identity` regardless, to prevent Stripe API abuse |
| Forged webhook events to the proxy | Mitigated identically to today's `Webhook_Controller`: Stripe HMAC-SHA256 signature verification + timestamp tolerance, now happening at the proxy instead of the WordPress site |
| Forged entitlement-grant callback to a WordPress site | Mitigated by Ed25519 signature verification on the plugin side against its embedded public key — a forger without the proxy's private key cannot produce a valid signature |
| Proxy grants entitlement to the wrong site | `site_identity` must be threaded through unmodified from checkout-initiation through Checkout Session metadata through webhook event through signed grant — add a test asserting this end-to-end, not just at each hop |
| Replay of a valid signed grant payload | Include a nonce and `granted_at` timestamp in the signed payload; plugin should reject a grant it's already applied (idempotent by `stripe_session_id`, matching the existing `sam_processed_events` pattern) |
| Key compromise (Stripe secret, webhook secret, or Ed25519 private key) | **Must be written before this ships** — rotation, revocation, recovery, and incident-response procedures, added to the signing-key inventory in `docs/security-privacy-checklist.md` |
| Denial of service against the proxy blocking all checkouts fleet-wide | Cloudflare Workers' platform-level DDoS protection covers infrastructure-level attacks; add application-level rate limiting per IP/site_identity regardless |

## API contract (draft)

```
POST https://wp-sam.vcns.tech/checkout
  Request:  { site_identity, product_key, plugin_version }
  Response: { checkout_url }  |  4xx on invalid product_key

POST https://wp-sam.vcns.tech/webhook/stripe   (Stripe → proxy only)
  Verified via Stripe-Signature header, as today's Webhook_Controller does

GET https://wp-sam.vcns.tech/entitlement/{site_identity}
  Response: { payload: {...}, signature: "<base64 Ed25519 detached sig>" }
```

Exact field names, error codes, and rate limits are implementation detail to
finalise during implementation — this contract
is illustrative, not final.

## Migration for existing commercial installs

Sites that already have `wp_sam_stripe_secret_key_live` etc. populated today
need a transition path, not a silent breaking change:

1. Ship a plugin version that supports both paths simultaneously: if the
   proxy is reachable and the site has no legacy Stripe keys configured, use
   the proxy; if legacy keys are already present, keep using them (with an
   admin notice recommending migration) rather than breaking existing
   checkout flows outright.
2. Add a one-click "Migrate to VCNS-hosted checkout" action that clears the
   local Stripe key options once the proxy path is confirmed working.
3. After a deprecation window, remove the legacy direct-Stripe code path and
   its settings UI entirely — the fields the redacted `SECURITY.md` note and
   `docs/threat-model.md` currently describe as the known gap should no
   longer exist in the codebase at that point, not just be unused.
4. Rotate VCNS's current live Stripe secret key after migration completes,
   since it has been present in an unknown number of customer databases up to
   that point — treat this the same as any other credential that was exposed
   beyond its intended trust boundary, regardless of whether misuse is ever
   observed.

## Decided

1. **Entitlement delivery: poll.** The plugin polls
   `GET /entitlement/{site_identity}` once, shortly after the checkout
   redirect returns control to wp-admin (not on every page load), and
   verifies the signed response before writing to `sam_entitlements`. The
   proxy never makes outbound requests to customer-controlled URLs, avoiding
   SSRF-adjacent concerns and working behind firewalls/local dev.
2. **Ed25519 keypair: separate from remote-config signing.** This proxy uses
   its own entitlement-signing keypair, distinct from the (still
   unimplemented) product-config-signing keypair in
   `docs/remote-config-and-signing.md`. Different blast radius if compromised;
   rotating one must not force rotating the other.

## Still open

3. Repo name and Cloudflare account/ownership details — yours to decide.
4. Timeline for the migration/deprecation window in the section above.

## Sign-off

Poll-based delivery and separate keypairs are confirmed. This document should
not move to implementation until the new repo exists and items 3-4 above are
settled.
