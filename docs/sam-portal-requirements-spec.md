# VCNS SAM Portal
## Requirements Specification

**Product:** sam.vcns.tech (working name -- see §14.1 for the domain/naming decision this still needs)
**Repository:** New, separate repository -- not part of `vcns/security-automation-manager` (unchanged from `docs/checkout-proxy-design.md`'s recommendation)
**Baseline:** security-automation-manager v2.9.44
**Status:** Draft for sign-off
**Date:** 2 September 2026

---

# 1. Purpose

The commercial build's checkout flow today asks the customer's own WordPress install to hold VCNS's Stripe secret key and webhook signing secret as plaintext WordPress options (`includes/extensions/fully-automatic-mode.php`). That key can create charges and issue refunds against VCNS's entire Stripe account. Any compromise of any one commercial install -- a different plugin's vulnerability, a leaked backup, a malicious co-admin, a compromised host -- exposes it. `docs/security-privacy-checklist.md` already flags this as a known, unresolved gap, and GitHub issue #172 (closed 2026-09-02, redirected here) tracked building a fix.

This is not a new problem or a new proposed fix -- `docs/checkout-proxy-design.md` ("proposed, awaiting sign-off") already designed a Cloudflare Worker proxy to solve exactly this, and its threat model, non-goals, and most of its architecture stand. What changed on 2026-09-02 is the *delivery mechanism*: the product owner now wants a license-key model (customer holds a portable key, not a `site_identity` handshake) rather than the polling API `checkout-proxy-design.md` specified. This document is the requirements spec for that updated direction, reconciling it explicitly against the prior design rather than silently replacing it -- see §2.

**Design goal, unchanged from the prior proposal:** a customer using the WordPress plugin must never see, hold, or be able to extract a Stripe secret, under any circumstance -- not in wp-admin, not in the database, not in the shipped plugin code. The only architecture that satisfies this is one where the secret never leaves VCNS-controlled infrastructure.

---

# 2. Relationship to Prior Design Work

Three existing documents already cover adjacent ground. This spec builds on all three rather than re-deriving them:

| Document | What it covers | What this spec changes |
|---|---|---|
| `docs/checkout-proxy-design.md` | Cloudflare Worker architecture, threat model, non-goals, migration plan | Delivery model only: replaces `site_identity` + `GET /entitlement/{site_identity}` polling with a customer-held license key (§7) as the primary binding mechanism |
| `docs/stripe-operations.md` | Today's interim direct-Stripe flow: one-time payment, webhook-driven entitlement grant, `site_identity` = truncated SHA-256 of site URL | Becomes the portal's own internal flow instead of the plugin's; the plugin no longer holds Stripe keys at all (§12 migration) |
| `docs/remote-config-and-signing.md` | Ed25519 detached-signature pattern, DNS-discovered signed JSON config, key management/rotation guidance | Reused verbatim for entitlement-payload signing, with its own separate keypair -- already decided in `checkout-proxy-design.md`'s "Decided" §2, restated in §9.3 below |

Everything in `checkout-proxy-design.md`'s threat model (§9), non-goals (§11), and migration plan (§12) carries forward unless explicitly called out as changed here.

---

# 3. Product Model -- What This Is And Is Not

The portal **is**: a minimal checkout-initiation, license-issuance, and license-validation service. Three jobs, nothing else.

The portal **is not**:

- A customer account dashboard (no login, no order history UI beyond a one-time post-purchase confirmation page).
- A general SaaS backend or API platform.
- A fleet-management console (GitHub #188/#189 remain explicitly deferred -- this portal issues one license per purchase, it does not manage a fleet of sites).
- A support ticketing system.
- A subscription billing platform -- the commercial model stays one-time purchase, unchanged from `docs/stripe-operations.md`.

Keeping this list explicit matters: every one of these is a plausible scope-creep direction for "a portal," and this product should stay small and cheap on purpose (§13).

---

# 4. User Journeys

## 4.1 New customer, no license key yet

1. Admin clicks "Buy" inside wp-admin (Fully Automatic mode settings, `includes/extensions/fully-automatic-mode.php`).
2. Plugin redirects the browser to `https://sam.vcns.tech/buy?product=<product_key>&return_url=<wp-admin settings page URL>` -- no secret involved, nothing sensitive if intercepted.
3. Portal resolves `product_key` to a Stripe Price ID (server-side, from its own config -- not the plugin's remote config) and creates a Stripe Checkout Session. The browser is redirected straight to Stripe's hosted checkout page. Payment happens entirely on Stripe's page; the portal never touches card data, same as today.
4. On `checkout.session.completed`, Stripe posts a webhook to the portal (not the WordPress site). The portal verifies Stripe's signature, generates a license key, and stores a license record (§6).
5. The browser (still on Stripe's success-redirect back to the portal) lands on a one-time confirmation page showing the license key with a copy affordance, plus a "Back to your site" link built from the `return_url` passed in step 2.
6. Admin copies the key, returns to wp-admin, pastes it into a "License Key" field (§10), and saves.
7. The plugin calls the portal's validate endpoint (§8) with the key, verifies the signed response, and writes the entitlement locally.

## 4.2 Existing customer, already holds a license key

Admin pastes a previously-issued key directly into wp-admin without visiting the portal at all. Same validate -> verify -> write flow as step 7 above.

## 4.3 Re-validation

The plugin re-validates on a low-frequency schedule (daily cron, piggybacking on the existing `wp_sam_daily_scan` hook -- not a new cron entry), not on every page load. This preserves the existing "no per-request remote licence check during normal plugin runtime" invariant from `docs/stripe-operations.md`. Grace-period behaviour on a failed re-validation is specified in §10.2 and directly closes GitHub issue #174.

## 4.4 Lost license key

Out of scope for this portal's UI (no account/login system, per §3). A lost key is a support-mediated recovery: the customer contacts VCNS support with their Stripe receipt/customer email, and a human looks up the license via the portal's admin tooling (§8.5) and re-sends it. Not a self-service flow in v1.

---

# 5. Architecture

```
┌──────────────────────────┐        ┌────────────────────────────┐        ┌────────────┐
│  WordPress install        │        │  sam.vcns.tech              │        │   Stripe   │
│  (plugin, Fully Automatic │        │  (Cloudflare Worker)         │        │            │
│   mode)                   │        │                              │        │            │
│                            │  (1)   │  Holds:                      │  (2)   │            │
│  Holds:                    │ ─────► │  - Stripe secret key         │ ─────► │  Creates   │
│  - license key (customer- │        │  - Stripe webhook secret     │        │  Checkout  │
│    entered, plaintext but  │        │  - Ed25519 private key       │        │  Session   │
│    not a Stripe secret)    │        │  (all in Worker Secrets,     │        │            │
│  - Ed25519 PUBLIC key       │        │   never in git)              │        │            │
│  (safe to ship)             │ ◄───── │                              │ ◄───── │  Webhook   │
│                            │  (4)   │  Storage: Workers KV          │  (3)   │  event     │
└──────────────────────────┘        │  (license records, §6)       │        └────────────┘
                                     └────────────────────────────┘
```

1. Admin clicks "Buy"; plugin redirects to the portal's `/buy` endpoint (no secret in this request).
2. Portal creates a Stripe Checkout Session with its own (never-shipped) secret key.
3. Stripe posts the webhook event to the portal's own endpoint, not the WordPress site.
4. The plugin later calls `/license/{key}/validate` (initiated by the customer pasting the key, and periodically after that) and verifies the Ed25519-signed response before writing to `sam_entitlements`.

**Compute:** Cloudflare Workers (single service, no separate backend).
**Storage:** Workers KV, keyed by license key (§6). Eventual consistency is acceptable -- license validation is not a hard real-time-consistency requirement, and KV is materially cheaper and simpler to operate than D1 at this product's expected scale. Revisit only if a real need for relational queries across license history emerges.
**Payments:** Stripe Checkout Sessions (`mode: payment`, one-time), unchanged from `docs/stripe-operations.md`.
**Signing:** Ed25519 detached signatures, reusing the pattern in `docs/remote-config-and-signing.md` with a **separate keypair** (§9.3) -- different blast radius if compromised, and rotating one must never force rotating the other.

---

# 6. Data Model

One KV namespace, one record type, keyed by license key.

**License record:**

| Field | Type | Notes |
|---|---|---|
| `license_key` | string | The key itself; also the KV key |
| `product_key` | string | Matches the plugin's product identifiers |
| `tier` | string | e.g. `pro` |
| `status` | string | `issued` \| `active` \| `revoked` |
| `stripe_customer_id` | string | |
| `stripe_checkout_session_id` | string | Idempotency anchor -- a webhook redelivery for the same session must not issue a second key |
| `stripe_payment_intent_id` | string | |
| `issued_at` | ISO 8601 timestamp | |
| `revoked_at` | ISO 8601 timestamp \| null | |
| `revocation_reason` | string | Free text, human-readable, for support use |
| `bound_site_identity` | string \| null | Set on first successful validation, per the binding policy in §7 -- null until then |
| `last_validated_at` | ISO 8601 timestamp | Updated on every successful `/validate` call |

This deliberately mirrors -- but is not identical to -- the plugin-side `sam_entitlements` schema (`includes/extensions/commercial-services.php`, shipped via PR #289: `tier`, `status`, `stripe_customer_id/session_id/payment_intent_id`, `config_version`, `granted_at`, `expires_at`, `revoked_at`, `revocation_reason`, `grace_until`, `last_validated_at`). The plugin's copy is the *local, cached* view; the portal's copy is authoritative. Field names are kept close on purpose so the mapping stays obvious when writing the client integration (§10).

---

# 7. License Key Design

**Format:** human-typeable, low ambiguity -- `SAM-XXXX-XXXX-XXXX-XXXX`, Crockford Base32 alphabet (excludes `0`/`O`/`1`/`I`/`L` to reduce transcription errors when a customer copies it off a confirmation screen). At least 128 bits of entropy before formatting, so brute-forcing the validate endpoint stays infeasible even under generous rate limits.

**Site-binding policy -- open decision, recommendation given:** bind a key to the *first site* that successfully validates it; expose no self-service re-bind, only a support-mediated one (consistent with §4.4's lost-key flow -- both are rare, human-handled cases).

- Rejected alternative: unlimited validations per key, on the grounds that it reintroduces the exact "one shared secret, unlimited blast radius" problem this whole project exists to move away from -- a leaked key would work on any number of sites with no portal-side signal that anything is wrong.
- This is still a real product decision, not a technical one (it affects legitimate multi-site/migration customers), so it's called out again in §14.2 rather than treated as settled by this recommendation alone.

---

# 8. API Contract

```
GET https://sam.vcns.tech/buy?product=<product_key>&return_url=<url>
  Creates a Stripe Checkout Session for product_key, redirects the browser to it.
  4xx on an unrecognised product_key.

POST https://sam.vcns.tech/webhook/stripe          (Stripe -> portal only)
  Verified via the Stripe-Signature header, same HMAC + timestamp-tolerance
  pattern as today's Webhook_Controller. On checkout.session.completed,
  generates a license key (idempotent on stripe_checkout_session_id) and
  stores the license record.

GET https://sam.vcns.tech/license/{key}
  One-time, human-readable confirmation page. Only meaningfully reachable
  immediately after Stripe's success redirect in the purchase flow (§4.1
  step 5) -- not intended as a durable "look up your key" page, since there's
  no account system to authenticate the request.

GET https://sam.vcns.tech/license/{key}/validate
  Response: { payload: { product_key, tier, status, issued_at, nonce },
              signature: "<base64 Ed25519 detached sig>" }
  404-equivalent JSON error for a key that doesn't exist or is revoked --
  see §9.2 for why "doesn't exist" and "revoked" must not be distinguishable
  in this response.

Internal / admin-only, not customer-facing:
GET https://sam.vcns.tech/admin/license?stripe_customer_email=<email>
  Support-mediated lookup for the lost-key flow (§4.4). Requires its own
  authentication (§9.4) -- exact mechanism is an implementation decision,
  not specified here.
```

Exact field names, error codes, and rate limits are implementation detail to finalise during build -- this contract is illustrative, not final, same caveat `checkout-proxy-design.md` gave its own draft contract.

---

# 9. Security Requirements

## 9.1 Secrets

The Stripe secret key, Stripe webhook signing secret, and Ed25519 private key exist only in Cloudflare Worker Secrets (encrypted at rest, write-only via the Workers API once set) and never in git, never in a customer WordPress database, never in this repository.

## 9.2 License keys are bearer tokens -- treat them like one

Unlike `checkout-proxy-design.md`'s `site_identity` model (which carried no secret value and was useless to an attacker without the proxy's private key), a license key alone is sufficient to call `/validate` and receive a valid signed entitlement. This is a **new** threat surface the license-key model introduces:

- **Rate limit** `/validate` aggressively per source IP and per key prefix, to make brute-force enumeration of the key space impractical given the entropy in §7.
- **Do not leak existence.** A request for a key that doesn't exist and a request for a key that's been revoked must return indistinguishable responses (same status code, same generic error body) to an unauthenticated caller -- otherwise the endpoint becomes an oracle for enumerating valid-but-revoked keys, or for confirming a guessed key exists before trying to determine its status some other way.
- **Treat a leaked license key as a real incident**, not a shrug -- it grants working entitlement on whichever site validates it first (§7's binding policy), same severity class as a leaked API key, even though it can't touch Stripe or VCNS's account directly.

## 9.3 Signing

Ed25519 detached signatures, reusing the pattern already specified in `docs/remote-config-and-signing.md` (canonical JSON, stable key order, signature field excluded from the signed payload). **Separate keypair from the remote-config-signing key** -- confirmed carried over from `checkout-proxy-design.md`'s "Decided" §2; do not reuse the same key for both purposes.

## 9.4 Everything else

The remainder of `checkout-proxy-design.md`'s threat table (§9 in that document) applies unchanged: Worker deploy pipeline hardening, webhook forgery mitigation (Stripe HMAC + timestamp tolerance), replay protection on the signed grant payload (nonce + timestamp, idempotent by `stripe_checkout_session_id`), and Cloudflare's platform-level DDoS protection plus application-level rate limiting. The admin lookup endpoint in §8 needs its own authentication design, not specified here -- flagged as an implementation task, not a decision this document resolves.

---

# 10. Plugin-Side Integration Requirements

## 10.1 UI and storage

- New settings field in `includes/extensions/fully-automatic-mode.php`: "License Key" -- a text input, masked/write-only on redisplay after save (matching the existing pattern for `wp_sam_webhook_secret` in the same file).
- New `admin_post` handler: takes the pasted key, calls `/license/{key}/validate`, verifies the Ed25519 signature against the plugin's embedded public key constant, and writes the result into `sam_entitlements` -- exactly mirroring how `Webhook_Controller` writes entitlements today, preserving the "entitlements written only after verified signature/webhook" invariant.
- The Stripe secret key, publishable key, and webhook secret settings fields in `fully-automatic-mode.php` are retired once migration (§12) completes -- they should not coexist indefinitely with the license-key field.

## 10.2 Grace period -- closes GitHub #174

This is the concrete implementation surface for GitHub issue #174 ("Fail-safe entitlement validation with grace periods"), which was kept open specifically because this integration work was the missing piece. Requirements, carried directly from that issue:

- A transient portal outage or failed re-validation (§4.3) must **never** immediately revoke a currently-active entitlement.
- Use the `grace_until` column already present in `sam_entitlements` (shipped via PR #289, currently unused by any code): on a failed re-validation, do not change `status`; only update it once the portal explicitly returns a `revoked` status, or once `grace_until` has passed with no successful re-validation in between.
- Never disable an already-enforced security header or control because entitlement validation is temporarily unreachable -- locally enforceable security controls stay enforced regardless of billing-validation availability.
- Record validation failures (for diagnostics) distinctly from an actual revocation (for entitlement state) -- these must never be conflated in the stored data or the admin-facing messaging.

---

# 11. Non-Goals

Carried forward from `checkout-proxy-design.md`, unchanged:

- Subscription billing -- the commercial model is one-time purchase.
- Multi-tenant fleet billing (#188/#189) -- out of scope until fleet management itself is designed.
- Replacing `Feature_Gate`'s local-decision runtime model -- this portal changes how entitlements are *granted*, not how they're *checked* at runtime (still local DB only, no per-request network call).

Added for this spec specifically:

- No customer account/login system (§3, §4.4).
- No self-service license re-binding or transfer in v1 (§7) -- support-mediated only.
- No general product/price catalog exposed publicly beyond what `/buy` needs to resolve one `product_key` -- the plugin's existing DNS-discovered remote config (`docs/remote-config-and-signing.md`) remains the source of truth for what products/tiers/features exist; the portal only needs to know how to turn a `product_key` into a Stripe Price ID.

---

# 12. Migration From the Interim Direct-Stripe Implementation

1. Ship a plugin version supporting both paths simultaneously: if a license key is present, use it; if legacy Stripe keys are already configured and no license key has been entered yet, keep using the legacy path (with an admin notice recommending migration) rather than breaking an existing commercial install outright.
2. Add a one-click "Migrate to VCNS-hosted licensing" action that walks an existing customer through obtaining a license key (support-issued, mapped from their existing `stripe_customer_id`, since they already paid) and clears the local Stripe key options once confirmed working.
3. After a deprecation window (length is an open decision, §14.4), remove the legacy direct-Stripe code path and its settings UI entirely -- per `docs/security-privacy-checklist.md`'s existing note, the fields it currently flags as the known gap should no longer exist in the codebase at that point, not just be unused.
4. Rotate VCNS's current live Stripe secret key after migration completes, since it has been present in an unknown number of customer databases up to that point -- treat this as a credential that was exposed beyond its intended trust boundary, regardless of whether misuse is ever observed.

---

# 13. Operational Requirements -- Cost and Ops

This product must stay cheap and small, by design, per the product owner's explicit framing ("cheap"):

- **Compute:** Cloudflare Workers free tier (100,000 requests/day) comfortably covers expected checkout + validation volume at this product's scale; only move to Workers Paid ($5/month) if volume or KV usage genuinely exceeds free-tier limits -- don't provision for hypothetical scale up front.
- **Storage:** Workers KV free tier (1 GB storage, 100,000 reads/day, 1,000 writes/day) -- license records are small and write-infrequent (one write per purchase, one write per re-validation), well within free-tier limits at any realistic near-term customer count.
- **Observability:** Cloudflare's built-in Worker logs/analytics are sufficient at this scale -- no separate APM or logging service needed for v1.
- **Repository:** new, separate repo (`checkout-proxy-design.md`'s naming suggestion, `vcns/wp-sam-checkout-proxy`, is unresolved against today's `sam.vcns.tech` domain choice -- see §14.1), with its own CI (lint, unit tests for signing/verification logic, a secret scan matching this repo's `secret-scan` job), its own `SECURITY.md`, and its own deployment workflow authenticated via a Cloudflare API token stored as a GitHub Actions secret **on that repo only** -- this repository's CI/CD should never hold Cloudflare or Stripe credentials.

---

# 14. Open Decisions Requiring Sign-Off

Nothing in this document should move to implementation until these are settled -- same posture `checkout-proxy-design.md` took with its own "Still open" section.

## 14.1 Domain and repository naming

The product owner specified `https://sam.vcns.tech` on 2026-09-02. `docs/checkout-proxy-design.md` references a *different*, previously-used domain, `wp-sam.vcns.tech` (per PR #122's changelog -- an earlier Worker at that domain existed and was removed in PR #143). Confirm: is `sam.vcns.tech` a deliberate rename, or should the historical domain be reused? This also determines the repo name (`checkout-proxy-design.md` suggested `vcns/wp-sam-checkout-proxy`, which would no longer match if the domain drops the `wp-` prefix).

## 14.2 License-key site-binding policy

Bind-on-first-validation (recommended, §7) vs. unlimited validations per key. Affects legitimate multi-site/migration customers directly -- a product/support-policy decision, not purely technical.

## 14.3 Whether `/buy` needs its own hosted product page

The simplest version (recommended) resolves `product_key` to a Stripe Price ID server-side and redirects straight into Stripe Checkout, with no portal-rendered product page at all. A richer version could show pricing/feature comparison on the portal first. Recommend starting with the simpler version -- fewer moving parts, faster to ship, consistent with §13's "stay small" framing -- and only add a product page if there's a concrete reason (e.g. multiple tiers needing comparison) once this exists.

## 14.4 Migration/deprecation window length

`checkout-proxy-design.md` left this open; it's still open. Needs a concrete timeframe once the portal actually exists and the first real migration is attempted.

## 14.5 Admin lookup authentication (§8, §9.4)

The support-mediated lost-key/lookup endpoint needs an authentication mechanism -- not specified in this document. Simplest options (Cloudflare Access in front of the route, a separate admin-only API token) are both reasonable; pick one during implementation rather than blocking this spec on it.

---

# 15. Definition of Done for v1

- A customer can complete a purchase entirely via Stripe-hosted checkout, without any Stripe secret ever touching their WordPress install.
- A customer can enter a license key in wp-admin and see their commercial features activate within one validation round-trip.
- A transient portal or network outage never revokes an already-active entitlement or disables an already-enforced security control (§10.2 / #174).
- The legacy direct-Stripe settings fields and code path are either removed or clearly marked deprecated with a migration path (§12).
- Every item in §14 has an explicit answer, recorded in this document or its successor, before the new repository's first production deploy.
