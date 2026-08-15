# Security and Privacy Requirements Checklist

## Purpose

Section 20 of the roadmap specification sets out one set of security and privacy
requirements that applies to every roadmap issue's implementation work, plus a
documentation requirement for every signing key in use. Rather than copying this
list into 39 separate issues, it lives here once. Every roadmap issue's acceptance
criteria carries an implicit "Cross-cutting requirements: see
`docs/security-privacy-checklist.md`" footer — this document is the authoritative
copy; issue bodies should not duplicate it.

Resolves roadmap issue #152.

## Requirements for all new functionality

Each item below is normative for any PR that adds or changes plugin behaviour.
Reviewers should check new code against this list the way they'd check it against
`phpcs.xml.dist` — a PR that fails one of these silently is a defect, not a style
preference.

| # | Requirement | What "done" looks like |
|---|---|---|
| 1 | Follow WordPress coding standards | `composer run lint:phpcs` passes against `phpcs.xml.dist` |
| 2 | Use capability checks | Every admin action gated on `current_user_can()` with the narrowest applicable capability (`manage_options` for this plugin's settings surfaces) |
| 3 | Use nonces for state-changing administrator actions | `wp_verify_nonce()` / `check_admin_referer()` on every form POST and REST write; nonce action strings scoped per form, not shared globally |
| 4 | Sanitize inputs | `sanitize_text_field()`, `absint()`, `sanitize_key()`, etc. applied at the point input enters the system, not deferred to output |
| 5 | Escape outputs | `esc_html()`, `esc_attr()`, `esc_url()`, `wp_kses_post()` applied at the point of output, not at storage time |
| 6 | Use prepared database queries | `$wpdb->prepare()` for every query with a variable component; no string-concatenated SQL |
| 7 | Avoid logging secrets | Audit log, PHP error log, and debug output must never contain a raw secret, API key, or webhook payload signature value |
| 8 | Minimise external data transmission | A new feature that talks to an external service sends only what that service needs to do its job — see the data-protection and retention model (`docs/data-protection-and-retention.md`) for the specific inventory |
| 9 | Document retention | Any new stored data type gets a retention period recorded in `docs/data-protection-and-retention.md` before or alongside the PR that introduces it |
| 10 | Support deletion | New data types are covered by `uninstall.php` (full removal) and, where the data is personal or site-identifying, by an explicit deletion path reachable without uninstalling the whole plugin |
| 11 | Record material actions | Anything that changes policy, entitlement state, or configuration writes an audit-log entry via `Audit_Log` |
| 12 | Fail safely | On error, ambiguity, or an unverifiable external response, the plugin falls back to the more restrictive / less-automated state (see the "Enforce mode requires an approved source" and "entitlement fails closed" invariants in `docs/threat-model.md`) — never to a more permissive one |
| 13 | Avoid arbitrary remote code execution | No `eval()`, no dynamic `include`/`require` of a path built from external input, no deserialization of untrusted data into executable structures |
| 14 | Treat browser violation reports as untrusted input | CSP/report-endpoint payloads are used for discovery only; never trusted for policy decisions or auto-approval without the existing rate-limit, origin-check, and dedup controls |
| 15 | Treat remote configuration as untrusted until verified | Any config fetched from outside the WordPress install (DNS-discovered config, a future control-plane response) is rejected unless its signature verifies against an embedded public key |
| 16 | Preserve local protections when commercial services are unavailable | If the entitlement service, external verification service, or webhook/SIEM integration is unreachable, previously-applied security headers and policies keep working; the plugin degrades to free-tier behaviour, it does not disable protections |

## Signing key inventory

Every signing or shared-secret key used by updates, entitlements, configuration
import, or fleet management must have all six properties below documented before
it ships. This table is the single place that documentation lives; it should be
updated in the same PR that introduces or changes a key.

| Key | Purpose | Ownership | Storage | Rotation | Revocation | Recovery | Incident response |
|---|---|---|---|---|---|---|---|
| Stripe webhook signing secret (`wp_sam_webhook_secret`) | HMAC-SHA256 verification of inbound Stripe webhook events (`Webhook_Controller`) | Per-site operator (self-generated in the Stripe dashboard, pasted into plugin settings) | WordPress option, plaintext, on the site that receives the webhook | Operator-driven: regenerate in Stripe, update the option; no plugin-side rotation tooling exists today | Operator deletes/regenerates the Stripe-side endpoint secret; old value becomes inert immediately since Stripe stops signing with it | No plugin-side recovery mechanism; operator must re-fetch from the Stripe dashboard | Not documented today — **gap**, tracked below |
| Stripe API secret key (test/live) (`wp_sam_stripe_secret_key_test`/`_live`) | Authenticates direct Stripe API calls to create Checkout Sessions | VCNS (this is VCNS's own account-wide key, not a per-customer key) | WordPress option, plaintext, on whichever site runs the "Fully Automatic checkout" flow | No rotation process exists | No revocation process exists | No recovery process exists | Not documented — **this is the known gap described in `SECURITY.md`; superseded by the VCNS-hosted checkout/entitlement proxy design, see `docs/checkout-proxy-design.md` and roadmap issue #172** |
| Remote-config Ed25519 keypair (`WP_SAM_CONFIG_PUBLIC_KEY` constant + private key) | Was intended to verify signed, DNS-discovered product/pricing config (`docs/remote-config-and-signing.md`) | VCNS (private key); public key shipped in every plugin install | Public key: PHP constant in plugin source. Private key: documented as "secrets manager or equivalent," no implementation exists | Documented in `docs/remote-config-and-signing.md` §"Key rotation guidance" | Not documented | Not documented | Not documented — **the implementing class (`Config_Resolver`) was removed in PR #143; this key and its documentation describe a mechanism that does not currently exist in code. Either revive it (the checkout-proxy design reuses this exact pattern) or mark `docs/remote-config-and-signing.md` as aspirational until it is** |
| Future: entitlement validation key (#173/#174) | Not yet designed | — | — | — | — | — | Must be documented here before #173/#174 implementation lands |
| Future: configuration-as-code export/import signing key (#185) | Not yet designed | — | — | — | — | — | Must be documented here before #185 implementation lands |
| Future: fleet-management remote-change signing key (#188) | Not yet designed | — | — | — | — | — | Must be documented here before #188 implementation lands |

**Immediate gap:** two of the three keys currently in production use (the Stripe
API secret key and, functionally, the webhook secret) have no rotation,
revocation, incident-response, or recovery procedure written down anywhere. This
should be treated as part of closing #152, not deferred — see the "Follow-up"
section below.

## Follow-up

- [ ] Write a short incident-response runbook for "Stripe webhook secret or API
      secret key suspected compromised" (revoke in Stripe dashboard, rotate,
      confirm no unauthorised charges/refunds, notify affected sites if the key
      is shared across installs).
- [ ] Once the checkout-proxy design (`docs/checkout-proxy-design.md`) is
      implemented, remove the Stripe API secret key row's "known gap" status —
      the key will no longer be present on any customer install.
- [ ] Reconcile `docs/remote-config-and-signing.md` with the fact that
      `Config_Resolver` doesn't currently exist in code (tracked under #163,
      documentation consistency audit).
