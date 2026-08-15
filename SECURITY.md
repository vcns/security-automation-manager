# Security Policy

## Supported versions

| Version | Supported |
| --- | --- |
| 2.4.x | Yes |
| < 2.4.0 | No |

## Reporting a vulnerability

Do not disclose suspected vulnerabilities in a public GitHub issue, pull request, or WordPress.org support thread.

Send a private report to `security@vcns.tech` with:

- A concise description of the issue.
- Impact and attack preconditions.
- Reproduction steps.
- A proof of concept or request sample if relevant.
- The affected plugin version and WordPress version.

## Response targets

- Initial acknowledgement: within 3 business days.
- Triage decision: within 7 business days.
- Status update cadence: at least every 7 business days while the report remains open.
- Fix release target for confirmed high-severity issues: as quickly as practical, normally within 30 days.

## Preferred report quality

Helpful reports include:

- Exact request or payload examples.
- Relevant plugin settings or environment assumptions.
- Whether the issue requires admin access, editor access, or no authentication.
- Whether the issue depends on a particular caching, security, or e-commerce plugin.

## Safe-harbor expectations

Good-faith security research is welcome provided you:

- Avoid privacy violations, destructive testing, service interruption, or data exfiltration.
- Limit testing to environments you own or are explicitly authorised to assess.
- Give a reasonable opportunity to remediate before public disclosure.

## Security design notes

Current design assumptions for this plugin:

- Premium entitlement decisions are made locally from database state and verified Stripe webhook events.
- Remote product configuration must never contain secrets.
- Enforce-mode CSP rollout is intentionally gated behind an approval workflow to reduce lockout risk.

**Known gap (tracked, not yet remediated):** in the current commercial build, the Stripe API secret key and webhook signing secret are entered through the CSP dashboard's Settings tab and stored as WordPress options (`wp_sam_stripe_secret_key_test`, `wp_sam_stripe_secret_key_live`, `wp_sam_webhook_secret`) on the WordPress install that runs checkout, rather than held exclusively in VCNS-controlled infrastructure. This is a regression from an earlier architecture where these secrets lived only in a Cloudflare Worker's Worker secrets and were never transmitted to or stored by the WordPress plugin. A VCNS-hosted checkout/entitlement proxy that restores that separation is in design; see the roadmap tracking issue for status. Until remediated, treat a report of Stripe-secret exposure via database access, backup exfiltration, or a co-installed plugin on a commercial-build install as an in-scope, already-known finding — please still report it so we can prioritise the fix, but expect us to reference this note rather than treat it as new information.

## Non-vulnerability reports

The following generally do not qualify as security issues by themselves:

- Missing best-practice headers unrelated to this plugin's execution path.
- Abuse requiring direct admin access to the target WordPress install.
- Issues caused solely by unsupported WordPress, PHP, or host configurations.
- Requests to support older, end-of-life PHP versions.
