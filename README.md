# Security Automation Manager

Security Automation Manager is a WordPress plugin that automates rollout of strict HTTP security headers. Content Security Policy (CSP) is its most capable pillar -- per-surface profiles, nonce injection, source discovery, violation reporting, and audit-first policy-change review -- with X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, Strict-Transport-Security, Cross-Origin-Resource-Policy, Cross-Origin-Opener-Policy, Cross-Origin-Embedder-Policy, and X-Permitted-Cross-Domain-Policies as simpler per-surface pillars alongside it.

## Features

**Content Security Policy**

- Per-surface CSP profiles for `frontend`, `admin`, `login`, and `api`
- Strict defaults across CSP directives, including `upgrade-insecure-requests`, `child-src`, and the `sandbox` document directive
- `report-sample` support in fetch directives so inline snippets can appear in violation reports
- Direct `report-uri` browser reporting by default, with optional Reporting API headers
- Configurable origin policy header name for Cloudflare, CDN, and reverse-proxy deployments
- Per-request nonce injection for compatible WordPress script output
- Report-only rollout mode
- CSP violation reporting endpoint with content-type and origin checks
- Automatic purge of old violation reports
- Append-only audit log for significant plugin events
- Source discovery and administrator approval workflow
- "Start Here" tab covering the report-only, learning-window, and manual-promotion workflow; the default landing tab on the CSP dashboard
- Full-dataset sorting and per-column filtering (multi-select, free-text, numeric, date-range) on the Violations, For Review, and Policy Changes tables
- Per-row metadata popover on the Violations table showing document URI, source file, line/column, referrer, user agent, and any captured data-URI payload
- Risk-ranked CSP change proposals with reason-required approve, reject, revert, and undo decisions
- Revert-and-suppress workflow so a reversed source is not proposed again automatically
- Policy version snapshots, policy diffs, decision provenance, and deterministic rule findings
- Policy Audit tab (on the CSP page) and privileged admin REST endpoints for current policy, pending reviews, decisions, history, and manual automation configuration
- Readiness admin view for plugin-specific schema and runtime checks, with an authenticated reset flow that clears CSP data and disables header emission until rollout is restarted
- Automation configuration scaffold that defaults every surface to `automatic_high_approval` -- every proposed CSP source below the high-risk threshold is auto-approved into the report-only policy on its own evidence, high-risk sources still require a human decision. This governs approval only, never enforcement: CSP still starts report-only on every surface, and promotion to enforce still requires a deliberate administrator action through the learning window and promotion gate
- Multi-surface scan support
- `strict-dynamic` with automatic host-source suppression
- Per-surface Trusted Types toggle (Profiles tab): sends `require-trusted-types-for 'script'`, always report-only regardless of surface mode
- Conflict detection for competing CSP headers from `.htaccess`, server config, or other security-header plugins
- Scheduled rescans with audit logging

**Other header pillars**

- X-Frame-Options: per-surface `DENY` or `SAMEORIGIN` (a fallback for browsers that don't honor CSP's `frame-ancestors`)
- X-Content-Type-Options: per-surface on/off (`nosniff`)
- Referrer-Policy: per-surface value from the eight standard tokens, defaulting to `strict-origin-when-cross-origin`
- Permissions-Policy: per-surface, per-directive picker (`none` / `self` / `all`) across a starter set of seven browser features (geolocation, camera, microphone, fullscreen, payment, usb, autoplay)
- Strict-Transport-Security: per-surface `max-age`, `includeSubDomains`, and `preload`. Only ever sent over HTTPS, and `preload` stays off until `max-age` and `includeSubDomains` already meet hstspreload.org's submission minimum -- this header is sticky (browsers cache it), so it warrants more care than the other four
- Cross-Origin-Resource-Policy: per-surface `same-site` / `same-origin` / `cross-origin`, controlling which sites may load this site's own resources cross-origin. Low risk -- it only restricts who can embed this site's content, not what this site can embed
- Cross-Origin-Opener-Policy: per-surface `unsafe-none` / `same-origin` / `same-origin-allow-popups`, isolating this site's browsing context from cross-origin windows it opens or is opened by. `same-origin` severs `window.opener` access from any cross-origin popup, including popup-based OAuth/SSO flows -- `same-origin-allow-popups` is the safer choice for sites that rely on those
- Cross-Origin-Embedder-Policy: per-surface `unsafe-none` / `require-corp` / `credentialless`, the highest-risk pillar this plugin manages. `require-corp` blocks any cross-origin subresource (fonts, embeds, ad tags) that doesn't explicitly opt in via CORP or CORS -- most third-party embeds don't, so enabling this carelessly can silently break unrelated page content. Only actually needed for sites that require cross-origin isolation (`SharedArrayBuffer`, high-resolution timers); most WordPress sites do not
- X-Permitted-Cross-Domain-Policies: per-surface `none` / `master-only` / `by-content-type` / `all`, a legacy Flash/Acrobat-era header controlling cross-domain policy file loading. `none` is almost always correct for a modern site

These nine pillars are simple by design: no report-only mode, discovery workflow, or automation -- each header is either sent exactly as configured, or not sent at all.

**Content rewrite protections**

Two further protections rewrite the rendered HTML body itself rather than emit a header, sharing a `Content_Rewriter` envelope (request/response eligibility, buffering, fail-open on any uncertainty) alongside the header pillars' own `Header_Builder` envelope:

- Reverse Tabnabbing Protection: per-surface, adds `rel="noopener"` to `target="_blank"` links missing `noopener`/`noreferrer`, closing off `window.opener` access a new tab could otherwise use to redirect the original tab to a phishing page. Purely additive -- it never blocks or breaks a link.
- External Scripts: passively inventories third-party `<script>`/`<link rel="stylesheet">` origins observed on real page loads (no dedicated crawl, origin only -- never a path or query string), lets an administrator classify each one (Unclassified / Approved-immutable with SRI / Approved-mutable provider / Exception / Blocked), and supports Subresource Integrity. A freshly discovered origin is always `unclassified`, matching this plugin's report-first philosophy -- report mode (the default) never removes anything, and even enforce mode only ever removes an origin explicitly marked Blocked or an "immutable" origin whose SRI hash no longer matches what the page served. SRI hashes are never fetched from a third party and auto-trusted -- the plugin only ever compares against a hash the administrator already trusts, either typed in directly or computed by fetching a URL the administrator themselves supplied ("Suggest" button). A daily check proactively re-verifies pinned hashes against this site's own homepage (never third-party content) so drift is caught before a real visitor triggers a removal.

A third pillar, Internal Script Integrity (`Internal_Script_Integrity_Builder`), is architecturally distinct from the two above: rather than the `Content_Rewriter` body-buffering envelope, it hooks the same `script_loader_tag`/`style_loader_tag` filters `Nonce_Manager` already uses. Per-surface opt-in; when enabled, it reads a first-party script/stylesheet's local file directly (never a network fetch -- this server already has the exact file it's about to serve), computes its SHA-384 hash, and adds it as the tag's `integrity` attribute automatically. Cached by file size/mtime, so an unchanged file is never re-read, and a changed one (a plugin/theme update, a manual edit) is picked up on the next request that serves it -- nothing to remember to update by hand, and nothing to classify or approve, since the hash can never legitimately drift from what's on disk the way an admin-declared third-party hash can. External Scripts and Internal Script Integrity share one admin page (Scripts), each its own tab, alongside a Start Here tab explaining the distinction.

Every pillar, all rewrite protections, and three of the four CSP automation modes are available locally without payment, remote entitlement checks, or third-party licensing calls. The exception is Fully Automatic CSP mode, which requires an active subscription -- see Automation Posture below.

## Requirements

- WordPress 6.4+
- PHP 8.1+

## Installation

### From the WordPress plugin directory

Once published to WordPress.org:

1. Go to **Plugins -> Add New Plugin**.
2. Search for `Security Automation Manager`.
3. Click **Install**, then **Activate**.

### Install from GitHub Releases

Tagged releases publish ready-to-install ZIPs to the
[Releases page](https://github.com/vcns/security-automation-manager/releases).

1. Download `security-automation-manager-github-vX.Y.Z.zip` from the release assets when installing from GitHub.
2. In WordPress go to **Plugins -> Add New Plugin -> Upload Plugin**.
3. Choose the downloaded ZIP and click **Install Now**.
4. Activate the plugin.

The GitHub-channel ZIP includes a checksum-verified updater that uses WordPress' native plugin update screen and the `https://vcns.github.io/wp-updates/security-automation-manager/update.json` manifest. The plain `security-automation-manager-vX.Y.Z.zip` artifact is the WordPress.org-safe package and does not contain the GitHub updater.

## Getting Started

1. Install and activate the plugin.
2. Open **Security Automation Manager -> CSP**; the Start Here tab explains the workflow below.
3. Run an initial scan from the Profiles tab.
4. Review and approve only the external sources your site actually requires from the For Review tab.
5. Reject or revert unwanted sources so the same fingerprint is suppressed from future proposals.
6. Use the Policy Audit tab to inspect why a proposal exists and what policy version resulted from decisions.
7. Use the Readiness page when validating schema health or deliberately resetting CSP data for a clean rollout attempt.
8. After a reset, re-enable the required surfaces in report-only mode when you are ready to restart rollout.
9. Stay in report-only mode until violations are understood.
10. Promote one surface at a time into enforce mode.

## Automation Posture

Automation defaults to `Manual` for every surface. Administrators may explicitly select each surface posture from the Profiles tab or the Settings tab:

- `Manual` -- free
- `Automatic (with medium+high approvals)` -- free
- `Automatic (with high approvals only)` -- free
- `Fully Automatic` -- requires an active subscription (£1.99/month or £19.99/year, billed via Stripe Checkout); without one, a surface selecting it is kept on `Automatic (with high approvals only)` instead

Automatic approvals are bounded by deterministic risk rules, hard exclusions, configured directive/scheme limits, evidence requirements, and per-run caps. Automatic decisions record `automation_engine` provenance and can be undone without rewriting history.

Future AI-assisted recommendation work must keep deterministic product rules as the authority. AI output must not directly modify an enforced CSP policy.

## External Services

The WordPress.org plugin package does not contact third-party services for plugin updates, licensing, checkout, telemetry, or remote product configuration.

The GitHub-channel ZIP checks `https://vcns.github.io/wp-updates/security-automation-manager/update.json` from administrator update contexts only, validates the advertised package host and SHA-256 checksum, and then lets WordPress perform the update. Define `WP_SAM_DISABLE_AUTO_UPDATE` as `true` in `wp-config.php` to prevent background auto-updates for the GitHub-channel package.

By default, the plugin emits CSP reporting headers that point browsers back to this WordPress site's own REST endpoint:

- `/wp-json/security-manager/v1/report`

Administrators may override the reporting server URL when the public HTTPS endpoint differs from the WordPress-detected site URL, such as behind a proxy, CDN, or load balancer. If the override points to another host, browsers will send CSP reports to that configured endpoint; local report learning only works when the URL routes back to this plugin's report endpoint.

Administrators may also configure an origin-only policy header name, such as `X-Origin-CSP-Policy`, when a proxy needs to copy the WordPress-generated policy into the browser-facing `Content-Security-Policy-Report-Only` or `Content-Security-Policy` header. Leaving the setting blank preserves the normal mode-aware CSP header names. Custom names are validated as HTTP header field names and unsafe hop-by-hop or cookie headers are rejected.

Browser-submitted CSP violation reports received by this plugin are validated and stored in the local WordPress database. They are not sent to any external provider by default.

## Privacy

The plugin keeps operational data local to WordPress.

- Browser CSP violation reports are stored in the local database.
- Source inventory, hashes, scan logs, policy versions, and decision records are stored locally.
- No telemetry or background tracking is intended as part of the normal plugin runtime.

## Repository Guides

- Architecture: [docs/architecture.md](docs/architecture.md)
- Testing and quality: [docs/testing-and-quality.md](docs/testing-and-quality.md)
- Release and publishing: [docs/release-and-publishing.md](docs/release-and-publishing.md)
- Security policy: [SECURITY.md](SECURITY.md)

## GitHub Pages Help Site

The repository also publishes a public help site from the `docs/` directory:

- https://vcns.github.io/security-automation-manager/

## Development And Release Flow

- `feature/*` and `fix/*` branches target `development`
- `release/*` branches are cut from `development`
- `main` is the release and publishing branch
- WordPress.org deployment is tag-driven

## Notes For Maintainers

- Keep `README.md` GitHub-friendly and concise.
- Keep `readme.txt` aligned with actual shipped behaviour for WordPress.org.
- Update both when installation, features, external services, or release flow changes.
