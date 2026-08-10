# Security Automation Manager

Security Automation Manager is a WordPress plugin that automates rollout of strict HTTP security headers. Content Security Policy (CSP) is its most capable pillar -- per-surface profiles, nonce injection, source discovery, violation reporting, and audit-first policy-change review -- with X-Frame-Options, X-Content-Type-Options, and Referrer-Policy as simpler per-surface pillars alongside it.

## Features

**Content Security Policy**

- Per-surface CSP profiles for `frontend`, `admin`, `login`, and `api`
- Strict defaults across CSP directives, including `upgrade-insecure-requests`, `child-src`, `fenced-frame-src`, and the `sandbox` document directive
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
- Policy Audit admin view and privileged admin REST endpoints for current policy, pending reviews, decisions, history, and manual automation configuration
- Readiness admin view for plugin-specific schema and runtime checks, with an authenticated reset flow that clears CSP data and disables header emission until rollout is restarted
- Automation configuration scaffold that defaults every surface to `manual`; no proposal is auto-approved on install or upgrade
- Multi-surface scan support
- `strict-dynamic` with automatic host-source suppression
- Trusted Types directives, report-only by default
- Conflict detection for competing CSP headers from `.htaccess`, server config, or other security-header plugins
- Scheduled rescans with audit logging

**Other header pillars**

- X-Frame-Options: per-surface `DENY` or `SAMEORIGIN` (a fallback for browsers that don't honor CSP's `frame-ancestors`)
- X-Content-Type-Options: per-surface on/off (`nosniff`)
- Referrer-Policy: per-surface value from the eight standard tokens, defaulting to `strict-origin-when-cross-origin`
- Permissions-Policy: per-surface, per-directive picker (`none` / `self` / `all`) across a starter set of seven browser features (geolocation, camera, microphone, fullscreen, payment, usb, autoplay)

These four pillars are simple by design: no report-only mode, discovery workflow, or automation -- each header is either sent exactly as configured, or not sent at all.

Every pillar and three of the four CSP automation modes are available locally without payment, remote entitlement checks, or third-party licensing calls. The exception is Fully Automatic CSP mode, which requires an active subscription -- see Automation Posture below.

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
6. Use the Policy Audit page to inspect why a proposal exists and what policy version resulted from decisions.
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
