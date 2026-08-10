# Changelog

All notable changes to this project will be documented in this file.

The format is based on Keep a Changelog, and this project follows semantic versioning for plugin releases.

## [2.1.1] - 2026-08-10

### Fixed

- Fixed a fatal error on the External Scripts admin page: `Call to undefined method WP_SAM\Admin\Table_Query::equals_where()`. The published 2.1.0 GitHub release was built from a commit where `page-external-scripts.php` (merged as part of the External Scripts pillar) called `equals_where()` before the PR that actually added that method to `Table_Query` had been merged -- an artifact of resolving several long-open, out-of-order pull requests. `main` had carried the fix since the `equals_where()` PR merged; this release exists purely to publish a working build. No other code changes.

## [2.1.0] - 2026-08-10

### Added

- Added Strict-Transport-Security (HSTS) as a sixth pillar: per-surface Max-Age, Include Subdomains, and Preload. Unlike the other simple pillars, this header is only ever emitted over an HTTPS request, and Preload cannot be enabled until Max-Age and Include Subdomains already meet hstspreload.org's submission minimum (Max-Age >= 1 year, Include Subdomains on) -- guardrails against a header that, once cached by a browser, cannot be walked back the way the other pillars can.
- Added Reverse Tabnabbing Protection: per-surface, adds `rel="noopener"` to `target="_blank"` links missing `noopener`/`noreferrer`, closing a `window.opener` phishing gap. A content rewrite rather than a header, built on a new shared `Content_Rewriter` base (`includes/security/class-content-rewriter.php`) alongside the existing header-pillar envelope.
- Added External Scripts: passively inventories third-party `<script>`/`<link rel="stylesheet">` origins from real page loads (no dedicated crawl, origin only -- never a path or query string), lets an administrator classify each one, and supports Subresource Integrity. A freshly discovered origin is always `unclassified`, never `prohibited` -- report mode (the default) never removes anything, and even enforce mode only ever removes an origin explicitly marked Blocked or an "immutable" origin whose administrator-declared SRI hash no longer matches. SRI hashes are never fetched or computed by the plugin, only compared against what the administrator already trusts and typed in.

### Changed

- Set Fully Automatic subscription pricing at £1.99/month or £19.99/year. Checkout now creates a recurring Stripe subscription (previously a one-time payment) and the Upgrade control lets the administrator choose the billing interval before starting checkout.
- Moved Policy Audit from a standalone top-level admin page into a tab on the CSP dashboard (it was always CSP-specific content). The pending review queue and full decision ledger it used to duplicate now live only on the adjacent For Review and Policy Changes tabs; Policy Audit itself keeps just the at-a-glance current-policy summary.

## [2.0.0] - 2026-08-10

### Added

- Added full-dataset sorting and per-column filtering (multi-select, free-text, numeric, date-range) to the Violations, For Review, and Policy Changes tables, replacing plain unsortable pagination.
- Added a per-row metadata popover on the Violations table showing document URI, source file, line/column, referrer, user agent, and any captured data-URI payload for a violation.
- Added a "Start Here" tab explaining the report-only, learning-window, and manual enforce-promotion workflow; it is now the default landing tab on the CSP dashboard.
- Renamed the plugin to Security Automation Manager: CSP becomes the first of several HTTP security-header pillars, with X-Frame-Options, X-Content-Type-Options, and Referrer-Policy joining it as simpler per-surface pillars (no report-only mode, discovery workflow, or automation for these three).
- Added a top-level "Security Automation Manager" admin menu with a new Overview page summarizing every pillar's per-surface status, plus dedicated X-Frame-Options, X-Content-Type-Options, and Referrer-Policy pages. The CSP dashboard moves to a "CSP" submenu at its existing URL.
- Added a shared `Header_Builder` envelope (hook registration, header-emission guard, conflict-probe suppression, surface detection) and a `sam_pillar_profiles` table so future pillars can reuse the same plumbing as CSP without duplicating it.
- Added Permissions-Policy as a fourth pillar: per-surface, per-directive control (`none`/`self`/`all`) over a starter set of seven browser features (geolocation, camera, microphone, fullscreen, payment, usb, autoplay). No report-only mode, discovery workflow, or automation, matching the other simple pillars.

### Changed

- Merged the standalone Settings page into the CSP dashboard as a tab, alongside Start Here, Profiles, For Review, Policy Changes, Violations, and Scan Log.
- Fully Automatic mode (zero-review auto-apply of deterministic policy changes) now requires a paid subscription. Sites without an active entitlement have Fully Automatic selections downgraded to "Automatic (with high approvals only)"; the free/local WordPress.org and GitHub-channel builds are unaffected otherwise. An "Upgrade" action is shown on the CSP Settings tab where a Checkout flow is available.

### Removed

- Removed the "Allow eligible auto-approvals" checkbox and its underlying `emergency_disabled` field. Automation Mode alone now governs whether a surface's proposals can be auto-approved; the field could previously be silently reset by an unrelated settings save due to how defaults were merged, which is no longer possible now that it no longer exists.

## [1.0.16] - 2026-08-04

### Added

- Added a separate GitHub-channel release ZIP with native WordPress update integration, plugin-information support, stale-offer suppression, package host validation, checksum verification, cache busting, and a `WP_CSP_DISABLE_AUTO_UPDATE` kill switch.
- Added release workflow generation of `vcns/wp-updates` metadata for GitHub-channel installs when `WP_UPDATES_TOKEN` is configured.
- Added administrator-selectable automation postures for manual approval, low-risk automation, low-plus-medium automation, and fully automatic deterministic approval within hard safety exclusions.

### Changed

- Split release artifacts so the plain ZIP remains WordPress.org-safe while the GitHub-channel ZIP contains the updater and generated `Update URI` metadata.
- Updated installed-plugin row messaging and release documentation to identify the active update channel.
- Replaced the dashboard Strict-Dynamic display column with an Automation dropdown so each surface can be switched between manual and automatic postures directly from Profiles.

## [1.0.15] - 2026-08-04

### Changed

- Renamed the dashboard Source Inventory tab to For Review so the operator queue matches the approval workflow.
- Expanded the Policy Changes tab into a policy activity timeline that includes discovered proposals, decisions, actors, suppression state, and policy version snapshots.
- Added per-surface deterministic automation settings and automatic low-risk approval records with actor `automation_engine`.

## [1.0.14] - 2026-08-04

### Changed

- CSP reporting now defaults to direct `report-uri` delivery so browser violations reach the local report endpoint promptly during learning.
- Added an administrator setting to opt into Reporting API headers and the `report-to` directive when required.

## [1.0.13] - 2026-08-04

### Fixed

- Policy version table creation now avoids the reserved `trigger` index name, fixing MariaDB activation failures.
- Activation now skips initial policy version seeding when the policy version table could not be created, preventing missing-table follow-on errors.
- Activation-time policy snapshots now use a safe local report endpoint fallback until WordPress REST routing has initialised.

## [1.0.12] - 2026-08-03

### Fixed

- CSP directives now remove `'none'` when approved sources are merged into the same directive, avoiding browser warnings and ignored `'none'` values such as `frame-src 'none' example.com`.
- CSP report ingestion now accepts document hosts that match the configured public reporting endpoint host or forwarded request host, so proxied deployments do not silently discard valid browser reports.
- The Violations empty state now reflects that browser reports can be collected from either report-only or enforce CSP headers.

## [1.0.11] - 2026-08-03

### Fixed

- CSP surface detection is now path-aware so `wp-admin` URLs that produce redirects or 404 responses still use the admin surface configuration.

## [1.0.10] - 2026-08-03

### Changed

- Destructive CSP data reset now leaves all policy surfaces disabled so the plugin stops emitting CSP headers until rollout is deliberately restarted.
- CSP headers are emitted before WordPress redirects so unauthenticated `wp-admin` redirects are easier to diagnose.

## [1.0.9] - 2026-08-03

### Added

- Configurable origin policy header name for Cloudflare, CDN, and reverse-proxy deployments that copy an origin header back to the browser-facing CSP header.

### Fixed

- Schema self-healing now recreates missing plugin tables even when the stored database schema version already matches the current code schema.

## [1.0.8] - 2026-08-03

### Changed

- Clarified the Violations empty state so administrators understand that manual scans do not create browser violation reports and can see the expected reporting endpoint.

## [1.0.7] - 2026-08-03

### Added

- Readiness admin page with plugin-version, database-schema, table-row, reporting-endpoint, scheduled-scan, and default automation posture checks.
- Installed Plugins Reset action linking to a destructive reset panel that requires current administrator password re-authentication and a typed confirmation before clearing CSP Automation Manager data.

## [1.0.6] - 2026-08-03

### Added

- CSP conflict detection now scans `.htaccess` Header directives and treats any CSP still present during the internal probe as a likely web-server or security-header-plugin conflict.
- Source approval, rejection, reversion, and undo decisions now require administrator reasons, and approved/rejected source decisions can be undone without rewriting history.
- Dashboard tabs now include operator guidance through hover titles, screen-reader descriptions, and an active-tab help note.
- Reporting server URL override for sites whose public HTTPS endpoint differs from the WordPress-detected REST URL, with a settings button to use the current site endpoint.
- Installed Plugins now shows a Settings action and an explicit WordPress.org-only update posture note.

## [1.0.5] - 2026-07-16

### Changed

- Renamed the repository, package slug, text domain, main plugin file, GitHub Pages links, WordPress.org deployment slug, and release ZIP naming to `csp-automation-manager`.
- Updated release packaging checks so tagged releases build `csp-automation-manager-vX.Y.Z.zip` with the `csp-automation-manager/` plugin root.

## [1.0.4] - 2026-07-15

### Changed

- Made all shipped CSP capabilities available locally without payment, remote entitlement checks, or trialware-style feature locking.
- Updated readme, package metadata, and public copy to reflect the WordPress.org build's local-only runtime behaviour.

### Removed

- Removed the custom runtime update checker and third-party update manifest polling from the WordPress.org plugin package.
- Removed licensing, checkout, and remote product configuration admin surfaces from the WordPress.org plugin package.
- Removed legacy production defaults for remote configuration, licensing, and custom update endpoints from the plugin bootstrap.

## [1.0.3] - 2026-07-15

### Changed

- Renamed the public plugin display name to `CSP Automation Manager` to comply with WordPress.org plugin naming requirements.

## [1.0.2] - 2026-07-15

### Changed

- Tightened the release package so development-only files, internal policy notes, and local cache files are excluded from distributed ZIP builds.
- Moved default configuration and licensing endpoints to VCNS-owned service hostnames while preserving `wp-config.php` overrides.
- Added explicit external-services disclosure for VCNS configuration, licensing, checkout, and GitHub update metadata requests.
- Added release workflow checks that fail if submission-only or development-only files are present in the packaged ZIP.

## [1.0.1] - 2026-07-15

This release includes database migrations through schema version 7. Existing installations can migrate directly from earlier schema versions through the normal `dbDelta()` activation path. CSP runtime behaviour remains local and does not depend on remote billing, licensing, or update services during normal page rendering.

### Added

- `Reporting-Endpoints` header emission alongside CSP headers, with legacy `Report-To` fallback.
- Forbidden directive denylist for removed or deprecated CSP directives.
- `strict-dynamic` host-source suppression when licensed and enabled.
- `upgrade-insecure-requests`, `child-src`, `fenced-frame-src`, sandbox handling, and Trusted Types defaults in policy profiles.
- `'report-sample'` defaults for script and style directives.
- `sample` column in `csp_violation_reports` for violation snippets. DB version 3.
- `csp_audit_log` append-only table. DB version 4.
- Violation retention purge with `wp_csp_violation_retention_days`.
- Content-Type validation, cross-origin `document-uri` rejection, and sample-field normalisation for violation reports.
- wp-admin enforce-mode limitation notice.
- CSP policy change proposals, risk classification, administrator approve/reject/revert decisions, and rejected/reverted fingerprint suppression.
- `csp_policy_change_decisions` append-only decision ledger. DB version 5.
- Violation report rollups with `first_reported_at`, `last_reported_at`, unique fingerprint upsert support, and occurrence counts. DB version 6.
- Policy audit foundation with policy version snapshots, deterministic rule-evaluation provenance, manual automation configuration defaults, privileged admin REST endpoints, and a Policy Audit admin page.
- `csp_policy_versions` append-oriented surface policy snapshots. DB version 7.
- `csp_decision_rule_evaluations` deterministic rule findings linked to proposals and decisions. DB version 7.
- GitHub-distributed update checking. This runtime updater was removed from the WordPress.org plugin package in 1.0.4.
### Changed

- Plugin version metadata now targets `1.0.1` for the initial GitHub release package.
- `WP_CSP_DB_VERSION` bumped from `'2'` to `'7'` (v3 = sample column; v4 = audit log table; v5 = policy change decision ledger and proposal metadata; v6 = violation rollups; v7 = provenance and policy history foundation).
- Policy builder emits `Reporting-Endpoints` and `Report-To` headers immediately before the CSP header — any code that expects the CSP to be the first header will need updating.
- Product copy no longer describes all premium access as a one-time payment; entitlement-gated capabilities are compatible with future VCNS Portal account management.

### Fixed

- Fixed silent Reporting API delivery failure where the CSP string referenced `report-to csp-endpoint` without declaring the endpoint through `Reporting-Endpoints`.

## [0.2.0] - 2026-06-03

### Added

- Initial public plugin implementation for WordPress 6.4+ and PHP 8.1+.
- Bootstrap file with plugin headers, constants, autoloader, activation, deactivation, and uninstall hooks.
- Database installer for seven custom tables covering policy profiles, source inventory, hash inventory, violation reports, scan logs, entitlements, and processed Stripe webhook events.
- Per-surface CSP engine for frontend, admin, login, and REST API requests.
- Strict defaults for all CSP directives.
- Nonce generation and injection through native WordPress 6.4+ script attribute hooks with legacy tag-filter fallback.
- Policy builder capable of emitting strict `Content-Security-Policy` and `Content-Security-Policy-Report-Only` headers.
- Crawl-based discovery workflow for external sources with approval and deny actions.
- Inline block hash recording and retirement support.
- Violation reporting REST endpoint with deduplication and transient-based rate limiting.
- Daily scheduler for rescans and policy-change notifications.
- Conflict detector for duplicate CSP headers from other plugins or server layers.
- Stripe checkout session creation without the Stripe PHP SDK, using the WordPress HTTP API.
- Webhook verification with HMAC-SHA256 signing, replay-window tolerance, and idempotent event recording.
- Local entitlement store bound to a stable hash of the site URL, including configurable grace periods.
- Feature gate with explicit free-tier capabilities and local tier checks.
- Remote product configuration fetched from DNS-discovered HTTPS JSON with Ed25519 signature verification.
- Transient-cached remote configuration with configurable TTL and grace-window handling.
- Admin UI covering dashboard, settings, entitlement display, checkout initiation, and manual rescans.
- Full uninstall routine that drops all custom tables and removes plugin-owned `wp_csp_*` options.

### Security

- Enforced prepared SQL access for parameterised queries and consistent escaping in admin output.
- Added promotion gate so enforce mode is blocked until at least one approved source or hash exists.
- Restricted admin actions to `manage_options` users with nonce verification.
- Kept Stripe secret material out of browser-delivered code and remote DNS configuration.

## Release policy

- `main` is the shipping branch for tagged releases.
- WordPress.org release artifacts are built from a clean tag only.
- Database schema changes must increment `WP_CSP_DB_VERSION` and include upgrade logic.
