=== Security Automation Manager ===
Contributors: vcns
Tags: security, csp, content security policy, headers, wordpress security
Requires at least: 6.4
Tested up to: 7.0
Requires PHP: 8.1
Stable tag: 2.1.1
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Automates strict HTTP security header rollout -- Content Security Policy, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, and Strict-Transport-Security -- plus Reverse Tabnabbing Protection and third-party script/stylesheet governance with Subresource Integrity, with violation reporting, source discovery, and policy-change review for WordPress.

== Description ==

Security Automation Manager helps site owners roll out strict HTTP security headers safely and incrementally. Content Security Policy (CSP) is its most capable pillar; X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, and Strict-Transport-Security are simpler per-surface pillars alongside it. Reverse Tabnabbing Protection and External Scripts round it out as two further protections that rewrite the rendered page itself rather than emit a header.

The CSP pillar provides per-surface profiles, nonce injection, source discovery, violation reporting, policy-change review, reason-required append-only audit records, policy history, readiness checks, and conflict detection for existing CSP emitters. The other five pillars are simple per-surface toggles/value pickers with no report-only mode, discovery workflow, or automation. External Scripts follows the same report-first philosophy as CSP: a freshly discovered third-party origin is always unclassified, never blocked, until an administrator decides.

Every pillar and three of the four CSP automation modes are free. The exception is Fully Automatic mode (zero-review auto-apply of deterministic policy changes), which requires an active subscription: £1.99/month or £19.99/year.

== External services ==

This WordPress.org build does not contact third-party services for plugin updates, licensing, checkout, telemetry, or remote product configuration.

GitHub release builds are published separately for administrators who install from GitHub rather than WordPress.org. The GitHub-channel ZIP checks https://vcns.github.io/wp-updates/security-automation-manager/update.json from administrator update contexts only, validates the advertised package host and SHA-256 checksum, and then lets WordPress perform the update. Define WP_SAM_DISABLE_AUTO_UPDATE as true in wp-config.php to prevent background auto-updates for the GitHub-channel package.

By default, the plugin emits CSP reporting headers that point browsers back to this WordPress site's own REST endpoint:

* `/wp-json/security-manager/v1/report`

Administrators may override the reporting server URL when the public HTTPS endpoint differs from the WordPress-detected site URL, such as behind a proxy, CDN, or load balancer. If the override points to another host, browsers will send CSP reports to that configured endpoint; local report learning only works when the URL routes back to this plugin's report endpoint.

Purpose:
* receive browser-generated CSP violation reports for this site;
* store reports locally so administrators can review and refine policy safely.

Data handled:
* browser CSP violation report fields such as blocked URL, document URL, violated directive, referrer, user agent, line/column where provided, and an optional script sample where the active policy requests `report-sample`.

Reports received by this plugin are validated and stored in this site's WordPress database. They are not sent to any external provider by default.

For Cloudflare, CDN, and reverse-proxy deployments, administrators can configure an origin-only policy header name such as X-Origin-CSP-Policy. The proxy can then copy that origin header into the browser-facing Content-Security-Policy-Report-Only or Content-Security-Policy header.

== Changelog ==

= 2.1.1 =

* Fixes a fatal error on the External Scripts admin page (Call to undefined method Table_Query::equals_where()). The 2.1.0 release ZIP was built from a commit where that page's filters referenced a helper method that hadn't actually merged yet. No other functional changes.

= 2.1.0 =

* Adds Strict-Transport-Security (HSTS) as a sixth pillar: per-surface Max-Age, Include Subdomains, and Preload. Only ever sent over HTTPS; Preload cannot be enabled until Max-Age and Include Subdomains already meet hstspreload.org's submission minimum.
* Adds Reverse Tabnabbing Protection: per-surface, adds rel="noopener" to target="_blank" links missing noopener/noreferrer.
* Adds External Scripts: passively inventories third-party script/stylesheet origins from real page loads, lets an administrator classify each one, and supports Subresource Integrity. Report mode (the default) never removes anything; a freshly discovered origin is always unclassified, never blocked by default.
* Reworks the Violations and For Review filter panels to match Policy Changes' collapsible layout; Surface is now a single-select combobox and Directive is free-text search.
* Moves Policy Audit from a standalone top-level admin page into a tab on the CSP dashboard.
* Makes the Fully Automatic upgrade call-to-action more prominent on the CSP Settings tab.
* Sets Fully Automatic subscription pricing at £1.99/month or £19.99/year with a recurring Stripe subscription and a billing-interval choice.

= 2.0.0 =

* Renames the plugin to Security Automation Manager. Content Security Policy becomes the first of five HTTP security-header pillars, joined by X-Frame-Options, X-Content-Type-Options, Referrer-Policy, and Permissions-Policy as simpler per-surface pillars with no report-only mode, discovery workflow, or automation.
* Adds a top-level "Security Automation Manager" admin menu with an Overview page summarizing every pillar's per-surface status.
* Adds full-dataset sorting and per-column filtering to the Violations, For Review, and Policy Changes tables, and a per-row metadata popover on Violations.
* Adds a "Start Here" tab and merges the standalone Settings page into the CSP dashboard as a tab.
* Fully Automatic mode (zero-review auto-apply of deterministic policy changes) now requires a paid subscription; sites without an active entitlement are kept on "Automatic (with high approvals only)" instead. Every other feature remains free, with no remote licensing calls in the WordPress.org build.
* Removes the "Allow eligible auto-approvals" checkbox and its underlying field; Automation Mode alone now governs automatic approval eligibility.

= 1.0.16 =

* Adds a separate GitHub-channel release ZIP with checksum-verified native WordPress update integration.
* Keeps the plain release ZIP WordPress.org-safe by excluding the GitHub updater and Update URI header.
* Publishes GitHub-channel update metadata for vcns/wp-updates when the release pipeline has a WP_UPDATES_TOKEN.
* Adds selectable automation postures on Profiles and Settings: Manual, Automatic with medium+high approvals, Automatic with high approvals only, and Fully Automatic within deterministic hard safety exclusions.
* Replaces the dashboard Strict-Dynamic display column with a per-surface Automation dropdown.

= 1.0.15 =

* Renames the dashboard source review queue to "For Review".
* Expands Policy Changes into a policy activity timeline showing source proposals, decisions, actors, suppression state, and policy snapshots.
* Adds per-surface deterministic automation settings and records eligible automatic approvals as `automation_engine` decisions.

= 1.0.14 =

* Changes the default CSP reporting transport to direct `report-uri` so browser violations reach the local endpoint promptly during learning.
* Adds a Reporting transport setting for opting into Reporting API headers when required.

= 1.0.13 =

* Fixes policy version table creation on MariaDB by avoiding a reserved index name.
* Prevents activation from querying policy version snapshots when the snapshot table could not be created.
* Avoids calling WordPress REST routing too early while activation-time policy snapshots are being built.

= 1.0.12 =

* Normalizes CSP directives so `'none'` is removed when approved sources are merged into the same directive.
* Accepts CSP reports from configured public reporting endpoint and forwarded hostnames so proxied deployments do not silently discard valid browser reports.
* Clarifies that browser violation reports can be collected from either report-only or enforce CSP headers.

= 1.0.11 =

* Makes CSP surface detection path-aware so wp-admin URLs that produce redirects or 404 responses still use the admin surface configuration.

= 1.0.10 =

* Makes the destructive CSP data reset return all surfaces to disabled mode so the plugin stops emitting CSP headers until rollout is deliberately restarted.
* Emits CSP headers before WordPress redirects, making unauthenticated wp-admin redirects easier to diagnose.

= 1.0.9 =

* Adds a configurable origin policy header name for Cloudflare, CDN, and reverse-proxy deployments that copy an origin header back to the browser-facing CSP header.
* Adds schema self-healing so missing CSP tables are recreated even when the stored database version already matches the current schema version.

= 1.0.8 =

* Clarifies the Violations empty state so administrators know manual scans do not create browser violation reports and can see the expected reporting endpoint.

= 1.0.7 =

* Adds a CSP Manager Readiness page for plugin-specific schema, database, reporting endpoint, scan schedule, and automation posture checks.
* Adds a Reset action in the Installed Plugins row that links to a destructive reset panel requiring current administrator password re-authentication and typed confirmation.

= 1.0.6 =

* Adds CSP conflict detection for existing `.htaccess`, server, and security-header-plugin CSP emitters.
* Requires administrator reasons for source approval, rejection, reversion, and undo decisions.
* Adds undo support for approved and rejected source decisions without rewriting history.
* Adds dashboard tab guidance, configurable reporting server URL support, and an Installed Plugins Settings link.

= 1.0.5 =

* Renames the package slug, text domain, main plugin file, release ZIP, and WordPress.org deployment slug to `csp-automation-manager`.
* Updates WordPress.org scanner metadata and includes the declared `languages` directory.

= 1.0.4 =

* Removes the custom runtime update checker and all third-party update manifest polling from the WordPress.org plugin package.
* Removes legacy external-service admin surfaces from the WordPress.org plugin package.
* Makes all shipped CSP capabilities available locally without payment, remote entitlement checks, or trialware-style feature locking.
* Updates package copy and disclosures for WordPress.org guideline alignment.

= 1.0.3 =

* Renames the public plugin display name to `CSP Automation Manager` to comply with WordPress.org plugin naming requirements.

= 1.0.2 =

* Tightens the release package so development-only files, internal policy notes, and local cache files are excluded from distributed ZIP builds.
* Adds release workflow checks that fail if submission-only or development-only files are present in the packaged ZIP.

= 1.0.1 =
* Adds Reporting API headers, forbidden-directive filtering, violation sample persistence, audit logging, policy-change proposals, decision suppression, revert behaviour, violation rollups, policy history, and review APIs.

= 0.2.0 =
* Initial public plugin implementation.
