# Architecture

## Purpose

Security Automation Manager is a WordPress plugin that helps site owners roll out strict HTTP security headers without maintaining the policy by hand. Content Security Policy is its most capable pillar -- combining local discovery and policy management with optional entitlement-gated premium capabilities -- with simpler per-surface pillars (X-Frame-Options, X-Content-Type-Options, Referrer-Policy) alongside it. Billing and account management are expected to move through VCNS licensing services rather than being owned by the CSP runtime.

## Primary design principles

- Default-safe rollout: every surface starts in report-only mode.
- Local enforcement decisions: runtime feature access is resolved from local database state.
- No secrets in remote config: DNS-discovered configuration contains only public product metadata.
- WordPress-native integration: use core hooks, REST APIs, cron, transients, and HTTP APIs instead of parallel infrastructure.
- Progressive hardening: approvals and policy promotion are explicit human actions.
- Deterministic authority: recommendation systems may advise, but policy mutation remains controlled by local deterministic rules and administrator decisions.

## Top-level component map

### Bootstrap

`security-automation-manager.php`

Responsibilities:

- declares plugin metadata
- defines version, path, and DB version constants (`WP_SAM_DB_VERSION`)
- registers the autoloader
- wires activation and deactivation hooks
- starts the plugin on `plugins_loaded`

### Lifecycle

`includes/class-activator.php`
`includes/class-deactivator.php`
`uninstall.php`

Responsibilities:

- create and seed custom tables, including audit, decision, policy version, and rule evaluation tables
- register default settings (including violation retention policy) and default policy profiles
- schedule daily cron jobs
- remove cron jobs on deactivation
- remove plugin-owned data on uninstall

### Core runtime coordinator

`includes/class-plugin.php`

Responsibilities:

- construct shared services
- register REST routes
- register admin UI and CSP runtime hooks
- run DB schema migrations via `maybe_upgrade_db()` on each boot when `WP_SAM_DB_VERSION` exceeds the stored option value, when the current schema has not yet been verified, or when an admin request detects missing plugin tables
- expose the central singleton used by cross-cutting helpers

### CSP runtime

`includes/csp/*`

Responsibilities:

- create a per-request nonce (≥128-bit entropy from CSPRNG)
- inject nonce attributes into script and style tags
- build per-surface CSP headers (including direct `report-uri` reporting by default, optional Reporting API headers, and optional origin-only policy header names for proxy deployments)
- strip deprecated and forbidden directives from policy overrides at emit time
- discover remote sources from crawled pages
- record inline hashes
- ingest violation reports (with Content-Type and origin validation)
- risk-score discovered and report-learned source proposals before administrator approval
- record administrator approve/reject/revert decisions and suppress rejected/reverted fingerprints
- capture policy version snapshots for material decisions
- record deterministic rule findings for policy decisions
- run scheduled and manual scans (including post-scan violation purge)
- detect conflicting CSP headers from WordPress filters, `.htaccess`, server configuration, or other security-header plugins

### Shared header envelope and simple pillars

`includes/security/*`

`Header_Builder` (`includes/security/class-header-builder.php`) is the pillar-agnostic envelope every header pillar registers on `send_headers`/`wp_redirect`: the `header_emitted`/`headers_sent()` guard, the internal conflict-probe suppression, and surface detection. CSP's `Policy_Builder` extends it directly, since CSP's own storage (`csp_policy_profiles`) and header assembly (directives, overrides, strict-dynamic, Reporting API) are too specific to share.

`Pillar_Header_Builder` extends `Header_Builder` for pillars simple enough to store their per-surface state as a single JSON `payload` in the shared `sam_pillar_profiles` table rather than CSP's directive/override shape:

- **X-Frame-Options** (`X_Frame_Options_Builder`) -- per-surface `DENY` or `SAMEORIGIN`. CSP's `frame-ancestors` directive supersedes this header in browsers that support it; this remains a fallback for older browsers. `ALLOW-FROM` is deliberately not offered (deprecated, unsupported by modern browsers).
- **X-Content-Type-Options** (`X_Content_Type_Options_Builder`) -- per-surface on/off. `nosniff` is the only defined value, so there is nothing to configure beyond enabling it.
- **Referrer-Policy** (`Referrer_Policy_Builder`) -- per-surface value from the eight standard tokens, defaulting to `strict-origin-when-cross-origin`. HTTP header only; no `<meta name="referrer">` injection.
- **Permissions-Policy** (`Permissions_Policy_Builder`) -- the first pillar with multiple independently-configurable directives per surface, rather than a single scalar value: `payload` holds a directive-name => allowlist-token map (a starter set of seven directives -- `geolocation`, `camera`, `microphone`, `fullscreen`, `payment`, `usb`, `autoplay` -- not the full ~30-directive registry). Each directive is `none` (`()`), `self` (`(self)`), or `all` (`(*)`); free-text origin lists are deliberately not offered in v1, to avoid reopening the header-injection sanitization surface CSP already solves for source hosts. A directive absent from the map is simply not emitted, so the browser's own default applies to that feature.

None of these four pillars have a report-only mode, a discovery workflow, or Decision Engine wiring -- each header is either sent exactly as configured, or not sent at all. `Permissions-Policy-Report-Only` exists only in draft form with minimal real browser support, so even the pillar closest in shape to CSP still skips it. `sam_pillar_profiles` and `Automation_Config`/`Decision_Engine`/`Policy_Change_Manager` remain unconnected until a future pillar actually needs discovery or risk-scoring for its allowlists.

### Entitlement and payment runtime

`offline/modules/*` (`Config_Resolver`, `Checkout_Service`, `Webhook_Controller`, `Entitlement_Store`) -- gitignored, never bundled into a WordPress.org or GitHub-channel release ZIP. `Feature_Gate` (`includes/modules/class-feature-gate.php`) is the only always-shipped piece; it accepts these as optional dependencies and runs in a free-only posture when they're absent, which is the case for every distributed build today.

Responsibilities:

- `Config_Resolver`: fetch and Ed25519-verify the signed remote product config from `https://wp-sam.vcns.tech/`, with transient caching and stale-cache fallback
- `Checkout_Service`: start a Stripe Checkout session (subscription mode) via `https://wp-sam.vcns.tech/checkout` for the selected billing interval (monthly £1.99 / annual £19.99)
- `Webhook_Controller`: verify Stripe webhook signatures and grant entitlements on `checkout.session.completed`
- `Entitlement_Store`: read/write local entitlement rows, falling back to `https://wp-sam.vcns.tech/entitlement` when none exists locally
- `Feature_Gate`: gates exactly one feature -- `fully_automatic` -- behind an active entitlement; everything else is free regardless of entitlement state
- provide structured operational logging (append-only DB audit trail via `Audit_Log`)

### Admin runtime

`includes/admin/*`
`assets/js/admin.js`
`assets/css/admin.css`

Responsibilities:

- render the Overview, CSP dashboard (Start Here, Profiles, For Review, Policy Changes, Violations, Scan Log, and Settings tabs), X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, policy audit, and readiness pages
- support full-dataset sorting and per-column filtering on the Violations, For Review, and Policy Changes tables, plus a per-row metadata popover on Violations (document URI, source file, line/column, referrer, user agent, captured data-URI payload)
- support source review and mode switching
- trigger scans and config refreshes
- surface one-per-session warnings for known platform constraints (e.g. wp-admin strict CSP limitation)
- expose a destructive reset flow that requires `manage_options`, a nonce, current administrator password re-authentication, and typed confirmation before clearing plugin-owned runtime data

## Runtime request flow

### 1. WordPress boot

1. WordPress loads the plugin file.
2. The plugin singleton is initialized on `plugins_loaded`.
3. `maybe_upgrade_db()` compares `WP_SAM_DB_VERSION` against the stored option and the schema verification marker; if either is stale, `Activator::activate()` is called and `dbDelta()` migrates or repairs the schema. Admin requests also check for missing plugin tables so a partially upgraded installation can self-heal.
4. Shared services are instantiated.
5. Hooks for admin UI, REST endpoints, nonce generation, CSP emission, cron, and conflict detection are registered.

### 2. Frontend or admin page request

1. `Nonce_Manager` generates a random nonce early in the request lifecycle.
2. Script and inline-script attributes receive the nonce through WordPress 6.4+ hooks, with legacy fallback filters for broader compatibility.
3. `Policy_Builder` identifies the current surface: `frontend`, `admin`, `login`, or `api`. REST requests use the API surface, `wp-admin` request paths use the admin surface even on redirects or 404 responses, and `wp-login.php` paths use the login surface.
4. The relevant profile is loaded from the database.
5. Approved sources and active hashes are merged into the directive set.
6. Forbidden or deprecated directives (`plugin-types`, `block-all-mixed-content`, `navigate-to`, `prefetch-src`) are stripped from overrides; any stripped directive is logged to `sam_audit_log` at `warning` severity.
7. If enabled and licensed, `'strict-dynamic'` is appended to `script-src`; approved host sources are suppressed from `script-src` at this point (browsers silently ignore host allowlists when `strict-dynamic` is present — CSP3 §8.2).
8. `sandbox` is skipped if null or if the profile is in report-only mode (CSP spec — `sandbox` is ignored in `Content-Security-Policy-Report-Only`).
9. Trusted Types directives (`require-trusted-types-for`, `trusted-types`) are skipped when their arrays are empty; when enabled they are always emitted as report-only regardless of surface mode.
10. The reporting endpoint is resolved from `wp_sam_report_endpoint_url` when an administrator has configured an absolute `http` or `https` override; otherwise it falls back to `rest_url( 'security-manager/v1/report' )`.
11. The CSP includes `report-uri <report_uri>` by default so browser reports are delivered directly and promptly to the local learning endpoint.
12. If `wp_sam_reporting_transport` is set to `both` or `report-to`, two additional Reporting API headers are emitted before the CSP header:
    - `Reporting-Endpoints: csp-endpoint="<report_uri>"` — Structured Fields Dictionary (RFC 9651); required for browsers to honour `report-to csp-endpoint` in the CSP
    - `Report-To: {"group":"csp-endpoint","max_age":86400,"endpoints":[{"url":"<report_uri>"}]}` — deprecated JSON format retained as a legacy fallback for pre-Reporting-API browsers
13. The policy header name is resolved from `wp_sam_policy_header_name`. Blank emits the normal mode-aware `Content-Security-Policy-Report-Only` or `Content-Security-Policy` header. A validated custom value emits the exact origin header name for a proxy to copy back into the browser-facing CSP header.
14. The CSP or CSP-Report-Only policy value is emitted via `send_headers`.

### Conflict detection

`Conflict_Detector` checks for CSP headers before administrators promote a policy:

- `wp_headers` is inspected late for CSP values added by other WordPress plugins.
- `ABSPATH/.htaccess` is scanned for Apache or LiteSpeed `Header` directives that set, add, append, merge, or edit CSP headers.
- A throttled internal `HEAD` probe sends `X-WP-CSP-Probe: 1`; `Policy_Builder` suppresses this plugin's own CSP output for that request so any remaining CSP header is treated as likely coming from web-server configuration or another security-header plugin.

Conflicts are warning-level audit events. The detector never removes or rewrites another component's header because browser behaviour with multiple CSP policies is cumulative and site-specific.

### 3. Scan flow

1. A scan is triggered manually or by WP Cron.
2. `Audit_Log::start_scan()` opens a `csp_scan_logs` record with status `running`.
3. `Discovery` crawls the target URL for each allowed surface.
4. External origins are classified by directive type.
5. New origins are upserted into the source inventory as `pending`.
6. `Policy_Change_Manager` assigns a risk level and skips any source whose latest administrator decision suppresses the same fingerprint.
7. Hash retirement is run to mark previously seen inline hashes as stale when absent.
8. `Audit_Log::finish_scan()` records scan summary and sets status to `completed` or `failed`.
9. `Scheduler::purge_old_violations()` deletes `csp_violation_reports` rows older than `wp_sam_violation_retention_days` days (default 90); the count deleted is logged to `sam_audit_log`.

### 4. Violation ingestion flow

1. Browser submits a violation report to the configured reporting endpoint. By default this is `/wp-json/security-manager/v1/report`; proxy/CDN deployments can advertise an administrator-provided public URL that must route back to this plugin endpoint for local learning. A legacy alias at `/wp-json/csp-manager/v1/report` (the pre-rename REST namespace) remains registered against the same handler, since browsers holding a CSP header issued before the rename keep POSTing to it until they receive a fresh policy; remove the alias a couple of releases after the rename ships.
2. `Violation_Reporter` validates the `Content-Type` header; requests with a content type other than `application/csp-report`, `application/reports+json`, or `application/json` are rejected with HTTP 400.
3. The payload is normalised from either the legacy `application/csp-report` format (hyphenated field names: `document-uri`, `blocked-uri`, `script-sample`, etc.) or the Reporting API `application/reports+json` format (camelCase field names: `documentURL`, `blockedURL`, `sample`, etc.).
4. The `document-uri` hostname is compared against the WordPress site origin (RFC 6454); reports from a different origin are silently discarded — CSP reports are client-generated and spoofable.
5. Per-surface transient-based rate limiting is enforced (500 reports/hour).
6. A fingerprint is computed over `(profile_surface, blocked_uri, violated_directive)` to deduplicate repeat reports.
7. The `sample` field (inline script/style snippet, populated only when `'report-sample'` is in the emitting directive) is captured and stored in `csp_violation_reports.sample`.
8. A new or existing row in the violation table is upserted; duplicate fingerprints increment `occurrence_count`.
9. While the learning window is open, host-based cross-origin blocked URLs become pending source proposals through `Policy_Change_Manager`; rejected or reverted fingerprints are not proposed again unless a later administrator approval clears suppression.

### 5. Policy change-control flow

1. Discovery and report-endpoint learning create pending source proposals, not approved policy.
2. `Policy_Change_Manager` computes a stable fingerprint from `(surface, directive, source_host)`.
3. High-risk proposals include script/style execution, connection, form, frame, worker, wildcard, cleartext HTTP, broad browser schemes, and unsafe keyword patterns.
4. `Decision_Engine` evaluates proposals through versioned deterministic rules and returns risk, hard exclusions, automation eligibility, and rule findings.
5. Administrators approve, reject, revert, or undo decisions from the For Review queue. Every material administrator decision requires a reason.
6. When a surface is explicitly configured for automation and a per-run limit is set, deterministic proposals within that mode's risk ceiling may be approved automatically with actor `automation_engine`. Automation Mode alone gates eligibility -- there is no separate kill-switch field; setting a surface to Manual is how automatic approval is stopped.
7. Medium, high, unknown, ambiguous, hard-excluded, disallowed-scheme, excluded-directive, and AI-agreement-required proposals remain pending for administrator review.
8. Every decision is appended to `csp_policy_change_decisions`, mirrored to `sam_audit_log`, and linked to deterministic rule findings in `csp_decision_rule_evaluations`.
9. Approved, automatically approved, and reverted decisions capture a `csp_policy_versions` snapshot for the affected surface.
10. Rejected and reverted decisions set suppression on that fingerprint; future automation skips the same source until a later approval or undo becomes the newest decision.

### 6. Policy audit flow

1. Administrators open **Security Automation Manager -> Policy Audit**.
2. The current surface summary shows CSP mode, automation mode, latest policy version, pending proposal count, unresolved high-risk count, and the latest captured header.
3. The For Review queue lists pending proposals with surface, directive, source, risk, evidence count, first seen, and last seen.
4. Recent decisions show actor, state, surface, directive, source, risk, decision-engine version, and linked policy version.
5. Privileged REST endpoints under `/wp-json/security-manager/v1/admin/*` expose policy history, policy diffs, decisions, pending reviews, and automation configuration for richer future UI workflows.

### 7. Readiness and reset flow

1. Administrators open **Security Automation Manager -> Readiness**.
2. `Readiness_Checker` reports plugin version, installed schema version, expected custom tables, plugin-owned row counts, reporting endpoint validity, policy header emission mode, scheduled scan status, policy-profile presence, policy-version snapshot presence, and automation posture.
3. The Installed Plugins row exposes **Settings** and **Reset** action links; Settings opens the CSP dashboard's Settings tab, and Reset opens the readiness page at the destructive reset panel.
4. Reset requires `manage_options`, a valid WordPress nonce, the current logged-in administrator's password, and the typed phrase `RESET CSP DATA`.
5. `Data_Resetter` clears rows from plugin-owned custom tables, deletes plugin-owned runtime options and transients, clears the plugin daily scan schedule, and then runs `Activator::activate()` to reseed default options, policy profiles, policy snapshots, and cron.
6. After reseeding, reset sets every policy profile to `disabled` so the plugin does not emit CSP headers until an administrator deliberately restarts rollout in report-only or enforce mode.
7. Reset is intentionally stronger than ordinary policy rollback: it is for pre-launch clean-room restarts and removes historical CSP records from this local installation.

### 8. Premium entitlement flow

1. Admin opens the entitlement page and starts the configured VCNS account-management flow.
2. Legacy installations may still initiate a compatibility checkout flow from signed remote config.
3. Billing events are handled by VCNS infrastructure, with Stripe acting as an external event source where applicable.
4. Verified entitlement data is cached locally by `Entitlement_Store`.
5. `Feature_Gate` exposes premium features from local entitlement state.
6. Normal CSP generation never performs a remote billing or entitlement lookup.

## Surface model

The plugin treats each of the following as an independent policy surface:

- `frontend`
- `admin`
- `login`
- `api`

Each surface has its own policy profile, scan target, approval set, and violation data. This separation is central to avoiding over-broad CSP allowlists.

**wp-admin surface constraint:** WordPress core Trac #59446 is unresolved — some core admin screens and bundled themes emit inline scripts outside the WordPress script API, preventing strict nonce-based enforcement for the admin surface. Strict enforcement on the admin surface is best-effort; the plugin surfaces a one-per-session admin notice when the admin profile mode is set to `enforce`.

## Trust boundaries

### Trusted local state

- plugin code
- WordPress options
- custom plugin tables
- capability checks and nonces in admin context

### Conditionally trusted external inputs

- DNS TXT record pointing to the remote config URL
- HTTPS remote config payload
- Stripe webhook requests
- browser-submitted CSP reports
- crawled HTML during discovery

Each of these inputs is validated before use:

- remote config is signature-verified when libsodium is available
- Stripe webhook bodies are HMAC-verified
- browser reports are validated for `Content-Type`, `document-uri` origin, normalized, rate-limited, and deduplicated
- discovered sources are not auto-approved
- rejected and reverted source fingerprints are not reintroduced by automation unless the latest administrator decision approves or undoes the suppressing decision

## Security-critical decisions

These design choices should not be changed casually:

- entitlements are granted only from verified webhooks, never from redirect query parameters alone
- enforce mode remains blocked until at least one source or hash is approved for the target surface
- remote config must contain public metadata only, never keys or webhook secrets
- local entitlement checks must not make network calls during page rendering
- per-site identity is derived from site URL hash rather than stored in plain text everywhere
- direct `report-uri` is the default reporting transport because operators need prompt feedback while learning a policy
- the `Reporting-Endpoints` header must always be emitted alongside any CSP containing `report-to`; without it browsers silently discard the directive and violation reports are never delivered
- `report-to` without a corresponding `Reporting-Endpoints` header is a silent failure, and browsers that use `report-to` may ignore `report-uri`, so Reporting API transport must remain an explicit administrator choice
- when `strict-dynamic` is active, host-based sources are suppressed from `script-src` at emit time; emitting them is harmless but creates misleading policy noise since browsers ignore them
- cross-origin violation reports are silently discarded; only reports whose `document-uri` matches the site's own origin are stored
- `sam_audit_log` is append-only — no `UPDATE` or `DELETE` may ever be issued against it; it is the permanent operational audit trail
- `csp_policy_change_decisions` is append-only; suppression is represented by the latest decision for a fingerprint, not by rewriting old decisions; undo appends a new non-suppressing decision and links to the decision it reverses where available
- the violation retention purge uses `UTC_TIMESTAMP()` not `NOW()` to avoid timezone-offset errors in environments where MySQL and PHP have different local time configurations

## Failure handling

### Remote config unavailable

- serve the cached config when available
- serve grace copy if current refresh fails but a stale signed copy exists
- write audit warnings to `sam_audit_log` for operator visibility

### Webhook replay or duplicate delivery

- reject invalid signatures
- use the `csp_processed_events` table for idempotency

### Scan failure

- record the scan result in the scan log table with status `failed`
- preserve existing policy state
- do not auto-promote or auto-approve anything
- `sam_audit_log` receives a `scan_exception` event with the exception message at `error` severity

### Violation ingestion failure

- malformed or unsupported `Content-Type` → HTTP 400 immediately, no DB write
- cross-origin `document-uri` → silently discard, no DB write
- DB write failure → silently swallowed (violation ingestion must not produce a user-visible error)

### Violation table growth

- rows are automatically purged after `wp_sam_violation_retention_days` days (default 90) by the daily cron scan
- per-surface transient rate limiting (500 reports/hour) prevents ingestion storms from filling the table between purge cycles
- set `wp_sam_violation_retention_days` to `0` to disable purging (keep forever); operators should add external archival in that case

## Operational dependencies

- WordPress 6.4+
- PHP 8.1+
- libsodium for strong remote-config verification
- outbound HTTPS to Stripe and the remote config endpoint
- WP Cron, or a server-side cron hitting WordPress regularly enough to execute scheduled scans (includes post-scan violation purge and audit log writes)

## Extension guidance

Future work should preserve existing seams:

- add new premium capabilities through `Feature_Gate`
- keep commercial tier labels separate from internal capability identifiers such as `automation_low_risk`, `automation_advanced`, and `ai_recommendations`
- add new remote config values through the existing signed JSON contract
- add new scan types through `Scheduler` and `Discovery`
- keep admin actions behind capability checks and nonces
- all significant plugin events must be logged to `sam_audit_log` via `Audit_Log::log()` — not only the wp_options FIFO queue
- document every new operational dependency before release
