# Architecture

## Purpose

Security Automation Manager is a WordPress plugin that helps site owners roll out strict HTTP security headers without maintaining the policy by hand. Content Security Policy is its most capable pillar -- combining local discovery and policy management with optional entitlement-gated premium capabilities -- with simpler per-surface pillars (X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, Strict-Transport-Security) alongside it. Billing and account management are expected to move through VCNS licensing services rather than being owned by the CSP runtime.

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
- **Strict-Transport-Security** (`Strict_Transport_Security_Builder`) -- per-surface `max-age`, `includeSubDomains`, and `preload`. The one pillar with real lock-in risk: browsers cache `max-age` and refuse plain-HTTP connections for that long regardless of what the header says afterward, and there's no report-only variant to rehearse a rollout with, so this builder enforces two guardrails the admin UI alone can't be trusted for -- the header is only ever emitted over an HTTPS request (`is_ssl()`), and `preload` is silently dropped unless the stored `max-age`/`includeSubDomains` combination already meets hstspreload.org's submission minimum (`max-age >= 31536000` and `includeSubDomains` present).
- **Cross-Origin-Resource-Policy** (`Cross_Origin_Resource_Policy_Builder`) -- per-surface `same-site` / `same-origin` / `cross-origin`. Low-risk: it only restricts which sites may load this site's own resources cross-origin, not what this site itself can embed.
- **Cross-Origin-Opener-Policy** (`Cross_Origin_Opener_Policy_Builder`) -- per-surface `unsafe-none` / `same-origin` / `same-origin-allow-popups`. `same-origin` severs `window.opener` access from any cross-origin popup this site opens or is opened by -- including popup-based OAuth/SSO flows -- so `same-origin-allow-popups` is the safer enforcing value for sites that rely on those.
- **Cross-Origin-Embedder-Policy** (`Cross_Origin_Embedder_Policy_Builder`) -- per-surface `unsafe-none` / `require-corp` / `credentialless`. The highest-risk pillar this plugin manages: `require-corp` blocks any cross-origin subresource (fonts, embeds, ad tags) lacking an explicit CORP/CORS opt-in, and most third-party embeds don't opt in by default, so enabling this carelessly breaks unrelated page content silently rather than with an obvious error. Only actually required for sites that need cross-origin isolation (`SharedArrayBuffer`, high-resolution timers); most WordPress sites don't.
- **X-Permitted-Cross-Domain-Policies** (`X_Permitted_Cross_Domain_Policies_Builder`) -- per-surface `none` / `master-only` / `by-content-type` / `all`. A legacy Flash/Acrobat-era header; `none` closes the (permissive) browser default and is almost always correct for a modern site.

None of these nine pillars have a report-only mode, a discovery workflow, or Decision Engine wiring -- each header is either sent exactly as configured, or not sent at all. `Permissions-Policy-Report-Only` exists only in draft form with minimal real browser support, so even the pillar closest in shape to CSP still skips it. `sam_pillar_profiles` and `Automation_Config`/`Decision_Engine`/`Policy_Change_Manager` remain unconnected until a future pillar actually needs discovery or risk-scoring for its allowlists.

`Request_Surface` (`includes/security/class-request-surface.php`) holds the surface-detection and conflict-probe logic `Header_Builder` used to own directly; both `Header_Builder` and `Content_Rewriter` extend it now, so header pillars and body-rewriting components classify a request identically without either depending on the other.

### Content rewrite protections

`includes/security/*`

`Content_Rewriter` (`includes/security/class-content-rewriter.php`) is the counterpart to `Header_Builder` for components that rewrite the rendered HTML body instead of emitting a header. It opens a plugin-owned output buffer at `template_redirect` (late enough that headers, sent earlier from `WP::send_headers()`, are unaffected), excludes admin/login/AJAX/REST/XML-RPC/cron/CLI/feed/robots/sitemap/non-GET-HEAD requests the same way the header pillars already exclude the CSP conflict probe, and requires a successful, non-streamed, HTML response before calling the concrete subclass's `rewrite()`. Every failure mode -- a parser exception, an unresolvable rewrite, a fatal-error shutdown mid-request -- fails open to the original response, and the Content-Length header is dropped only when the body actually changed and headers haven't been sent yet, so a stale length can never truncate a rewritten response.

- **Reverse Tabnabbing Protection** (`Reverse_Tabnabbing_Builder`) -- adds `rel="noopener"` to `target="_blank"` anchors missing `noopener`/`noreferrer` via `WP_HTML_Tag_Processor`, preserving every other `rel` token. Enabled state lives in `sam_pillar_profiles` (no configurable value, same shape as X-Content-Type-Options) even though it isn't a header pillar, purely for admin-UI and storage consistency.
- **External Scripts** (`Dependency_Governance_Builder`) -- passively inventories third-party `<script src>` / `<link rel="stylesheet" href>` origins into a new `sam_dependency_inventory` table during real page renders (never a dedicated crawl), deduplicating at the origin (scheme + host) level so a CDN serving content-hashed filenames still collapses to one row per origin. Each row also keeps `last_seen_url` -- the most recently observed full URL (path and query included) -- so the "Suggest" hash helper has an exact file to fetch without the administrator having to already know or go find that URL themselves. A freshly discovered origin is always `unclassified`; this deliberately diverges from a naive default-deny design where anything off an allowlist is blocked immediately. Per-surface mode (`report` | `enforce`, default `report`) lives in `sam_pillar_profiles` alongside `enabled`, matching the rest of this plugin's report-first philosophy. Enforce mode still only ever removes an origin the administrator explicitly classified `prohibited`, or an `immutable_pinned` origin whose administrator-declared `expected_sri` no longer matches what the page actually served -- an `unclassified` origin is never silently blocked, even in enforce mode. `expected_sri` is admin-supplied only: this class only ever *compares* against it, never computes a hash from a live fetch, which would defeat the point of SRI if the remote origin were compromised. Because this plugin never injects an `integrity` attribute itself, `immutable_pinned` only has an effect for elements whose own markup (the site owner's, not a third party's) already carries a matching `integrity` attribute -- e.g. a version-pinned library added via a child theme, not a vendor-injected tracking script. Element removal marks matched tags via a private data attribute during the `WP_HTML_Tag_Processor` pass, then strips the marked spans with a narrow, quote-aware regex afterward, since `WP_HTML_Tag_Processor` in this plugin's supported WordPress versions has no element-deletion API; any surviving marker (an element that couldn't be resolved) discards the rewrite and returns the original response instead.
- **`Dependency_Integrity_Monitor`** (`includes/security/class-dependency-integrity-monitor.php`) -- a daily, transient-gated proactive check (same pattern as `Conflict_Detector`'s probe) that catches `immutable_pinned` hash drift before a real visitor triggers `Dependency_Governance_Builder`'s reactive removal. It fetches this site's own frontend homepage -- never third-party content -- and re-runs the same "does the live element's `integrity` attribute still match the pinned `expected_sri`" comparison, logging a warning via `Audit_Log` on mismatch. Deliberately does not fetch and auto-trust a hash from any third-party origin: doing so would defeat SRI's own threat model (a compromised CDN would just have its malicious content faithfully pinned as "expected" on the next scan). `Admin_UI::ajax_suggest_dependency_sri()` is the safe alternative for reducing hash-pinning friction -- it fetches and hashes a URL the administrator explicitly supplies (restricted to an origin already in the inventory, to avoid becoming an arbitrary fetch proxy) and returns the computed hash to prefill the "Expected SRI" field; the administrator still has to accept it via the normal classification save before it's ever compared against anything.

### Internal Script Integrity

`includes/security/class-internal-script-integrity-builder.php`

`Internal_Script_Integrity_Builder` is `Dependency_Governance_Builder`'s first-party counterpart, but it isn't a `Content_Rewriter` subclass -- it extends `Request_Surface` directly and hooks `script_loader_tag`/`style_loader_tag`, the same filters `Nonce_Manager` already uses, rather than buffering and rewriting the response body. Per-surface opt-in (`sam_pillar_profiles`, enabled-only, no configurable value, same shape as X-Content-Type-Options). When active for the current surface, `resolve_local_path()` maps the tag's URL back to a local filesystem path via longest-prefix matching against `content_url()`/`includes_url()`/`admin_url()`/`site_url()`, rejecting anything that isn't first-party (`Dependency_Governance_Builder::is_first_party()`) and anything that fails a `realpath()` containment check against `ABSPATH` (path-traversal defense) -- any uncertainty fails closed, leaving the tag untouched. The hash itself is computed by reading that local file directly and never by fetching a URL, which is the fundamental difference from third-party SRI: there is no remote origin to trust, so there's no "compromised CDN" risk to guard against, only tampering or caching-layer drift between this server and the browser. `sam_internal_asset_inventory` caches the computed hash alongside the file's `mtime`/`size`; a cheap stat comparison on every request skips the expensive re-hash unless the file has actually changed (a plugin/theme update, a manual edit), so the pinned hash for a given surface is always recalculated by the very next request that serves the changed file. Nothing here is admin-configurable beyond the per-surface on/off toggle -- there's no classification step, because a first-party file's hash can never legitimately diverge from what's on disk the way an administrator-declared third-party `expected_sri` can.

### Entitlement and payment runtime

`offline/modules/*` (`Checkout_Service`, `Webhook_Controller`, `Entitlement_Store`) -- gitignored, never bundled into a WordPress.org or GitHub-channel release ZIP. `Feature_Gate` (`includes/modules/class-feature-gate.php`) is the only always-shipped piece; it accepts these as optional dependencies and runs in a free-only posture when they're absent, which is the case for every distributed build today.

Every piece of this runtime calls the Stripe API directly from the WordPress install -- there is no external proxy or worker. Stripe secret keys, Price IDs, and the webhook signing secret are configured locally (CSP dashboard, Settings tab, "Stripe Configuration" section, only rendered when `Checkout_Service` is present).

Responsibilities:

- `Checkout_Service`: create a Stripe Checkout Session (subscription mode) by calling `https://api.stripe.com/v1/checkout/sessions` directly with a locally-configured secret key and Price ID for the selected billing interval and Stripe mode (test/live)
- `Webhook_Controller`: receive Stripe's webhook directly at `/wp-json/sam/v1/webhook/stripe`, verify its signature against the locally-configured webhook secret, and grant entitlements on `checkout.session.completed` / `checkout.session.async_payment_succeeded`
- `Entitlement_Store`: read/write local entitlement rows (`sam_entitlements`) -- entitlement state never leaves this site's own database
- `Feature_Gate`: gates exactly one feature -- `fully_automatic` -- behind an active entitlement; everything else is free regardless of entitlement state
- provide structured operational logging (append-only DB audit trail via `Audit_Log`)

### Admin runtime

`includes/admin/*`
`assets/js/admin.js`
`assets/css/admin.css`

Responsibilities:

- render the Overview page (Overview, Readiness, Updates -- installed version, active build channel, manifest/checksum/applied-update diagnostics behind an early branch so a WordPress.org build never references the GitHub update service -- and About tabs), CSP dashboard (Start Here, Profiles, For Review, Policy Changes, Policy Audit, Violations, Scan Log, and Settings tabs), Cross-Origin Policies page (Cross-Origin-Embedder-Policy, Cross-Origin-Opener-Policy, Cross-Origin-Resource-Policy, and X-Permitted-Cross-Domain-Policies tabs), Scripts page (Start Here, External, and Internal tabs), X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, Strict-Transport-Security, and Reverse Tabnabbing pages
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
5. Approved sources and active hashes are merged into the directive set. Each approved host source is prefixed with its captured scheme (`source_scheme`, default `https`) rather than emitted bare -- a scheme-less CSP source matches that host on any scheme, including plain HTTP.
6. Forbidden or deprecated directives (`plugin-types`, `block-all-mixed-content`, `navigate-to`, `prefetch-src`) are stripped from overrides; any stripped directive is logged to `sam_audit_log` at `warning` severity.
7. If enabled and licensed, `'strict-dynamic'` is appended to `script-src`; approved host sources are suppressed from `script-src` at this point (browsers silently ignore host allowlists when `strict-dynamic` is present - CSP3 §8.2).
8. `sandbox` is skipped if null or if the profile is in report-only mode (CSP spec - `sandbox` is ignored in `Content-Security-Policy-Report-Only`).
9. `upgrade-insecure-requests` is skipped if the profile is in report-only mode -- browsers ignore it there too, same rationale as `sandbox`.
10. The per-surface Trusted Types toggle (Profiles tab) sets `require-trusted-types-for 'script'` when enabled. Trusted Types directives (`require-trusted-types-for`, `trusted-types`) are each skipped independently when empty; when `require-trusted-types-for` is enabled it is always emitted as report-only regardless of surface mode. `trusted-types` is stripped on its own whenever empty, so enabling the toggle alone never emits a bare, valueless `trusted-types` token.
11. The reporting endpoint is resolved from `wp_sam_report_endpoint_url` when an administrator has configured an absolute `http` or `https` override; otherwise it falls back to `rest_url( 'sam/v1/report' )`.
12. The CSP includes `report-uri <report_uri>` by default so browser reports are delivered directly and promptly to the local learning endpoint.
13. If `wp_sam_reporting_transport` is set to `both` or `report-to`, two additional Reporting API headers are emitted before the CSP header:
    - `Reporting-Endpoints: csp-endpoint="<report_uri>"` - Structured Fields Dictionary (RFC 9651); required for browsers to honour `report-to csp-endpoint` in the CSP
    - `Report-To: {"group":"csp-endpoint","max_age":86400,"endpoints":[{"url":"<report_uri>"}]}` - deprecated JSON format retained as a legacy fallback for pre-Reporting-API browsers
14. The policy header name is resolved from `wp_sam_policy_header_name`. Blank emits the normal mode-aware `Content-Security-Policy-Report-Only` or `Content-Security-Policy` header. A validated custom value emits the exact origin header name for a proxy to copy back into the browser-facing CSP header.
15. The CSP or CSP-Report-Only policy value is emitted via `send_headers`.

### Conflict detection

`Conflict_Detector` checks for CSP headers before administrators promote a policy:

- `wp_headers` is inspected late for CSP values added by other WordPress plugins.
- `ABSPATH/.htaccess` is scanned for Apache or LiteSpeed `Header` directives that set, add, append, merge, or edit CSP headers.
- A throttled internal `HEAD` probe sends `X-WP-SAM-Probe: 1` (`Request_Surface::CONFLICT_PROBE_HEADER`); every header pillar built on `Header_Builder`/`Pillar_Header_Builder` suppresses its own output for that request via `Request_Surface::is_conflict_probe_request()`, so any remaining CSP header is treated as likely coming from web-server configuration or another security-header plugin.

Conflicts are warning-level audit events. The detector never removes or rewrites another component's header because browser behaviour with multiple CSP policies is cumulative and site-specific.

### 3. Scan flow

1. A scan is triggered manually or by WP Cron.
2. `Audit_Log::start_scan()` opens a `sam_scan_logs` record with status `running`.
3. `Discovery` crawls the target URL for each allowed surface.
4. External origins are classified by directive type.
5. New origins are upserted into the source inventory as `pending`.
6. `Policy_Change_Manager` assigns a risk level and skips any source whose latest administrator decision suppresses the same fingerprint.
7. Hash retirement is run to mark previously seen inline hashes as stale when absent.
8. `Audit_Log::finish_scan()` records scan summary and sets status to `completed` or `failed`.
9. `Scheduler::purge_old_violations()` deletes `csp_violation_reports` rows older than `wp_sam_violation_retention_days` days (default 90); the count deleted is logged to `sam_audit_log`.

### 4. Violation ingestion flow

1. Browser submits a violation report to the configured reporting endpoint. By default this is `/wp-json/sam/v1/report`; proxy/CDN deployments can advertise an administrator-provided public URL that must route back to this plugin endpoint for local learning. A legacy alias at `/wp-json/security-manager/v1/report` (the immediately-prior REST namespace) remains registered against the same handler, since browsers holding a CSP header issued before the rename keep POSTing to it until they receive a fresh policy; remove the alias a couple of releases after the rename ships. The even older `/wp-json/csp-manager/v1/report` alias, from the original CSP Manager plugin rename, has already been retired.
2. `Violation_Reporter` validates the `Content-Type` header; requests with a content type other than `application/csp-report`, `application/reports+json`, or `application/json` are rejected with HTTP 400.
3. The payload is normalised from either the legacy `application/csp-report` format (hyphenated field names: `document-uri`, `blocked-uri`, `script-sample`, etc.) or the Reporting API `application/reports+json` format (camelCase field names: `documentURL`, `blockedURL`, `sample`, etc.).
4. The `document-uri` hostname is compared against the WordPress site origin (RFC 6454); reports from a different origin are silently discarded - CSP reports are client-generated and spoofable.
5. Per-surface transient-based rate limiting is enforced (500 reports/hour).
6. A fingerprint is computed over `(profile_surface, blocked_host_or_blocked_uri, violated_directive)` to deduplicate repeat reports. Whenever a host can be extracted from `blocked_uri` (`Violation_Reporter::extract_blocked_host()`), the fingerprint groups on that host, not the exact URL - a CDN or font provider serving each request from a distinct, content-hashed filename under the same host collapses to one row instead of a permanent row per file, matching the host-level granularity CSP source-approval already uses. Keyword-like values with no host (`inline`, `eval`, `data:`, `blob:`, `about:`) keep their exact-value fingerprint.
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
8. Every decision is appended to `sam_policy_change_decisions`, mirrored to `sam_audit_log`, and linked to deterministic rule findings in `sam_decision_rule_evaluations`.
9. Approved, automatically approved, and reverted decisions capture a `sam_policy_versions` snapshot for the affected surface.
10. Rejected and reverted decisions set suppression on that fingerprint; future automation skips the same source until a later approval or undo becomes the newest decision.

### 6. Policy audit flow

1. Administrators open **Security Automation Manager -> CSP -> Policy Audit** (a tab on the CSP page, not a separate top-level menu item -- it's CSP-specific content).
2. The current surface summary shows CSP mode, automation mode, latest policy version, pending proposal count, unresolved high-risk count, and the latest captured header.
3. The pending review queue lives on the adjacent For Review tab (surface, directive, source, risk, evidence count, first seen, last seen); the full decision ledger lives on the Policy Changes tab (actor, state, surface, directive, source, risk, decision-engine version, linked policy version) -- Policy Audit itself only shows the at-a-glance summary, not either underlying list.
4. Privileged REST endpoints under `/wp-json/sam/v1/admin/*` expose policy history, policy diffs, decisions, pending reviews, and automation configuration for richer future UI workflows.

### 7. Readiness, recovery, and reset flow

1. Administrators open **Security Automation Manager -> Readiness** for plugin/schema/operational health, or **Security Automation Manager -> Recovery** for schema-downgrade status, snapshot restore, configuration export/import, and the destructive reset panel.
2. `Readiness_Checker` reports plugin version, installed schema version, expected custom tables, plugin-owned row counts, reporting endpoint validity, policy header emission mode, scheduled scan status, policy-profile presence, policy-version snapshot presence, and automation posture.
3. The Installed Plugins row exposes **Settings** and **Reset** action links; Settings opens the CSP dashboard's Settings tab, and Reset opens the Recovery tab at the destructive reset panel.
4. `Rollback_Guard` refuses to run a migration when the installed schema is already ahead of the running code, and takes an automatic snapshot immediately before every schema upgrade; the Recovery tab lists restorable snapshots and lets an administrator undo a migration's data effects while staying on the current plugin code.
5. `Config_Portability` exports and imports administrator-authored configuration -- policy profiles, source/hash approvals, other pillar profiles, dependency classifications, non-secret certificate settings, and automation/reporting options -- for moving between sites or archiving outside the database; it never includes secrets, credentials, private key material, the audit log, or violation history, and import only ever writes tables/options on its own allowlist.
6. Reset requires `manage_options`, a valid WordPress nonce, the current logged-in administrator's password, and the typed phrase `RESET SAM PLUGIN DATA`.
7. `Data_Resetter` clears rows from every plugin-owned custom table across all pillars (not just CSP), deletes plugin-owned runtime options and transients, clears the plugin daily scan schedule, and then runs `Activator::activate()` to reseed default options, policy profiles, policy snapshots, and cron.
8. After reseeding, reset sets every policy profile to `disabled` so the plugin does not emit CSP headers until an administrator deliberately restarts rollout in report-only or enforce mode.
9. Reset is intentionally stronger than ordinary policy rollback: it is for pre-launch clean-room restarts and removes historical records for every pillar from this local installation, not just CSP.

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

**wp-admin surface constraint:** WordPress core Trac #59446 is unresolved - some core admin screens and bundled themes emit inline scripts outside the WordPress script API, preventing strict nonce-based enforcement for the admin surface. Strict enforcement on the admin surface is best-effort; the plugin surfaces a one-per-session admin notice when the admin profile mode is set to `enforce`.

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
- `sam_audit_log` is append-only - no `UPDATE` or `DELETE` may ever be issued against it; it is the permanent operational audit trail
- `sam_policy_change_decisions` is append-only; suppression is represented by the latest decision for a fingerprint, not by rewriting old decisions; undo appends a new non-suppressing decision and links to the decision it reverses where available
- the violation retention purge uses `UTC_TIMESTAMP()` not `NOW()` to avoid timezone-offset errors in environments where MySQL and PHP have different local time configurations

## Failure handling

### Remote config unavailable

- serve the cached config when available
- serve grace copy if current refresh fails but a stale signed copy exists
- write audit warnings to `sam_audit_log` for operator visibility

### Webhook replay or duplicate delivery

- reject invalid signatures
- use the `sam_processed_events` table for idempotency

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
- all significant plugin events must be logged to `sam_audit_log` via `Audit_Log::log()` - not only the wp_options FIFO queue
- document every new operational dependency before release
