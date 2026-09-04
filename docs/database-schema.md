# Database Schema

## Overview

The plugin creates custom tables on activation. All table names are prefixed with the site's configured WordPress table prefix (default `wp_`). Tables are created and migrated via `dbDelta()` in `includes/class-activator.php`; the current schema version is tracked in the `wp_sam_db_version` option and compared against the `WP_SAM_DB_VERSION` constant on every boot.

| Version | Change |
|---------|--------|
| v1 | Initial schema - seven tables |
| v2 | `csp_policy_profiles` gains `override_expires_at`, `override_owner` |
| v3 | `csp_violation_reports` gains `sample` column |
| v4 | `sam_audit_log` append-only table added (named `csp_audit_log` until v9) |
| v5 | source proposal risk/decision metadata and `sam_policy_change_decisions` append-only ledger added (named `csp_policy_change_decisions` until v9) |
| v6 | `csp_violation_reports` gains first/last reported roll-up timestamps and unique fingerprint upsert support |
| v7 | decision provenance columns, policy version snapshots, deterministic rule evaluations, and manual automation defaults |
| v8 | adds `last_seen_at` and `source_host` indexes to `csp_source_inventory`, and an `occurrence_count` index to `csp_violation_reports`, for the sortable/filterable dashboard tables |
| v9 | renames the shared/generic tables (`csp_scan_logs`→`sam_scan_logs`, `csp_entitlements`→`sam_entitlements`, `csp_processed_events`→`sam_processed_events`, `csp_audit_log`→`sam_audit_log`, `csp_policy_change_decisions`→`sam_policy_change_decisions`, `csp_policy_versions`→`sam_policy_versions`, `csp_decision_rule_evaluations`→`sam_decision_rule_evaluations`) via `RENAME TABLE`, ahead of multi-pillar support. The four CSP-owned tables (`csp_policy_profiles`, `csp_source_inventory`, `csp_hash_inventory`, `csp_violation_reports`) are unchanged. |
| v10 | adds `sam_pillar_profiles`, a shared per-surface profile table for header pillars simple enough not to need CSP's directive/override/strict-dynamic shape (X-Frame-Options, X-Content-Type-Options, Referrer-Policy). Created empty; unused until those pillars ship. |
| v11 | adds `sam_dependency_inventory` (third-party script/stylesheet origin governance). |
| v12 | migrates `fenced-frame-src` out of any already-seeded profile's stored `directives` JSON (removed from the default set as an experimental, non-standard directive commonly flagged by CSP linters); adds `trusted_types` to `csp_policy_profiles` for the per-surface Trusted Types toggle. |
| v13 | adds `sam_pillar_violation_reports`, a generic Reporting API violation store for pillars other than CSP (Cross-Origin-Opener-Policy and Cross-Origin-Embedder-Policy). See `Pillar_Violation_Store`. |
| v14 | adds `blocked_host` to `csp_violation_reports` and switches violation dedup from exact-URL to host granularity, so a CDN/font-provider serving each request from a distinct, content-hashed filename under the same host no longer gets a permanent row per file. See `Violation_Reporter::extract_blocked_host()`. |
| v15 | widens `sam_pillar_profiles.pillar` from `varchar(32)` to `varchar(48)` -- `x-permitted-cross-domain-policies` is 33 characters, one over the old column length. |
| v16 | adds `sam_internal_asset_inventory`, a first-party (theme/plugin/core) script and stylesheet integrity inventory. See `Internal_Script_Integrity_Builder`. |
| v17 | `default_directives()` no longer includes `data:` in `img-src`. Migrates any existing profile whose `img-src` still exactly matches the old default; a profile an administrator has already customised is left untouched. |
| v18 | seeds a vetted, enabled configuration for X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, Reverse Tabnabbing, Cross-Origin-Resource-Policy, Cross-Origin-Opener-Policy, Cross-Origin-Embedder-Policy, and X-Permitted-Cross-Domain-Policies on every surface without an existing row (HSTS deliberately excluded). Also changes the default CSP automation-approval mode from `manual` to `automatic_high_approval` for newly-seeded profiles -- approval only, never enforcement; an upgrade never changes an existing selection. |
| v19 | adds `last_seen_url` to `sam_dependency_inventory` -- the most recently observed full URL (path and query included) for a governed third-party origin, so the "Suggest" SRI hash helper has an exact file URL to fetch. |
| v20 | adds `bypass_img_src_data`, `bypass_font_src_data` tinyint columns to `csp_policy_profiles` for the Profiles tab's "Bypass Best Practices" toggles -- a small, hardcoded, per-surface opt-in for specific directive+token relaxations (`data:` URIs in `img-src`/`font-src`) that are safe despite being classified high-risk for automation purposes. See `Policy_Builder::BYPASS_CATALOG`. |
| v21 | adds `sam_certificates` for ACME (Let's Encrypt) certificate automation: issued certificate metadata, sealed private key, and expiry tracking for the renewal scheduler. See `Certificates\Certificate_Store`. |
| v22 | adds `bypass_style_attr_unsafe_hashes` tinyint column to `csp_policy_profiles`. Moves `'unsafe-hashes'` emission on `style-src-attr` out of automatic (previously added whenever any `style-src-attr` hash existed) and into `Policy_Builder::BYPASS_CATALOG` as its own labelled, per-surface opt-in -- a scanner-flaggable keyword, so enabling it is now a conscious admin decision rather than something the plugin decided on its own. See `docs/threat-model.md` "Bypass Best Practices catalog". |
| v23 | adds `sam_migration_snapshots`: a bounded (last 5) history of configuration-state table contents captured immediately before each forward schema migration, so an unwanted migration's data effects can be undone without reinstalling old plugin code. See `Rollback_Guard`. |
| v24 | `default_directives()` now seeds `media-src` as `['self']` instead of `['none']` -- same-origin video/audio can't execute script, and the old default broke WordPress core's native Video/Audio blocks out of the box. Migrates any existing profile whose `media-src` still exactly matches the old default; a profile an administrator has already customised is left untouched. |
| v25 | adds `bypass_flags` (JSON array of enabled `Policy_Builder::BYPASS_CATALOG` keys) to `csp_policy_profiles`, replacing the three legacy per-entry tinyint columns (`bypass_img_src_data`, `bypass_font_src_data`, `bypass_style_attr_unsafe_hashes`) -- a single column rather than one per catalog entry, so the catalog can keep growing without a schema migration for every addition. Legacy columns are converted once via `migrate_consolidate_bypass_flags_into_json()` and left in place afterwards (`dbDelta()` cannot drop columns) but are no longer read by anything. |
| v26 | adds `sam_request_events` for the Request Observation Framework (Continuous Intelligence). Ships empty -- no detector is registered yet. See `Intelligence\Event_Store`. |
| v27 | adds `sam_scanner_vendors` and `sam_scanner_identities` (Identity and Scanner Intelligence). `sam_scanner_vendors` is seeded with two built-in, FCrDNS-verified search crawlers (Googlebot, Bingbot); administrators can add their own. See `Intelligence\Scanner_Identity_Store`. |
| v28 | adds `sam_traffic_policies`, `sam_ip_rules`, and `sam_traffic_blocks` (Traffic Controls) -- the first schema supporting actively rejecting a request rather than only adding response headers. Every surface seeds in `observe` mode; nothing blocks until an administrator promotes a surface to `enforce`. See `Intelligence\Traffic_Guard`. |
| v29 | adds `sam_security_baselines`, `sam_drift_records`, and `sam_change_log` (Baseline and Drift). Ships with no baseline approved -- nothing to diff against until an administrator explicitly captures one. See `Intelligence\Baseline_State_Builder` and `Intelligence\Drift_Scanner`. |
| v30 | adds `sam_campaigns`, `sam_honeypaths`, `sam_change_windows`, and an indexed `ip` column on `sam_request_events` (campaign detection, deception/honeypaths, integrity monitoring, change-attribution timeline, and security change windows). Every new capability observes/records only by default. |
| v31 | adds `sam_tor_exit_nodes` (Tor Awareness): the Tor Project's own public bulk exit-node list, refreshed daily. Observation only -- Tor identity never implies malicious intent and nothing blocks by default. See `Intelligence\Tor_Exit_List_Store`. |
| v32 | adds `sam_asn_cache` (ASN Controls): caches Team Cymru's free, unauthenticated per-IP ASN DNS lookup so its cost is paid once per IP, not on every request. Observation only. See `Intelligence\Asn_Lookup_Store`. |
| v33 | adds `sam_geoip_cache` (Geo-IP Controls): entirely opt-in and bring-your-own-credentials -- disabled until an administrator enters their own IPinfo API token, sealed via `Credential_Vault`. Observation only; Geo-IP blocking is never enabled by default. See `Intelligence\Geo_Ip_Store`. |
| v34 | adds `sam_detector_policies` (the control-action framework): an optional per-detector admin override -- enabled/disabled, and which control action (`observe`/`enforce`) a match should trigger. A missing row means "enabled, detector's own default." See `Intelligence\Detector_Policy_Store`. |
| v35 | no new table -- bumped purely to re-run `Activator::seed_default_scanner_vendors()` on every already-upgraded site, adding GPTBot, ClaudeBot, CCBot, and PerplexityBot to the built-in `sam_scanner_vendors` catalogue. |
| v36 | adds `recent_paths` to `sam_scanner_identities`: a bounded JSON array (oldest dropped first) of an identity's recent request paths, read by `Uri_Pattern_Analyzer` to recognise sequential/enumerating access (e.g. `/product/101`, `/product/102`, `/product/103`) as a bot-classification signal. See `Intelligence\Scanner_Identity_Store`. |
| v37 | adds `sam_custom_detector_rules` (admin-authored, fail2ban-style custom regex detection rules): pattern, which request field to match it against, severity, and applicable surfaces. One row per rule; `Plugin::register_detectors()` constructs and registers a `Custom_Rule_Detector` per row on every request, flowing through the exact same `Detector_Registry`/`Detector_Policy_Store`/`Detector_Engine` pipeline every built-in detector family already uses. See `Intelligence\Custom_Rule_Store`. |

## Table list

### `csp_policy_profiles`

Purpose:

- stores per-surface CSP policy mode, directive configuration, and temporary override state

Key columns:

- `id`
- `surface` - `frontend`, `admin`, `login`, `api`
- `mode` - `disabled`, `report-only`, `enforce`
- `directives` - JSON array map of directive name → source list (e.g. `{"script-src":["'self'"],"img-src":["'self'"]}`)
- `overrides` - JSON map of admin-applied temporary directive overrides merged on top of `directives` at emit time
- `strict_dynamic` - `0` or `1`; when `1` and the `strict_dynamic` feature is licensed, `'strict-dynamic'` is appended to `script-src` and approved host sources are suppressed from `script-src` (host allowlists are silently ignored by browsers when `strict-dynamic` is present - CSP3 §8.2)
- `trusted_types` - `0` or `1`; when `1`, emits `require-trusted-types-for 'script'` (always report-only regardless of surface mode)
- `bypass_img_src_data`, `bypass_font_src_data`, `bypass_style_attr_unsafe_hashes` - legacy per-entry tinyint toggles, superseded by `bypass_flags` (schema v25). Left in place (`dbDelta()` cannot drop columns) but unread by any code after `Activator::migrate_consolidate_bypass_flags_into_json()` runs once on upgrade
- `bypass_flags` - JSON array of enabled `Policy_Builder::BYPASS_CATALOG` keys (e.g. `["img_src_data","worker_src_blob"]`) for this surface -- a single column rather than one per catalog entry, so the catalog can grow without a schema migration for every addition. See `Policy_Builder::BYPASS_CATALOG` and `docs/threat-model.md` "Bypass Best Practices catalog" for the full reasoning behind each entry. The Profiles tab only shows an entry once the surface has actually triggered it at least once (or it's already enabled) -- not every entry in the catalog is relevant to every site
- `override_expires_at` - UTC datetime at which the current override should be considered stale
- `override_owner` - identifier of the admin user who applied the override
- `created_at`, `updated_at`

Operational notes:

- seeded on activation with strict defaults (`default-src 'none'`, `object-src 'none'`, `base-uri 'none'`, etc.)
- one logical row per surface; `surface` is UNIQUE-constrained
- `strict_dynamic` should be ignored unless the `strict_dynamic` feature gate is licensed
- directives that are deprecated or removed by W3C (`plugin-types`, `block-all-mixed-content`, `navigate-to`, `prefetch-src`) are stripped from `overrides` at emit time and never appear in the emitted header

### `csp_source_inventory`

Purpose:

- stores discovered external origins that may be added to a surface's CSP policy

Key columns:

- `id`
- `surface`
- `directive` - the CSP directive this source applies to (e.g. `script-src`, `img-src`)
- `source_uri` - full URL of the discovered source
- `source_scheme` - scheme component (e.g. `https`)
- `source_host` - host component as it should appear in the CSP directive value
- `owner_component` - plugin or theme that introduced this source (if detectable)
- `owner_type` - `plugin`, `theme`, `core`, or `custom`
- `approval_state` - `pending`, `approved`, `denied`
- `first_seen_at`, `last_seen_at`
- `approved_at` - set when an admin approves the row
- `expires_at` - optional expiry; stale approved sources should be flagged for review
- `notes` - free-text admin annotation
- `risk_level` - `high`, `medium`, or `low`; computed from directive/source impact
- `risk_reason` - human-readable risk rationale
- `decision_fingerprint` - SHA-256 of `(surface, directive, source_host)` used for suppression
- `evidence_count` - number of observations of the same candidate
- `last_decision`, `decision_reason`, `decided_at`, `decided_by` - latest administrator decision metadata

Operational notes:

- discovery upserts rows by `(surface, directive, source_host)` rather than inserting duplicates
- approval state is operator-controlled only; sources are never auto-approved
- rejected and reverted fingerprints are suppressed by the latest matching row in `sam_policy_change_decisions`
- same-origin resources must not be stored as inventory rows
- only `approved` rows are included in emitted CSP headers

### `csp_hash_inventory`

Purpose:

- stores SHA-256 (or SHA-384 / SHA-512) content hashes for inline script and style blocks, enabling hash-based CSP allowlisting without `'unsafe-inline'`

Key columns:

- `id`
- `surface`
- `directive` - `script-src`, `style-src`, or `style-src-attr` (inline `style="..."` attribute values; unlike the element directives, Policy_Builder must also add `'unsafe-hashes'` to `style-src-attr` for a hash there to take effect, per CSP3 §6.1.2)
- `hash_algo` - `sha256`, `sha384`, or `sha512`
- `hash_value` - Base64-encoded hash of the raw block content
- `content_fingerprint` - `sha256(content)` hex digest; currently derived from the exact same content as `hash_value` (a different encoding of the same exact-match comparison), not a separate near-duplicate/similarity signal
- `source_file` - the request path (`REQUEST_URI`) the block was captured on, populated on insert. Output-buffer-based capture cannot recover the actual PHP template/file that echoed the block, only the page it appeared on; that's the practical starting point for triage
- `source_context` - a normalised, ~300-character excerpt of the hashed content, populated on insert, so an admin can recognise which script/style block a row corresponds to without reconstructing it from the hash alone
- `status` - `active`, `retired`
- `first_seen_at`, `last_seen_at` - `last_seen_at` is bumped (without a new row) every time identical content is seen again; a row whose `last_seen_at` stops advancing is a candidate for `Hash_Manager::prune_stale_by_age()`
- `retired_at` - set when the block is no longer observed during rescans, or pruned by age

Growth safety (added after the 2026-08-19 incident -- see `Hash_Manager::MAX_NEW_HASHES_PER_HOUR` and `Policy_Builder::MAX_HASH_TOKEN_BUDGET_BYTES`): a single surface is capped at 30 brand-new rows per rolling hour, and the header built from this table can never emit more than a fixed byte budget of hash tokens regardless of how many active rows exist, dropping the least-recently-seen ones first. `Hash_Manager::prune_stale_by_age()` (run from the daily cron scan) retires any active row not seen again within 30 days, independent of any in-request capture data.

Root cause, and the actual fix (also added after the same incident): WordPress core's own Global Styles inline stylesheet (and any theme/plugin inline `<style>` block added via `wp_add_inline_style()`) can genuinely differ in content between renders of the exact same page -- an exact-content hash allowlist can never usefully cover that, no matter how the growth-safety caps above are tuned. `Hash_Manager::inject_nonce_into_wp_inline_style_blocks()` nonces any `<style id="{handle}-inline-css">` block (WordPress's stable naming convention for `wp_add_inline_style()` output) before hash extraction runs, so that whole category of content is covered by the per-request nonce instead and never reaches `csp_hash_inventory` at all.

Operational notes:

- hashes are computed from observed inline content; there is no approval workflow because the hash already binds to exact content
- stale hashes (blocks no longer emitted) are marked `retired` during scheduled rescans
- policy construction includes only `active` hashes
- any whitespace or formatting change in the inline block produces a different hash - canonicalization at capture time is critical for stability

### `csp_violation_reports`

Purpose:

- records browser-submitted CSP violations, normalised from both the legacy `application/csp-report` format (CSP Level 2/3) and the modern `application/reports+json` format (Reporting API)

Key columns:

- `id`
- `profile_surface` - the surface that issued the policy generating this violation
- `blocked_uri` - the URL or token that was blocked
- `document_uri` - the page URL where the violation occurred
- `violated_directive` - the directive as reported in the `violated-directive` field
- `effective_directive` - the directive actually enforced (may differ from `violated_directive` due to fallback)
- `original_policy` - the full policy string active when the violation occurred
- `source_file` - file and URL containing the offending script or style
- `line_number`, `column_number`
- `status_code` - HTTP status of the document that triggered the violation
- `disposition` - `enforce` or `report`
- `referrer`
- `user_agent`
- `sample` - first ~40 characters of the offending inline block; populated only when `'report-sample'` is present in the emitting directive (legacy field: `script-sample`; Reporting API field: `sample`)
- `reported_at` - UTC datetime of first or most recent report
- `fingerprint` - SHA-256 of `(profile_surface, blocked_uri, violated_directive)` used for deduplication
- `occurrence_count` - incremented on each duplicate report

Operational notes:

- the endpoint validates `Content-Type` and rejects non-CSP payloads with HTTP 400
- the endpoint validates that `document-uri` belongs to this site's origin; cross-origin reports are silently discarded (CSP reports are client-generated and spoofable)
- duplicate reports (same fingerprint) increment `occurrence_count` rather than inserting new rows
- rows are purged automatically after `wp_sam_violation_retention_days` days (default: 90) by the daily cron scan; set to `0` to disable purging

#### v6 roll-up columns and migration

Schema v6 adds `first_reported_at` and `last_reported_at` to `csp_violation_reports`, backfills them from `reported_at`, collapses historic duplicate fingerprints, and converts `fingerprint` to a unique key where required. Duplicate reports increment `occurrence_count` and update the latest timestamp rather than inserting additional rows.

### `sam_scan_logs`

Purpose:

- records the execution history of scheduled and manual policy rescans

Key columns:

- `id`
- `trigger_type` - `manual`, `cron`
- `status` - `running`, `completed`, `failed`
- `sources_added`, `sources_removed` - count of source inventory changes
- `hashes_added`, `hashes_removed` - count of hash inventory changes
- `policy_changed` - `0` or `1`; set when the scan altered the effective policy
- `diff_summary` - JSON summary of specific policy changes for operator review
- `warnings` - JSON array of non-fatal issues encountered during the scan
- `started_at`
- `completed_at`

Operational notes:

- used for operator auditability and troubleshooting
- `diff_summary` and `warnings` should remain compact enough for admin rendering
- a `running` row with no `completed_at` may indicate a stuck or killed cron job

### `sam_entitlements`

Purpose:

- stores site-local premium licence state granted after verified Stripe webhook delivery

Key columns:

- `id`
- `site_identity` - truncated SHA-256 hash of the site URL; binds the entitlement to a specific WordPress install
- `product_key` - identifies the premium product tier (e.g. `csp-automation-manager`, the stable identifier `Feature_Gate::PRODUCT_KEY` uses -- retained from the plugin's pre-rename name so existing entitlement rows keep matching after the display-name change)
- `tier` - `free`, `pro`
- `status` - `active`, `revoked`, `expired`, `grace`
- `stripe_customer_id`, `stripe_session_id`, `stripe_payment_intent_id`
- `config_version` - the remote config version active at grant time
- `granted_at`
- `expires_at` - if populated, entitlement expires at this UTC datetime
- `revoked_at`, `revocation_reason`
- `grace_until` - deadline before `grace` status downgrades to `expired`
- `last_validated_at`
- `created_at`, `updated_at`

Operational notes:

- feature checks use this table only and must not make network calls during page rendering
- grace handling is based on `last_validated_at` plus the configured grace hours option
- `stripe_session_id` is UNIQUE-constrained to prevent duplicate grants from webhook retries

### `sam_processed_events`

Purpose:

- stores processed Stripe webhook event IDs for idempotency; prevents duplicate entitlement logic on webhook retries

Key columns:

- `id`
- `stripe_event_id` - Stripe-assigned event identifier; UNIQUE-constrained
- `stripe_session_id` - Checkout Session ID if applicable
- `event_type` - the Stripe event type (e.g. `checkout.session.completed`)
- `processed_at`
- `outcome` - `granted`, `revoked`, `ignored`, `error`
- `detail` - short human-readable description for support and debugging

Operational notes:

- before processing any webhook event, the handler checks this table and skips if the `stripe_event_id` is already present
- outcome strings should remain stable to support log triage

### `sam_audit_log`

Purpose:

- append-only structured log of all significant plugin events (policy changes, scan results, override grants, webhook processing, config failures, and forbidden-directive suppression)

Key columns:

- `id`
- `component` - originating module (e.g. `policy_builder`, `webhook`, `scheduler`, `config_resolver`)
- `event` - machine-readable event type (e.g. `forbidden_directive_stripped`, `signature_failed`, `violations_purged`)
- `detail` - human-readable description
- `severity` - `info`, `warning`, `error`
- `user_id` - WordPress user ID of the logged-in admin who triggered the event, if applicable
- `created_at` - UTC datetime

Operational notes:

- **this table is strictly append-only** - no `UPDATE` or `DELETE` is ever issued against it; it is the permanent, immutable audit trail
- `warning` and `error` events are additionally written to the PHP `error_log` and pushed to the admin notices FIFO queue (max 20 entries) for transient display
- events are written before the associated action completes where possible, so that failures are always recorded

### `sam_policy_change_decisions`

Purpose:

- records administrator decisions for CSP source proposals and determines whether future automation should suppress the same source fingerprint

Key columns:

- `id`
- `change_type` - currently `source`
- `surface`
- `directive`
- `source_host`, `source_uri`
- `decision_fingerprint` - SHA-256 of `(surface, directive, source_host)`
- `action` - `approved`, `rejected`, `reverted`, or `undone`
- `risk_level`, `risk_reason`
- `reason` - required administrator-provided decision note
- `user_id`
- `state` - explicit lifecycle state such as `approved`, `rejected`, `reverted`, or `pending` for an undone decision
- `actor_type`, `actor_id` - final decision actor metadata; AI providers are recommendation sources, not actors
- `previous_policy_version_id`, `policy_version_id` - policy snapshot references when the decision materially changes policy
- `decision_engine_version`, `deterministic_result` - versioned deterministic rule output
- `evidence_snapshot` - compact source inventory evidence present when the decision was made
- `software_version`
- `suppression_active` - `1` when this decision suppresses future proposals for the fingerprint
- `created_at`

Operational notes:

- this table is append-only; do not update or delete prior decisions
- the latest row for a `decision_fingerprint` controls suppression state
- approving a previously rejected source or undoing a prior approval/rejection appends a new non-suppressing decision, making that action the latest decision
- rejecting or reverting a source marks the source row denied and appends a suppressing decision

### `sam_policy_versions`

Purpose:

- stores append-oriented snapshots of the effective policy for each surface after material policy decisions

Key columns:

- `id`
- `surface`
- `version_number`
- `mode`
- `effective_header`
- `policy_snapshot` - JSON snapshot containing directives, approved sources, active hashes, and metadata
- `previous_version_id`
- `trigger_type`, `trigger_id`
- `software_version`
- `created_at`

Operational notes:

- rollback must create a new policy version instead of deleting or rewriting prior versions
- snapshots are used by the audit UI and REST API to show policy history and diffs

### `sam_decision_rule_evaluations`

Purpose:

- records the deterministic rule path used for a proposal or final decision

Key columns:

- `id`
- `proposal_id`
- `decision_id`
- `engine_version`
- `rule_id`, `rule_version`
- `result`
- `risk_effect`
- `automation_effect`
- `explanation`
- `created_at`

Operational notes:

- rule IDs are stable product identifiers such as `CSP-SRC-003`
- these rows explain why a proposal was eligible, blocked, or required administrator review

### `sam_pillar_profiles`

Purpose:

- per-surface configuration for header pillars that don't need CSP's directive/override/strict-dynamic shape

Key columns:

- `id`
- `pillar` - e.g. `x-frame-options`, `x-content-type-options`, `referrer-policy`
- `surface` - `frontend` | `admin` | `login` | `api`
- `enabled`
- `payload` - JSON, shape is pillar-specific (e.g. `{"value": "SAMEORIGIN"}`); the column is `NOT NULL`, so a pillar with no configurable value (e.g. X-Content-Type-Options) must still store valid JSON such as `{}` rather than an empty string
- `override_expires_at`, `override_owner`
- `created_at`, `updated_at`

Operational notes:

- unique on `(pillar, surface)` - one row per pillar per surface
- added in v10; empty and unused until X-Frame-Options, X-Content-Type-Options, and Referrer-Policy ship

## Relationships

The schema is intentionally loose and operational rather than deeply relational.

Primary runtime relationships:

- `csp_policy_profiles.surface` is joined logically with `csp_source_inventory.surface`, `csp_hash_inventory.surface`, and `csp_violation_reports.profile_surface`
- `sam_entitlements.site_identity` represents the active licence state for the local install
- `sam_processed_events.stripe_event_id` gates whether a Stripe event can mutate entitlements
- `sam_audit_log` is not joined to other tables; it records events by component name
- `sam_policy_change_decisions.decision_fingerprint` controls whether discovery or report learning may propose the same source again
- `sam_policy_change_decisions.policy_version_id` links a decision to the resulting `sam_policy_versions` snapshot when applicable
- `sam_decision_rule_evaluations.decision_id` links deterministic rule findings to final decisions

## Index guidance

The following fields are indexed or uniquely constrained in the activation SQL:

- `csp_source_inventory`: `surface`, `directive`, `approval_state`, `risk_level`, `last_seen_at`, `source_host`; UNIQUE on `(surface, directive, source_host)`
- `csp_hash_inventory`: `surface`, `directive`, `status`; UNIQUE on `(directive, hash_value)`
- `csp_violation_reports`: `profile_surface`, `violated_directive`, `fingerprint`, `reported_at`, `last_reported_at`, `occurrence_count`
- `sam_scan_logs`: `status`, `trigger_type`
- `sam_entitlements`: `site_identity`, `product_key`, `status`; UNIQUE on `stripe_session_id`
- `sam_processed_events`: UNIQUE on `stripe_event_id`; index on `stripe_session_id`
- `sam_audit_log`: `severity`, `created_at`
- `sam_policy_change_decisions`: `decision_fingerprint`, `action`, `risk_level`, `suppression_active`, `created_at`
- `sam_policy_versions`: UNIQUE on `(surface, version_number)`, indexes on `surface`, `previous_version_id`, `trigger_type/trigger_id`, `created_at`
- `sam_decision_rule_evaluations`: `proposal_id`, `decision_id`, `rule_id`, `created_at`

If performance issues appear under high violation volume, first review:

- `csp_violation_reports(fingerprint)` - fingerprint lookup on every report ingestion
- `csp_violation_reports(reported_at)` - used by the daily purge query
- `csp_source_inventory(surface, approval_state)` - scanned on every header build
- `csp_hash_inventory(surface, directive, status)` - scanned on every header build
- `sam_entitlements(site_identity, product_key)` - checked on every feature gate call

## Migration rules

Whenever schema changes are introduced:

1. Increment `WP_SAM_DB_VERSION` in `security-automation-manager.php`.
2. Update the `CREATE TABLE` SQL in `includes/class-activator.php`. `dbDelta()` handles adding new columns and new tables; it cannot drop columns or change column types.
3. Add explicit upgrade logic in `Plugin::maybe_upgrade_db()` for any change that `dbDelta()` cannot handle automatically.
4. Update this document, the version table at the top of this file, and `CHANGELOG.md`.
5. Test activation on a fresh install and the `maybe_upgrade_db()` path on an existing install.

## Data lifecycle

### Created on activation

- all plugin tables are created if absent
- default settings and default per-surface policy profiles are seeded
- the `wp_sam_db_version` option is set to `WP_SAM_DB_VERSION`

### Updated during runtime

- profiles mutate through admin actions and scheduled scans
- source inventory and hashes mutate through scans
- violation reports are upserted from browser-submitted reports; old rows are purged by the daily cron
- entitlements mutate through verified Stripe webhooks
- processed events are appended per webhook receipt
- `sam_audit_log` is appended to by all significant plugin operations; never mutated in place
- `sam_policy_change_decisions` is appended to whenever an administrator approves, rejects, or reverts a source proposal
- `sam_policy_versions` is appended to for approved and reverted source decisions
- `sam_decision_rule_evaluations` is appended to for decision rule provenance

### Removed on uninstall

- all plugin tables are dropped
- all `wp_sam_*` options are deleted
- plugin transients are deleted
- scheduled cron events are cleared

## Operational risks

| Risk | Mitigation |
|------|-----------|
| High-volume violation reports filling the table | Automatic purge of rows older than `wp_sam_violation_retention_days` days (default 90) runs after every daily cron scan. Per-surface transient rate limiting (500 reports/hour) throttles ingestion. |
| Large source inventories on plugin-heavy installs | Review and deny unnecessary pending sources regularly. Expired approved sources are flagged automatically. |
| Stale entitlements if webhook setup is broken | Grace period allows continued access during transient Stripe outages; surfaced via audit log warnings. |
| Stale remote config if DNS or HTTPS endpoint is neglected | Grace-copy fallback serves the last verified config until the grace TTL expires; audit log warning is emitted. |
| Forbidden directives injected via overrides | `Policy_Builder::build_policy_string()` strips `plugin-types`, `block-all-mixed-content`, `navigate-to`, and `prefetch-src` from overrides at emit time and logs a warning to `sam_audit_log`. |
