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
| v11 | adds `bypass_img_src_data`, `bypass_font_src_data` tinyint columns to `csp_policy_profiles` for the Profiles tab's "Bypass Best Practices" toggles -- a small, hardcoded, per-surface opt-in for specific directive+token relaxations (`data:` URIs in `img-src`/`font-src`) that are safe despite being classified high-risk for automation purposes. See `Policy_Builder::BYPASS_CATALOG`. |
| v12 | adds `bypass_style_attr_unsafe_hashes` tinyint column to `csp_policy_profiles`. Moves `'unsafe-hashes'` emission on `style-src-attr` out of automatic (previously added whenever any `style-src-attr` hash existed) and into `Policy_Builder::BYPASS_CATALOG` as its own labelled, per-surface opt-in -- a scanner-flaggable keyword, so enabling it is now a conscious admin decision rather than something the plugin decided on its own. See `docs/threat-model.md` "Bypass Best Practices catalog". |

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
- `bypass_img_src_data`, `bypass_font_src_data` - `0` or `1`; per-surface "Bypass Best Practices" toggles that append `data:` to `img-src`/`font-src` respectively (low risk: never extended to a directive where a `data:`/`blob:` source has real execution risk)
- `bypass_style_attr_unsafe_hashes` - `0` or `1`; per-surface toggle that appends `'unsafe-hashes'` to `style-src-attr` (medium risk: only takes effect together with an approved `style-src-attr` hash; never affects `script-src-attr` or script execution). See `Policy_Builder::BYPASS_CATALOG` and `docs/threat-model.md` "Bypass Best Practices catalog" for the full reasoning behind each entry
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
- `content_fingerprint` - deterministic fingerprint of the raw content used for deduplication and change detection
- `source_file` - the template or PHP file that emits this block, if detectable
- `source_context` - optional surrounding context for operator review
- `status` - `active`, `retired`
- `first_seen_at`, `last_seen_at`
- `retired_at` - set when the block is no longer observed during rescans

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
- `product_key` - identifies the premium product tier (e.g. `security-automation-manager`)
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
