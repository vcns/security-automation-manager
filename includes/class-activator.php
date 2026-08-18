<?php
/**
 * Fired during plugin activation.
 * Creates custom database tables, seeds default option values, and
 * schedules the daily rescan cron event.
 *
 * Schema version 2 adds override_expires_at and override_owner to
 * csp_policy_profiles to support the full promotion gate checks (§4.12).
 */

declare( strict_types=1 );

namespace WP_SAM;

use WP_SAM\CSP\Automation_Config;
use WP_SAM\CSP\Violation_Reporter;
use WP_SAM\Security\Cross_Origin_Embedder_Policy_Builder;
use WP_SAM\Security\Cross_Origin_Opener_Policy_Builder;
use WP_SAM\Security\Cross_Origin_Resource_Policy_Builder;
use WP_SAM\Security\Permissions_Policy_Builder;
use WP_SAM\Security\Referrer_Policy_Builder;
use WP_SAM\Security\Reverse_Tabnabbing_Builder;
use WP_SAM\Security\X_Content_Type_Options_Builder;
use WP_SAM\Security\X_Frame_Options_Builder;
use WP_SAM\Security\X_Permitted_Cross_Domain_Policies_Builder;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Activator {

	public static function activate(): void {
		self::create_tables();
		self::migrate_v9_option_renames();
		self::migrate_remove_fenced_frame_src_directive();
		self::migrate_tighten_img_src_default();
		self::set_default_options();
		self::seed_default_profiles();
		self::seed_default_pillar_profiles();
		self::seed_initial_policy_versions();
		self::schedule_events();
		self::mark_schema_verified();
	}

	/**
	 * Schema v9: migrates option values stored under the pre-rename wp_csp_
	 * prefix to the new wp_sam_ prefix (e.g. wp_csp_automation_config ->
	 * wp_sam_automation_config), so upgrading sites keep their configured
	 * automation posture, report endpoint, cron hour, and other settings
	 * instead of silently reverting to defaults. Copies the value and leaves
	 * the old option in place (harmless leftover, not read by anything after
	 * this migration); only copies when the new key isn't already set, so
	 * this is safe to run on every activation.
	 */
	private static function migrate_v9_option_renames(): void {
		foreach ( self::get_option_names() as $new_key ) {
			$old_key = 'wp_csp_' . substr( $new_key, strlen( 'wp_sam_' ) );
			if ( $old_key === $new_key || false !== get_option( $new_key, false ) ) {
				continue;
			}

			$old_value = get_option( $old_key, false );
			if ( false !== $old_value ) {
				add_option( $new_key, $old_value );
			}
		}
	}

	/**
	 * Schema v12: fenced-frame-src is no longer part of default_directives() --
	 * it's an experimental Privacy Sandbox directive, not the CSP living
	 * standard, and real-world CSP linters commonly flag it as "should not be
	 * used". default_directives() only affects newly-seeded profiles, so a
	 * site whose csp_policy_profiles rows were seeded before this change would
	 * otherwise keep emitting it forever. Strips the key from every existing
	 * profile's stored directives JSON; a no-op for a profile that already had
	 * it removed. Runs after create_tables() in activate(), so the table is
	 * always present by the time this executes -- no existence guard needed.
	 */
	private static function migrate_remove_fenced_frame_src_directive(): void {
		global $wpdb;
		$table = $wpdb->prefix . 'csp_policy_profiles';

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.NotPrepared
		$rows = $wpdb->get_results( "SELECT id, directives FROM {$table}", ARRAY_A );
		foreach ( ! empty( $rows ) ? $rows : array() as $row ) {
			$directives = json_decode( (string) $row['directives'], true );
			if ( ! is_array( $directives ) || ! array_key_exists( 'fenced-frame-src', $directives ) ) {
				continue;
			}

			unset( $directives['fenced-frame-src'] );
			$wpdb->update(
				$table,
				array( 'directives' => wp_json_encode( $directives ) ),
				array( 'id' => (int) $row['id'] ),
				array( '%s' ),
				array( '%d' )
			);
		}
	}

	/**
	 * Schema v17: default_directives() no longer includes data: in img-src --
	 * data: URIs can't execute active content so the risk was always low, but
	 * a site that never customised this directive gets a tighter default.
	 * default_directives() only affects newly-seeded profiles, so this strips
	 * 'data:' from any existing profile's stored img-src, but ONLY when it
	 * still exactly matches the old default (['self', 'data:']) -- a profile
	 * an administrator has already customised (added a CDN, removed 'self',
	 * whatever) is left untouched, since there's no way to tell their
	 * customisation apart from the old default by value alone once it
	 * diverges. Runs after create_tables() in activate(), so the table is
	 * always present by the time this executes -- no existence guard needed.
	 */
	private static function migrate_tighten_img_src_default(): void {
		global $wpdb;
		$table = $wpdb->prefix . 'csp_policy_profiles';

		$old_default = array( "'self'", 'data:' );

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.NotPrepared
		$rows = $wpdb->get_results( "SELECT id, directives FROM {$table}", ARRAY_A );
		foreach ( ! empty( $rows ) ? $rows : array() as $row ) {
			$directives = json_decode( (string) $row['directives'], true );
			if ( ! is_array( $directives ) || ! array_key_exists( 'img-src', $directives ) ) {
				continue;
			}
			if ( $directives['img-src'] !== $old_default ) {
				continue;
			}

			$directives['img-src'] = array( "'self'" );
			$wpdb->update(
				$table,
				array( 'directives' => wp_json_encode( $directives ) ),
				array( 'id' => (int) $row['id'] ),
				array( '%s' ),
				array( '%d' )
			);
		}
	}

	public static function get_missing_table_names(): array {
		global $wpdb;

		$missing = array();
		foreach ( self::get_table_suffixes() as $suffix ) {
			$table = $wpdb->prefix . $suffix;
			if ( ! self::table_exists( $table ) ) {
				$missing[] = $table;
			}
		}

		return $missing;
	}

	public static function get_table_suffixes(): array {
		return array(
			'csp_policy_profiles',
			'csp_source_inventory',
			'csp_hash_inventory',
			'csp_violation_reports',
			'sam_scan_logs',
			'sam_entitlements',
			'sam_processed_events',
			'sam_audit_log',
			'sam_policy_change_decisions',
			'sam_policy_versions',
			'sam_decision_rule_evaluations',
			'sam_pillar_profiles',
			'sam_dependency_inventory',
			'sam_pillar_violation_reports',
			'sam_internal_asset_inventory',
			'sam_certificates',
		);
	}

	public static function get_option_names(): array {
		return array(
			'wp_sam_db_version',
			'wp_sam_enforce_gate_violation_window',
			'wp_sam_cron_hour',
			'wp_sam_notify_email',
			'wp_sam_violation_retention_days',
			'wp_sam_learning_window_hours',
			'wp_sam_policy_header_name',
			'wp_sam_report_endpoint_url',
			'wp_sam_reporting_transport',
			'wp_sam_schema_verified_version',
			'wp_sam_last_material_change_at',
			'wp_sam_automation_config',
			'wp_sam_admin_notices',
			'wp_sam_conflict_dismissed_at',
			'wp_sam_cert_config',
			'wp_sam_acme_account_keys',
			'wp_sam_acme_http_tokens',
			'wp_sam_cert_last_run',
			// Stripe configuration for the (commercial-build-only) Fully
			// Automatic checkout flow -- see Checkout_Service and
			// Webhook_Controller in offline/modules/.
			'wp_sam_stripe_mode',
			'wp_sam_stripe_secret_key_test',
			'wp_sam_stripe_secret_key_live',
			'wp_sam_stripe_price_id_monthly_test',
			'wp_sam_stripe_price_id_annual_test',
			'wp_sam_stripe_price_id_monthly_live',
			'wp_sam_stripe_price_id_annual_live',
			'wp_sam_webhook_secret',
		);
	}

	public static function get_transient_names(): array {
		return array(
			'wp_sam_conflict_probe_ran',
		);
	}

	// ── Database tables ───────────────────────────────────────────────────────

	private static function create_tables(): void {
		global $wpdb;
		require_once ABSPATH . 'wp-admin/includes/upgrade.php';

		self::migrate_v9_table_renames();

		$cc = $wpdb->get_charset_collate();
		$p  = $wpdb->prefix;

		// 1. Per-surface CSP policy profiles
		// v2: adds override_expires_at and override_owner for promotion gate §4.12.
		dbDelta(
			"CREATE TABLE {$p}csp_policy_profiles (
  id bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT,
  surface varchar(32) NOT NULL,
  mode varchar(16) NOT NULL DEFAULT 'report-only',
  directives longtext NOT NULL,
  overrides longtext NOT NULL,
  strict_dynamic tinyint(1) NOT NULL DEFAULT 0,
  trusted_types tinyint(1) NOT NULL DEFAULT 0,
  bypass_img_src_data tinyint(1) NOT NULL DEFAULT 0,
  bypass_font_src_data tinyint(1) NOT NULL DEFAULT 0,
  bypass_style_attr_unsafe_hashes tinyint(1) NOT NULL DEFAULT 0,
  override_expires_at datetime DEFAULT NULL,
  override_owner varchar(255) DEFAULT NULL,
  created_at datetime NOT NULL,
  updated_at datetime NOT NULL,
  PRIMARY KEY  (id),
  UNIQUE KEY surface (surface)
) {$cc};"
		);

		// 2. Discovered / approved external source URLs
		dbDelta(
			"CREATE TABLE {$p}csp_source_inventory (
  id bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT,
  surface varchar(32) NOT NULL,
  directive varchar(64) NOT NULL,
  source_uri varchar(2048) NOT NULL,
  source_scheme varchar(16) NOT NULL,
  source_host varchar(255) NOT NULL,
  owner_component varchar(255) DEFAULT NULL,
  owner_type varchar(32) DEFAULT NULL,
  approval_state varchar(16) NOT NULL DEFAULT 'pending',
  first_seen_at datetime NOT NULL,
  last_seen_at datetime NOT NULL,
  approved_at datetime DEFAULT NULL,
  expires_at datetime DEFAULT NULL,
  notes text DEFAULT NULL,
  risk_level varchar(16) NOT NULL DEFAULT 'low',
  risk_reason text DEFAULT NULL,
  decision_fingerprint varchar(64) DEFAULT NULL,
  evidence_count int(11) NOT NULL DEFAULT 1,
  last_decision varchar(16) DEFAULT NULL,
  decision_reason text DEFAULT NULL,
  decided_at datetime DEFAULT NULL,
  decided_by bigint(20) UNSIGNED DEFAULT NULL,
  PRIMARY KEY  (id),
  KEY surface (surface),
  KEY directive (directive),
  KEY approval_state (approval_state),
  KEY risk_level (risk_level),
  KEY decision_fingerprint (decision_fingerprint),
  KEY last_seen_at (last_seen_at),
  KEY source_host (source_host(191)),
  UNIQUE KEY surf_dir_host (surface, directive, source_host(191))
) {$cc};"
		);

		// 3. Inline script/style SHA-256 hashes
		dbDelta(
			"CREATE TABLE {$p}csp_hash_inventory (
  id bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT,
  surface varchar(32) NOT NULL,
  directive varchar(64) NOT NULL,
  hash_algo varchar(16) NOT NULL DEFAULT 'sha256',
  hash_value varchar(128) NOT NULL,
  content_fingerprint varchar(64) NOT NULL,
  source_file varchar(512) DEFAULT NULL,
  source_context text DEFAULT NULL,
  status varchar(16) NOT NULL DEFAULT 'active',
  first_seen_at datetime NOT NULL,
  last_seen_at datetime NOT NULL,
  retired_at datetime DEFAULT NULL,
  PRIMARY KEY  (id),
  KEY surface (surface),
  KEY directive (directive),
  KEY status (status),
  UNIQUE KEY hash_uniq (directive, hash_value)
) {$cc};"
		);

		// 4. Ingested CSP violation reports
		// v3: adds sample column — populated only when 'report-sample' is in the policy.
		// v6: adds first/last roll-up timestamps and unique fingerprint support.
		// v8: adds occurrence_count index for the sortable Violations dashboard tab.
		dbDelta(
			"CREATE TABLE {$p}csp_violation_reports (
  id bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT,
  profile_surface varchar(32) NOT NULL,
  blocked_uri varchar(2048) NOT NULL,
  blocked_host varchar(255) DEFAULT NULL,
  document_uri varchar(2048) DEFAULT NULL,
  violated_directive varchar(128) NOT NULL,
  effective_directive varchar(128) DEFAULT NULL,
  original_policy text DEFAULT NULL,
  source_file varchar(512) DEFAULT NULL,
  line_number int(11) DEFAULT NULL,
  column_number int(11) DEFAULT NULL,
  status_code smallint(6) DEFAULT NULL,
  disposition varchar(16) NOT NULL DEFAULT 'report',
  referrer varchar(2048) DEFAULT NULL,
  user_agent varchar(512) DEFAULT NULL,
  sample varchar(256) DEFAULT NULL,
  reported_at datetime NOT NULL,
  first_reported_at datetime DEFAULT NULL,
  last_reported_at datetime DEFAULT NULL,
  fingerprint varchar(64) NOT NULL,
  occurrence_count int(11) NOT NULL DEFAULT 1,
  PRIMARY KEY  (id),
  KEY profile_surface (profile_surface),
  KEY violated_directive (violated_directive),
  KEY reported_at (reported_at),
  KEY last_reported_at (last_reported_at),
  KEY occurrence_count (occurrence_count),
  KEY blocked_host (blocked_host),
  UNIQUE KEY fingerprint (fingerprint)
) {$cc};"
		);

		self::migrate_dedupe_violation_reports_by_host();

		self::migrate_violation_report_rollups();

		// 5. Scan / rescan run history
		dbDelta(
			"CREATE TABLE {$p}sam_scan_logs (
  id bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT,
  trigger_type varchar(16) NOT NULL,
  status varchar(16) NOT NULL DEFAULT 'running',
  sources_added int(11) NOT NULL DEFAULT 0,
  sources_removed int(11) NOT NULL DEFAULT 0,
  hashes_added int(11) NOT NULL DEFAULT 0,
  hashes_removed int(11) NOT NULL DEFAULT 0,
  policy_changed tinyint(1) NOT NULL DEFAULT 0,
  diff_summary text DEFAULT NULL,
  warnings text DEFAULT NULL,
  started_at datetime NOT NULL,
  completed_at datetime DEFAULT NULL,
  PRIMARY KEY  (id),
  KEY status (status),
  KEY trigger_type (trigger_type)
) {$cc};"
		);

		// 6. Legacy per-site entitlement compatibility records.
		dbDelta(
			"CREATE TABLE {$p}sam_entitlements (
  id bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT,
  site_identity varchar(255) NOT NULL,
  product_key varchar(64) NOT NULL,
  tier varchar(32) NOT NULL DEFAULT 'free',
  status varchar(16) NOT NULL DEFAULT 'active',
  stripe_customer_id varchar(64) DEFAULT NULL,
  stripe_session_id varchar(255) DEFAULT NULL,
  stripe_payment_intent_id varchar(255) DEFAULT NULL,
  config_version varchar(32) DEFAULT NULL,
  granted_at datetime NOT NULL,
  expires_at datetime DEFAULT NULL,
  revoked_at datetime DEFAULT NULL,
  revocation_reason varchar(255) DEFAULT NULL,
  grace_until datetime DEFAULT NULL,
  last_validated_at datetime DEFAULT NULL,
  created_at datetime NOT NULL,
  updated_at datetime NOT NULL,
  PRIMARY KEY  (id),
  KEY site_identity (site_identity(191)),
  KEY product_key (product_key),
  KEY status (status),
  UNIQUE KEY session_id (stripe_session_id)
) {$cc};"
		);

		// 7. Legacy external event idempotency log.
		dbDelta(
			"CREATE TABLE {$p}sam_processed_events (
  id bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT,
  stripe_event_id varchar(255) NOT NULL,
  stripe_session_id varchar(255) DEFAULT NULL,
  event_type varchar(128) NOT NULL,
  processed_at datetime NOT NULL,
  outcome varchar(16) NOT NULL,
  detail varchar(512) DEFAULT NULL,
  PRIMARY KEY  (id),
  UNIQUE KEY stripe_event_id (stripe_event_id),
  KEY stripe_session_id (stripe_session_id)
) {$cc};"
		);

		// 8. Append-only structured audit log (R10).
		// No UPDATE or DELETE is ever issued against this table — it is an immutable record.
		dbDelta(
			"CREATE TABLE {$p}sam_audit_log (
  id bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT,
  component varchar(64) NOT NULL,
  event varchar(128) NOT NULL,
  detail text DEFAULT NULL,
  severity varchar(16) NOT NULL DEFAULT 'info',
  user_id bigint(20) UNSIGNED DEFAULT NULL,
  created_at datetime NOT NULL,
  PRIMARY KEY  (id),
  KEY severity (severity),
  KEY created_at (created_at)
) {$cc};"
		);

		// 9. Append-only policy change decision ledger.
		// v7 extends this with provenance fields; existing action/suppression semantics remain authoritative.
		dbDelta(
			"CREATE TABLE {$p}sam_policy_change_decisions (
  id bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT,
  change_type varchar(32) NOT NULL DEFAULT 'source',
  source_inventory_id bigint(20) UNSIGNED DEFAULT NULL,
  surface varchar(32) NOT NULL,
  directive varchar(64) NOT NULL,
  source_host varchar(255) DEFAULT NULL,
  source_uri varchar(2048) DEFAULT NULL,
  decision_fingerprint varchar(64) NOT NULL,
  action varchar(16) NOT NULL,
  state varchar(24) NOT NULL DEFAULT '',
  risk_level varchar(16) NOT NULL DEFAULT 'low',
  risk_reason text DEFAULT NULL,
  reason text DEFAULT NULL,
  user_id bigint(20) UNSIGNED DEFAULT NULL,
  actor_type varchar(32) NOT NULL DEFAULT 'administrator',
  actor_id varchar(64) DEFAULT NULL,
  previous_policy_version_id bigint(20) UNSIGNED DEFAULT NULL,
  policy_version_id bigint(20) UNSIGNED DEFAULT NULL,
  decision_engine_version varchar(32) DEFAULT NULL,
  deterministic_result longtext DEFAULT NULL,
  evidence_snapshot longtext DEFAULT NULL,
  reverted_decision_id bigint(20) UNSIGNED DEFAULT NULL,
  software_version varchar(32) DEFAULT NULL,
  suppression_active tinyint(1) NOT NULL DEFAULT 0,
  created_at datetime NOT NULL,
  PRIMARY KEY  (id),
  KEY source_inventory_id (source_inventory_id),
  KEY decision_fingerprint (decision_fingerprint),
  KEY action (action),
  KEY state (state),
  KEY actor_type (actor_type),
  KEY policy_version_id (policy_version_id),
  KEY risk_level (risk_level),
  KEY suppression_active (suppression_active),
  KEY created_at (created_at)
) {$cc};"
		);

		// 10. Immutable policy version snapshots per surface.
		dbDelta(
			"CREATE TABLE {$p}sam_policy_versions (
  id bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT,
  surface varchar(32) NOT NULL,
  version_number bigint(20) UNSIGNED NOT NULL,
  mode varchar(16) NOT NULL DEFAULT 'report-only',
  effective_header longtext NOT NULL,
  policy_snapshot longtext NOT NULL,
  previous_version_id bigint(20) UNSIGNED DEFAULT NULL,
  trigger_type varchar(32) NOT NULL DEFAULT 'system',
  trigger_id bigint(20) UNSIGNED DEFAULT NULL,
  software_version varchar(32) DEFAULT NULL,
  created_at datetime NOT NULL,
  PRIMARY KEY  (id),
  UNIQUE KEY surface_version (surface, version_number),
  KEY surface (surface),
  KEY previous_version_id (previous_version_id),
  KEY trigger_lookup (trigger_type, trigger_id),
  KEY created_at (created_at)
) {$cc};"
		);

		// 11. Deterministic rule evaluation provenance.
		dbDelta(
			"CREATE TABLE {$p}sam_decision_rule_evaluations (
  id bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT,
  proposal_id bigint(20) UNSIGNED DEFAULT NULL,
  decision_id bigint(20) UNSIGNED DEFAULT NULL,
  engine_version varchar(32) NOT NULL,
  rule_id varchar(32) NOT NULL,
  rule_version varchar(16) NOT NULL,
  result varchar(16) NOT NULL,
  risk_effect varchar(16) DEFAULT NULL,
  automation_effect varchar(32) DEFAULT NULL,
  explanation text DEFAULT NULL,
  created_at datetime NOT NULL,
  PRIMARY KEY  (id),
  KEY proposal_id (proposal_id),
  KEY decision_id (decision_id),
  KEY rule_id (rule_id),
  KEY created_at (created_at)
) {$cc};"
		);

		// 12. Per-surface profiles for pillars simple enough not to need CSP's
		// directive/override/strict-dynamic shape (X-Frame-Options,
		// X-Content-Type-Options, Referrer-Policy, and future pillars).
		// payload is NOT NULL: writers must always store valid JSON, e.g. '{}'
		// for a pillar with no configurable value (X-Content-Type-Options).
		// pillar is varchar(48), not (32): X_Permitted_Cross_Domain_Policies_Builder::PILLAR_KEY
		// ('x-permitted-cross-domain-policies') is 33 characters, one over a
		// 32-length column. Under strict SQL mode the INSERT in
		// Admin_UI::ajax_set_pillar_value() silently failed for every toggle
		// on that one pillar; without strict mode it was truncated to a
		// different string than the constant, so it could never be read back
		// by key -- the Overview table always showed it as "Off" no matter
		// what was saved. 48 leaves headroom for future pillar keys longer
		// than today's.
		dbDelta(
			"CREATE TABLE {$p}sam_pillar_profiles (
  id bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT,
  pillar varchar(48) NOT NULL,
  surface varchar(32) NOT NULL,
  enabled tinyint(1) NOT NULL DEFAULT 0,
  payload longtext NOT NULL,
  override_expires_at datetime DEFAULT NULL,
  override_owner varchar(255) DEFAULT NULL,
  created_at datetime NOT NULL,
  updated_at datetime NOT NULL,
  PRIMARY KEY  (id),
  UNIQUE KEY pillar_surface (pillar, surface)
) {$cc};"
		);

		// 13. Passive inventory of third-party <script src> / <link rel=stylesheet>
		// origins observed on real page loads (never a dedicated crawl or extra
		// request). Deduplication stays at the origin (scheme+host) level --
		// unchanged -- so a CDN serving content-hashed filenames still collapses
		// to one row per origin rather than a permanent row per file variant.
		// classification defaults to 'unclassified': a fresh discovery is
		// neither trusted nor blocked until an administrator decides, matching
		// this plugin's report-first philosophy everywhere else. expected_sri is
		// admin-supplied only -- this plugin never fetches a remote resource to
		// compute a hash itself.
		// v19: adds last_seen_url -- the most recently observed full URL (path
		// and query included) for this origin. Needed because the "Suggest"
		// hash helper (ajax_suggest_dependency_sri()) fetches a real file and
		// computes its hash for review, which requires an exact file URL, not
		// just an origin -- previously the administrator had to already know
		// or go find that URL themselves before they could use Suggest at all.
		dbDelta(
			"CREATE TABLE {$p}sam_dependency_inventory (
  id bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT,
  surface varchar(32) NOT NULL,
  resource_type varchar(16) NOT NULL,
  origin varchar(255) NOT NULL,
  classification varchar(32) NOT NULL DEFAULT 'unclassified',
  expected_sri varchar(128) DEFAULT NULL,
  last_seen_url varchar(2048) DEFAULT NULL,
  evidence_count bigint(20) UNSIGNED NOT NULL DEFAULT 1,
  first_seen_at datetime NOT NULL,
  last_seen_at datetime NOT NULL,
  created_at datetime NOT NULL,
  updated_at datetime NOT NULL,
  PRIMARY KEY  (id),
  UNIQUE KEY surface_type_origin (surface, resource_type, origin),
  KEY classification (classification)
) {$cc};"
		);

		// 14. Reporting API violation reports for pillars other than CSP --
		// currently Cross-Origin-Opener-Policy and Cross-Origin-Embedder-Policy,
		// the only two pillars with a browser-native report-only + reporting
		// delivery mechanism (Chromium only). Deliberately generic rather than
		// CSP-shaped: COOP/COEP report bodies carry different fields from each
		// other and from a CSP violation report, and their exact field names
		// are less stable, so pillar-specific fields live in the `detail` JSON
		// blob rather than named columns. See Pillar_Violation_Store.
		dbDelta(
			"CREATE TABLE {$p}sam_pillar_violation_reports (
  id bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT,
  pillar varchar(32) NOT NULL,
  surface varchar(32) NOT NULL,
  disposition varchar(16) NOT NULL DEFAULT 'reporting',
  report_type varchar(64) NOT NULL,
  detail longtext NOT NULL,
  fingerprint varchar(64) NOT NULL,
  occurrence_count int(11) NOT NULL DEFAULT 1,
  first_seen_at datetime NOT NULL,
  last_seen_at datetime NOT NULL,
  PRIMARY KEY  (id),
  KEY pillar (pillar),
  KEY surface (surface),
  KEY last_seen_at (last_seen_at),
  UNIQUE KEY fingerprint (fingerprint)
) {$cc};"
		);

		// 15. First-party (theme/plugin/core) script and stylesheet integrity
		// inventory. Unlike sam_dependency_inventory (third-party origins,
		// admin-supplied expected_sri, never fetched by this plugin), every
		// row here is hashed directly from a local file this WordPress
		// install itself is about to serve -- not a remote fetch, so it
		// carries none of the "trusting a compromised third party" risk a
		// self-fetched third-party hash would. path is the resolved absolute
		// filesystem path (identity key, together with resource_type);
		// file_size/file_mtime are a cheap stat()-only cache-invalidation
		// check so an unchanged file is never re-read and re-hashed on every
		// request -- only a changed mtime/size triggers a re-hash. url,
		// surface and handle reflect only the most recently observed
		// request; a file enqueued identically on multiple surfaces still
		// gets one row.
		dbDelta(
			"CREATE TABLE {$p}sam_internal_asset_inventory (
  id bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT,
  resource_type varchar(16) NOT NULL,
  path varchar(255) NOT NULL,
  url varchar(255) NOT NULL,
  surface varchar(32) NOT NULL,
  handle varchar(191) NOT NULL,
  hash varchar(128) NOT NULL,
  file_size bigint(20) UNSIGNED NOT NULL,
  file_mtime int(11) UNSIGNED NOT NULL,
  first_seen_at datetime NOT NULL,
  last_seen_at datetime NOT NULL,
  created_at datetime NOT NULL,
  updated_at datetime NOT NULL,
  PRIMARY KEY  (id),
  UNIQUE KEY resource_path (resource_type, path),
  KEY surface (surface)
) {$cc};"
		);

		// Schema v21: ACME-issued certificates. key_pem holds the private key
		// SEALED by Credential_Vault (sodium secretbox), never plaintext -- a
		// database dump alone must not yield usable key material. fullchain_pem
		// is public by definition. environment separates Let's Encrypt staging
		// orders (configuration testing) from production ones.
		dbDelta(
			"CREATE TABLE {$p}sam_certificates (
  id bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT,
  domains text NOT NULL,
  environment varchar(16) NOT NULL DEFAULT 'production',
  status varchar(16) NOT NULL DEFAULT 'issued',
  key_pem text NOT NULL,
  fullchain_pem text NOT NULL,
  not_before datetime DEFAULT NULL,
  not_after datetime DEFAULT NULL,
  created_at datetime NOT NULL,
  updated_at datetime NOT NULL,
  PRIMARY KEY  (id),
  KEY environment_status (environment, status),
  KEY not_after (not_after)
) {$cc};"
		);

		update_option( 'wp_sam_db_version', WP_SAM_DB_VERSION );
	}

	/**
	 * Schema v9: renames the shared/generic tables (scan logs, entitlements,
	 * processed events, audit log, policy change decisions, policy versions,
	 * decision rule evaluations) from a csp_ prefix to sam_, ahead of
	 * multi-pillar support -- these tables have no CSP-specific columns and
	 * will be shared by future header pillars. The four CSP-owned tables
	 * (csp_policy_profiles, csp_source_inventory, csp_hash_inventory,
	 * csp_violation_reports) are unaffected; they hold CSP's own data.
	 *
	 * Uses RENAME TABLE, not create+copy+drop, so existing decision history,
	 * audit trail, and policy version snapshots are preserved intact. Safe to
	 * call on every activation: a no-op once the old-named table is gone.
	 */
	private static function migrate_v9_table_renames(): void {
		global $wpdb;

		$renames = array(
			'csp_scan_logs'                 => 'sam_scan_logs',
			'csp_entitlements'              => 'sam_entitlements',
			'csp_processed_events'          => 'sam_processed_events',
			'csp_audit_log'                 => 'sam_audit_log',
			'csp_policy_change_decisions'   => 'sam_policy_change_decisions',
			'csp_policy_versions'           => 'sam_policy_versions',
			'csp_decision_rule_evaluations' => 'sam_decision_rule_evaluations',
		);

		foreach ( $renames as $old_suffix => $new_suffix ) {
			$old_table = $wpdb->prefix . $old_suffix;
			$new_table = $wpdb->prefix . $new_suffix;

			if ( self::table_exists( $old_table ) && ! self::table_exists( $new_table ) ) {
				// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				$wpdb->query( "RENAME TABLE {$old_table} TO {$new_table}" );
			}
		}
	}

	/**
	 * Schema v14: recomputes each violation report's fingerprint at host
	 * granularity instead of exact-URL granularity (see
	 * Violation_Reporter::extract_blocked_host()) and merges any existing
	 * rows that now collapse under the same fingerprint -- e.g. every
	 * fonts.gstatic.com/.../<hash>.woff2 file an install already logged as a
	 * separate row becomes one "fonts.gstatic.com" row, matching how CSP
	 * source approval already groups at host granularity. Rows with no
	 * extractable host (inline/eval/data:/blob:/about:) keep their
	 * exact-value fingerprint and are only backfilled, never merged.
	 */
	private static function migrate_dedupe_violation_reports_by_host(): void {
		global $wpdb;
		$table = $wpdb->prefix . 'csp_violation_reports';

		if ( ! self::table_exists( $table ) ) {
			return;
		}

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$rows = $wpdb->get_results(
			"SELECT id, profile_surface, blocked_uri, violated_directive, occurrence_count, first_reported_at, last_reported_at FROM {$table}",
			ARRAY_A
		);
		if ( empty( $rows ) ) {
			return;
		}

		$groups = array();
		foreach ( $rows as $row ) {
			$host        = Violation_Reporter::extract_blocked_host( (string) $row['blocked_uri'] );
			$subject     = $host ?? (string) $row['blocked_uri'];
			$fingerprint = hash( 'sha256', $row['profile_surface'] . '|' . $subject . '|' . $row['violated_directive'] );

			if ( ! isset( $groups[ $fingerprint ] ) ) {
				$groups[ $fingerprint ] = array(
					'host' => $host,
					'rows' => array(),
				);
			}
			$groups[ $fingerprint ]['rows'][] = $row;
		}

		foreach ( $groups as $fingerprint => $group ) {
			$group_rows = $group['rows'];

			if ( 1 === count( $group_rows ) ) {
				$wpdb->update(
					$table,
					array(
						'fingerprint'  => $fingerprint,
						'blocked_host' => $group['host'],
					),
					array( 'id' => (int) $group_rows[0]['id'] ),
					array( '%s', '%s' ),
					array( '%d' )
				);
				continue;
			}

			// Multiple rows collapse into one: keep the row most recently seen
			// (its blocked_uri is the freshest real example for that host),
			// sum occurrence counts, keep the earliest first-seen timestamp.
			usort( $group_rows, static fn( array $a, array $b ): int => strcmp( (string) $b['last_reported_at'], (string) $a['last_reported_at'] ) );
			$survivor = $group_rows[0];
			$others   = array_slice( $group_rows, 1 );

			$total_occurrences = array_sum( array_map( static fn( array $r ): int => (int) $r['occurrence_count'], $group_rows ) );
			$first_seen        = min( array_map( static fn( array $r ): string => (string) $r['first_reported_at'], $group_rows ) );
			$last_seen         = (string) $survivor['last_reported_at'];

			$wpdb->update(
				$table,
				array(
					'fingerprint'       => $fingerprint,
					'blocked_host'      => $group['host'],
					'occurrence_count'  => $total_occurrences,
					'first_reported_at' => $first_seen,
					'last_reported_at'  => $last_seen,
					'reported_at'       => $last_seen,
				),
				array( 'id' => (int) $survivor['id'] ),
				array( '%s', '%s', '%d', '%s', '%s', '%s' ),
				array( '%d' )
			);

			$other_ids = array_map( static fn( array $r ): int => (int) $r['id'], $others );
			$in_clause = implode( ',', array_fill( 0, count( $other_ids ), '%d' ) );
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.NotPrepared
			$wpdb->query(
				$wpdb->prepare(
					// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared,WordPress.DB.PreparedSQLPlaceholders.UnfinishedPrepare -- {$in_clause} is a runtime-built string of %d placeholders, one per element of the spread $other_ids below; phpcs cannot see through the interpolation.
					"DELETE FROM {$table} WHERE id IN ({$in_clause})",
					...$other_ids
				)
			);
		}
	}

	private static function migrate_violation_report_rollups(): void {
		global $wpdb;

		$table = $wpdb->prefix . 'csp_violation_reports';

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
		$table_exists = $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $table ) );
		if ( $table_exists !== $table ) {
			return;
		}

		// Backfill new roll-up timestamps from the legacy reported_at column.
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$wpdb->query( "UPDATE {$table} SET first_reported_at = reported_at WHERE first_reported_at IS NULL" );
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$wpdb->query( "UPDATE {$table} SET last_reported_at = reported_at WHERE last_reported_at IS NULL" );

		// Collapse any historic duplicate fingerprints before enforcing uniqueness.
		// The current reporter has deduped for some time, but this keeps upgrades safe.
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$duplicates = $wpdb->get_results(
			"SELECT fingerprint, MIN(id) AS keep_id, SUM(occurrence_count) AS total_count, MIN(first_reported_at) AS first_seen, MAX(last_reported_at) AS last_seen
			 FROM {$table}
			 GROUP BY fingerprint
			 HAVING COUNT(*) > 1",
			ARRAY_A
		);

		foreach ( is_array( $duplicates ) ? $duplicates : array() as $duplicate ) {
			$keep_id = (int) $duplicate['keep_id'];
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.NotPrepared
			$wpdb->query(
				$wpdb->prepare(
					// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
					"UPDATE {$table}
					 SET occurrence_count = %d, first_reported_at = %s, last_reported_at = %s, reported_at = %s
					 WHERE id = %d",
					(int) $duplicate['total_count'],
					(string) $duplicate['first_seen'],
					(string) $duplicate['last_seen'],
					(string) $duplicate['last_seen'],
					$keep_id
				)
			);

			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.NotPrepared
			$wpdb->query(
				$wpdb->prepare(
					// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
					"DELETE FROM {$table} WHERE fingerprint = %s AND id <> %d",
					(string) $duplicate['fingerprint'],
					$keep_id
				)
			);
		}

		// Convert the fingerprint index to a unique index if required.
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$index = $wpdb->get_row( "SHOW INDEX FROM {$table} WHERE Key_name = 'fingerprint' AND Non_unique = 0" );
		if ( null === $index ) {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			$wpdb->query( "ALTER TABLE {$table} DROP INDEX fingerprint" );
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			$wpdb->query( "ALTER TABLE {$table} ADD UNIQUE KEY fingerprint (fingerprint)" );
		}
	}

	// ── Default options ───────────────────────────────────────────────────────

	private static function set_default_options(): void {
		$defaults = array(
			'wp_sam_cron_hour'                     => 2,
			'wp_sam_notify_email'                  => get_option( 'admin_email' ),
			// Promotion gate: minimum hours without a high-severity violation
			// before enforce mode is permitted. Default: 24 hours.
			'wp_sam_enforce_gate_violation_window' => 24,
			// Data retention: violation reports older than this many days are purged
			// by the daily cron scan. 0 = keep forever (not recommended for busy sites).
			'wp_sam_violation_retention_days'      => 90,
			// Report-endpoint learning closes after this many hours from the latest
			// post, page, or plugin material change.
			'wp_sam_learning_window_hours'         => 48,
			// Blank uses rest_url( 'sam/v1/report' ); set only when a
			// public proxy/CDN hostname must be advertised to browsers.
			'wp_sam_report_endpoint_url'           => '',
			// Direct report-uri reporting is the default because it gives the
			// fastest feedback loop for report-endpoint learning.
			'wp_sam_reporting_transport'           => 'report-uri',
			// Blank emits normal CSP headers. Set only when an edge proxy copies
			// an origin-only policy header back to a browser-facing CSP header.
			'wp_sam_policy_header_name'            => '',
			'wp_sam_last_material_change_at'       => current_time( 'mysql', true ),
			'wp_sam_automation_config'             => self::default_automation_config(),
		);

		foreach ( $defaults as $key => $value ) {
			if ( false === get_option( $key ) ) {
				add_option( $key, $value );
			}
		}
	}

	private static function default_automation_config(): array {
		// Automatic (high approvals only): every proposal below the high-risk
		// threshold is auto-approved into the report-only policy on its own
		// evidence, with only high-risk sources still requiring a human
		// decision -- this is what "automate security" means for this
		// pillar. It does not touch CSP enforcement: a surface still starts
		// in report-only mode (seed_default_profiles() above) and promotion
		// to enforce still requires an administrator to act, still passes
		// through the learning window and promotion gate. Automation here
		// only ever governs what's proposed for approval, never whether a
		// surface starts blocking anything.
		$surface_config = array(
			'mode'                           => Automation_Config::MODE_AUTOMATIC_HIGH_APPROVAL,
			'enabled_directives'             => array(),
			'excluded_directives'            => array(),
			'allowed_source_schemes'         => array( 'https' ),
			'treat_same_origin_as_low'       => true,
			'treat_known_cdn_as_low'         => false,
			'allow_wildcards'                => false,
			'allow_cleartext_http'           => false,
			'allow_browser_schemes'          => false,
			'allow_ip_literals'              => false,
			'allow_non_standard_ports'       => false,
			'approval_confidence_threshold'  => 1.0,
			'require_ai_agreement'           => false,
			'automatic_rejection_enabled'    => false,
			// Must be positive whenever mode isn't manual: Policy_Change_Manager
			// treats <= 0 as "automation disabled" regardless of mode, so 0 here
			// would leave a surface claiming automatic approval while silently
			// approving nothing. 50 matches the admin UI's own input cap
			// (max="50") and what update_surface_mode() seeds when an admin
			// switches a surface onto any automatic mode by hand.
			'max_automatic_changes_per_scan' => 50,
			'change_rate_guardrail'          => 0,
		);

		return array(
			'frontend' => $surface_config,
			'admin'    => $surface_config,
			'login'    => $surface_config,
			'api'      => $surface_config,
		);
	}

	// ── Seed default CSP profiles ─────────────────────────────────────────────

	private static function seed_default_profiles(): void {
		global $wpdb;
		$table = $wpdb->prefix . 'csp_policy_profiles';
		$now   = current_time( 'mysql', true );

		foreach ( array( 'frontend', 'admin', 'login', 'api' ) as $surface ) {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			$exists = $wpdb->get_var( $wpdb->prepare( "SELECT id FROM {$table} WHERE surface = %s LIMIT 1", $surface ) );
			if ( ! $exists ) {
				$wpdb->insert(
					$table,
					array(
						'surface'                         => $surface,
						'mode'                            => 'report-only',
						'directives'                      => wp_json_encode( self::default_directives( $surface ) ),
						'overrides'                       => wp_json_encode( array() ),
						'strict_dynamic'                  => 0,
						'trusted_types'                   => 0,
						'bypass_img_src_data'             => 0,
						'bypass_font_src_data'            => 0,
						'bypass_style_attr_unsafe_hashes' => 0,
						'override_expires_at'             => null,
						'override_owner'                  => null,
						'created_at'                      => $now,
						'updated_at'                      => $now,
					),
					array( '%s', '%s', '%s', '%s', '%d', '%d', '%d', '%d', '%d', '%s', '%s', '%s', '%s' )
				);
			}
		}
	}

	/**
	 * Schema v18: seeds a vetted, enabled-by-default configuration for every
	 * "simple" header pillar plus Reverse Tabnabbing, on every surface that
	 * doesn't already have a row -- so a fresh install ships with this
	 * hardening active out of the box instead of requiring an administrator
	 * to find and individually enable nine separate admin pages. Only ever
	 * inserts a missing (pillar, surface) pair, same "fill in what's
	 * missing, never touch what's already there" pattern as
	 * seed_default_profiles() above -- a surface an administrator has
	 * already configured (enabled or deliberately left disabled) already
	 * has a row and is never touched by this on a later upgrade.
	 *
	 * HSTS is deliberately NOT included here. Unlike everything seeded
	 * below, HSTS is sticky and extremely hard to undo once a browser has
	 * cached it (worse still with includeSubDomains/preload) -- see
	 * Strict_Transport_Security_Builder's own DEFAULT_MAX_AGE reasoning.
	 * It stays a deliberate, informed, per-surface opt-in rather than a
	 * blind default a fresh install could get burned by.
	 *
	 * Cross-Origin-Opener-Policy and Cross-Origin-Embedder-Policy are
	 * seeded with 'unsafe-none' -- the spec's no-op value for both headers.
	 * This adds no real cross-origin isolation; it exists purely so the
	 * header is present for scanners (securityheaders.com, Mozilla
	 * Observatory) that check for it. A genuinely tighter value needs
	 * real evidence this site's own scripts/embeds can tolerate isolation,
	 * which is exactly what a future periodic self-scan is meant to
	 * establish -- see the "COOP/COEP readiness" idea tracked against the
	 * roadmap rather than guessed at here.
	 */
	private static function seed_default_pillar_profiles(): void {
		global $wpdb;
		$table = $wpdb->prefix . 'sam_pillar_profiles';
		$now   = current_time( 'mysql', true );

		$empty_payload = wp_json_encode( array() );

		$permissions_directives_default = array(
			'geolocation' => 'none',
			'camera'      => 'none',
			'microphone'  => 'none',
			'fullscreen'  => 'none',
			'payment'     => 'none',
			'usb'         => 'none',
			'autoplay'    => 'none',
		);
		$permissions_payload_default    = wp_json_encode( array( 'directives' => $permissions_directives_default ) );
		$permissions_payload_frontend   = wp_json_encode( array( 'directives' => array_merge( $permissions_directives_default, array( 'autoplay' => 'self' ) ) ) );

		foreach ( array( 'frontend', 'admin', 'login', 'api' ) as $surface ) {
			$is_api = 'api' === $surface;

			$rows = array(
				X_Frame_Options_Builder::PILLAR_KEY        => wp_json_encode( array( 'value' => $is_api ? 'DENY' : 'SAMEORIGIN' ) ),
				X_Content_Type_Options_Builder::PILLAR_KEY => $empty_payload,
				Referrer_Policy_Builder::PILLAR_KEY        => wp_json_encode( array( 'value' => $is_api ? 'no-referrer' : Referrer_Policy_Builder::DEFAULT_VALUE ) ),
				Permissions_Policy_Builder::PILLAR_KEY     => 'frontend' === $surface ? $permissions_payload_frontend : $permissions_payload_default,
				Reverse_Tabnabbing_Builder::PILLAR_KEY     => $empty_payload,
				Cross_Origin_Resource_Policy_Builder::PILLAR_KEY => wp_json_encode( array( 'value' => $is_api ? 'same-site' : 'cross-origin' ) ),
				Cross_Origin_Opener_Policy_Builder::PILLAR_KEY => wp_json_encode( array( 'value' => 'unsafe-none' ) ),
				Cross_Origin_Embedder_Policy_Builder::PILLAR_KEY => wp_json_encode( array( 'value' => 'unsafe-none' ) ),
				X_Permitted_Cross_Domain_Policies_Builder::PILLAR_KEY => wp_json_encode( array( 'value' => 'none' ) ),
			);

			foreach ( $rows as $pillar => $payload ) {
				// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				$exists = $wpdb->get_var( $wpdb->prepare( "SELECT id FROM {$table} WHERE pillar = %s AND surface = %s", $pillar, $surface ) );
				if ( $exists ) {
					continue;
				}

				// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
				$wpdb->insert(
					$table,
					array(
						'pillar'     => $pillar,
						'surface'    => $surface,
						'enabled'    => 1,
						'payload'    => $payload,
						'created_at' => $now,
						'updated_at' => $now,
					),
					array( '%s', '%s', '%d', '%s', '%s', '%s' )
				);
			}
		}
	}

	private static function seed_initial_policy_versions(): void {
		if ( ! class_exists( 'WP_SAM\CSP\Policy_Version_Manager' ) ) {
			return;
		}

		global $wpdb;
		$table   = $wpdb->prefix . 'sam_policy_versions';
		$manager = new \WP_SAM\CSP\Policy_Version_Manager();

		if ( ! self::table_exists( $table ) ) {
			return;
		}

		foreach ( array( 'frontend', 'admin', 'login', 'api' ) as $surface ) {
			$exists = $wpdb->get_var(
				$wpdb->prepare(
					// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
					"SELECT id FROM {$table} WHERE surface = %s LIMIT 1",
					$surface
				)
			);

			if ( ! $exists ) {
				$manager->capture_snapshot( $surface, 'system_migration', 0 );
			}
		}
	}

	private static function table_exists( string $table ): bool {
		global $wpdb;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
		return $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $table ) ) === $table;
	}

	private static function default_directives( string $surface ): array {
		// 'report-sample' added to script/style-src so browsers include the offending
		// inline code snippet in violation reports (R7). Harmless when no violation occurs.
		$d = array(
			'default-src'               => array( "'none'" ),
			'script-src'                => array( "'report-sample'" ),
			'script-src-elem'           => array( "'report-sample'" ),
			'script-src-attr'           => array( "'none'" ),
			'style-src'                 => array( "'report-sample'" ),
			'style-src-elem'            => array( "'report-sample'" ),
			'style-src-attr'            => array( "'none'" ),
			// img-src: 'self' only. data: was dropped from the default (see
			// migrate_tighten_img_src_default() below, which tightens profiles
			// seeded before this change) -- data: URIs can't execute script, so
			// the risk was always low, but a site that doesn't actually need
			// inline/base64 images gets a tighter default out of the box; a site
			// that does can still add it back via the Profiles tab.
			'img-src'                   => array( "'self'" ),
			'font-src'                  => array( "'self'" ),
			'connect-src'               => array( "'self'" ),
			'frame-src'                 => array( "'none'" ),
			'frame-ancestors'           => array( "'none'" ),
			'base-uri'                  => array( "'none'" ),
			'form-action'               => array( "'self'" ),
			'object-src'                => array( "'none'" ),
			'media-src'                 => array( "'none'" ),
			// worker-src: explicitly set on all surfaces. child-src is also set as a
			// legacy fallback: Safari falls back worker-src → child-src → script-src,
			// so without child-src the nonce would bleed through to workers in Safari.
			'worker-src'                => array( "'none'" ),
			'child-src'                 => array( "'none'" ),
			'manifest-src'              => array( "'self'" ),
			// upgrade-insecure-requests: auto-upgrades http→https for sub-resource requests.
			// Boolean directive (empty array = valueless). Does NOT replace HSTS (RFC 6797).
			// Skipped on the api surface (REST responses have no navigable resources).
			// Not emitted on api surface — handled below.
			// fenced-frame-src is deliberately NOT a default: it's an experimental
			// Privacy Sandbox directive, not part of the CSP living standard, and
			// third-party CSP linters commonly flag it as "should not be used" --
			// removed after real-world scan feedback (see migrate_remove_fenced_frame_src_directive()
			// below, which strips it from profiles seeded before this change).
			// sandbox: null = disabled. Set to an array of allow-* flags to enable.
			// Ignored by browsers in CSP-Report-Only mode and in <meta http-equiv>.
			'sandbox'                   => null,
			// Trusted Types directives: empty = disabled.
			// When enabled, always deploy in report-only first (Chromium-strong; R5).
			'require-trusted-types-for' => array(),
			'trusted-types'             => array(),
		);

		if ( 'admin' === $surface ) {
			$d['frame-src']       = array( "'self'" );
			$d['frame-ancestors'] = array( "'self'" );
		}

		// upgrade-insecure-requests on all surfaces except api.
		if ( 'api' !== $surface ) {
			$d['upgrade-insecure-requests'] = array();
		}

		return $d;
	}

	// ── WP Cron ───────────────────────────────────────────────────────────────

	private static function schedule_events(): void {
		$hook = 'wp_sam_daily_scan';
		if ( wp_next_scheduled( $hook ) ) {
			return;
		}
		$hour      = max( 0, min( 23, (int) get_option( 'wp_sam_cron_hour', 2 ) ) );
		$now       = time();
		$today     = mktime( $hour, 0, 0, (int) gmdate( 'n', $now ), (int) gmdate( 'j', $now ), (int) gmdate( 'Y', $now ) );
		$first_run = ( $today > $now ) ? $today : $today + DAY_IN_SECONDS;
		wp_schedule_event( $first_run, 'daily', $hook );
	}

	public static function mark_schema_verified(): void {
		update_option( 'wp_sam_schema_verified_version', WP_SAM_DB_VERSION );
	}
}
