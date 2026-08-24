<?php
/**
 * Runs when the plugin is deleted from the Plugins screen.
 * Removes all custom database tables and option entries.
 */

if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
	exit;
}

global $wpdb;

// This file runs standalone -- WordPress does not load the plugin's own
// bootstrap for uninstall.php, so an extension (see includes/extensions/,
// physically absent from the WordPress.org build) gets no chance to
// register itself unless required directly here. Only the
// wp_sam_option_names filter registration below (add_filter, a pure
// closure) actually needs to fire in this minimal context -- no autoloaded
// class is ever instantiated during an uninstall run.
$wp_sam_extension_files = glob( __DIR__ . '/includes/extensions/*.php' );
foreach ( false !== $wp_sam_extension_files ? $wp_sam_extension_files : array() as $wp_sam_extension_file ) {
	require $wp_sam_extension_file;
}
unset( $wp_sam_extension_files, $wp_sam_extension_file );

// ── Drop custom tables ────────────────────────────────────────────────────────
$tables = array(
	'csp_policy_profiles',
	'csp_source_inventory',
	'csp_hash_inventory',
	'csp_violation_reports',
	'sam_scan_logs',
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

// Extension-owned tables (e.g. a paid automation mode's own commercial
// service schema) are added here, not named in this file -- see the
// require loop above, which gives an extension the chance to register its
// own suffixes via this same filter Activator::get_all_table_suffixes()
// uses elsewhere.
$tables = apply_filters( 'wp_sam_table_suffixes', $tables );

foreach ( $tables as $table ) {
	// phpcs:ignore WordPress.DB.DirectDatabaseQuery,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
	$wpdb->query( "DROP TABLE IF EXISTS {$wpdb->prefix}{$table}" );
}

// ── Delete options ────────────────────────────────────────────────────────────
$options = array(
	'wp_sam_db_version',
	'wp_sam_enforce_gate_violation_window',
	'wp_sam_cron_hour',
	'wp_sam_notify_email',
	'wp_sam_violation_retention_days',
	'wp_sam_learning_window_hours',
	'wp_sam_policy_header_name',
	'wp_sam_schema_verified_version',
	'wp_sam_last_material_change_at',
	'wp_sam_automation_config',
	'wp_sam_admin_notices',
	'wp_sam_conflict_dismissed_at',
	'wp_sam_cert_config',
	'wp_sam_acme_account_keys',
	'wp_sam_acme_http_tokens',
	'wp_sam_cert_last_run',
	'wp_sam_update_diagnostics',
);

// Extension-owned option names (e.g. a paid automation mode's own
// payment-provider settings) are added here, not named in this file --
// see the require loop above.
$options = apply_filters( 'wp_sam_option_names', $options );

foreach ( $options as $option ) {
	delete_option( $option );
}

// ── Remove transients ─────────────────────────────────────────────────────────
delete_transient( 'wp_sam_conflict_probe_ran' );

// ── Clear scheduled hooks ─────────────────────────────────────────────────────
wp_clear_scheduled_hook( 'wp_sam_daily_scan' );
wp_clear_scheduled_hook( 'wp_sam_cert_issue' );
wp_clear_scheduled_hook( 'wp_sam_cert_renewal_check' );
