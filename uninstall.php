<?php
/**
 * Runs when the plugin is deleted from the Plugins screen.
 * Removes all custom database tables and option entries.
 */

if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
	exit;
}

global $wpdb;

// ── Drop custom tables ────────────────────────────────────────────────────────
$tables = array(
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
);

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
	'wp_sam_stripe_mode',
	'wp_sam_stripe_secret_key_test',
	'wp_sam_stripe_secret_key_live',
	'wp_sam_stripe_price_id_monthly_test',
	'wp_sam_stripe_price_id_annual_test',
	'wp_sam_stripe_price_id_monthly_live',
	'wp_sam_stripe_price_id_annual_live',
	'wp_sam_webhook_secret',
);

foreach ( $options as $option ) {
	delete_option( $option );
}

// ── Remove transients ─────────────────────────────────────────────────────────
delete_transient( 'wp_sam_conflict_probe_ran' );

// ── Clear scheduled hooks ─────────────────────────────────────────────────────
wp_clear_scheduled_hook( 'wp_sam_daily_scan' );
