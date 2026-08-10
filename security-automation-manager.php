<?php
/**
 * Plugin Name:       Security Automation Manager
 * Plugin URI:        https://github.com/vcns/security-automation-manager
 * Description:       Automates strict HTTP security header rollout (Content Security Policy and related headers), enforcement, and violation analysis for WordPress.
 * Version:           2.1.1
 * Requires at least: 6.4
 * Requires PHP:      8.1
 * Author:            VCNS Tech Ltd
 * Author URI:        https://vcns.tech
 * License:           GPL-2.0-or-later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       security-automation-manager
 * Domain Path:       /languages
 */

declare( strict_types=1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

// ── Core constants ────────────────────────────────────────────────────────────
define( 'WP_SAM_VERSION', '2.1.1' );

/**
 * Schema version. Increment whenever a database schema change is made.
 * maybe_upgrade_db() in Plugin compares this against the stored value and
 * calls Activator::activate() (which runs dbDelta) when they differ.
 *
 * v1 -- initial schema (7 tables)
 * v2 -- adds override_expires_at and override_owner to csp_policy_profiles
 * v3 -- adds sample column to csp_violation_reports (R7: report-sample support)
 * v4 -- adds csp_audit_log append-only table (R10: immutable audit log)
 * v5 -- adds policy change proposal metadata and decision/suppression ledger
 * v6 -- adds violation first/last reported roll-up timestamps and unique fingerprint upsert support
 * v7 -- adds decision provenance, policy version snapshots, and deterministic rule evaluations
 * v8 -- adds last_seen_at and source_host indexes to csp_source_inventory, and an
 *        occurrence_count index to csp_violation_reports, for the sortable/filterable
 *        dashboard tables
 * v9 -- renames shared/generic tables (csp_scan_logs, csp_entitlements,
 *        csp_processed_events, csp_audit_log, csp_policy_change_decisions,
 *        csp_policy_versions, csp_decision_rule_evaluations) to a sam_ prefix
 *        ahead of multi-pillar support; CSP-owned tables (csp_policy_profiles,
 *        csp_source_inventory, csp_hash_inventory, csp_violation_reports) are
 *        unchanged. Existing installs are migrated via RENAME TABLE, not
 *        create+copy+drop, so no data is lost.
 * v10 -- adds sam_pillar_profiles, a shared per-surface profile table for
 *        header pillars simple enough not to need CSP's directive/override/
 *        strict-dynamic shape (X-Frame-Options, X-Content-Type-Options,
 *        Referrer-Policy, and future pillars). Starts empty; nothing reads
 *        or writes it until those pillars ship.
 */
define( 'WP_SAM_DB_VERSION', '11' );

define( 'WP_SAM_FILE', __FILE__ );
define( 'WP_SAM_DIR', plugin_dir_path( __FILE__ ) );
define( 'WP_SAM_URL', plugin_dir_url( __FILE__ ) );
define( 'WP_SAM_PLUGIN_BASENAME', plugin_basename( __FILE__ ) );

$wp_sam_build_channel = WP_SAM_DIR . 'includes/build-channel.php';
if ( is_readable( $wp_sam_build_channel ) ) {
	require $wp_sam_build_channel;
}
unset( $wp_sam_build_channel );

if ( ! defined( 'WP_SAM_DISTRIBUTION_CHANNEL' ) ) {
	define( 'WP_SAM_DISTRIBUTION_CHANNEL', 'wordpress-org' );
}

if ( ! defined( 'WP_SAM_UPDATE_MANIFEST_URL' ) ) {
	define( 'WP_SAM_UPDATE_MANIFEST_URL', 'https://vcns.github.io/wp-updates/security-automation-manager/update.json' );
}


// ── PSR-4 autoloader ──────────────────────────────────────────────────────────
spl_autoload_register(
	static function ( string $class_name ): void {
		$prefix = 'WP_SAM\\';
		if ( strncmp( $prefix, $class_name, strlen( $prefix ) ) !== 0 ) {
			return;
		}
		$relative = substr( $class_name, strlen( $prefix ) );
		$parts    = explode( '\\', $relative );
		$filename = 'class-' . strtolower( str_replace( '_', '-', (string) array_pop( $parts ) ) ) . '.php';
		$subdir   = ! empty( $parts ) ? strtolower( implode( '/', $parts ) ) . '/' : '';

		// Public includes/ directory.
		$file = WP_SAM_DIR . 'includes/' . $subdir . $filename;
		if ( is_readable( $file ) ) {
			require $file;
			return;
		}

		// offline/ directory: proprietary modules never committed to the repository.
		$file = WP_SAM_DIR . 'offline/' . $subdir . $filename;
		if ( is_readable( $file ) ) {
			require $file;
		}
	}
);

// ── Lifecycle hooks ───────────────────────────────────────────────────────────
register_activation_hook( __FILE__, array( 'WP_SAM\\Activator', 'activate' ) );
register_deactivation_hook( __FILE__, array( 'WP_SAM\\Deactivator', 'deactivate' ) );

// ── Bootstrap ─────────────────────────────────────────────────────────────────
add_action(
	'plugins_loaded',
	static function (): void {
		WP_SAM\Plugin::instance()->init();

		if (
			'github' === WP_SAM_DISTRIBUTION_CHANNEL
			&& ( is_admin() || wp_doing_cron() )
			&& is_readable( WP_SAM_DIR . 'includes/modules/class-github-update-checker.php' )
		) {
			( new WP_SAM\Modules\Github_Update_Checker() )->register();
		}
	}
);
