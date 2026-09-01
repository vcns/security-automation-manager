<?php
/**
 * Plugin Name:       VCNS Security Automation Manager
 * Plugin URI:        https://github.com/vcns/security-automation-manager
 * Description:       Ten security headers that learn your site before enforcing -- nothing breaks. Plus free automatic TLS certificates and script integrity. No paywall.
 * Version:           2.9.33
 * Requires at least: 6.4
 * Requires PHP:      8.1
 * Author:            VCNS Tech Ltd
 * Author URI:        https://vcns.tech
 * License:           GPL-2.0-or-later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       vcns-security-automation-manager
 * Domain Path:       /languages
 */

declare( strict_types=1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

// ── Core constants ────────────────────────────────────────────────────────────
define( 'WP_SAM_VERSION', '2.9.33' );

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
 * v11 -- adds sam_dependency_inventory (third-party script/stylesheet origin
 *        governance).
 * v12 -- migrates fenced-frame-src out of any already-seeded profile's stored
 *        directives JSON (removed from the default set as an experimental,
 *        non-standard directive commonly flagged by CSP linters); adds
 *        trusted_types to csp_policy_profiles for the per-surface Trusted
 *        Types toggle.
 * v13 -- adds sam_pillar_violation_reports, a generic Reporting API violation
 *        store for pillars other than CSP (currently Cross-Origin-Opener-Policy
 *        and Cross-Origin-Embedder-Policy, the only two with a browser-native
 *        report-only + reporting delivery mechanism). See Pillar_Violation_Store.
 * v14 -- adds blocked_host to csp_violation_reports and switches violation
 *        dedup from exact-URL to host granularity (see
 *        Violation_Reporter::extract_blocked_host()) -- a CDN/font-provider
 *        serving each request from a distinct, content-hashed filename under
 *        the same host no longer gets a permanent row per file. Existing
 *        rows are merged accordingly on upgrade.
 * v15 -- widens sam_pillar_profiles.pillar from varchar(32) to varchar(48).
 *        X_Permitted_Cross_Domain_Policies_Builder::PILLAR_KEY
 *        ('x-permitted-cross-domain-policies') is 33 characters, one over
 *        the old column length, so every toggle for that one pillar either
 *        failed outright (strict SQL mode) or was silently truncated to a
 *        different, unreadable key (non-strict mode) -- the Overview table
 *        always showed it as "Off" regardless of what was saved.
 * v16 -- adds sam_internal_asset_inventory, a first-party (theme/plugin/core)
 *        script and stylesheet integrity inventory. See
 *        Internal_Script_Integrity_Builder.
 * v17 -- default_directives() no longer includes data: in img-src (data: URIs
 *        can't execute active content, so the risk was always low, but a site
 *        that doesn't need inline/base64 images gets a tighter default).
 *        Migrates any existing profile whose img-src still exactly matches
 *        the old default; a profile an administrator has already customised
 *        is left untouched. See migrate_tighten_img_src_default().
 * v18 -- seeds a vetted, enabled configuration for X-Frame-Options,
 *        X-Content-Type-Options, Referrer-Policy, Permissions-Policy,
 *        Reverse Tabnabbing, Cross-Origin-Resource-Policy,
 *        Cross-Origin-Opener-Policy, Cross-Origin-Embedder-Policy, and
 *        X-Permitted-Cross-Domain-Policies on every surface that doesn't
 *        already have a row, so a fresh install ships with this hardening
 *        active by default. HSTS is deliberately excluded -- see
 *        seed_default_pillar_profiles(). Also changes the default CSP
 *        automation-approval mode from manual to automatic (high approvals
 *        only); this only affects who approves a proposed CSP source, not
 *        CSP enforcement, which still requires a deliberate admin
 *        promotion through the existing learning window and promotion
 *        gate regardless of automation mode.
 * v19 -- adds last_seen_url to sam_dependency_inventory: the most recently
 *        observed full URL (path and query included) for a governed
 *        third-party origin. The dedup key stays origin-only (scheme+host),
 *        but the "Suggest" SRI hash helper needs an exact file URL to fetch
 *        and hash, which the origin alone can't provide.
 * v20 -- adds bypass_img_src_data, bypass_font_src_data tinyint columns to
 *        csp_policy_profiles for the Profiles tab's "Bypass Best Practices"
 *        toggles: a small, hardcoded, per-surface opt-in for specific
 *        directive+token relaxations (data: URIs in img-src/font-src) that
 *        are safe despite being high-risk for automation. See
 *        Policy_Builder::BYPASS_CATALOG.
 * v21 -- adds sam_certificates for ACME (Let's Encrypt) certificate
 *        automation: issued certificate metadata, sealed private key, and
 *        expiry tracking for the renewal scheduler. See
 *        Certificates\Certificate_Store.
 * v22 -- adds bypass_style_attr_unsafe_hashes tinyint column to
 *        csp_policy_profiles, and moves 'unsafe-hashes' emission on
 *        style-src-attr out of automatic (whenever a hash exists) and into
 *        BYPASS_CATALOG as its own explicit, labelled opt-in -- a scanner
 *        will flag this keyword, so enabling it must be a conscious admin
 *        decision, not something the plugin decided on its own.
 * v23 -- adds sam_migration_snapshots: a bounded (last 5) history of
 *        configuration-state table contents captured immediately before
 *        each forward schema migration, so a migration whose data effects
 *        turn out to be unwanted can be undone without reinstalling old
 *        plugin code. See Rollback_Guard.
 * v24 -- default_directives() now seeds media-src as ['self'] instead of
 *        ['none'] -- same-origin video/audio can't execute script, and
 *        blocking it by default broke WordPress core's own native
 *        Video/Audio blocks (self-hosted media) out of the box for no
 *        corresponding security benefit; every other same-origin-safe
 *        directive (img-src, font-src, connect-src, form-action) already
 *        defaulted to 'self'. Migrates any existing profile whose
 *        media-src still exactly matches the old ['none'] default; a
 *        profile an administrator has already customised is left
 *        untouched. See migrate_loosen_media_src_default().
 * v25 -- adds bypass_flags (JSON array of enabled Policy_Builder::
 *        BYPASS_CATALOG keys) to csp_policy_profiles, replacing the three
 *        legacy per-entry tinyint columns (bypass_img_src_data,
 *        bypass_font_src_data, bypass_style_attr_unsafe_hashes) -- a
 *        single column rather than one per catalog entry, so the "Bypass
 *        Best Practices" catalog can keep growing without a schema
 *        migration for every addition. The catalog itself grows from 3 to
 *        9 entries in this same release. Legacy columns are converted once
 *        via migrate_consolidate_bypass_flags_into_json() and left in
 *        place afterwards (dbDelta() cannot drop columns) but are no
 *        longer read by anything.
 */
define( 'WP_SAM_DB_VERSION', '25' );

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

// ── Optional extensions ───────────────────────────────────────────────────────
// Files here self-register via WordPress hooks (see class-plugin.php's
// wp_sam_register_automation_modes action) -- this file has no knowledge of
// what, if anything, exists in this directory, and never references any
// extension's class or file name. The WordPress.org-channel build removes
// this directory entirely (see .github/workflows/wporg-deploy.yml and
// release-package.yml); on that channel this glob returns nothing and the
// loop body never runs.
$wp_sam_extension_files = glob( WP_SAM_DIR . 'includes/extensions/*.php' );
foreach ( false !== $wp_sam_extension_files ? $wp_sam_extension_files : array() as $wp_sam_extension_file ) {
	require $wp_sam_extension_file;
}
unset( $wp_sam_extension_files, $wp_sam_extension_file );

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
