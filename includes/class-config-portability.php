<?php
/**
 * Cross-site configuration export/import.
 *
 * Distinct from Rollback_Guard's snapshot/restore, which is same-site,
 * same-schema-version only and exists to undo a migration's data effects.
 * This is meant to move configuration between sites (or archive it outside
 * the database entirely) -- schema-version-independent within reason, and
 * far more defensive about what it will read from an uploaded file, since
 * that file's origin can never be trusted the way an internal snapshot row
 * can.
 *
 * Scope, and why: every table/option here is administrator-authored
 * configuration -- what should the policy be -- never secrets, credentials,
 * telemetry, or history.
 *   - PORTABLE_TABLE_SUFFIXES: CSP policy profiles, source/hash approval
 *     decisions, the other nine header pillars' profiles, and
 *     External Scripts/SRI classifications. Never sam_certificates -- an
 *     issued certificate is a domain-bound artifact tied to a specific
 *     ACME account and DNS setup, not portable configuration, and its key
 *     material must never leave this site regardless. Never any
 *     log/ledger-shaped table (violation reports, scan logs, the audit
 *     log, decision history, migration snapshots) -- those are history,
 *     not configuration, and importing rows into an append-only table
 *     would corrupt its own definition.
 *   - PORTABLE_OPTIONS: automation posture, reporting/cron/retention
 *     settings. Never wp_sam_db_version or wp_sam_schema_verified_version
 *     (code-tied, meaningless to move between sites), never any
 *     runtime-state option (admin notices queue, last-material-change
 *     timestamp), never anything Stripe-related (commercial/secret,
 *     offline-only in any case).
 *   - Certificate configuration is exported separately from
 *     PORTABLE_OPTIONS, via export_cert_config()/apply_cert_config(),
 *     because wp_sam_cert_config mixes portable fields (domains, DNS
 *     provider choice, key type) with sealed secrets
 *     (Certificate_Store::SECRET_FIELDS) in the same option -- those three
 *     fields are stripped before export and never written by import,
 *     mirrored here rather than imported from that private constant.
 */

declare( strict_types=1 );

namespace WP_SAM;

use WP_SAM\Certificates\Certificate_Store;
use WP_SAM\Modules\Audit_Log;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Config_Portability {

	public const FORMAT_VERSION = 1;

	public const PORTABLE_TABLE_SUFFIXES = array(
		'csp_policy_profiles',
		'csp_source_inventory',
		'csp_hash_inventory',
		'sam_pillar_profiles',
		'sam_dependency_inventory',
	);

	public const PORTABLE_OPTIONS = array(
		'wp_sam_enforce_gate_violation_window',
		'wp_sam_cron_hour',
		'wp_sam_notify_email',
		'wp_sam_violation_retention_days',
		'wp_sam_learning_window_hours',
		'wp_sam_policy_header_name',
		'wp_sam_report_endpoint_url',
		'wp_sam_reporting_transport',
		'wp_sam_automation_config',
	);

	/**
	 * Mirrors Certificate_Store::SECRET_FIELDS (private to that class) --
	 * duplicated deliberately rather than exposed, so a change to that
	 * class's secret-field list doesn't silently change what this class is
	 * allowed to export just because the constant became reachable.
	 * Covered by a unit test that fails if the two lists ever diverge.
	 */
	private const CERT_CONFIG_SECRET_FIELDS = array( 'dns_credentials', 'cpanel_token', 'custom_key_pem' );

	private Audit_Log $audit;

	public function __construct( Audit_Log $audit ) {
		$this->audit = $audit;
	}

	/**
	 * @return array<string,mixed>
	 */
	public function export(): array {
		global $wpdb;

		$tables = array();
		foreach ( self::PORTABLE_TABLE_SUFFIXES as $suffix ) {
			$table = $wpdb->prefix . $suffix;
			if ( ! $this->table_exists( $table ) ) {
				continue;
			}
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			$rows              = $wpdb->get_results( "SELECT * FROM {$table}", ARRAY_A );
			$tables[ $suffix ] = is_array( $rows ) ? $rows : array();
		}

		$options = array();
		foreach ( self::PORTABLE_OPTIONS as $option ) {
			$value = get_option( $option, null );
			if ( null !== $value ) {
				$options[ $option ] = $value;
			}
		}

		$this->audit->log(
			'config_portability',
			'config_exported',
			sprintf( 'Configuration exported: %d table(s), %d option(s), certificate config included (secrets excluded).', count( $tables ), count( $options ) ),
			'info'
		);

		return array(
			'format_version' => self::FORMAT_VERSION,
			'exported_at'    => current_time( 'mysql', true ),
			'plugin_version' => defined( 'WP_SAM_VERSION' ) ? WP_SAM_VERSION : '',
			'schema_version' => defined( 'WP_SAM_DB_VERSION' ) ? (int) WP_SAM_DB_VERSION : 0,
			'site_url'       => home_url(),
			'options'        => $options,
			'cert_config'    => $this->export_cert_config(),
			'tables'         => $tables,
		);
	}

	/**
	 * Strips Certificate_Store::SECRET_FIELDS before export. Never returns
	 * dns_credentials, cpanel_token, or custom_key_pem regardless of what
	 * this site currently has stored for them.
	 *
	 * @return array<string,mixed>
	 */
	private function export_cert_config(): array {
		$config = ( new Certificate_Store() )->get_config();
		foreach ( self::CERT_CONFIG_SECRET_FIELDS as $secret_field ) {
			unset( $config[ $secret_field ] );
		}
		return $config;
	}

	/**
	 * Validates an uploaded export's top-level shape without applying
	 * anything. Callers should validate before showing a confirmation UI,
	 * then call apply() only after the administrator confirms.
	 *
	 * @return array{ok:bool, reason?:string, summary?:array<string,int>}
	 */
	public function validate( mixed $decoded ): array {
		if ( ! is_array( $decoded ) ) {
			return array(
				'ok'     => false,
				'reason' => __( 'That file is not a valid configuration export (not a JSON object).', 'vcns-security-automation-manager' ),
			);
		}

		if ( ( $decoded['format_version'] ?? null ) !== self::FORMAT_VERSION ) {
			return array(
				'ok'     => false,
				'reason' => sprintf(
					/* translators: %s: the format_version value found in the uploaded file, or "none" */
					__( 'Unrecognised export format (format_version: %s). This importer only understands format_version 1.', 'vcns-security-automation-manager' ),
					isset( $decoded['format_version'] ) ? (string) $decoded['format_version'] : 'none'
				),
			);
		}

		if ( ! isset( $decoded['tables'] ) || ! is_array( $decoded['tables'] ) ) {
			return array(
				'ok'     => false,
				'reason' => __( 'That file has no "tables" section -- it does not look like a Security Automation Manager configuration export.', 'vcns-security-automation-manager' ),
			);
		}

		$summary = array(
			'tables'  => 0,
			'rows'    => 0,
			'options' => is_array( $decoded['options'] ?? null ) ? count( $decoded['options'] ) : 0,
		);
		foreach ( self::PORTABLE_TABLE_SUFFIXES as $suffix ) {
			if ( isset( $decoded['tables'][ $suffix ] ) && is_array( $decoded['tables'][ $suffix ] ) ) {
				++$summary['tables'];
				$summary['rows'] += count( $decoded['tables'][ $suffix ] );
			}
		}

		return array(
			'ok'      => true,
			'summary' => $summary,
		);
	}

	/**
	 * Applies a previously-validated export. Every key read from $decoded
	 * is checked against PORTABLE_TABLE_SUFFIXES/PORTABLE_OPTIONS before
	 * use -- an uploaded file is untrusted input, so nothing here ever
	 * writes an option or table this class didn't already decide, by name,
	 * it was willing to import, regardless of what else the file contains.
	 *
	 * @return array{tables_imported:array<int,string>, options_imported:array<int,string>, cert_config_imported:bool}
	 */
	public function apply( array $decoded ): array {
		global $wpdb;

		$tables_imported = array();
		$data_tables     = is_array( $decoded['tables'] ?? null ) ? $decoded['tables'] : array();

		foreach ( self::PORTABLE_TABLE_SUFFIXES as $suffix ) {
			if ( ! array_key_exists( $suffix, $data_tables ) || ! is_array( $data_tables[ $suffix ] ) ) {
				continue;
			}

			$table = $wpdb->prefix . $suffix;
			if ( ! $this->table_exists( $table ) ) {
				continue;
			}

			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			$wpdb->query( "DELETE FROM {$table}" );
			foreach ( $data_tables[ $suffix ] as $row ) {
				if ( ! is_array( $row ) ) {
					continue;
				}
				$wpdb->insert( $table, $row );
			}

			$tables_imported[] = $suffix;
		}

		$options_imported = array();
		$data_options     = is_array( $decoded['options'] ?? null ) ? $decoded['options'] : array();
		foreach ( self::PORTABLE_OPTIONS as $option ) {
			if ( array_key_exists( $option, $data_options ) ) {
				update_option( $option, $data_options[ $option ], false );
				$options_imported[] = $option;
			}
		}

		$cert_config_imported = false;
		if ( is_array( $decoded['cert_config'] ?? null ) ) {
			$this->apply_cert_config( $decoded['cert_config'] );
			$cert_config_imported = true;
		}

		$this->audit->log(
			'config_portability',
			'config_imported',
			sprintf(
				'Configuration imported: %d table(s), %d option(s), certificate config %s.',
				count( $tables_imported ),
				count( $options_imported ),
				$cert_config_imported ? 'updated' : 'not included'
			),
			'warning'
		);

		return array(
			'tables_imported'      => $tables_imported,
			'options_imported'     => $options_imported,
			'cert_config_imported' => $cert_config_imported,
		);
	}

	/**
	 * Merges imported certificate config fields on top of what's already
	 * stored, explicitly refusing to ever write CERT_CONFIG_SECRET_FIELDS
	 * from an uploaded file -- even if a hand-edited or malicious file
	 * includes them, Certificate_Store::save_config() only ever receives
	 * the non-secret subset here.
	 */
	private function apply_cert_config( array $imported ): void {
		foreach ( self::CERT_CONFIG_SECRET_FIELDS as $secret_field ) {
			unset( $imported[ $secret_field ] );
		}

		$store   = new Certificate_Store();
		$current = $store->get_config();
		$store->save_config( array_merge( $current, $imported ) );
	}

	private function table_exists( string $table ): bool {
		global $wpdb;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
		return $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $table ) ) === $table;
	}
}
