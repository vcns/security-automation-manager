<?php
/**
 * Plugin-specific operational readiness checks.
 */

declare( strict_types=1 );

namespace WP_SAM\Admin;

use WP_SAM\Activator;
use WP_SAM\CSP\Policy_Builder;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Readiness_Checker {

	public function get_report(): array {
		return array(
			'plugin' => $this->get_plugin_details(),
			'schema' => $this->get_schema_health(),
			'health' => $this->get_runtime_health(),
		);
	}

	private function get_plugin_details(): array {
		$installed_schema = (string) get_option( 'wp_sam_db_version', '0' );

		return array(
			array(
				'label'  => __( 'Plugin version', 'vcns-security-automation-manager' ),
				'value'  => WP_SAM_VERSION,
				'status' => 'pass',
			),
			array(
				'label'  => __( 'Database schema version', 'vcns-security-automation-manager' ),
				'value'  => sprintf(
					/* translators: 1: installed schema version, 2: code schema version */
					__( 'Installed %1$s, code expects %2$s', 'vcns-security-automation-manager' ),
					$installed_schema,
					WP_SAM_DB_VERSION
				),
				'status' => (string) WP_SAM_DB_VERSION === $installed_schema ? 'pass' : 'fail',
			),
			array(
				'label'  => __( 'Plugin file', 'vcns-security-automation-manager' ),
				'value'  => plugin_basename( WP_SAM_FILE ),
				'status' => 'pass',
			),
			array(
				'label'  => __( 'Table prefix in use', 'vcns-security-automation-manager' ),
				'value'  => $this->get_table_prefix(),
				'status' => 'pass',
			),
		);
	}

	private function get_schema_health(): array {
		global $wpdb;

		$health = array();
		foreach ( Activator::get_table_suffixes() as $suffix ) {
			$table  = $wpdb->prefix . $suffix;
			$exists = $this->table_exists( $table );
			$count  = null;

			if ( $exists ) {
				// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				$count = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$table}" );
			}

			$health[] = array(
				'table'  => $table,
				'status' => $exists ? 'pass' : 'fail',
				'rows'   => $count,
			);
		}

		return $health;
	}

	private function get_runtime_health(): array {
		$report_endpoint = (string) get_option( 'wp_sam_report_endpoint_url', '' );
		if ( '' === trim( $report_endpoint ) ) {
			$report_endpoint = rest_url( 'sam/v1/report' );
		}

		$profile_count = $this->count_table_rows_where(
			'csp_policy_profiles',
			"surface IN ('frontend', 'admin', 'login', 'api')"
		);
		$version_count = $this->count_table_rows_where( 'sam_policy_versions', '1=1' );

		return array(
			array(
				'label'  => __( 'Required policy profiles', 'vcns-security-automation-manager' ),
				'value'  => sprintf(
					/* translators: %d: policy profile count */
					__( '%d of 4 expected surfaces are present', 'vcns-security-automation-manager' ),
					$profile_count
				),
				'status' => 4 === $profile_count ? 'pass' : 'fail',
			),
			array(
				'label'  => __( 'Policy version snapshots', 'vcns-security-automation-manager' ),
				'value'  => sprintf(
					/* translators: %d: policy version count */
					__( '%d snapshot records found', 'vcns-security-automation-manager' ),
					$version_count
				),
				'status' => $version_count >= 4 ? 'pass' : 'warning',
			),
			array(
				'label'  => __( 'Reporting endpoint', 'vcns-security-automation-manager' ),
				'value'  => $report_endpoint,
				'status' => $this->is_valid_http_url( $report_endpoint ) ? 'pass' : 'fail',
			),
			array(
				'label'  => __( 'Policy header emission', 'vcns-security-automation-manager' ),
				'value'  => $this->policy_header_summary(),
				'status' => 'pass',
			),
			array(
				'label'  => __( 'Daily scan schedule', 'vcns-security-automation-manager' ),
				'value'  => wp_next_scheduled( 'wp_sam_daily_scan' )
					? __( 'Scheduled', 'vcns-security-automation-manager' )
					: __( 'Not scheduled', 'vcns-security-automation-manager' ),
				'status' => wp_next_scheduled( 'wp_sam_daily_scan' ) ? 'pass' : 'warning',
			),
			array(
				'label'  => __( 'Automation default posture', 'vcns-security-automation-manager' ),
				'value'  => $this->automation_modes_summary(),
				'status' => 'pass',
			),
		);
	}

	private function count_table_rows_where( string $suffix, string $where ): int {
		global $wpdb;

		$table = $wpdb->prefix . $suffix;
		if ( ! $this->table_exists( $table ) ) {
			return 0;
		}

		// The table suffix and where clause are fixed by this class, never user input.
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		return (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$table} WHERE {$where}" );
	}

	private function table_exists( string $table ): bool {
		global $wpdb;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
		return $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $table ) ) === $table;
	}

	private function get_table_prefix(): string {
		global $wpdb;

		return $wpdb->prefix;
	}

	private function is_valid_http_url( string $url ): bool {
		$parts  = wp_parse_url( $url );
		$scheme = is_array( $parts ) ? strtolower( (string) ( $parts['scheme'] ?? '' ) ) : '';
		$host   = is_array( $parts ) ? (string) ( $parts['host'] ?? '' ) : '';

		return '' !== $host && in_array( $scheme, array( 'http', 'https' ), true );
	}

	private function automation_modes_summary(): string {
		$config = get_option( 'wp_sam_automation_config', array() );
		if ( ! is_array( $config ) || empty( $config ) ) {
			return __( 'No automation configuration found', 'vcns-security-automation-manager' );
		}

		$modes = array();
		foreach ( array( 'frontend', 'admin', 'login', 'api' ) as $surface ) {
			$surface_config = $config[ $surface ] ?? array();
			$modes[]        = $surface . ': ' . ( is_array( $surface_config ) ? ( $surface_config['mode'] ?? 'manual' ) : 'manual' );
		}

		return implode( ', ', $modes );
	}

	private function policy_header_summary(): string {
		$custom = Policy_Builder::sanitize_custom_policy_header_name( get_option( 'wp_sam_policy_header_name', '' ) );
		if ( '' !== $custom ) {
			return sprintf(
				/* translators: %s: custom policy header name */
				__( 'Custom origin header: %s', 'vcns-security-automation-manager' ),
				$custom
			);
		}

		return sprintf(
			/* translators: 1: report-only header name, 2: enforce header name */
			__( 'Mode based: %1$s or %2$s', 'vcns-security-automation-manager' ),
			Policy_Builder::DEFAULT_REPORT_ONLY_HEADER,
			Policy_Builder::DEFAULT_ENFORCE_HEADER
		);
	}
}
