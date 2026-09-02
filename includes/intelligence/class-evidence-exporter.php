<?php
/**
 * Builds a read-only evidence bundle for security reviews, MSP reporting,
 * audit preparation, and technical control review (Phase 3I, .roadmap/
 * phase3_early_plan.md §26 Evidence and Assurance).
 *
 * Deliberately distinct from Config_Portability: that class exists to
 * back up and restore this plugin's own configuration (destructive
 * re-import, excludes every log/ledger table by design -- see its own
 * docblock); this class exists to describe the current state of controls
 * to a third party and never gets imported back into anything. Every
 * export explicitly disclaims compliance/certification -- §26 is
 * explicit: "The product must not claim that technical evidence alone
 * establishes compliance or certification."
 */

declare( strict_types=1 );

namespace WP_SAM\Intelligence;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Evidence_Exporter {

	private const AUDIT_LOG_EXCERPT_LIMIT = 50;

	/** @return array<string, mixed> JSON-serialisable evidence bundle. */
	public function build(): array {
		return array(
			'format_version'    => 1,
			'exported_at'       => current_time( 'mysql', true ),
			'site_url'          => get_bloginfo( 'url' ),
			'plugin_version'    => defined( 'WP_SAM_VERSION' ) ? WP_SAM_VERSION : '',
			'disclaimer'        => __( 'This export documents technical security controls as locally configured by this plugin. It is evidence to support a review, not a certification, attestation, or compliance determination of any kind. A named framework below is informational context only.', 'vcns-security-automation-manager' ),
			'framework_context' => array( 'Cyber Essentials', 'ISO/IEC 27001', 'PCI DSS', 'OWASP ASVS', 'CIS Controls' ),
			'health_summary'    => ( new Security_Health() )->get_report(),
			'controls'          => array(
				'csp'              => $this->csp_controls(),
				'pillars'          => $this->pillar_controls(),
				'traffic_controls' => $this->traffic_controls(),
			),
			'exceptions'        => $this->exceptions_detail(),
			'certificates'      => $this->certificates_detail(),
			'baseline'          => $this->baseline_detail(),
			'drift_open_count'  => count( ( new Drift_Store() )->all( 'unexplained' ) ),
			'recent_change_log' => ( new Change_Log_Store() )->all( 20 ),
			'audit_log_excerpt' => $this->audit_log_excerpt(),
		);
	}

	/** @return array<int, array<string, mixed>> */
	private function csp_controls(): array {
		global $wpdb;
		$table = $wpdb->prefix . 'csp_policy_profiles';
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$rows = $wpdb->get_results( "SELECT surface, mode, strict_dynamic, trusted_types FROM {$table} ORDER BY surface", ARRAY_A );
		return ! empty( $rows ) ? $rows : array();
	}

	/** @return array<int, array<string, mixed>> */
	private function pillar_controls(): array {
		global $wpdb;
		$table = $wpdb->prefix . 'sam_pillar_profiles';
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$rows = $wpdb->get_results( "SELECT pillar, surface, enabled FROM {$table} ORDER BY pillar, surface", ARRAY_A );
		return ! empty( $rows ) ? $rows : array();
	}

	/** @return array<int, array<string, mixed>> */
	private function traffic_controls(): array {
		global $wpdb;
		$table = $wpdb->prefix . 'sam_traffic_policies';
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$rows = $wpdb->get_results( "SELECT surface, mode, rate_limit_max_requests, rate_limit_window_seconds FROM {$table} ORDER BY surface", ARRAY_A );
		return ! empty( $rows ) ? $rows : array();
	}

	/** @return array<string, mixed> */
	private function exceptions_detail(): array {
		global $wpdb;
		$now = current_time( 'mysql', true );

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
		$ip_allow = $wpdb->get_results(
			$wpdb->prepare(
				// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				"SELECT cidr, surface, reason, created_at, expires_at FROM {$wpdb->prefix}sam_ip_rules WHERE list_type = %s",
				'allow'
			),
			ARRAY_A
		);
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$persistent_blocks = $wpdb->get_results( "SELECT ip, surface, reason, first_seen_at FROM {$wpdb->prefix}sam_traffic_blocks WHERE is_persistent = 1", ARRAY_A );
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
		$dep_exceptions = $wpdb->get_results(
			$wpdb->prepare(
				// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				"SELECT surface, resource_type, origin FROM {$wpdb->prefix}sam_dependency_inventory WHERE classification = %s",
				'exception'
			),
			ARRAY_A
		);
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
		$csp_overrides = $wpdb->get_results(
			$wpdb->prepare(
				// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				"SELECT surface, override_owner, override_expires_at FROM {$wpdb->prefix}csp_policy_profiles WHERE override_expires_at IS NOT NULL AND override_expires_at > %s",
				$now
			),
			ARRAY_A
		);

		return array(
			'ip_allow_rules'        => ! empty( $ip_allow ) ? $ip_allow : array(),
			'permanent_blocks'      => ! empty( $persistent_blocks ) ? $persistent_blocks : array(),
			'dependency_exceptions' => ! empty( $dep_exceptions ) ? $dep_exceptions : array(),
			'csp_overrides'         => ! empty( $csp_overrides ) ? $csp_overrides : array(),
		);
	}

	/** @return array<int, array<string, mixed>> */
	private function certificates_detail(): array {
		global $wpdb;
		$table = $wpdb->prefix . 'sam_certificates';
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
		$rows = $wpdb->get_results(
			$wpdb->prepare(
				// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				"SELECT domains, environment, status, not_before, not_after FROM {$table} WHERE status = %s",
				'issued'
			),
			ARRAY_A
		);
		return ! empty( $rows ) ? $rows : array();
	}

	/** @return array<string, mixed>|null */
	private function baseline_detail(): ?array {
		$current = ( new Baseline_Store() )->get_current();
		if ( null === $current ) {
			return null;
		}
		return array(
			'version_number' => $current['version_number'],
			'approved_at'    => $current['approved_at'],
			'note'           => $current['note'],
		);
	}

	/** @return array<int, array<string, mixed>> Most recent warning/error audit-log entries. */
	private function audit_log_excerpt(): array {
		global $wpdb;
		$table = $wpdb->prefix . 'sam_audit_log';
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.NotPrepared,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$rows = $wpdb->get_results(
			$wpdb->prepare(
				// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				"SELECT component, event, detail, severity, created_at FROM {$table} WHERE severity IN ('warning','error') ORDER BY created_at DESC LIMIT %d",
				self::AUDIT_LOG_EXCERPT_LIMIT
			),
			ARRAY_A
		);
		return ! empty( $rows ) ? $rows : array();
	}
}
