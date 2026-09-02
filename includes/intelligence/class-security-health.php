<?php
/**
 * Site Security Health: a non-gamified, at-a-glance operational summary
 * across every pillar this plugin manages (Phase 3I, .roadmap/phase3_
 * early_plan.md §21 Site Security Health, §26 Evidence and Assurance).
 *
 * Deliberately not a numeric score -- §21 is explicit that Phase 3 should
 * avoid "arbitrary gamified security scoring". Each row is a plain
 * {label, value, status, detail} tuple, the same shape Readiness_Checker
 * already uses, reused here for visual consistency even though this
 * class covers security *outcomes* (drift, certificate expiry, open
 * exceptions) rather than Readiness_Checker's plugin-operational checks
 * (schema version, table existence).
 *
 * "External verification" is included as its own row, always 'info',
 * because the roadmap's own example health summary lists it -- but
 * Phase 3G (the central verification service it would report on) is
 * deliberately not built yet, so this honestly says so rather than
 * omitting the row or faking a status.
 */

declare( strict_types=1 );

namespace WP_SAM\Intelligence;

use WP_SAM\CSP\Automation_Config;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Security_Health {

	private const CERT_EXPIRY_WARNING_DAYS = 14;

	private const SCAN_FRESHNESS_WARNING_HOURS = 48;

	/** @return array<string, array{label:string, value:string, status:string, detail:string}> */
	public function get_report(): array {
		return array(
			'enforcement'           => $this->enforcement_row(),
			'drift'                 => $this->drift_row(),
			'certificates'          => $this->certificates_row(),
			'dependencies'          => $this->dependencies_row(),
			'exceptions'            => $this->exceptions_row(),
			'automation'            => $this->automation_row(),
			'evidence_freshness'    => $this->evidence_freshness_row(),
			'external_verification' => $this->external_verification_row(),
		);
	}

	private function enforcement_row(): array {
		global $wpdb;
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$csp_enforcing = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$wpdb->prefix}csp_policy_profiles WHERE mode = 'enforce'" );
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$traffic_enforcing = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$wpdb->prefix}sam_traffic_policies WHERE mode = 'enforce'" );

		return array(
			'label'  => __( 'Enforcement', 'vcns-security-automation-manager' ),
			'value'  => sprintf(
				/* translators: 1: CSP surfaces enforcing, 2: traffic-control surfaces enforcing */
				__( 'CSP enforcing on %1$d/4 surfaces, Traffic Controls on %2$d/4', 'vcns-security-automation-manager' ),
				$csp_enforcing,
				$traffic_enforcing
			),
			'status' => ( $csp_enforcing > 0 || $traffic_enforcing > 0 ) ? 'pass' : 'info',
			'detail' => __( 'A surface stays in report-only/observe mode until an administrator explicitly promotes it -- this is expected on a new install.', 'vcns-security-automation-manager' ),
		);
	}

	private function drift_row(): array {
		$baseline = ( new Baseline_Store() )->get_current();
		if ( null === $baseline ) {
			return array(
				'label'  => __( 'Drift', 'vcns-security-automation-manager' ),
				'value'  => __( 'No baseline captured yet', 'vcns-security-automation-manager' ),
				'status' => 'info',
				'detail' => __( 'Capture a baseline from Baseline & Drift to start tracking configuration drift.', 'vcns-security-automation-manager' ),
			);
		}

		$open  = ( new Drift_Store() )->all( 'unexplained' );
		$count = count( $open );

		return array(
			'label'  => __( 'Drift', 'vcns-security-automation-manager' ),
			'value'  => sprintf(
				/* translators: %d: number of unexplained drift records */
				_n( '%d item requiring review', '%d items requiring review', $count, 'vcns-security-automation-manager' ),
				$count
			),
			'status' => $count > 0 ? 'warning' : 'pass',
			'detail' => __( 'Review open drift on the Baseline & Drift page.', 'vcns-security-automation-manager' ),
		);
	}

	private function certificates_row(): array {
		global $wpdb;
		$table = $wpdb->prefix . 'sam_certificates';
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
		$certs = $wpdb->get_results(
			$wpdb->prepare(
				// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				"SELECT not_after FROM {$table} WHERE status = %s",
				'issued'
			),
			ARRAY_A
		);
		$certs = ! empty( $certs ) ? $certs : array();

		if ( empty( $certs ) ) {
			return array(
				'label'  => __( 'Certificates', 'vcns-security-automation-manager' ),
				'value'  => __( 'None configured', 'vcns-security-automation-manager' ),
				'status' => 'info',
				'detail' => '',
			);
		}

		$now           = time();
		$expired       = 0;
		$expiring_soon = 0;
		foreach ( $certs as $cert ) {
			$not_after = strtotime( (string) $cert['not_after'] );
			if ( false === $not_after ) {
				continue;
			}
			if ( $not_after < $now ) {
				++$expired;
			} elseif ( $not_after < $now + ( self::CERT_EXPIRY_WARNING_DAYS * DAY_IN_SECONDS ) ) {
				++$expiring_soon;
			}
		}

		$status = 'pass';
		if ( $expired > 0 ) {
			$status = 'fail';
		} elseif ( $expiring_soon > 0 ) {
			$status = 'warning';
		}

		return array(
			'label'  => __( 'Certificates', 'vcns-security-automation-manager' ),
			'value'  => $expired > 0
				? sprintf( /* translators: %d: number of expired certificates */ _n( '%d expired', '%d expired', $expired, 'vcns-security-automation-manager' ), $expired )
				: ( $expiring_soon > 0
					? sprintf( /* translators: %d: number of certificates expiring soon */ _n( '%d expiring within 14 days', '%d expiring within 14 days', $expiring_soon, 'vcns-security-automation-manager' ), $expiring_soon )
					: __( 'Healthy', 'vcns-security-automation-manager' ) ),
			'status' => $status,
			'detail' => '',
		);
	}

	private function dependencies_row(): array {
		global $wpdb;
		$table = $wpdb->prefix . 'sam_dependency_inventory';
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
		$unclassified = (int) $wpdb->get_var(
			$wpdb->prepare(
				// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				"SELECT COUNT(*) FROM {$table} WHERE classification = %s",
				'unclassified'
			)
		);

		return array(
			'label'  => __( 'Third-party dependencies', 'vcns-security-automation-manager' ),
			'value'  => sprintf(
				/* translators: %d: number of unclassified dependencies */
				_n( '%d unclassified', '%d unclassified', $unclassified, 'vcns-security-automation-manager' ),
				$unclassified
			),
			'status' => $unclassified > 0 ? 'warning' : 'pass',
			'detail' => __( 'Review the Scripts page to approve, pin, or reject each origin.', 'vcns-security-automation-manager' ),
		);
	}

	private function exceptions_row(): array {
		global $wpdb;
		$now = current_time( 'mysql', true );

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
		$ip_allow = (int) $wpdb->get_var(
			$wpdb->prepare(
				// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				"SELECT COUNT(*) FROM {$wpdb->prefix}sam_ip_rules WHERE list_type = %s",
				'allow'
			)
		);
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$persistent_blocks = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$wpdb->prefix}sam_traffic_blocks WHERE is_persistent = 1" );
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
		$dep_exceptions = (int) $wpdb->get_var(
			$wpdb->prepare(
				// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				"SELECT COUNT(*) FROM {$wpdb->prefix}sam_dependency_inventory WHERE classification = %s",
				'exception'
			)
		);
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
		$csp_overrides = (int) $wpdb->get_var(
			$wpdb->prepare(
				// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				"SELECT COUNT(*) FROM {$wpdb->prefix}csp_policy_profiles WHERE override_expires_at IS NOT NULL AND override_expires_at > %s",
				$now
			)
		);
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
		$pillar_overrides = (int) $wpdb->get_var(
			$wpdb->prepare(
				// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				"SELECT COUNT(*) FROM {$wpdb->prefix}sam_pillar_profiles WHERE override_expires_at IS NOT NULL AND override_expires_at > %s",
				$now
			)
		);

		$total = $ip_allow + $persistent_blocks + $dep_exceptions + $csp_overrides + $pillar_overrides;

		return array(
			'label'  => __( 'Exceptions', 'vcns-security-automation-manager' ),
			'value'  => sprintf(
				/* translators: %d: total number of active exceptions across the plugin */
				_n( '%d active', '%d active', $total, 'vcns-security-automation-manager' ),
				$total
			),
			'status' => 'info',
			'detail' => sprintf(
				/* translators: 1: allowed IPs, 2: permanent traffic blocks, 3: dependency exceptions, 4: CSP overrides, 5: pillar overrides */
				__( 'IP allow rules: %1$d. Permanent traffic blocks: %2$d. Dependency exceptions: %3$d. CSP overrides: %4$d. Header overrides: %5$d.', 'vcns-security-automation-manager' ),
				$ip_allow,
				$persistent_blocks,
				$dep_exceptions,
				$csp_overrides,
				$pillar_overrides
			),
		);
	}

	private function automation_row(): array {
		$config      = ( new Automation_Config() )->all();
		$mode_counts = array();
		foreach ( $config as $surface_config ) {
			$mode                 = (string) ( $surface_config['mode'] ?? 'manual' );
			$mode_counts[ $mode ] = ( $mode_counts[ $mode ] ?? 0 ) + 1;
		}
		$parts = array();
		foreach ( $mode_counts as $mode => $count ) {
			$parts[] = sprintf( '%d %s', $count, Automation_Config::mode_label( $mode ) );
		}

		return array(
			'label'  => __( 'Automation', 'vcns-security-automation-manager' ),
			'value'  => ! empty( $parts ) ? implode( ', ', $parts ) : __( 'Not configured', 'vcns-security-automation-manager' ),
			'status' => 'info',
			'detail' => __( 'CSP source-approval automation posture, per surface.', 'vcns-security-automation-manager' ),
		);
	}

	private function evidence_freshness_row(): array {
		global $wpdb;
		$table = $wpdb->prefix . 'sam_scan_logs';
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
		$last_completed = $wpdb->get_var(
			$wpdb->prepare(
				// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				"SELECT completed_at FROM {$table} WHERE status = %s ORDER BY completed_at DESC LIMIT 1",
				'completed'
			)
		);

		if ( empty( $last_completed ) ) {
			return array(
				'label'  => __( 'Evidence freshness', 'vcns-security-automation-manager' ),
				'value'  => __( 'No scan has completed yet', 'vcns-security-automation-manager' ),
				'status' => 'warning',
				'detail' => '',
			);
		}

		$age_seconds = time() - strtotime( (string) $last_completed );
		$hours       = max( 0, (int) floor( $age_seconds / HOUR_IN_SECONDS ) );

		return array(
			'label'  => __( 'Evidence freshness', 'vcns-security-automation-manager' ),
			'value'  => sprintf(
				/* translators: %d: hours since the last completed scan */
				__( 'Last scan completed %d hour(s) ago', 'vcns-security-automation-manager' ),
				$hours
			),
			'status' => $hours <= self::SCAN_FRESHNESS_WARNING_HOURS ? 'pass' : 'warning',
			'detail' => '',
		);
	}

	private function external_verification_row(): array {
		return array(
			'label'  => __( 'External verification', 'vcns-security-automation-manager' ),
			'value'  => __( 'Not available yet', 'vcns-security-automation-manager' ),
			'status' => 'info',
			'detail' => __( 'Confirming what an external client actually receives requires a central verification service this build does not include -- a future phase.', 'vcns-security-automation-manager' ),
		);
	}
}
