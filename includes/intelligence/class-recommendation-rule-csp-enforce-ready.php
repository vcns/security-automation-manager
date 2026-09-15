<?php
/**
 * Recommendation rule: a report-only CSP surface has run quiet long enough
 * to suggest promoting it to enforce (Phase 4F, rule batch 2).
 *
 * Fires per surface, only when all three hold: the surface's own
 * `csp_policy_profiles.mode` is `report-only` (a `disabled` surface has no
 * policy running at all, a different situation this rule doesn't address);
 * no active `csp_enforce` exception exists for that surface -- an
 * administrator who has already recorded a deliberate reason to stay
 * report-only shouldn't be nudged to override their own decision; and zero
 * CSP violations have been reported on that surface in the quiet window
 * (`Violation_Reporter::count_since()`, the one new read method this batch
 * adds to a table that was previously write-only).
 *
 * Dismissible: a "quiet live condition" with no natural underlying per-item
 * record of its own (see Recommendation_Dismissal_Store's docblock) --
 * evidence_changed_at is the surface's own `csp_policy_profiles.updated_at`,
 * so a dismissal reopens if that surface's policy configuration changes
 * again, not on some unrelated timer.
 */

declare( strict_types=1 );

namespace WP_SAM\Intelligence;

use WP_SAM\CSP\Violation_Reporter;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Recommendation_Rule_Csp_Enforce_Ready implements Recommendation_Rule {

	private const QUIET_WINDOW_DAYS = 30;

	public function id(): string {
		return 'csp_enforce_ready';
	}

	/** @return array<int, array<string, mixed>> */
	public function evaluate(): array {
		global $wpdb;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$rows = $wpdb->get_results( "SELECT surface, mode, updated_at FROM {$wpdb->prefix}csp_policy_profiles", ARRAY_A );
		$rows = ! empty( $rows ) ? $rows : array();

		$exception_store = new Exception_Store();
		$recommendations = array();

		foreach ( $rows as $row ) {
			$surface = (string) $row['surface'];

			if ( 'report-only' !== $row['mode'] ) {
				continue;
			}
			if ( $exception_store->has_active_for( 'csp_enforce', $surface ) ) {
				continue;
			}
			if ( Violation_Reporter::count_since( $surface, self::QUIET_WINDOW_DAYS * 24 ) > 0 ) {
				continue;
			}

			$recommendations[] = array(
				'key'                 => 'csp_enforce_ready_' . $surface,
				'layer'               => __( 'Layer 4: Browser Security Policies', 'vcns-security-automation-manager' ),
				'pillar'              => __( 'Content Security Policy', 'vcns-security-automation-manager' ),
				'surface'             => $surface,
				'observed'            => sprintf(
					/* translators: 1: surface name (e.g. "frontend"), 2: number of days */
					__( "The %1\$s surface's Content Security Policy has been report-only with no violations reported in the last %2\$d days.", 'vcns-security-automation-manager' ),
					$surface,
					self::QUIET_WINDOW_DAYS
				),
				'why_it_matters'      => __( "A policy that has run quietly this long in report-only mode is a strong signal it already matches what your site actually loads -- enforcing it is what actually blocks the injected scripts and data exfiltration attempts CSP exists to stop. Report-only mode alone doesn't block anything.", 'vcns-security-automation-manager' ),
				'confidence'          => 'medium',
				'risk'                => 'low',
				'evidence'            => array(
					'surface'              => $surface,
					'quiet_window_days'    => self::QUIET_WINDOW_DAYS,
					'violations_in_window' => 0,
				),
				'recommended_action'  => __( 'Promote this surface to Enforce from the CSP Dashboard.', 'vcns-security-automation-manager' ),
				'alternative_action'  => __( "If you'd like more observation time first, no action is needed -- report-only mode keeps learning on its own.", 'vcns-security-automation-manager' ),
				'automation_eligible' => false,
				'rollback_position'   => __( 'A surface can be reverted to report-only at any time from the CSP Dashboard.', 'vcns-security-automation-manager' ),
				'evidence_changed_at' => (string) $row['updated_at'],
				'cta_url'             => admin_url( 'admin.php?page=security-automation-manager-dashboard' ),
				'dismissible'         => true,
			);
		}

		return $recommendations;
	}
}
