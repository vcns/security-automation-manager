<?php
/**
 * Recommendation rule: a report-only-capable pillar (currently Cross-Origin-
 * Opener-Policy and Cross-Origin-Embedder-Policy -- the only two simple
 * pillars with a genuine report-only learning mode, detected generically via
 * Pillar_Registry::pillars()'s own mode_status_map rather than a hardcoded
 * pillar-key list, so a future pillar gaining the same capability is picked
 * up automatically) has run quiet long enough to suggest promoting it to
 * enforce (Phase 4F, rule batch 3).
 *
 * Mirrors Recommendation_Rule_Csp_Enforce_Ready's shape exactly, on the
 * pillar side of the fence: report-only + no active exception + zero
 * violations in the quiet window. Exception control strings follow
 * `{pillar-key}_enforce` (e.g. `cross-origin-opener-policy_enforce`) --
 * mechanically derived from the pillar key itself, matching the existing
 * `csp_enforce` convention closely enough for an administrator to guess it,
 * without a separate abbreviation table to maintain.
 *
 * Dismissible: see Recommendation_Dismissal_Store's docblock. evidence_
 * changed_at is the pillar/surface row's own sam_pillar_profiles.updated_at.
 */

declare( strict_types=1 );

namespace WP_SAM\Intelligence;

use WP_SAM\Admin\Pillar_Registry;
use WP_SAM\Security\Pillar_Violation_Store;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Recommendation_Rule_Pillar_Enforce_Ready implements Recommendation_Rule {

	private const QUIET_WINDOW_DAYS = 30;

	public function id(): string {
		return 'pillar_enforce_ready';
	}

	/** @return array<int, array<string, mixed>> */
	public function evaluate(): array {
		global $wpdb;

		$exception_store   = new Exception_Store();
		$pillar_violations = new Pillar_Violation_Store();
		$recommendations   = array();

		foreach ( Pillar_Registry::pillars() as $pillar_key => $meta ) {
			if ( ! array_key_exists( 'report-only', $meta['mode_status_map'] ) ) {
				continue; // Only pillars with a genuine report-only learning mode are candidates.
			}

			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
			$rows = $wpdb->get_results(
				$wpdb->prepare(
					// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
					"SELECT surface, payload, updated_at FROM {$wpdb->prefix}sam_pillar_profiles WHERE pillar = %s AND enabled = 1",
					$pillar_key
				),
				ARRAY_A
			);
			$rows = ! empty( $rows ) ? $rows : array();

			foreach ( $rows as $row ) {
				$surface = (string) $row['surface'];
				$mode    = call_user_func( $meta['mode_extractor'], array( 'payload' => $row['payload'] ) );

				if ( 'report-only' !== $mode ) {
					continue;
				}
				if ( $exception_store->has_active_for( $pillar_key . '_enforce', $surface ) ) {
					continue;
				}
				if ( $pillar_violations->count_since( $pillar_key, $surface, self::QUIET_WINDOW_DAYS * 24 ) > 0 ) {
					continue;
				}

				$recommendations[] = array(
					'key'                 => 'pillar_enforce_ready_' . $pillar_key . '_' . $surface,
					'layer'               => __( 'Layer 4: Browser Security Policies', 'vcns-security-automation-manager' ),
					'pillar'              => $meta['label'],
					'surface'             => $surface,
					'observed'            => sprintf(
						/* translators: 1: pillar label (e.g. "Cross-Origin-Opener-Policy"), 2: surface name, 3: number of days */
						__( '%1$s on the %2$s surface has been report-only with no violations reported in the last %3$d days.', 'vcns-security-automation-manager' ),
						$meta['label'],
						$surface,
						self::QUIET_WINDOW_DAYS
					),
					'why_it_matters'      => __( 'Report-only mode observes and records what would happen but never actually blocks anything -- enforcing is what makes this protection real.', 'vcns-security-automation-manager' ),
					'confidence'          => 'medium',
					'risk'                => 'low',
					'evidence'            => array(
						'pillar'               => $pillar_key,
						'surface'              => $surface,
						'quiet_window_days'    => self::QUIET_WINDOW_DAYS,
						'violations_in_window' => 0,
					),
					'recommended_action'  => sprintf(
						/* translators: %s: pillar label */
						__( 'Promote %s to Enforce for this surface.', 'vcns-security-automation-manager' ),
						$meta['label']
					),
					'alternative_action'  => __( "If you'd like more observation time first, no action is needed -- report-only mode keeps learning on its own.", 'vcns-security-automation-manager' ),
					'automation_eligible' => false,
					'rollback_position'   => __( 'This can be reverted to report-only at any time from its own settings page.', 'vcns-security-automation-manager' ),
					'evidence_changed_at' => (string) $row['updated_at'],
					'cta_url'             => admin_url( 'admin.php?page=' . $meta['page'] . '&tab=' . $meta['tab'] ),
					'dismissible'         => true,
				);
			}
		}

		return $recommendations;
	}
}
