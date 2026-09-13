<?php
/**
 * Recommendation rule: high/critical-risk configuration drift is open and
 * unexplained (Phase 4F, rule batch 1).
 *
 * One aggregate recommendation covering every qualifying item, the same way
 * Security_Health::drift_row() summarises "N items requiring review" rather
 * than one row per item -- consistent with how this admin surface already
 * presents drift.
 *
 * Not dismissible: acting on this means dispositioning each item directly
 * on the Baseline & Drift page via the existing Drift_Store::disposition()
 * flow, which naturally drops it out of all('unexplained') -- no separate
 * dismissal storage needed (see Recommendation_Dismissal_Store's docblock).
 */

declare( strict_types=1 );

namespace WP_SAM\Intelligence;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Recommendation_Rule_Unexplained_Drift implements Recommendation_Rule {

	public function id(): string {
		return 'unexplained_high_risk_drift';
	}

	/** @return array<int, array<string, mixed>> */
	public function evaluate(): array {
		$items = array_values(
			array_filter(
				( new Drift_Store() )->all( 'unexplained' ),
				static fn( array $item ): bool => in_array( $item['risk_level'], array( 'high', 'critical' ), true )
			)
		);

		if ( empty( $items ) ) {
			return array();
		}

		$has_critical = false;
		$last_seen    = '';
		$summary      = array();
		foreach ( $items as $item ) {
			if ( 'critical' === $item['risk_level'] ) {
				$has_critical = true;
			}
			if ( (string) $item['last_seen_at'] > $last_seen ) {
				$last_seen = (string) $item['last_seen_at'];
			}
			$summary[] = sprintf( '%s/%s: %s', $item['category'], $item['surface'], $item['item_key'] );
		}

		return array(
			array(
				'key'                 => 'unexplained_high_risk_drift',
				'layer'               => __( 'Layer 3: Continuous Intelligence', 'vcns-security-automation-manager' ),
				'pillar'              => null,
				'surface'             => null,
				'observed'            => sprintf(
					/* translators: %d: number of unexplained high/critical-risk drift items */
					_n( '%d unexplained configuration-drift item is high or critical risk.', '%d unexplained configuration-drift items are high or critical risk.', count( $items ), 'vcns-security-automation-manager' ),
					count( $items )
				),
				'why_it_matters'      => __( "Drift this plugin can't already explain (e.g. against a known change window) may be an unreviewed configuration change, or something that shouldn't have happened at all.", 'vcns-security-automation-manager' ),
				'confidence'          => 'high',
				'risk'                => $has_critical ? 'critical' : 'high',
				'evidence'            => array( 'items' => $summary ),
				'recommended_action'  => __( 'Review each item on the Baseline & Drift page and record a disposition (expected, approved, or resolved).', 'vcns-security-automation-manager' ),
				'alternative_action'  => null,
				'automation_eligible' => false,
				'rollback_position'   => __( 'Reviewing an item only records a disposition -- it never changes any live configuration.', 'vcns-security-automation-manager' ),
				'evidence_changed_at' => $last_seen,
				'cta_url'             => admin_url( 'admin.php?page=security-automation-manager-baseline&tab=drift' ),
				'dismissible'         => false,
			),
		);
	}
}
