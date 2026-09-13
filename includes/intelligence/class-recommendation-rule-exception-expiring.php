<?php
/**
 * Recommendation rule: one or more active exceptions expire soon (Phase 4F,
 * rule batch 1).
 *
 * Reuses Exception_Store::due_for_notice() -- already purpose-built for
 * exactly this ("notify administrators before expiry" -- see its own
 * docblock) -- and the same admin-configurable notice window
 * Exception_Scheduler's daily cron email already uses
 * (wp_sam_exception_notice_window_days, default Exception_Scheduler::
 * DEFAULT_NOTICE_WINDOW_DAYS), so this recommendation and that email always
 * agree on what "soon" means rather than defining a second, independent
 * threshold.
 *
 * One aggregate recommendation, not dismissible -- acting on this means
 * extending or revoking each exception directly on the Exceptions tab via
 * the existing Exception_Store flow, which naturally drops it out of
 * due_for_notice() (see Recommendation_Dismissal_Store's docblock for why
 * rules like this don't need dismissal storage of their own).
 */

declare( strict_types=1 );

namespace WP_SAM\Intelligence;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Recommendation_Rule_Exception_Expiring implements Recommendation_Rule {

	private const RISK_RANK = array(
		'high'   => 2,
		'medium' => 1,
		'low'    => 0,
	);

	public function id(): string {
		return 'exception_expiring_soon';
	}

	/** @return array<int, array<string, mixed>> */
	public function evaluate(): array {
		$window_days = max( 1, (int) get_option( 'wp_sam_exception_notice_window_days', Exception_Scheduler::DEFAULT_NOTICE_WINDOW_DAYS ) );
		$exceptions  = ( new Exception_Store() )->due_for_notice( $window_days );

		if ( empty( $exceptions ) ) {
			return array();
		}

		$max_risk      = 'low';
		$latest_expiry = '';
		$summary       = array();
		foreach ( $exceptions as $exception ) {
			$classification = (string) ( $exception['risk_classification'] ?? 'medium' );
			if ( ( self::RISK_RANK[ $classification ] ?? 1 ) > ( self::RISK_RANK[ $max_risk ] ?? 0 ) ) {
				$max_risk = $classification;
			}
			if ( (string) $exception['expiry_date'] > $latest_expiry ) {
				$latest_expiry = (string) $exception['expiry_date'];
			}
			$summary[] = sprintf( '%s/%s (expires %s)', $exception['control'], $exception['surface'], $exception['expiry_date'] );
		}

		return array(
			array(
				'key'                 => 'exception_expiring_soon',
				'layer'               => __( 'Layer 1: Governance and Operations', 'vcns-security-automation-manager' ),
				'pillar'              => null,
				'surface'             => null,
				'observed'            => sprintf(
					/* translators: 1: number of active exceptions expiring soon, 2: notice window in days */
					_n( '%1$d active exception expires within %2$d days.', '%1$d active exceptions expire within %2$d days.', count( $exceptions ), 'vcns-security-automation-manager' ),
					count( $exceptions ),
					$window_days
				),
				'why_it_matters'      => __( 'Once an exception expires without action, the control or surface it covers reverts to its normal enforced behaviour -- worth a deliberate decision (extend, revoke, or let it lapse) rather than a surprise.', 'vcns-security-automation-manager' ),
				'confidence'          => 'high',
				'risk'                => $max_risk,
				'evidence'            => array( 'exceptions' => $summary ),
				'recommended_action'  => __( 'Review each expiring exception on the Exceptions tab: extend, revoke, or let it lapse.', 'vcns-security-automation-manager' ),
				'alternative_action'  => null,
				'automation_eligible' => false,
				'rollback_position'   => __( 'Reviewing an exception does not change it until you explicitly extend or revoke it.', 'vcns-security-automation-manager' ),
				'evidence_changed_at' => $latest_expiry,
				'cta_url'             => admin_url( 'admin.php?page=security-automation-manager&tab=exceptions' ),
				'dismissible'         => false,
			),
		);
	}
}
