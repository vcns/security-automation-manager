<?php
/**
 * Recommendation rule: a detector an administrator has explicitly disabled
 * had real matching activity shortly before -- worth confirming that was a
 * deliberate decision (Phase 4F, rule batch 4, the last of Phase 4F's
 * planned rule batches).
 *
 * Important correctness note this rule is built around: `Detector_Engine::
 * evaluate()` skips a disabled detector entirely (`if ( ! $this->policies->
 * is_enabled( $detector->id() ) ) { continue; }`) -- it is never evaluated,
 * so it can generate zero new Event_Store rows while disabled. This rule
 * can therefore never mean "a disabled detector is silently matching live
 * traffic right now"; that is structurally impossible. What it actually
 * means is "this detector had real, recorded matches within the lookback
 * window" -- which, for a detector that's currently disabled, can only be
 * activity from before (or right up to) the moment it was switched off.
 * The lookback window and Detector_Policy_Store's own updated_at (when the
 * disablement itself was made) working together are what make this
 * naturally stop firing once enough time has passed with the detector
 * switched off -- there is no separate expiry logic needed for that.
 *
 * Dismissible: see Recommendation_Dismissal_Store's docblock.
 * evidence_changed_at is Detector_Policy_Store's own updated_at for this
 * detector -- a dismissal reopens if the admin touches this detector's
 * configuration again (e.g. toggling it off a second time), not on a fixed
 * timer.
 */

declare( strict_types=1 );

namespace WP_SAM\Intelligence;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Recommendation_Rule_Detector_Disabled_But_Firing implements Recommendation_Rule {

	private const LOOKBACK_HOURS = 24 * 7; // 7 days.

	public function id(): string {
		return 'detector_disabled_but_firing';
	}

	/** @return array<int, array<string, mixed>> */
	public function evaluate(): array {
		$policy_store    = new Detector_Policy_Store();
		$event_store     = new Event_Store();
		$recommendations = array();

		foreach ( Detector_Registry::all() as $detector ) {
			$detector_id = $detector->id();

			if ( $policy_store->is_enabled( $detector_id ) ) {
				continue; // Only an explicitly disabled detector is a candidate.
			}

			$occurrences = $event_store->occurrences_since( $detector_id, self::LOOKBACK_HOURS );
			if ( $occurrences <= 0 ) {
				continue;
			}

			$policy              = $policy_store->get( $detector_id );
			$evidence_changed_at = null !== $policy ? (string) $policy['updated_at'] : current_time( 'mysql', true );

			$recommendations[] = array(
				'key'                 => 'detector_disabled_but_firing_' . $detector_id,
				'layer'               => __( 'Layer 3: Continuous Intelligence', 'vcns-security-automation-manager' ),
				'pillar'              => null,
				'surface'             => null,
				'observed'            => sprintf(
					/* translators: 1: detector id (e.g. "sql-injection"), 2: number of matches, 3: number of days in the lookback window */
					_n(
						'The %1$s detector is disabled, but matched %2$d time in the %3$d days before (or up to) being disabled.',
						'The %1$s detector is disabled, but matched %2$d times in the %3$d days before (or up to) being disabled.',
						$occurrences,
						'vcns-security-automation-manager'
					),
					$detector_id,
					$occurrences,
					(int) ( self::LOOKBACK_HOURS / 24 )
				),
				'why_it_matters'      => $this->why_it_matters_text( $detector->description() ),
				'confidence'          => 'high',
				'risk'                => 'high',
				'evidence'            => array(
					'detector_id'     => $detector_id,
					'detector_family' => $detector->family(),
					'occurrences'     => $occurrences,
					'lookback_days'   => (int) ( self::LOOKBACK_HOURS / 24 ),
				),
				'recommended_action'  => __( 'Review this detector on the Detectors tab (Traffic Controls) and re-enable it if disabling it was not deliberate.', 'vcns-security-automation-manager' ),
				'alternative_action'  => __( 'If it was disabled because it produced false positives, leave it disabled -- this recommendation will stop appearing once the matching activity ages out of the lookback window.', 'vcns-security-automation-manager' ),
				'automation_eligible' => false,
				'rollback_position'   => __( 'Re-enabling a detector only resumes observation -- it does not itself start blocking anything unless its control action is separately set to enforce.', 'vcns-security-automation-manager' ),
				'evidence_changed_at' => $evidence_changed_at,
				'cta_url'             => admin_url( 'admin.php?page=security-automation-manager-traffic&tab=detectors' ),
				'dismissible'         => true,
			);
		}

		return $recommendations;
	}

	/** A detector's own description() may be '' (base class default) -- keep the sentence grammatical either way. */
	private function why_it_matters_text( string $detector_description ): string {
		if ( '' === $detector_description ) {
			return __( "A disabled detector is never evaluated at all -- any further activity matching this pattern will go completely unobserved until it's re-enabled.", 'vcns-security-automation-manager' );
		}

		return sprintf(
			/* translators: %s: the detector's own description of what it flags */
			__( "A disabled detector is never evaluated at all -- %s Any further activity matching this pattern will go completely unobserved until it's re-enabled.", 'vcns-security-automation-manager' ),
			lcfirst( $detector_description )
		);
	}
}
