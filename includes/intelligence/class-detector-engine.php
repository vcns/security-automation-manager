<?php
/**
 * Runs every registered detector against a request context and collects
 * their Findings.
 *
 * Fails open: a detector that throws is skipped (its exception is
 * swallowed) so one broken detector can neither break the request nor stop
 * the remaining detectors from running. On an empty Detector_Registry
 * (every build until Phase 3C registers a real detector), evaluate()
 * always returns an empty array.
 *
 * A detector an administrator has disabled via Detector_Policy_Store (Phase
 * 4B) is skipped exactly like an unavailable one below -- disabled means
 * "don't run this detector at all," not "run it but discard the Finding."
 * Every Finding that IS produced carries the resolved 'control_action'
 * (Detector_Policy_Store::control_action_for()) so Request_Observer can act
 * on it without needing its own Detector_Registry/Detector_Policy_Store
 * lookups.
 */

declare( strict_types=1 );

namespace WP_SAM\Intelligence;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Detector_Engine {

	private Detector_Policy_Store $policies;

	public function __construct( ?Detector_Policy_Store $policies = null ) {
		$this->policies = $policies ?? new Detector_Policy_Store();
	}

	/**
	 * @param array<string, mixed> $context Request context built by Request_Observer.
	 * @return array<int, array<string, mixed>> One Finding per detector that matched.
	 */
	public function evaluate( array $context ): array {
		$surface  = (string) ( $context['surface'] ?? '' );
		$findings = array();

		foreach ( Detector_Registry::all() as $detector ) {
			$applicable_surfaces = $detector->applicable_surfaces();
			if ( ! empty( $applicable_surfaces ) && ! in_array( $surface, $applicable_surfaces, true ) ) {
				continue;
			}

			if ( ! $detector->is_available() ) {
				continue;
			}

			if ( ! $this->policies->is_enabled( $detector->id() ) ) {
				continue;
			}

			try {
				$result = $detector->evaluate( $context );
			} catch ( \Throwable $unused ) { // phpcs:ignore Generic.CodeAnalysis.EmptyStatement.DetectedCatch
				continue;
			}

			if ( null === $result ) {
				continue;
			}

			$findings[] = array_merge(
				array(
					'severity'   => 'unknown',
					'confidence' => null,
					'detail'     => array(),
				),
				$result,
				array(
					'detector_id'     => $detector->id(),
					'detector_family' => $detector->family(),
					'surface'         => $surface,
					'control_action'  => $this->policies->control_action_for( $detector ),
				)
			);
		}

		return $findings;
	}
}
