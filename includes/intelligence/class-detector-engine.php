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
 */

declare( strict_types=1 );

namespace WP_SAM\Intelligence;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Detector_Engine {

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
				)
			);
		}

		return $findings;
	}
}
