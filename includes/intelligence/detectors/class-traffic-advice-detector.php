<?php
/**
 * Recognises when a source fetches this site's traffic advice, the same
 * observation-only visit signal as the other well-known-file detectors.
 * The requests normally come from a private prefetch proxy, such as
 * Chrome's, checking whether it may prefetch pages here, so they are
 * recorded for correlation, never treated as evidence of anything.
 */

declare( strict_types=1 );

namespace WP_SAM\Intelligence\Detectors;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Traffic_Advice_Detector extends Pattern_Detector {

	public function id(): string {
		return 'traffic-advice-visit';
	}

	public function family(): string {
		return 'traffic-advice-visit';
	}

	public function description(): string {
		return __( 'Notes when a prefetch proxy fetches your traffic advice -- recorded for correlation only.', 'vcns-security-automation-manager' );
	}

	public function applicable_surfaces(): array {
		return array();
	}

	protected function subject( array $context ): string {
		return (string) ( $context['path'] ?? '' );
	}

	protected function rules(): array {
		return array(
			array(
				'id'          => 'TRAFFICADVICE-001',
				'pattern'     => '#^/\.well-known/traffic-advice$#i',
				'severity'    => 'low',
				'confidence'  => 0.95,
				'description' => 'Source fetched the traffic advice -- normally a private prefetch proxy, such as Chrome\'s, checking whether it may prefetch pages here; recorded for correlation only.',
			),
		);
	}
}
