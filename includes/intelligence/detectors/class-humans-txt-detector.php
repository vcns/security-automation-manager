<?php
/**
 * Recognises when a source examines humans.txt (Phase 4C extension, user-
 * requested, alongside Robots_Txt_Detector's own "robots.txt behaviour"
 * signal -- see that class's own docblock for why this is a low-severity,
 * observation-only positive signal rather than evidence of anything
 * adverse).
 */

declare( strict_types=1 );

namespace WP_SAM\Intelligence\Detectors;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Humans_Txt_Detector extends Pattern_Detector {

	public function id(): string {
		return 'humans-txt-visit';
	}

	public function family(): string {
		return 'humans-txt-visit';
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
				'id'          => 'HUMANS-001',
				'pattern'     => '#^/humans\.txt$#i',
				'severity'    => 'low',
				'confidence'  => 0.95,
				'description' => 'Source examined humans.txt -- an informal credits/colophon convention; recorded for correlation only, not evidence of malicious intent.',
			),
		);
	}
}
