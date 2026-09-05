<?php
/**
 * Recognises when a source examines agents.txt (Phase 4C extension, user-
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

final class Agents_Txt_Detector extends Pattern_Detector {

	public function id(): string {
		return 'agents-txt-visit';
	}

	public function family(): string {
		return 'agents-txt-visit';
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
				'id'          => 'AGENTS-001',
				'pattern'     => '#^/agents\.txt$#i',
				'severity'    => 'low',
				'confidence'  => 0.95,
				'description' => 'Source examined agents.txt -- typically a positive signal (a well-behaved AI agent/crawler checking access rules before proceeding), not evidence of malicious intent.',
			),
		);
	}
}
