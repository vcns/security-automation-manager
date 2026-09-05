<?php
/**
 * Recognises when a source examines security.txt (Phase 4C extension,
 * user-requested, alongside Robots_Txt_Detector's own "robots.txt
 * behaviour" signal -- see that class's own docblock for why this is a
 * low-severity, observation-only positive signal rather than evidence of
 * anything adverse). Matches either RFC 9116's canonical /.well-known/
 * security.txt location or the deprecated root-level fallback.
 */

declare( strict_types=1 );

namespace WP_SAM\Intelligence\Detectors;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Security_Txt_Detector extends Pattern_Detector {

	public function id(): string {
		return 'security-txt-visit';
	}

	public function family(): string {
		return 'security-txt-visit';
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
				'id'          => 'SECURITY-TXT-001',
				'pattern'     => '#^/(\.well-known/)?security\.txt$#i',
				'severity'    => 'low',
				'confidence'  => 0.95,
				'description' => 'Source examined security.txt -- typically a positive signal (a security researcher or scanner looking for a vulnerability-disclosure contact), not evidence of malicious intent.',
			),
		);
	}
}
