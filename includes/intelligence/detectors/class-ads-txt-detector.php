<?php
/**
 * Recognises when a source examines ads.txt (Phase 4C extension, user-
 * requested, alongside Robots_Txt_Detector's own "robots.txt behaviour"
 * signal -- see that class's own docblock for why this is a low-severity,
 * observation-only positive signal rather than evidence of anything
 * adverse). ads.txt has no Disallow-style directive to check compliance
 * against, so unlike robots.txt/agents.txt there is no second, compliance-
 * checking detector alongside this one -- see Ads_Txt_Store's own docblock.
 */

declare( strict_types=1 );

namespace WP_SAM\Intelligence\Detectors;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Ads_Txt_Detector extends Pattern_Detector {

	public function id(): string {
		return 'ads-txt-visit';
	}

	public function family(): string {
		return 'ads-txt-visit';
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
				'id'          => 'ADS-TXT-001',
				'pattern'     => '#^/ads\.txt$#i',
				'severity'    => 'low',
				'confidence'  => 0.95,
				'description' => 'Source examined ads.txt -- typically a positive signal (an ad-tech crawler verifying authorised sellers), not evidence of malicious intent.',
			),
		);
	}
}
