<?php
/**
 * Recognises when a source examines app-ads.txt (Phase 4C extension,
 * user-requested) -- the mobile-app counterpart to Ads_Txt_Detector. See
 * that class's own docblock for the shared reasoning.
 */

declare( strict_types=1 );

namespace WP_SAM\Intelligence\Detectors;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class App_Ads_Txt_Detector extends Pattern_Detector {

	public function id(): string {
		return 'app-ads-txt-visit';
	}

	public function family(): string {
		return 'app-ads-txt-visit';
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
				'id'          => 'APP-ADS-TXT-001',
				'pattern'     => '#^/app-ads\.txt$#i',
				'severity'    => 'low',
				'confidence'  => 0.95,
				'description' => 'Source examined app-ads.txt -- typically a positive signal (an ad-tech crawler verifying authorised sellers for mobile app inventory), not evidence of malicious intent.',
			),
		);
	}
}
