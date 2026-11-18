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

	/**
	 * Returns the stable id of the app-ads.txt probing detector.
	 *
	 * @return string Detector id.
	 */
	public function id(): string {
		return 'app-ads-txt-visit';
	}

	/**
	 * Returns the family the app-ads.txt probing detector belongs to.
	 *
	 * @return string Family label.
	 */
	public function family(): string {
		return 'app-ads-txt-visit';
	}

	/**
	 * Returns the plain-language description of the app-ads.txt probing detector shown in the Detectors tab.
	 *
	 * @return string Translated description.
	 */
	public function description(): string {
		return __( 'Notes when a source checks your app-ads.txt -- typically an ad-tech crawler verifying authorised sellers for mobile-app inventory.', 'vcns-security-automation-manager' );
	}

	/**
	 * Returns the surfaces the app-ads.txt probing detector runs on.
	 *
	 * @return array Surface slugs, or an empty array for every surface.
	 */
	public function applicable_surfaces(): array {
		return array();
	}

	/**
	 * Returns the request data (path) that the app-ads.txt probing rules are matched against.
	 *
	 * @param array $context Request context built by Request_Observer.
	 * @return string Text to match.
	 */
	protected function subject( array $context ): string {
		return (string) ( $context['path'] ?? '' );
	}

	/**
	 * Returns the app-ads.txt probing detection rules.
	 *
	 * @return array Rules, each with an id, pattern, severity and description.
	 */
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
