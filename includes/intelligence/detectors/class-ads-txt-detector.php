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

	/**
	 * Returns the stable id of the ads.txt probing detector.
	 *
	 * @return string Detector id.
	 */
	public function id(): string {
		return 'ads-txt-visit';
	}

	/**
	 * Returns the family the ads.txt probing detector belongs to.
	 *
	 * @return string Family label.
	 */
	public function family(): string {
		return 'ads-txt-visit';
	}

	/**
	 * Returns the plain-language description of the ads.txt probing detector shown in the Detectors tab.
	 *
	 * @return string Translated description.
	 */
	public function description(): string {
		return __( 'Notes when a source checks your ads.txt -- typically an ad-tech crawler verifying authorised sellers.', 'vcns-security-automation-manager' );
	}

	/**
	 * Returns the surfaces the ads.txt probing detector runs on.
	 *
	 * @return array Surface slugs, or an empty array for every surface.
	 */
	public function applicable_surfaces(): array {
		return array();
	}

	/**
	 * Returns the request data (path) that the ads.txt probing rules are matched against.
	 *
	 * @param array $context Request context built by Request_Observer.
	 * @return string Text to match.
	 */
	protected function subject( array $context ): string {
		return (string) ( $context['path'] ?? '' );
	}

	/**
	 * Returns the ads.txt probing detection rules.
	 *
	 * @return array Rules, each with an id, pattern, severity and description.
	 */
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
