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

	/**
	 * Returns the stable id of the security.txt probing detector.
	 *
	 * @return string Detector id.
	 */
	public function id(): string {
		return 'security-txt-visit';
	}

	/**
	 * Returns the family the security.txt probing detector belongs to.
	 *
	 * @return string Family label.
	 */
	public function family(): string {
		return 'security-txt-visit';
	}

	/**
	 * Returns the plain-language description of the security.txt probing detector shown in the Detectors tab.
	 *
	 * @return string Translated description.
	 */
	public function description(): string {
		return __( 'Notes when a source checks your security.txt -- typically a security researcher or scanner looking for a disclosure contact.', 'vcns-security-automation-manager' );
	}

	/**
	 * Returns the surfaces the security.txt probing detector runs on.
	 *
	 * @return array Surface slugs, or an empty array for every surface.
	 */
	public function applicable_surfaces(): array {
		return array();
	}

	/**
	 * Returns the request data (path) that the security.txt probing rules are matched against.
	 *
	 * @param array $context Request context built by Request_Observer.
	 * @return string Text to match.
	 */
	protected function subject( array $context ): string {
		return (string) ( $context['path'] ?? '' );
	}

	/**
	 * Returns the security.txt probing detection rules.
	 *
	 * @return array Rules, each with an id, pattern, severity and description.
	 */
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
