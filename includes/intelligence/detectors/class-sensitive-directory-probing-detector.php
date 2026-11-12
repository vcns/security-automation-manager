<?php
/**
 * Detects attempts to access host filesystem paths that have no legitimate
 * reason to appear in a WordPress request, including encoded traversal
 * attempts that resolve towards them (.roadmap/phase3_early_plan.md §11.8).
 *
 * Pattern_Detector::evaluate() decodes the subject (rawurldecode()) before
 * matching, so a percent-encoded traversal sequence resolves to the same
 * literal text a direct request would.
 */

declare( strict_types=1 );

namespace WP_SAM\Intelligence\Detectors;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Sensitive_Directory_Probing_Detector extends Pattern_Detector {

	/**
	 * Returns the stable id of the sensitive directory probing detector.
	 *
	 * @return string Detector id.
	 */
	public function id(): string {
		return 'sensitive-directories';
	}

	/**
	 * Returns the family the sensitive directory probing detector belongs to.
	 *
	 * @return string Family label.
	 */
	public function family(): string {
		return 'sensitive-directories';
	}

	/**
	 * Returns the plain-language description of the sensitive directory probing detector shown in the Detectors tab.
	 *
	 * @return string Translated description.
	 */
	public function description(): string {
		return __( 'Flags requests for Unix system paths like /etc/passwd or /proc/self/environ that have no place in a WordPress request.', 'vcns-security-automation-manager' );
	}

	/**
	 * Returns the surfaces the sensitive directory probing detector runs on.
	 *
	 * @return array Surface slugs, or an empty array for every surface.
	 */
	public function applicable_surfaces(): array {
		return array();
	}

	/**
	 * Returns the request data (path) that the sensitive directory probing rules are matched against.
	 *
	 * @param array $context Request context built by Request_Observer.
	 * @return string Text to match.
	 */
	protected function subject( array $context ): string {
		return (string) ( $context['path'] ?? '' );
	}

	/**
	 * Returns the sensitive directory probing detection rules.
	 *
	 * @return array Rules, each with an id, pattern, severity and description.
	 */
	protected function rules(): array {
		return array(
			array(
				'id'          => 'SDIR-001',
				'pattern'     => '#(?:^|/)etc/passwd#i',
				'severity'    => 'high',
				'confidence'  => 0.9,
				'description' => 'Unix password file.',
			),
			array(
				'id'          => 'SDIR-002',
				'pattern'     => '#(?:^|/)etc/shadow#i',
				'severity'    => 'high',
				'confidence'  => 0.9,
				'description' => 'Unix shadow password file.',
			),
			array(
				'id'          => 'SDIR-003',
				'pattern'     => '#(?:^|/)etc/hosts#i',
				'severity'    => 'medium',
				'confidence'  => 0.75,
				'description' => 'Unix hosts file.',
			),
			array(
				'id'          => 'SDIR-004',
				'pattern'     => '#(?:^|/)proc/self/(?:environ|cmdline|status)#i',
				'severity'    => 'high',
				'confidence'  => 0.9,
				'description' => 'Linux /proc process-introspection path.',
			),
			array(
				'id'          => 'SDIR-005',
				'pattern'     => '#^/(?:etc|usr|var|proc|root|boot|sys|dev)/#i',
				'severity'    => 'medium',
				'confidence'  => 0.55,
				'description' => 'Request path rooted directly at a Unix system directory.',
			),
		);
	}
}
