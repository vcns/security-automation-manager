<?php
/**
 * Detects attempts to inject alternate URI schemes into a parameter value
 * (.roadmap/phase3_early_plan.md §11.7).
 *
 * Every rule requires the scheme to appear immediately after `=` -- i.e. as
 * a parameter's VALUE, not merely present somewhere in the request -- since
 * that's the shape an actual SSRF/LFI-via-wrapper attempt takes. `data:`
 * URIs are deliberately not matched here: unlike the other schemes below,
 * `data:` never takes a `//` form (`data:text/plain;base64,...`), so a
 * `data://` pattern would never match a real payload.
 */

declare( strict_types=1 );

namespace WP_SAM\Intelligence\Detectors;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Protocol_Injection_Detector extends Pattern_Detector {

	/**
	 * Returns the stable id of the protocol injection detector.
	 *
	 * @return string Detector id.
	 */
	public function id(): string {
		return 'protocol-injection';
	}

	/**
	 * Returns the family the protocol injection detector belongs to.
	 *
	 * @return string Family label.
	 */
	public function family(): string {
		return 'protocol-injection';
	}

	/**
	 * Returns the plain-language description of the protocol injection detector shown in the Detectors tab.
	 *
	 * @return string Translated description.
	 */
	public function description(): string {
		return __( 'Flags php://, file://, and other non-HTTP URI schemes injected as a parameter value.', 'vcns-security-automation-manager' );
	}

	/**
	 * Returns the surfaces the protocol injection detector runs on.
	 *
	 * @return array Surface slugs, or an empty array for every surface.
	 */
	public function applicable_surfaces(): array {
		return array();
	}

	/**
	 * Returns the request data (path, query string) that the protocol injection rules are matched against.
	 *
	 * @param array $context Request context built by Request_Observer.
	 * @return string Text to match.
	 */
	protected function subject( array $context ): string {
		$path         = (string) ( $context['path'] ?? '' );
		$query_string = (string) ( $context['query_string'] ?? '' );

		return '' !== $query_string ? $path . '?' . $query_string : $path;
	}

	/**
	 * Returns the protocol injection detection rules.
	 *
	 * @return array Rules, each with an id, pattern, severity and description.
	 */
	protected function rules(): array {
		return array(
			array(
				'id'          => 'PROTO-001',
				'pattern'     => '#=\s*php://(?:filter|input)#i',
				'severity'    => 'critical',
				'confidence'  => 0.9,
				'description' => 'PHP stream wrapper commonly used for LFI/RCE (filter or input).',
			),
			array(
				'id'          => 'PROTO-002',
				'pattern'     => '#=\s*php://memory#i',
				'severity'    => 'medium',
				'confidence'  => 0.6,
				'description' => 'PHP memory stream wrapper.',
			),
			array(
				'id'          => 'PROTO-003',
				'pattern'     => '#=\s*file://#i',
				'severity'    => 'high',
				'confidence'  => 0.8,
				'description' => 'file:// scheme injected as a parameter value.',
			),
			array(
				'id'          => 'PROTO-004',
				'pattern'     => '#=\s*(?:ftp|gopher|dict|expect)://#i',
				'severity'    => 'medium',
				'confidence'  => 0.6,
				'description' => 'Non-HTTP URI scheme injected as a parameter value.',
			),
		);
	}
}
