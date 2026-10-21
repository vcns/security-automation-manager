<?php
/**
 * Recognises requests to legacy or commonly-abused WordPress endpoints
 * (.roadmap/phase3_early_plan.md §11.13).
 *
 * xmlrpc.php is the flagship signal here, and deliberately scored low/
 * medium rather than high/critical: it's still a legitimate, actively-used
 * core endpoint (the mobile app, pingback, some plugins), and this family
 * can only see the request path, not the XML-RPC method actually being
 * called (pingback.ping SSRF abuse and system.multicall credential-
 * stuffing both use the same URL with different POST bodies, which this
 * detector -- like every other Pattern_Detector -- never inspects). Per
 * the roadmap's own explicit wording ("RPC/XML-RPC controls must be
 * configurable rather than assumed universally safe to block"), this is
 * enforce-capable but still defaults to observation: whether xmlrpc.php
 * is even in genuine use is a per-site judgement call, not something this
 * detector can determine for every install.
 */

declare( strict_types=1 );

namespace WP_SAM\Intelligence\Detectors;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Legacy_Endpoint_Detector extends Pattern_Detector {

	/**
	 * Returns the stable id of the legacy endpoint detector.
	 *
	 * @return string Detector id.
	 */
	public function id(): string {
		return 'legacy-endpoints';
	}

	/**
	 * Returns the family the legacy endpoint detector belongs to.
	 *
	 * @return string Family label.
	 */
	public function family(): string {
		return 'legacy-endpoints';
	}

	/**
	 * Returns the plain-language description of the legacy endpoint detector shown in the Detectors tab.
	 *
	 * @return string Translated description.
	 */
	public function description(): string {
		return __( 'Flags requests to xmlrpc.php, trackback, and other older WordPress endpoints often targeted for abuse.', 'vcns-security-automation-manager' );
	}

	/**
	 * Returns the surfaces the legacy endpoint detector runs on.
	 *
	 * @return array Surface slugs, or an empty array for every surface.
	 */
	public function applicable_surfaces(): array {
		return array();
	}

	/**
	 * Returns the control actions the legacy endpoint detector may be set to.
	 *
	 * @return array Control action keys.
	 */
	public function allowed_control_actions(): array {
		return array( 'observe', 'enforce' );
	}

	/**
	 * Returns the request data (path) that the legacy endpoint rules are matched against.
	 *
	 * @param array $context Request context built by Request_Observer.
	 * @return string Text to match.
	 */
	protected function subject( array $context ): string {
		return (string) ( $context['path'] ?? '' );
	}

	/**
	 * Returns the legacy endpoint detection rules.
	 *
	 * @return array Rules, each with an id, pattern, severity and description.
	 */
	protected function rules(): array {
		return array(
			array(
				'id'          => 'LEGACY-001',
				'pattern'     => '#(?:^|/)xmlrpc\.php$#i',
				'severity'    => 'medium',
				'confidence'  => 0.55,
				'description' => 'XML-RPC endpoint -- still legitimate in some setups (pingback, the mobile app, some plugins), but also a common pingback-SSRF and system.multicall credential-stuffing target.',
			),
			array(
				'id'          => 'LEGACY-002',
				'pattern'     => '#(?:^|/)wp-trackback\.php$#i',
				'severity'    => 'medium',
				'confidence'  => 0.6,
				'description' => 'Trackback endpoint -- a long-standing spam and abuse vector, rarely used legitimately today.',
			),
			array(
				'id'          => 'LEGACY-003',
				'pattern'     => '#(?:^|/)wp-app\.php$#i',
				'severity'    => 'low',
				'confidence'  => 0.7,
				'description' => 'Atom Publishing Protocol endpoint, removed from WordPress core since 3.5 -- a hit almost certainly means a stale scanner signature, not a real endpoint.',
			),
		);
	}
}
