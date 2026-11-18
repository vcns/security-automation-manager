<?php
/**
 * Tor exit-node traffic filtering (Phase 4A extension, .roadmap/
 * phase3_early_plan.md §13.6 -- the "traffic control filtering" half of Tor
 * awareness that Phase 4A itself shipped as evidence-only via
 * Network_Intelligence_Resolver).
 *
 * Not a Pattern_Detector: there's no string to regex-match against, just a
 * membership check against Tor_Exit_List_Store's own local, daily-refreshed
 * table -- an indexed lookup, not a network call, so this is cheap enough to
 * run on every request like any other detector (unlike ASN/Geo-IP, which
 * stay lazy -- see Traffic_Guard's own docblock for why those are handled
 * differently, as an opt-in Network_Rule_Store block-list rather than a
 * detector).
 *
 * Enforce-capable: being a Tor exit node never implies malicious intent on
 * its own (§13.6), but an administrator who has decided their own site has
 * no legitimate reason to expect Tor traffic (e.g. a login surface, or a
 * regional site with no privacy-sensitive audience) is better placed to
 * judge that than a fixed default -- still observation-only until they
 * explicitly opt in, matching every other detector's default-safety
 * posture.
 */

declare( strict_types=1 );

namespace WP_SAM\Intelligence\Detectors;

use WP_SAM\Intelligence\Detector;
use WP_SAM\Intelligence\Tor_Exit_List_Store;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Tor_Exit_Detector extends Detector {

	private Tor_Exit_List_Store $tor_exit_list;

	/**
	 * Constructor.
	 *
	 * @param Tor_Exit_List_Store|null $tor_exit_list Tor exit list store, a new one is created when omitted.
	 */
	public function __construct( ?Tor_Exit_List_Store $tor_exit_list = null ) {
		$this->tor_exit_list = $tor_exit_list ?? new Tor_Exit_List_Store();
	}

	/**
	 * Returns the stable id of the Tor exit node detector.
	 *
	 * @return string Detector id.
	 */
	public function id(): string {
		return 'tor-exit-node';
	}

	/**
	 * Returns the family the Tor exit node detector belongs to.
	 *
	 * @return string Family label.
	 */
	public function family(): string {
		return 'network-intelligence';
	}

	/**
	 * Returns the plain-language description of the Tor exit node detector shown in the Detectors tab.
	 *
	 * @return string Translated description.
	 */
	public function description(): string {
		return __( 'Flags requests from a current Tor exit node -- not itself evidence of malicious intent.', 'vcns-security-automation-manager' );
	}

	/**
	 * Returns the surfaces the Tor exit node detector runs on.
	 *
	 * @return array Surface slugs, or an empty array for every surface.
	 */
	public function applicable_surfaces(): array {
		return array();
	}

	/**
	 * Returns the control actions the Tor exit node detector may be set to.
	 *
	 * @return array Control action keys.
	 */
	public function allowed_control_actions(): array {
		return array( 'observe', 'enforce' );
	}

	/**
	 * Flags a request that comes from a known Tor exit node.
	 *
	 * @param array $context Request context built by Request_Observer.
	 * @return array|null Finding data, or null when nothing was found.
	 */
	public function evaluate( array $context ): ?array {
		$ip = (string) ( $context['ip'] ?? '' );
		if ( '' === $ip || ! $this->tor_exit_list->is_exit_node( $ip ) ) {
			return null;
		}

		return array(
			'severity'   => 'low',
			'confidence' => 0.9,
			'detail'     => array(
				'description' => 'Request originated from a current Tor exit node -- not itself evidence of malicious intent, but recorded so an administrator can decide whether their own site expects this traffic.',
			),
		);
	}
}
