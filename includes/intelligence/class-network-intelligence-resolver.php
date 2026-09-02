<?php
/**
 * Resolves additional network-level facts about a source IP -- Tor exit
 * status today, ASN and Geo-IP in later Phase 4A increments
 * (.roadmap/phase4_plan.md). This is the `Network_Intelligence_Resolver`
 * named in .roadmap/phase3_early_plan.md §31 as a missing architecture
 * component; it exists now to avoid re-architecting when ASN/Geo-IP are
 * added on top of it.
 *
 * Mirrors Identity_Resolver's shape and cost profile deliberately: called
 * once per request from Request_Observer, backed only by fast indexed
 * local lookups, never a network call on the request path (Tor_Exit_
 * List_Store's own refresh is what does the network fetch, on a daily
 * schedule -- see Intelligence\Tor_Exit_List_Store).
 *
 * Resolved facts are evidence, not verdicts -- being a Tor exit node,
 * like being a recognised scanner, never implies malicious intent on its
 * own (.roadmap/phase3_early_plan.md §13.6). Nothing here blocks
 * anything; the result is only ever attached to Finding detail when some
 * other detector has already recorded evidence for the same request.
 */

declare( strict_types=1 );

namespace WP_SAM\Intelligence;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Network_Intelligence_Resolver {

	private Tor_Exit_List_Store $tor_exit_list;

	public function __construct( Tor_Exit_List_Store $tor_exit_list ) {
		$this->tor_exit_list = $tor_exit_list;
	}

	/** @return array{is_tor_exit: bool} */
	public function resolve( string $ip ): array {
		if ( '' === $ip ) {
			return array( 'is_tor_exit' => false );
		}

		return array(
			'is_tor_exit' => $this->tor_exit_list->is_exit_node( $ip ),
		);
	}
}
