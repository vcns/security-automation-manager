<?php
/**
 * Resolves additional network-level facts about a source IP -- Tor exit
 * status and ASN today, Geo-IP in a later Phase 4A increment
 * (.roadmap/phase4_plan.md). This is the `Network_Intelligence_Resolver`
 * named in .roadmap/phase3_early_plan.md §31 as a missing architecture
 * component; it exists now to avoid re-architecting when Geo-IP is added
 * on top of it.
 *
 * Mirrors Identity_Resolver's shape and cost profile deliberately: called
 * once per request from Request_Observer, backed only by fast local
 * lookups (an indexed DB match for Tor, a cached DB row for ASN in the
 * common case) -- never a network call on the request path itself.
 * Tor_Exit_List_Store's refresh and Asn_Lookup_Store's cache-miss DNS
 * query are the only places real network I/O happens, and both are
 * either scheduled (Tor) or cached with a long TTL (ASN) so that cost is
 * paid rarely, not per-request.
 *
 * Resolved facts are evidence, not verdicts -- being a Tor exit node or
 * belonging to a particular ASN, like being a recognised scanner, never
 * implies malicious intent on its own (.roadmap/phase3_early_plan.md
 * §13.5, §13.6). Nothing here blocks anything; the result is only ever
 * attached to Finding detail when some other detector has already
 * recorded evidence for the same request.
 */

declare( strict_types=1 );

namespace WP_SAM\Intelligence;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Network_Intelligence_Resolver {

	private Tor_Exit_List_Store $tor_exit_list;
	private Asn_Lookup_Store $asn_lookup;

	public function __construct( Tor_Exit_List_Store $tor_exit_list, Asn_Lookup_Store $asn_lookup ) {
		$this->tor_exit_list = $tor_exit_list;
		$this->asn_lookup    = $asn_lookup;
	}

	/** @return array{is_tor_exit: bool, asn: ?int, asn_org: ?string} */
	public function resolve( string $ip ): array {
		if ( '' === $ip ) {
			return array(
				'is_tor_exit' => false,
				'asn'         => null,
				'asn_org'     => null,
			);
		}

		return array_merge(
			array( 'is_tor_exit' => $this->tor_exit_list->is_exit_node( $ip ) ),
			$this->asn_lookup->resolve( $ip )
		);
	}
}
