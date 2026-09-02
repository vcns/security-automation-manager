<?php
/**
 * Resolves additional network-level facts about a source IP -- Tor exit
 * status, ASN, and (when an administrator has opted in) Geo-IP
 * (.roadmap/phase4_plan.md, Phase 4A, now complete). This is the
 * `Network_Intelligence_Resolver` named in .roadmap/phase3_early_plan.md
 * §31 as a missing architecture component.
 *
 * Mirrors Identity_Resolver's shape and cost profile deliberately: called
 * once per request from Request_Observer, backed only by fast local
 * lookups (an indexed DB match for Tor, a cached DB row for ASN/Geo-IP in
 * the common case) -- never a network call on the request path itself.
 * Tor_Exit_List_Store's refresh, Asn_Lookup_Store's cache-miss DNS query,
 * and Geo_Ip_Store's cache-miss HTTP call are the only places real
 * network I/O happens, and all three are either scheduled (Tor) or
 * cached with a long TTL (ASN, Geo-IP) so that cost is paid rarely, not
 * per-request. Geo_Ip_Store::resolve() is additionally a no-op entirely
 * (no DB query, no network call) until an administrator has opted in
 * with their own credentials -- see its own docblock.
 *
 * Resolved facts are evidence, not verdicts -- being a Tor exit node,
 * belonging to a particular ASN, or being geolocated to a given country,
 * like being a recognised scanner, never implies malicious intent on its
 * own (.roadmap/phase3_early_plan.md §13.4, §13.5, §13.6). Nothing here
 * blocks anything; the result is only ever attached to Finding detail
 * when some other detector has already recorded evidence for the same
 * request.
 */

declare( strict_types=1 );

namespace WP_SAM\Intelligence;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Network_Intelligence_Resolver {

	private Tor_Exit_List_Store $tor_exit_list;
	private Asn_Lookup_Store $asn_lookup;
	private Geo_Ip_Store $geo_ip;

	public function __construct( Tor_Exit_List_Store $tor_exit_list, Asn_Lookup_Store $asn_lookup, Geo_Ip_Store $geo_ip ) {
		$this->tor_exit_list = $tor_exit_list;
		$this->asn_lookup    = $asn_lookup;
		$this->geo_ip        = $geo_ip;
	}

	/** @return array{is_tor_exit: bool, asn: ?int, asn_org: ?string, country: ?string, region: ?string, city: ?string} */
	public function resolve( string $ip ): array {
		if ( '' === $ip ) {
			return array(
				'is_tor_exit' => false,
				'asn'         => null,
				'asn_org'     => null,
				'country'     => null,
				'region'      => null,
				'city'        => null,
			);
		}

		return array_merge(
			array( 'is_tor_exit' => $this->tor_exit_list->is_exit_node( $ip ) ),
			$this->asn_lookup->resolve( $ip ),
			$this->geo_ip->resolve( $ip )
		);
	}
}
