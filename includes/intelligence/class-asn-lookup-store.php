<?php
/**
 * ASN Controls (Phase 4A, second increment, .roadmap/phase4_plan.md,
 * .roadmap/phase3_early_plan.md §13.5).
 *
 * Resolves an IP's Autonomous System Number and organisation name via
 * Team Cymru's free, unauthenticated DNS-based origin-ASN lookup service
 * -- no account, API key, or licensing decision needed, the same reason
 * Tor Awareness was built before this (see Tor_Exit_List_Store's own
 * docblock). Unlike Tor's bulk-downloaded list, this is a live, per-IP DNS
 * query, so results are cached in sam_asn_cache (30-day TTL -- ASN
 * assignments change rarely) rather than queried fresh every time; a
 * failed lookup is cached too, so a persistently-unresolvable IP doesn't
 * pay the DNS round-trip cost again on its very next hit.
 *
 * Two-step query, mirroring Team Cymru's own documented protocol:
 *   1. `{reversed-octets}.origin.asn.cymru.com` (TXT) -> "ASN | prefix |
 *      country | registry | allocated" -- gives the ASN.
 *   2. `AS{asn}.asn.cymru.com` (TXT) -> "ASN | country | registry |
 *      allocated | AS Name" -- gives the organisation name.
 *
 * IPv4 only for this increment -- Team Cymru's IPv6 service uses a
 * different query format (origin6.asn.cymru.com, nibble-reversed hex);
 * not implemented yet, not silently pretended to work.
 *
 * The DNS query itself is injectable, mirroring Identity_Resolver's
 * reverse_lookup/forward_lookup pattern exactly: real dns_get_record() by
 * default, swappable in tests so no test ever makes a real DNS call. Like
 * every DNS call in this codebase (see Identity_Resolver's own docblock),
 * this has no explicit timeout control beyond the system resolver's own
 * behaviour -- accepted here for the same reason it's accepted there,
 * not a new gap.
 */

declare( strict_types=1 );

namespace WP_SAM\Intelligence;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Asn_Lookup_Store {

	private const CACHE_TTL_DAYS = 30;

	/** @var callable(string):array<int,string> Real dns_get_record() TXT lookup by default; injectable so tests never make a real DNS call. */
	private $txt_lookup;

	public function __construct( ?callable $txt_lookup = null ) {
		$this->txt_lookup = $txt_lookup ?? static function ( string $hostname ): array {
			// phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- dns_get_record() emits a warning on lookup failure; failure is a normal, expected outcome here, same rationale as Identity_Resolver's gethostbyaddr()/gethostbyname() calls.
			$records = @dns_get_record( $hostname, DNS_TXT );
			if ( false === $records ) {
				return array();
			}
			return array_values( array_filter( array_column( $records, 'txt' ) ) );
		};
	}

	/** @return array{asn: ?int, asn_org: ?string} */
	public function resolve( string $ip ): array {
		if ( '' === $ip || false === filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 ) ) {
			return array(
				'asn'     => null,
				'asn_org' => null,
			);
		}

		$cached = $this->cached( $ip );
		if ( null !== $cached ) {
			return $cached;
		}

		$result = $this->live_lookup( $ip );
		$this->remember( $ip, $result['asn'], $result['asn_org'] );

		return $result;
	}

	/** @return array{asn: ?int, asn_org: ?string}|null */
	private function cached( string $ip ): ?array {
		global $wpdb;
		$table = $wpdb->prefix . 'sam_asn_cache';
		$since = gmdate( 'Y-m-d H:i:s', time() - ( self::CACHE_TTL_DAYS * DAY_IN_SECONDS ) );

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
		$row = $wpdb->get_row(
			$wpdb->prepare(
				// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				"SELECT asn, asn_org FROM {$table} WHERE ip = %s AND resolved_at >= %s",
				$ip,
				$since
			),
			ARRAY_A
		);

		if ( ! is_array( $row ) ) {
			return null;
		}

		return array(
			'asn'     => null !== $row['asn'] ? (int) $row['asn'] : null,
			'asn_org' => '' !== (string) $row['asn_org'] ? (string) $row['asn_org'] : null,
		);
	}

	private function remember( string $ip, ?int $asn, ?string $asn_org ): void {
		global $wpdb;
		$table = $wpdb->prefix . 'sam_asn_cache';
		$now   = current_time( 'mysql', true );

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
		$existing_id = $wpdb->get_var(
			$wpdb->prepare(
				// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				"SELECT id FROM {$table} WHERE ip = %s",
				$ip
			)
		);

		$data = array(
			'ip'          => $ip,
			'asn'         => $asn,
			'asn_org'     => $asn_org ?? '',
			'resolved_at' => $now,
		);

		if ( $existing_id ) {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
			$wpdb->update( $table, $data, array( 'id' => (int) $existing_id ) );
			return;
		}

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
		$wpdb->insert( $table, $data );
	}

	/** @return array{asn: ?int, asn_org: ?string} */
	private function live_lookup( string $ip ): array {
		$reversed = implode( '.', array_reverse( explode( '.', $ip ) ) );
		$origin   = ( $this->txt_lookup )( "{$reversed}.origin.asn.cymru.com" );

		if ( empty( $origin ) ) {
			return array(
				'asn'     => null,
				'asn_org' => null,
			);
		}

		$origin_fields = array_map( 'trim', explode( '|', $origin[0] ) );
		$asn           = (int) ( $origin_fields[0] ?? 0 );
		if ( $asn <= 0 ) {
			return array(
				'asn'     => null,
				'asn_org' => null,
			);
		}

		$asn_org = null;
		$name    = ( $this->txt_lookup )( "AS{$asn}.asn.cymru.com" );
		if ( ! empty( $name ) ) {
			$name_fields = array_map( 'trim', explode( '|', $name[0] ) );
			$asn_org     = '' !== ( $name_fields[4] ?? '' ) ? $name_fields[4] : null;
		}

		return array(
			'asn'     => $asn,
			'asn_org' => $asn_org,
		);
	}
}
