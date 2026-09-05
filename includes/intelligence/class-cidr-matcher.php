<?php
/**
 * IPv4/IPv6 CIDR membership checks for Identity_Resolver's network-match
 * step (Phase 3D, .roadmap/phase3_early_plan.md §8/§31 "Network Intelligence
 * Resolver").
 *
 * Uses inet_pton()'s fixed-width binary form (4 bytes for IPv4, 16 for
 * IPv6) and a byte-wise prefix comparison rather than string parsing, so
 * the same logic is correct for both families without a separate code path
 * for each.
 */

declare( strict_types=1 );

namespace WP_SAM\Intelligence;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Cidr_Matcher {

	/**
	 * RFC 5735 IPv4 loopback block (127.0.0.0/8) and the IPv6 loopback
	 * address (::1) -- the single source of truth for "is this IP
	 * loopback", shared by Identity_Resolver's identity/classification
	 * recognition and Traffic_Guard's automatic-escalation exemption so the
	 * two can never silently disagree on the definition.
	 */
	public const LOOPBACK_CIDRS = array( '127.0.0.0/8', '::1/128' );

	public static function ip_in_cidr( string $ip, string $cidr ): bool {
		$parts = explode( '/', $cidr, 2 );
		if ( 2 !== count( $parts ) ) {
			return false;
		}
		list( $subnet, $prefix_raw ) = $parts;
		if ( ! ctype_digit( $prefix_raw ) ) {
			return false;
		}
		$prefix = (int) $prefix_raw;

		$ip_bin     = @inet_pton( $ip ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- inet_pton() emits a warning on a malformed address; failure (false) is a normal, expected outcome here.
		$subnet_bin = @inet_pton( $subnet ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- same rationale.
		if ( false === $ip_bin || false === $subnet_bin || strlen( $ip_bin ) !== strlen( $subnet_bin ) ) {
			return false;
		}

		$max_prefix = strlen( $ip_bin ) * 8;
		if ( $prefix < 0 || $prefix > $max_prefix ) {
			return false;
		}

		$full_bytes = intdiv( $prefix, 8 );
		$rem_bits   = $prefix % 8;

		if ( $full_bytes > 0 && substr( $ip_bin, 0, $full_bytes ) !== substr( $subnet_bin, 0, $full_bytes ) ) {
			return false;
		}

		if ( 0 === $rem_bits ) {
			return true;
		}

		$mask = chr( ( 0xFF << ( 8 - $rem_bits ) ) & 0xFF );
		return ( $ip_bin[ $full_bytes ] & $mask ) === ( $subnet_bin[ $full_bytes ] & $mask );
	}

	/**
	 * @param array<string> $cidrs
	 */
	public static function ip_in_any_cidr( string $ip, array $cidrs ): bool {
		foreach ( $cidrs as $cidr ) {
			if ( self::ip_in_cidr( $ip, $cidr ) ) {
				return true;
			}
		}
		return false;
	}
}
