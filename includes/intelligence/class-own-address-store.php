<?php
/**
 * This site's own public addresses, declared by an administrator on
 * Control → Traffic Controls → IP Rules.
 *
 * A server or container that reaches its own site through a public address
 * (a container calling its own wp-cron.php via the host's public IP, say)
 * looks to this plugin like any other visitor, so it could climb the block
 * ladder, be counted into a campaign and be labelled "Aggressive". Private
 * and loopback addresses already avoid all of that (Cidr_Matcher::is_local());
 * includes() extends the same treatment to the addresses listed here, and is
 * what every "never auto-block this site" path calls: Traffic_Guard,
 * Traffic_Block_Store, Identity_Resolver and Campaign_Detector.
 *
 * Unlike an Allow rule, which only exempts an address from Traffic_Guard's
 * decision, this also stops violations being recorded and campaigns counting
 * the address. An explicit Block rule on IP Rules still applies, exactly as
 * it does for a private address.
 *
 * Stored as one autoloaded option, so includes() costs no query on a
 * request: WordPress has already loaded it.
 */

declare( strict_types=1 );

namespace WP_SAM\Intelligence;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Own_Address_Store {

	public const OPTION = 'wp_sam_own_addresses';

	public const MAX_ENTRIES = 64;

	/**
	 * The broadest range accepted. A hosting provider's whole allocation is
	 * shared with other customers, and listing it would exempt their traffic
	 * too; a /16 (65,536 addresses) is already far more than one site needs.
	 */
	private const MIN_PREFIX_IPV4 = 16;
	private const MIN_PREFIX_IPV6 = 48;

	/** True for a loopback or private address, or one this site has declared as its own. */
	public static function includes( string $ip ): bool {
		if ( '' === $ip ) {
			return false;
		}
		if ( Cidr_Matcher::is_local( $ip ) ) {
			return true;
		}

		foreach ( self::all() as $entry ) {
			if ( Cidr_Matcher::ip_in_cidr( $ip, self::as_cidr( $entry ) ) ) {
				return true;
			}
		}
		return false;
	}

	/** @return array<int, string> The saved entries, each a bare address or a CIDR range. */
	public static function all(): array {
		$saved = get_option( self::OPTION, array() );
		if ( ! is_array( $saved ) ) {
			return array();
		}
		return array_values( array_filter( $saved, 'is_string' ) );
	}

	/**
	 * Replaces the list with the valid entries in $input (one per line, or
	 * separated by commas or spaces). Invalid entries are left out and
	 * returned with the reason, so the form can show them.
	 *
	 * @return array{saved: array<int, string>, rejected: array<int, array{entry: string, reason: string}>}
	 */
	public static function save( string $input ): array {
		$saved    = array();
		$rejected = array();

		$entries = preg_split( '/[\s,]+/', $input, -1, PREG_SPLIT_NO_EMPTY );
		foreach ( false !== $entries ? $entries : array() as $entry ) {
			$entry  = strtolower( $entry );
			$reason = self::rejection_reason( $entry );

			if ( null !== $reason ) {
				$rejected[] = array(
					'entry'  => $entry,
					'reason' => $reason,
				);
				continue;
			}
			if ( in_array( $entry, $saved, true ) ) {
				continue;
			}
			if ( count( $saved ) >= self::MAX_ENTRIES ) {
				$rejected[] = array(
					'entry'  => $entry,
					/* translators: %d: maximum number of entries. */
					'reason' => sprintf( __( 'Only %d entries can be saved.', 'vcns-security-automation-manager' ), self::MAX_ENTRIES ),
				);
				continue;
			}
			$saved[] = $entry;
		}

		update_option( self::OPTION, $saved, true );

		return array(
			'saved'    => $saved,
			'rejected' => $rejected,
		);
	}

	/** Null when $entry can be saved; otherwise why not, for the administrator. */
	private static function rejection_reason( string $entry ): ?string {
		$parts   = explode( '/', $entry, 2 );
		$address = $parts[0];
		$binary  = @inet_pton( $address ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- inet_pton() warns on a malformed address; false is the expected outcome then.

		if ( false === $binary ) {
			return __( 'Not an IP address or CIDR range.', 'vcns-security-automation-manager' );
		}

		$is_ipv6 = 16 === strlen( $binary );
		if ( 2 === count( $parts ) ) {
			$max_prefix = $is_ipv6 ? 128 : 32;
			if ( ! ctype_digit( $parts[1] ) || (int) $parts[1] > $max_prefix ) {
				return __( 'The range after "/" is not valid.', 'vcns-security-automation-manager' );
			}
			if ( (int) $parts[1] < ( $is_ipv6 ? self::MIN_PREFIX_IPV6 : self::MIN_PREFIX_IPV4 ) ) {
				return $is_ipv6
					? __( 'Too broad: the widest range accepted is /48.', 'vcns-security-automation-manager' )
					: __( 'Too broad: the widest range accepted is /16.', 'vcns-security-automation-manager' );
			}
		}

		if ( Cidr_Matcher::is_local( $address ) ) {
			return __( 'Private and loopback addresses are already treated as this site, so they don\'t need listing.', 'vcns-security-automation-manager' );
		}

		return null;
	}

	/** A bare address is shorthand for an exact match, as on IP Rules. */
	private static function as_cidr( string $entry ): string {
		if ( str_contains( $entry, '/' ) ) {
			return $entry;
		}
		return str_contains( $entry, ':' ) ? $entry . '/128' : $entry . '/32';
	}
}
