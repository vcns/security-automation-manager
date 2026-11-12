<?php
/**
 * One-time credential for Conflict_Detector's internal probe request.
 *
 * The probe sends Request_Surface::CONFLICT_PROBE_HEADER so that, for that
 * one request, this plugin suppresses its own security headers, its request
 * observation and Traffic Guard. The header used to carry a fixed value
 * ('1'), so any client could send it to skip Traffic Guard entirely --
 * rate limits, block stages and even explicit IP block rules -- and stay
 * invisible to every detector. The value is now a random token issued for
 * that one probe, stored only as a hash, valid for a short window, and
 * revoked as soon as the probe returns.
 */

declare( strict_types=1 );

namespace WP_SAM\Security;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Conflict_Probe_Token {

	private const TRANSIENT_PREFIX = 'wp_sam_probe_';

	/** Comfortably longer than the probe's own 10-second request timeout. */
	private const TTL_SECONDS = 60;

	public static function issue(): string {
		$token = bin2hex( random_bytes( 32 ) );
		set_transient( self::key( $token ), 1, self::TTL_SECONDS );
		return $token;
	}

	/**
	 * Rejects anything that isn't shaped like an issued token before
	 * touching storage, so a client sending junk in the header costs no
	 * lookup at all.
	 */
	public static function is_valid( string $token ): bool {
		if ( 1 !== preg_match( '/^[0-9a-f]{64}$/', $token ) ) {
			return false;
		}
		return (bool) get_transient( self::key( $token ) );
	}

	public static function revoke( string $token ): void {
		delete_transient( self::key( $token ) );
	}

	private static function key( string $token ): string {
		return self::TRANSIENT_PREFIX . hash( 'sha256', $token );
	}
}
