<?php
/**
 * Emits X-Frame-Options on enabled surfaces.
 *
 * Only DENY and SAMEORIGIN are supported -- ALLOW-FROM is deprecated and
 * unsupported by modern browsers, so it is deliberately not offered. CSP's
 * frame-ancestors directive supersedes this header in browsers that support
 * it; this remains a fallback for older browsers that don't.
 */

declare( strict_types=1 );

namespace WP_SAM\Security;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class X_Frame_Options_Builder extends Pillar_Header_Builder {

	public const PILLAR_KEY = 'x-frame-options';

	public const VALID_VALUES = array( 'DENY', 'SAMEORIGIN' );

	/**
	 * Restricts a value to the X-Frame-Options values this pillar allows.
	 *
	 * @param mixed $value Submitted value.
	 * @return string A permitted value, or an empty string when the value is not allowed.
	 */
	public static function sanitize_value( mixed $value ): string {
		$value = strtoupper( trim( (string) $value ) );
		return in_array( $value, self::VALID_VALUES, true ) ? $value : '';
	}

	/**
	 * Sends the X-Frame-Options header for a profile.
	 *
	 * @param array  $profile Pillar profile row.
	 * @param string $surface Surface slug, unused.
	 * @return bool True when the header was sent.
	 */
	protected function emit_profile_header( array $profile, string $surface ): bool {
		unset( $surface );
		$value = self::extract_value( $profile );
		if ( '' === $value ) {
			return false;
		}

		header( 'X-Frame-Options: ' . $value );
		return true;
	}

	/**
	 * Reads the X-Frame-Options value from a profile's stored payload.
	 *
	 * @param array $profile Pillar profile row.
	 * @return string A permitted value, or an empty string.
	 */
	public static function extract_value( array $profile ): string {
		$payload = json_decode( (string) ( $profile['payload'] ?? '' ), true );
		$value   = is_array( $payload ) ? (string) ( $payload['value'] ?? '' ) : '';
		return self::sanitize_value( $value );
	}
}
