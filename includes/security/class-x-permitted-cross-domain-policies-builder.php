<?php
/**
 * Emits X-Permitted-Cross-Domain-Policies on enabled surfaces.
 *
 * A legacy header from the Adobe Flash/Acrobat era, controlling whether
 * Flash and PDF plugins may load a cross-domain policy file (crossdomain.xml)
 * from this site. Flash is dead and PDF.js doesn't consult this header, so
 * "none" is almost always the correct value for a modern site -- this
 * pillar exists mainly to explicitly close a legacy attack surface that
 * would otherwise sit at its (permissive) browser default.
 */

declare( strict_types=1 );

namespace WP_SAM\Security;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class X_Permitted_Cross_Domain_Policies_Builder extends Pillar_Header_Builder {

	public const PILLAR_KEY = 'x-permitted-cross-domain-policies';

	public const VALID_VALUES = array( 'none', 'master-only', 'by-content-type', 'all' );

	/**
	 * Restricts a value to the X-Permitted-Cross-Domain-Policies values this pillar allows.
	 *
	 * @param mixed $value Submitted value.
	 * @return string A permitted value, or an empty string when the value is not allowed.
	 */
	public static function sanitize_value( mixed $value ): string {
		$value = strtolower( trim( (string) $value ) );
		return in_array( $value, self::VALID_VALUES, true ) ? $value : '';
	}

	/**
	 * Sends the X-Permitted-Cross-Domain-Policies header for a profile.
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

		header( 'X-Permitted-Cross-Domain-Policies: ' . $value );
		return true;
	}

	/**
	 * Reads the X-Permitted-Cross-Domain-Policies value from a profile's stored payload.
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
