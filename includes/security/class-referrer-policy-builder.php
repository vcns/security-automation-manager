<?php
/**
 * Emits Referrer-Policy on enabled surfaces.
 *
 * HTTP header only -- no <meta name="referrer"> injection, consistent with
 * this plugin's header-only architecture and to avoid a new page-content
 * modification attack surface.
 */

declare( strict_types=1 );

namespace WP_SAM\Security;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Referrer_Policy_Builder extends Pillar_Header_Builder {

	public const PILLAR_KEY = 'referrer-policy';

	public const VALID_VALUES = array(
		'no-referrer',
		'no-referrer-when-downgrade',
		'origin',
		'origin-when-cross-origin',
		'same-origin',
		'strict-origin',
		'strict-origin-when-cross-origin',
		'unsafe-url',
	);

	public const DEFAULT_VALUE = 'strict-origin-when-cross-origin';

	public static function sanitize_value( mixed $value ): string {
		$value = strtolower( trim( (string) $value ) );
		return in_array( $value, self::VALID_VALUES, true ) ? $value : '';
	}

	protected function emit_profile_header( array $profile, string $surface ): bool {
		unset( $surface );
		$value = self::extract_value( $profile );
		if ( '' === $value ) {
			return false;
		}

		header( 'Referrer-Policy: ' . $value );
		return true;
	}

	public static function extract_value( array $profile ): string {
		$payload = json_decode( (string) ( $profile['payload'] ?? '' ), true );
		$value   = is_array( $payload ) ? (string) ( $payload['value'] ?? '' ) : '';
		return self::sanitize_value( $value );
	}
}
