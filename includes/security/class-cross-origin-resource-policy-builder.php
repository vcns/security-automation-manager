<?php
/**
 * Emits Cross-Origin-Resource-Policy (CORP) on enabled surfaces.
 *
 * Controls whether other origins may load this site's own resources
 * (scripts, images, fonts, etc.) via <img>, <script>, fetch(), and similar.
 * The lowest-risk of this plugin's cross-origin headers to enable: a
 * misconfiguration can stop a legitimate third party (a CDN, a partner
 * embedding one of this site's assets) from loading this site's own
 * resource, but it never breaks resources this site itself loads from
 * elsewhere.
 */

declare( strict_types=1 );

namespace WP_SAM\Security;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Cross_Origin_Resource_Policy_Builder extends Pillar_Header_Builder {

	public const PILLAR_KEY = 'cross-origin-resource-policy';

	public const VALID_VALUES = array( 'same-site', 'same-origin', 'cross-origin' );

	/**
	 * Restricts a value to the Cross-Origin-Resource-Policy values this pillar allows.
	 *
	 * @param mixed $value Submitted value.
	 * @return string A permitted value, or an empty string when the value is not allowed.
	 */
	public static function sanitize_value( mixed $value ): string {
		$value = strtolower( trim( (string) $value ) );
		return in_array( $value, self::VALID_VALUES, true ) ? $value : '';
	}

	/**
	 * Sends the Cross-Origin-Resource-Policy header for a profile.
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

		header( 'Cross-Origin-Resource-Policy: ' . $value );
		return true;
	}

	/**
	 * Reads the Cross-Origin-Resource-Policy value from a profile's stored payload.
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
