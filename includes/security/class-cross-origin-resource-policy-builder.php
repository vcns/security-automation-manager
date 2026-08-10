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

		header( 'Cross-Origin-Resource-Policy: ' . $value );
		return true;
	}

	public static function extract_value( array $profile ): string {
		$payload = json_decode( (string) ( $profile['payload'] ?? '' ), true );
		$value   = is_array( $payload ) ? (string) ( $payload['value'] ?? '' ) : '';
		return self::sanitize_value( $value );
	}
}
