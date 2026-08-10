<?php
/**
 * Emits Cross-Origin-Opener-Policy (COOP) on enabled surfaces.
 *
 * Isolates this site's browsing context group from cross-origin windows it
 * opens or is opened by, closing off cross-window/Spectre-style leaks. Real
 * breakage risk: "same-origin" severs window.opener access from any
 * cross-origin popup this site opens (or is opened by) -- including the
 * popup-based OAuth/SSO flows many login and payment integrations rely on.
 * "same-origin-allow-popups" keeps isolation for this site's own top-level
 * navigation while still permitting popups to hold a (restricted) opener
 * reference back, which is what most sites that need popups actually want.
 */

declare( strict_types=1 );

namespace WP_SAM\Security;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Cross_Origin_Opener_Policy_Builder extends Pillar_Header_Builder {

	public const PILLAR_KEY = 'cross-origin-opener-policy';

	public const VALID_VALUES = array( 'unsafe-none', 'same-origin', 'same-origin-allow-popups' );

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

		header( 'Cross-Origin-Opener-Policy: ' . $value );
		return true;
	}

	public static function extract_value( array $profile ): string {
		$payload = json_decode( (string) ( $profile['payload'] ?? '' ), true );
		$value   = is_array( $payload ) ? (string) ( $payload['value'] ?? '' ) : '';
		return self::sanitize_value( $value );
	}
}
