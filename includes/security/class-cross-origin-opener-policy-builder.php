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
 *
 * Supports a report-only learning mode, unlike the other simple pillars:
 * Chromium supports a native Cross-Origin-Opener-Policy-Report-Only header
 * plus Reporting API delivery, so a real breakage signal can be gathered
 * before committing to enforcement -- see payload.mode below.
 */

declare( strict_types=1 );

namespace WP_SAM\Security;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Cross_Origin_Opener_Policy_Builder extends Pillar_Header_Builder {

	public const PILLAR_KEY = 'cross-origin-opener-policy';

	public const VALID_VALUES = array( 'unsafe-none', 'same-origin', 'same-origin-allow-popups' );

	/**
	 * disabled: no header emitted at all.
	 * report-only: Cross-Origin-Opener-Policy-Report-Only + Reporting API
	 *   endpoint, so violations are observable without breaking anything.
	 * enforce: the real, enforcing Cross-Origin-Opener-Policy header.
	 */
	public const VALID_MODES = array( 'disabled', 'report-only', 'enforce' );

	public static function sanitize_value( mixed $value ): string {
		$value = strtolower( trim( (string) $value ) );
		return in_array( $value, self::VALID_VALUES, true ) ? $value : '';
	}

	public static function sanitize_mode( mixed $mode ): string {
		$mode = strtolower( trim( (string) $mode ) );
		return in_array( $mode, self::VALID_MODES, true ) ? $mode : '';
	}

	protected function emit_profile_header( array $profile, string $surface ): bool {
		unset( $surface );
		$value = self::extract_value( $profile );
		if ( '' === $value ) {
			return false;
		}

		$mode = self::extract_mode( $profile );
		if ( 'disabled' === $mode ) {
			return false;
		}

		if ( 'report-only' === $mode ) {
			header( 'Cross-Origin-Opener-Policy-Report-Only: ' . $value );
			// COOP/COEP have no report-uri equivalent -- the Reporting API is the
			// only delivery mechanism, so this is unconditional (unlike CSP's
			// optional report-to, which is one of two delivery paths).
			Reporting_Endpoint::emit_headers();
			return true;
		}

		header( 'Cross-Origin-Opener-Policy: ' . $value );
		return true;
	}

	public static function extract_value( array $profile ): string {
		$payload = json_decode( (string) ( $profile['payload'] ?? '' ), true );
		$value   = is_array( $payload ) ? (string) ( $payload['value'] ?? '' ) : '';
		return self::sanitize_value( $value );
	}

	/**
	 * Defaults to 'enforce' when absent/invalid -- every profile that
	 * predates the mode field was, by definition, unconditionally
	 * enforcing whenever enabled; an upgrade must not silently switch
	 * it to report-only or stop emitting the header.
	 */
	public static function extract_mode( array $profile ): string {
		$payload = json_decode( (string) ( $profile['payload'] ?? '' ), true );
		$mode    = is_array( $payload ) ? self::sanitize_mode( $payload['mode'] ?? '' ) : '';
		return '' !== $mode ? $mode : 'enforce';
	}
}
