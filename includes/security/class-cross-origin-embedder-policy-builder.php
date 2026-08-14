<?php
/**
 * Emits Cross-Origin-Embedder-Policy (COEP) on enabled surfaces.
 *
 * The highest-risk header this plugin manages. "require-corp" blocks every
 * cross-origin subresource (fonts, images, iframes, scripts) that doesn't
 * explicitly opt in via a matching Cross-Origin-Resource-Policy header or
 * CORS -- most third-party embeds, ad tags, and CDN-hosted fonts (including
 * Google Fonts, unless self-hosted or already CORS-enabled) do not opt in
 * by default, so enabling this carelessly silently breaks unrelated page
 * content rather than producing an obvious error. "credentialless" is
 * usually the safer of the two enforcing values: cross-origin resources
 * load without credentials instead of being blocked outright, at the cost
 * of breaking anything that genuinely needs a credentialed cross-origin
 * request. COEP is only actually required for sites that need cross-origin
 * isolation (SharedArrayBuffer, high-resolution timers, and similar APIs);
 * most WordPress sites do not need it at all.
 *
 * Supports a report-only learning mode, unlike the other simple pillars:
 * Chromium supports a native Cross-Origin-Embedder-Policy-Report-Only header
 * plus Reporting API delivery, so a real breakage signal can be gathered
 * before committing to enforcement -- see payload.mode below.
 */

declare( strict_types=1 );

namespace WP_SAM\Security;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Cross_Origin_Embedder_Policy_Builder extends Pillar_Header_Builder {

	public const PILLAR_KEY = 'cross-origin-embedder-policy';

	public const VALID_VALUES = array( 'unsafe-none', 'require-corp', 'credentialless' );

	/**
	 * disabled: no header emitted at all.
	 * report-only: Cross-Origin-Embedder-Policy-Report-Only + Reporting API
	 *   endpoint, so violations are observable without breaking anything.
	 * enforce: the real, enforcing Cross-Origin-Embedder-Policy header.
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
			header( 'Cross-Origin-Embedder-Policy-Report-Only: ' . $value );
			// COOP/COEP have no report-uri equivalent -- the Reporting API is the
			// only delivery mechanism, so this is unconditional (unlike CSP's
			// optional report-to, which is one of two delivery paths).
			Reporting_Endpoint::emit_headers();
			return true;
		}

		header( 'Cross-Origin-Embedder-Policy: ' . $value );
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
