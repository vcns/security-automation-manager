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
 */

declare( strict_types=1 );

namespace WP_SAM\Security;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Cross_Origin_Embedder_Policy_Builder extends Pillar_Header_Builder {

	public const PILLAR_KEY = 'cross-origin-embedder-policy';

	public const VALID_VALUES = array( 'unsafe-none', 'require-corp', 'credentialless' );

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

		header( 'Cross-Origin-Embedder-Policy: ' . $value );
		return true;
	}

	public static function extract_value( array $profile ): string {
		$payload = json_decode( (string) ( $profile['payload'] ?? '' ), true );
		$value   = is_array( $payload ) ? (string) ( $payload['value'] ?? '' ) : '';
		return self::sanitize_value( $value );
	}
}
