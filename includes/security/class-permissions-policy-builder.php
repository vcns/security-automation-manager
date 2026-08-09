<?php
/**
 * Emits Permissions-Policy on enabled surfaces.
 *
 * Unlike X-Frame-Options/X-Content-Type-Options/Referrer-Policy, this
 * pillar has multiple independently-configurable directives per surface
 * (closer in shape to CSP's directive model) -- the payload JSON holds a
 * directive-name => allowlist-token map rather than a single scalar value.
 *
 * v1 deliberately offers a constrained allowlist token set (none/self/all)
 * rather than free-text origin lists, to avoid reopening the header-
 * injection sanitization surface CSP already solves for source hosts. A
 * directive absent from the map is simply not emitted, so the browser's
 * own default policy applies to that feature -- this is standard
 * Permissions-Policy behaviour, not a plugin limitation.
 *
 * No report-only mode: Permissions-Policy-Report-Only exists only in
 * draft form with minimal real browser support. No discovery workflow or
 * Decision Engine wiring either -- deferred until a pillar genuinely
 * needs it, per the same reasoning as the other simple pillars.
 */

declare( strict_types=1 );

namespace WP_SAM\Security;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Permissions_Policy_Builder extends Pillar_Header_Builder {

	public const PILLAR_KEY = 'permissions-policy';

	/**
	 * A deliberately small starter set of the most security/privacy-relevant
	 * directives, not the full ~30-directive registry. More can be added
	 * later without a schema change -- the payload shape already supports it.
	 */
	public const KNOWN_DIRECTIVES = array(
		'geolocation',
		'camera',
		'microphone',
		'fullscreen',
		'payment',
		'usb',
		'autoplay',
	);

	public const ALLOWED_TOKENS = array( 'none', 'self', 'all' );

	public static function sanitize_token( mixed $value ): string {
		$value = strtolower( trim( (string) $value ) );
		return in_array( $value, self::ALLOWED_TOKENS, true ) ? $value : '';
	}

	public static function token_to_allowlist( string $token ): string {
		switch ( $token ) {
			case 'none':
				return '()';
			case 'self':
				return '(self)';
			case 'all':
				return '(*)';
			default:
				return '';
		}
	}

	protected function emit_profile_header( array $profile, string $surface ): bool {
		unset( $surface );
		$directives = self::extract_directives( $profile );
		if ( empty( $directives ) ) {
			return false;
		}

		$parts = array();
		foreach ( $directives as $directive => $token ) {
			$allowlist = self::token_to_allowlist( (string) $token );
			if ( '' === $allowlist || ! in_array( $directive, self::KNOWN_DIRECTIVES, true ) ) {
				continue;
			}
			$parts[] = $directive . '=' . $allowlist;
		}

		if ( empty( $parts ) ) {
			return false;
		}

		header( 'Permissions-Policy: ' . implode( ', ', $parts ) );
		return true;
	}

	/**
	 * @return array<string,string> directive => sanitized token, unknown
	 *                               directives and invalid tokens dropped.
	 */
	public static function extract_directives( array $profile ): array {
		$payload    = json_decode( (string) ( $profile['payload'] ?? '' ), true );
		$raw        = is_array( $payload ) ? ( $payload['directives'] ?? null ) : null;
		$directives = array();

		if ( ! is_array( $raw ) ) {
			return $directives;
		}

		foreach ( $raw as $directive => $token ) {
			if ( ! in_array( $directive, self::KNOWN_DIRECTIVES, true ) ) {
				continue;
			}
			$sanitized = self::sanitize_token( $token );
			if ( '' !== $sanitized ) {
				$directives[ $directive ] = $sanitized;
			}
		}

		return $directives;
	}
}
