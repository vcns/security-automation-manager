<?php
/**
 * Shared request-classification helpers, extracted from Request_Surface so
 * code outside the header/content-rewriting hierarchy (the Request
 * Observation Framework) can reuse the exact same surface detection without
 * extending a class shaped around header emission.
 *
 * Request_Surface's own methods delegate here so the two can never drift
 * apart -- see CONFLICT_PROBE_HEADER's own docblock for the one time they
 * already did.
 */

declare( strict_types=1 );

namespace WP_SAM\Intelligence;

use WP_SAM\Security\Request_Surface;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Surface_Classifier {

	/**
	 * Conflict_Detector issues an internal request carrying
	 * Request_Surface::CONFLICT_PROBE_HEADER to see what security headers
	 * other plugins/web-server config are already sending, without this
	 * plugin's own header (or, here, its own request-observation) masking
	 * the result.
	 */
	public static function is_conflict_probe_request(): bool {
		$server_key = 'HTTP_' . strtoupper( str_replace( '-', '_', Request_Surface::CONFLICT_PROBE_HEADER ) );

		return isset( $_SERVER[ $server_key ] ) && '1' === (string) $_SERVER[ $server_key ];
	}

	// ── Surface detection ─────────────────────────────────────────────────────

	public static function detect(): string {
		if ( defined( 'REST_REQUEST' ) && REST_REQUEST ) {
			return 'api';
		}

		if ( isset( $GLOBALS['pagenow'] ) && 'wp-login.php' === $GLOBALS['pagenow'] ) {
			return 'login';
		}

		$request_path = self::request_path();
		if ( preg_match( '#(?:^|/)wp-admin(?:/|$)#', $request_path ) ) {
			return 'admin';
		}
		if ( preg_match( '#(?:^|/)wp-login\.php$#', $request_path ) ) {
			return 'login';
		}

		if ( is_admin() ) {
			return 'admin';
		}
		return 'frontend';
	}

	public static function request_path(): string {
		$uri = self::raw_server_value( 'REQUEST_URI' );
		if ( '' === $uri ) {
			return '';
		}

		$path = wp_parse_url( $uri, PHP_URL_PATH );
		return is_string( $path ) ? rtrim( $path, '/' ) : '';
	}

	public static function query_string(): string {
		return self::raw_server_value( 'QUERY_STRING' );
	}

	/**
	 * Reads a raw $_SERVER value with WordPress's own magic-quotes
	 * unslashing and a defensive strip of raw control characters, but
	 * deliberately WITHOUT sanitize_text_field() -- that function's own
	 * documented behaviour ("Remove percent-encoded characters", see
	 * _sanitize_text_fields() in wp-includes/formatting.php) strips every
	 * %XX sequence outright, which would silently defeat exactly the
	 * encoded-evasion detection (e.g. %2e%2e%2f traversal, %27 in a query
	 * value) this class exists to preserve for. sanitize_text_field() is
	 * built for sanitizing text meant for display, not for preserving a
	 * raw request component for security analysis.
	 */
	private static function raw_server_value( string $key ): string {
		if ( ! isset( $_SERVER[ $key ] ) ) {
			return '';
		}

		$value    = wp_unslash( (string) $_SERVER[ $key ] );
		$filtered = preg_replace( '/[\x00-\x1F\x7F]/', '', $value );
		return null !== $filtered ? $filtered : '';
	}
}
