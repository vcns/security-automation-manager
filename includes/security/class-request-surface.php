<?php
/**
 * Shared request-classification helpers for anything that behaves
 * differently per site surface (frontend/admin/login/api) or needs to
 * recognise Conflict_Detector's internal probe request.
 *
 * Split out of Header_Builder so Content_Rewriter (body-rewriting
 * components like reverse-tabnabbing and dependency governance) can reuse
 * the exact same surface detection without extending a header-emission
 * class it has nothing to do with.
 */

declare( strict_types=1 );

namespace WP_SAM\Security;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

abstract class Request_Surface {

	/**
	 * HTTP header name Conflict_Detector's internal probe sends, and this
	 * class checks the corresponding $_SERVER key for, to recognise and
	 * suppress the plugin's own CSP output during that one request. Defined
	 * once and referenced by both sides so they can never silently drift
	 * apart again -- they already did once (the outgoing probe header was
	 * never updated during the WP_CSP -> WP_SAM rename while this check
	 * was), which meant the suppression never actually triggered and every
	 * probe misreported this plugin's own live CSP header as a "competing"
	 * header from another plugin or the web server.
	 */
	public const CONFLICT_PROBE_HEADER = 'X-WP-SAM-Probe';

	/**
	 * Conflict_Detector issues an internal request carrying CONFLICT_PROBE_HEADER
	 * to see what security headers other plugins/web-server config are already
	 * sending, without this plugin's own header masking the result.
	 */
	protected function is_conflict_probe_request(): bool {
		$server_key = 'HTTP_' . strtoupper( str_replace( '-', '_', self::CONFLICT_PROBE_HEADER ) );

		return isset( $_SERVER[ $server_key ] ) && '1' === (string) $_SERVER[ $server_key ];
	}

	// ── Surface detection ─────────────────────────────────────────────────────

	protected function detect_surface(): string {
		if ( defined( 'REST_REQUEST' ) && REST_REQUEST ) {
			return 'api';
		}

		if ( isset( $GLOBALS['pagenow'] ) && 'wp-login.php' === $GLOBALS['pagenow'] ) {
			return 'login';
		}

		$request_path = $this->get_request_path();
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

	protected function get_request_path(): string {
		$uri = isset( $_SERVER['REQUEST_URI'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '';
		if ( '' === $uri ) {
			return '';
		}

		$path = wp_parse_url( $uri, PHP_URL_PATH );
		return is_string( $path ) ? rtrim( $path, '/' ) : '';
	}
}
