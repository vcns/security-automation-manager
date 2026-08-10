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
	 * Conflict_Detector issues an internal request carrying this header to
	 * see what security headers other plugins/web-server config are already
	 * sending, without this plugin's own header masking the result.
	 */
	protected function is_conflict_probe_request(): bool {
		return isset( $_SERVER['HTTP_X_WP_SAM_PROBE'] )
			&& '1' === (string) $_SERVER['HTTP_X_WP_SAM_PROBE'];
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
		$uri = isset( $_SERVER['REQUEST_URI'] ) ? (string) wp_unslash( $_SERVER['REQUEST_URI'] ) : '';
		if ( '' === $uri ) {
			return '';
		}

		$path = wp_parse_url( $uri, PHP_URL_PATH );
		return is_string( $path ) ? rtrim( $path, '/' ) : '';
	}
}
