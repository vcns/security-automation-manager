<?php
/**
 * http-01 challenge responder.
 *
 * Serves /.well-known/acme-challenge/{token} straight from a stored token map
 * without touching rewrite rules or writing files into the webroot -- it
 * intercepts the request at parse_request, before WordPress routing, so it
 * works with or without pretty permalinks and regardless of .htaccess state.
 *
 * http-01 is the fallback when no DNS provider is configured. It cannot
 * validate wildcard names (the CA requires dns-01 for those) and requires
 * the CA to reach this site over port 80.
 */

declare( strict_types=1 );

namespace WP_SAM\Certificates;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Challenge_Http {

	private const OPTION = 'wp_sam_acme_http_tokens';
	private const PREFIX = '/.well-known/acme-challenge/';

	public function register(): void {
		add_action( 'parse_request', array( $this, 'maybe_serve_token' ), 0 );
	}

	public function put_token( string $token, string $key_authorization ): void {
		$tokens = $this->tokens();

		$tokens[ $token ] = array(
			'key_authorization' => $key_authorization,
			'created_at'        => time(),
		);

		update_option( self::OPTION, $tokens, false );
	}

	public function delete_token( string $token ): void {
		$tokens = $this->tokens();
		unset( $tokens[ $token ] );
		update_option( self::OPTION, $tokens, false );
	}

	/**
	 * Fired on parse_request. Serves the key authorization for known tokens.
	 */
	public function maybe_serve_token(): void {
		$request_uri = isset( $_SERVER['REQUEST_URI'] ) ? (string) wp_unslash( $_SERVER['REQUEST_URI'] ) : '';
		$path        = (string) wp_parse_url( $request_uri, PHP_URL_PATH );

		if ( ! str_starts_with( $path, self::PREFIX ) ) {
			return;
		}

		$token  = substr( $path, strlen( self::PREFIX ) );
		$tokens = $this->tokens();

		// Tokens are single-purpose and short-lived; anything over a day old is
		// leftover state from a failed order and is treated as unknown.
		if (
			'' === $token
			|| ! isset( $tokens[ $token ] )
			|| ( time() - (int) $tokens[ $token ]['created_at'] ) > DAY_IN_SECONDS
		) {
			status_header( 404 );
			exit;
		}

		status_header( 200 );
		header( 'Content-Type: text/plain' );
		echo $tokens[ $token ]['key_authorization']; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- RFC 8555 key authorization string (base64url token . thumbprint), no markup context.
		exit;
	}

	private function tokens(): array {
		$tokens = get_option( self::OPTION, array() );

		return is_array( $tokens ) ? $tokens : array();
	}
}
