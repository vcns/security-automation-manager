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
		$request_uri = isset( $_SERVER['REQUEST_URI'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '';
		$path        = (string) wp_parse_url( $request_uri, PHP_URL_PATH );

		$result = $this->resolve( $path );
		if ( null === $result ) {
			return;
		}

		$this->emit_status( $result['status'] );
		if ( 200 === $result['status'] ) {
			$this->emit_content_type( 'text/plain' );
			$this->emit_body( (string) $result['body'] );
		}
		$this->terminate();
	}

	// ── Response emission ─────────────────────────────────────────────────────
	//
	// Each side effect below is its own small protected method purely so a
	// test can override them to capture what maybe_serve_token() decided to
	// do without actually sending headers or terminating the PHP process --
	// production always calls status_header()/header()/echo/exit() exactly
	// as before. See test/unit/ChallengeHttpTest.php.

	protected function emit_status( int $status ): void {
		status_header( $status );
	}

	protected function emit_content_type( string $content_type ): void {
		header( 'Content-Type: ' . $content_type );
	}

	protected function emit_body( string $body ): void {
		echo $body; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- RFC 8555 key authorization string (base64url token . thumbprint), no markup context.
	}

	protected function terminate(): void {
		exit;
	}

	/**
	 * Pure decision logic for a given request path: what status/body (if any)
	 * this request should get. Never touches headers, output, or exit() --
	 * split out from maybe_serve_token() specifically so it's unit-testable
	 * (that method's status_header()/exit() calls can't be observed from a
	 * PHPUnit process without terminating it).
	 *
	 * @return array{status:int, body:?string}|null null = not a challenge
	 *         request at all; the caller should let normal routing continue.
	 */
	public function resolve( string $path ): ?array {
		if ( ! str_starts_with( $path, self::PREFIX ) ) {
			return null;
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
			return array(
				'status' => 404,
				'body'   => null,
			);
		}

		return array(
			'status' => 200,
			'body'   => $tokens[ $token ]['key_authorization'],
		);
	}

	private function tokens(): array {
		$tokens = get_option( self::OPTION, array() );

		return is_array( $tokens ) ? $tokens : array();
	}
}
