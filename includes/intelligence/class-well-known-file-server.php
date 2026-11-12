<?php
/**
 * Serves the well-known files an administrator saved in this plugin
 * (Well_Known_File_Store), through WordPress itself. No file is written
 * into the site's folder, so deactivating the plugin puts back whatever
 * the site served before.
 *
 * robots.txt goes through WordPress core's own robots_txt filter, which
 * core applies when it answers /robots.txt. The filter runs last so the
 * saved version is exactly what visitors get, replacing core's default
 * and anything an SEO plugin added -- the editor says so before anyone
 * saves. WordPress's "Discourage search engines" setting (Settings →
 * Reading) is unaffected: since WordPress 5.3 it adds a noindex tag to
 * every page rather than using robots.txt.
 *
 * The others have no handler in core. They are answered at parse_request,
 * before WordPress routing, the same way Certificates\Challenge_Http
 * answers ACME challenges.
 *
 * Either way, a real file at the same path wins: the web server sends it
 * without running WordPress. Well_Known_File_Editor checks what visitors
 * actually get after each save.
 */

declare( strict_types=1 );

namespace WP_SAM\Intelligence;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Well_Known_File_Server {

	private Well_Known_File_Store $store;

	public function __construct( ?Well_Known_File_Store $store = null ) {
		$this->store = $store ?? new Well_Known_File_Store();
	}

	public function register(): void {
		add_filter( 'robots_txt', array( $this, 'filter_robots_txt' ), PHP_INT_MAX );
		add_action( 'parse_request', array( $this, 'maybe_serve' ), 0 );
	}

	/** @param mixed $output Core's robots.txt, plus anything earlier filters added. */
	public function filter_robots_txt( $output ): string {
		return $this->store->content( 'robots' ) ?? (string) $output;
	}

	/** Fired on parse_request. Answers a saved file's path and ends the request. */
	public function maybe_serve(): void {
		$method = isset( $_SERVER['REQUEST_METHOD'] ) ? strtoupper( sanitize_text_field( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) ) : 'GET';
		if ( 'GET' !== $method && 'HEAD' !== $method ) {
			return;
		}

		$request_uri = isset( $_SERVER['REQUEST_URI'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '';
		$body        = $this->resolve( (string) wp_parse_url( $request_uri, PHP_URL_PATH ) );
		if ( null === $body ) {
			return;
		}

		$this->emit_status( 200 );
		$this->emit_header( 'Content-Type: text/plain; charset=utf-8' );
		$this->emit_header( 'X-Content-Type-Options: nosniff' );
		if ( 'HEAD' !== $method ) {
			$this->emit_body( $body );
		}
		$this->terminate();
	}

	/**
	 * The saved file this request path asks for, or null to let WordPress
	 * carry on. robots.txt is never answered here (see the class docblock).
	 */
	public function resolve( string $path ): ?string {
		$key = Well_Known_File_Catalog::key_for_path( $path );
		if ( null === $key || 'robots' === $key ) {
			return null;
		}
		return $this->store->content( $key );
	}

	// ── Response emission ─────────────────────────────────────────────────────
	//
	// Separate methods only so a test can capture what maybe_serve() decided
	// without sending headers or ending the PHP process -- the same split
	// as Certificates\Challenge_Http.

	protected function emit_status( int $status ): void {
		status_header( $status );
	}

	protected function emit_header( string $header ): void {
		header( $header );
	}

	protected function emit_body( string $body ): void {
		echo $body; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- served as text/plain with nosniff, never as HTML.
	}

	protected function terminate(): void {
		exit;
	}
}
