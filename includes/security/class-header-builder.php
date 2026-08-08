<?php
/**
 * Shared envelope for per-surface security-header pillars (CSP today;
 * X-Frame-Options / X-Content-Type-Options / Referrer-Policy and others
 * to follow).
 *
 * Owns hook registration, the header_emitted/headers_sent() guard, the
 * internal conflict-probe suppression, and surface detection. Each pillar
 * subclass owns its own storage (load_profile()), its own "should this
 * surface get a header at all" rule (is_profile_active()), and the actual
 * header name/value construction (emit_profile_header()).
 */

declare( strict_types=1 );

namespace WP_SAM\Security;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

abstract class Header_Builder {

	protected bool $header_emitted = false;

	// ── Bootstrap ─────────────────────────────────────────────────────────────

	public function register(): void {
		// send_headers fires before any output, ideal for emitting headers.
		add_action( 'send_headers', array( $this, 'emit_header' ) );
		add_filter( 'wp_redirect', array( $this, 'emit_header_before_redirect' ), 1, 2 );
	}

	// ── Header emission ───────────────────────────────────────────────────────

	public function emit_header(): void {
		// Skip if headers already sent (e.g. a plugin flushed output early).
		if ( $this->header_emitted || headers_sent() ) {
			return;
		}

		if ( $this->is_conflict_probe_request() ) {
			return;
		}

		$surface = $this->detect_surface();
		$profile = $this->load_profile( $surface );

		if ( null === $profile || ! $this->is_profile_active( $profile ) ) {
			return;
		}

		if ( $this->emit_profile_header( $profile, $surface ) ) {
			$this->header_emitted = true;
		}
	}

	public function emit_header_before_redirect( string $location, int $status = 302 ): string {
		unset( $status );
		$this->emit_header();
		return $location;
	}

	/**
	 * Loads this pillar's stored profile for the given surface, or null if
	 * none exists yet (e.g. before activation seeding has run).
	 */
	abstract protected function load_profile( string $surface ): ?array;

	/**
	 * Whether the loaded profile should result in a header being emitted at
	 * all (e.g. CSP's 'disabled' mode, or a simple pillar's 'enabled' flag).
	 */
	abstract protected function is_profile_active( array $profile ): bool;

	/**
	 * Builds and sends the actual header(s) for this profile. Returns true
	 * if a header was sent, false if emission was skipped (e.g. CSP's
	 * empty-policy case) so the caller leaves header_emitted false and a
	 * later hook fire (send_headers, then wp_redirect) can retry.
	 */
	abstract protected function emit_profile_header( array $profile, string $surface ): bool;

	// ── Conflict-probe suppression ───────────────────────────────────────────

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

	// ── Custom header-name override ─────────────────────────────────────────

	/**
	 * Validates an admin-supplied custom header name: must be a legal RFC
	 * 7230 token, and must not collide with a small set of headers whose
	 * semantics WordPress/browsers rely on.
	 */
	public static function sanitize_custom_policy_header_name( mixed $header_name ): string {
		$header_name = trim( (string) $header_name );
		if ( '' === $header_name ) {
			return '';
		}

		if ( ! preg_match( "/^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/", $header_name ) ) {
			return '';
		}

		$blocked = array(
			'connection',
			'content-length',
			'host',
			'keep-alive',
			'proxy-authenticate',
			'proxy-authorization',
			'set-cookie',
			'set-cookie2',
			'te',
			'trailer',
			'transfer-encoding',
			'upgrade',
		);

		return in_array( strtolower( $header_name ), $blocked, true ) ? '' : $header_name;
	}
}
