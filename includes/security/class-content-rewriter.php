<?php
/**
 * Shared envelope for components that rewrite the rendered HTML body itself
 * rather than emit a header (reverse-tabnabbing noopener injection,
 * dependency governance's script/stylesheet inventory and enforcement).
 *
 * Opens a single plugin-owned output buffer at template_redirect -- late
 * enough that headers (sent earlier, from WP::send_headers()) are already
 * queued and cannot be affected, and nested inside any buffer a page-cache
 * plugin opened earlier in the request, so the transformed HTML is what
 * gets cached. Each subclass gets its own independent buffer; PHP nests
 * output buffers correctly (LIFO), and none of this plugin's own rewriters
 * touch the same element types, so buffer ordering between them never
 * matters.
 *
 * The request/response eligibility rules mirror what Conflict_Detector and
 * every header pillar already assume is safe to skip -- admin, login,
 * AJAX, REST, XML-RPC, cron, CLI, feeds, trackbacks, robots.txt, favicon,
 * sitemaps, non-GET/HEAD methods, and any response that isn't a successful
 * (2xx), non-streamed HTML document. Every failure mode -- a parser
 * exception, an unresolvable rewrite, a fatal-error shutdown mid-request --
 * fails open to the original, unmodified response.
 */

declare( strict_types=1 );

namespace WP_SAM\Security;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

abstract class Content_Rewriter extends Request_Surface {

	private bool $buffer_started = false;
	private ?int $buffer_level   = null;
	private bool $streamed       = false;
	private string $surface      = 'frontend';

	// ── Bootstrap ─────────────────────────────────────────────────────────────

	public function register(): void {
		add_action( 'template_redirect', array( $this, 'maybe_start_buffer' ) );
		// Normal closure point: wp_footer is the standard "page output is
		// essentially complete" signal, and request_exclusion_reason()
		// above excludes admin and login entirely, so this buffer only
		// ever opens for the front-end surface -- wp_footer is the one
		// relevant footer hook, not a three-surface set. Priority
		// PHP_INT_MAX so this runs after WordPress core's and every other
		// plugin's own wp_footer output has already been generated into
		// our buffer.
		add_action( 'wp_footer', array( $this, 'maybe_end_buffer' ), PHP_INT_MAX );
		// Fallback only, for what wp_footer cannot cover: a redirect,
		// wp_die(), or fatal error between template_redirect and wp_footer
		// (wp_footer never fires at all), or the rare theme that echoes a
		// small amount of markup after its wp_footer() call returns (e.g.
		// closing </body></html> tags) -- that trailing content is still
		// flushed through by this fallback, just not passed through
		// rewrite() the way content captured before wp_footer is, since it
		// was never inside our buffer to begin with. maybe_end_buffer() is
		// idempotent: if wp_footer already closed this buffer,
		// buffer_started is already false and this is a genuine no-op --
		// see its docblock. Priority PHP_INT_MAX for the same reason as
		// above.
		add_action( 'shutdown', array( $this, 'maybe_end_buffer' ), PHP_INT_MAX );
	}

	/**
	 * Whether this component is enabled for the given surface. Checked once,
	 * before the (comparatively expensive) buffer is opened at all.
	 */
	abstract protected function is_active( string $surface ): bool;

	/**
	 * Rewrites a completed, eligible HTML response. Must fail open (return
	 * $html unchanged) on any uncertainty -- never throw.
	 */
	abstract protected function rewrite( string $html, string $surface ): string;

	// ── Buffer lifecycle ──────────────────────────────────────────────────────

	public function maybe_start_buffer(): void {
		if ( $this->buffer_started ) {
			return;
		}

		if ( $this->is_conflict_probe_request() ) {
			return;
		}

		if ( null !== $this->request_exclusion_reason() ) {
			return;
		}

		$this->surface = $this->detect_surface();
		if ( ! $this->is_active( $this->surface ) ) {
			return;
		}

		if ( ob_start( array( $this, 'filter_output' ), 0 ) ) {
			$this->buffer_started = true;
			$this->buffer_level   = ob_get_level();
		}
	}

	/**
	 * Explicitly closes this instance's own buffer, and only this instance's
	 * own buffer -- never a buffer another component or plugin opened.
	 * Registered on BOTH wp_footer (the normal closure point) and shutdown
	 * (the fallback -- see register()) as the exact same callback, which is
	 * safe and idempotent: buffer_started is set false as this method's
	 * very last step on every path that does anything at all, so whichever
	 * hook fires second finds buffer_started already false and returns
	 * immediately at the guard below, without touching the buffer stack a
	 * second time.
	 *
	 * ob_get_level() is recorded at the moment maybe_start_buffer() opens
	 * this buffer, and re-checked here before touching anything:
	 * - If the current level is BELOW the recorded one, something else
	 *   already closed our buffer (and possibly others) first -- e.g. an
	 *   aggressive page-cache plugin unwinding the whole buffer stack.
	 *   Nothing to do; closing again would act on a buffer we don't own.
	 * - If the current level is AT OR ABOVE the recorded one, every buffer
	 *   from the top of the stack down to (and including) ours is closed
	 *   via ob_end_flush() -- never ob_end_clean(), since a buffer nested
	 *   inside ours that we don't own must have its content preserved, not
	 *   discarded. This is the only way to reach and close our own buffer
	 *   when something nested inside it hasn't closed cleanly by the time
	 *   `shutdown` fires -- PHP's buffer stack is strictly LIFO, so there is
	 *   no way to close a buffer out from under buffers still open above it.
	 */
	public function maybe_end_buffer(): void {
		if ( ! $this->buffer_started || null === $this->buffer_level ) {
			return;
		}

		if ( ob_get_level() < $this->buffer_level ) {
			$this->buffer_started = false;
			return;
		}

		while ( ob_get_level() >= $this->buffer_level ) {
			ob_end_flush();
		}

		$this->buffer_started = false;
	}

	/**
	 * Returns the reason the current request must not be buffered, or null
	 * when it is a public front-end page request eligible for rewriting.
	 */
	protected function request_exclusion_reason(): ?string {
		$method = $_SERVER['REQUEST_METHOD'] ?? null;
		if ( is_string( $method ) && ! in_array( strtoupper( $method ), array( 'GET', 'HEAD' ), true ) ) {
			return 'method';
		}

		if ( is_admin() ) {
			return 'admin';
		}

		if ( isset( $GLOBALS['pagenow'] ) && 'wp-login.php' === $GLOBALS['pagenow'] ) {
			return 'login';
		}

		if ( function_exists( 'wp_doing_ajax' ) && wp_doing_ajax() ) {
			return 'ajax';
		}

		if ( defined( 'REST_REQUEST' ) && REST_REQUEST ) {
			return 'rest';
		}

		if ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST ) {
			return 'xmlrpc';
		}

		if ( function_exists( 'wp_doing_cron' ) && wp_doing_cron() ) {
			return 'cron';
		}

		if ( function_exists( 'wp_is_json_request' ) && wp_is_json_request() ) {
			return 'json';
		}

		if ( function_exists( 'wp_is_xml_request' ) && wp_is_xml_request() ) {
			return 'xml';
		}

		// Front-end conditional tags need the main query; without it, fail closed.
		if ( ! isset( $GLOBALS['wp_query'] ) || ! $GLOBALS['wp_query'] instanceof \WP_Query ) {
			return 'no-main-query';
		}

		if ( is_feed() ) {
			return 'feed';
		}

		if ( is_trackback() ) {
			return 'trackback';
		}

		if ( is_robots() ) {
			return 'robots';
		}

		if ( function_exists( 'is_favicon' ) && is_favicon() ) {
			return 'favicon';
		}

		if ( '' !== (string) get_query_var( 'sitemap', '' ) || '' !== (string) get_query_var( 'sitemap-stylesheet', '' ) ) {
			return 'sitemap';
		}

		if ( 'cli' === PHP_SAPI || 'phpdbg' === PHP_SAPI || ( defined( 'WP_CLI' ) && WP_CLI ) ) {
			return 'cli';
		}

		return null;
	}

	/**
	 * Output-buffer callback: rewrites the completed response when eligible.
	 * Fails open -- any unexpected condition returns the original buffer.
	 */
	public function filter_output( string $buffer, int $phase ): string {
		try {
			if ( 0 !== ( $phase & PHP_OUTPUT_HANDLER_START ) ) {
				$this->streamed = false;
			}

			// A flush before the final phase means the response is being
			// streamed in chunks; rewriting fragments is unsafe.
			if ( 0 === ( $phase & PHP_OUTPUT_HANDLER_FINAL ) ) {
				$this->streamed = true;
				return $buffer;
			}

			if ( $this->streamed || '' === $buffer ) {
				return $buffer;
			}

			// Never rewrite the diagnostics of a fatal-error shutdown.
			$last_error = error_get_last();
			if ( is_array( $last_error )
				&& in_array( $last_error['type'] ?? 0, array( E_ERROR, E_PARSE, E_CORE_ERROR, E_COMPILE_ERROR ), true ) ) {
				return $buffer;
			}

			if ( ! $this->is_processable_response( $buffer ) ) {
				return $buffer;
			}

			$rewritten = $this->rewrite( $buffer, $this->surface );

			if ( $rewritten !== $buffer && ! headers_sent() ) {
				foreach ( headers_list() as $header ) {
					if ( 0 === stripos( $header, 'Content-Length:' ) ) {
						header_remove( 'Content-Length' );
						break;
					}
				}
			}

			return $rewritten;
		} catch ( \Throwable $unused ) {
			return $buffer;
		}
	}

	/**
	 * Determines whether the completed response may be rewritten: a
	 * successful (2xx) status, and text/html or application/xhtml+xml
	 * (from the Content-Type header when present, otherwise a heuristic
	 * check of the body itself).
	 */
	protected function is_processable_response( string $buffer, ?string $content_type = null, ?int $status = null ): bool {
		if ( null === $status ) {
			$code   = http_response_code();
			$status = is_int( $code ) ? $code : 200;
		}

		if ( $status < 200 || $status >= 300 ) {
			return false;
		}

		if ( null === $content_type ) {
			$content_type = $this->response_content_type();
		}

		if ( is_string( $content_type ) && '' !== $content_type ) {
			$parts = explode( ';', $content_type, 2 );
			$mime  = strtolower( trim( $parts[0] ) );

			return in_array( $mime, array( 'text/html', 'application/xhtml+xml' ), true );
		}

		return $this->looks_like_html( $buffer );
	}

	private function response_content_type(): ?string {
		$content_type = null;

		foreach ( headers_list() as $header ) {
			if ( 0 === stripos( $header, 'Content-Type:' ) ) {
				$content_type = trim( substr( $header, strlen( 'Content-Type:' ) ) );
			}
		}

		return $content_type;
	}

	protected function looks_like_html( string $buffer ): bool {
		$head = substr( $buffer, 0, 1024 );

		if ( 0 === strncmp( $head, "\xEF\xBB\xBF", 3 ) ) {
			$head = substr( $head, 3 );
		}
		$head = ltrim( $head );

		if ( 0 === stripos( $head, '<!doctype html' ) ) {
			return true;
		}

		return false !== stripos( $head, '<html' );
	}
}
