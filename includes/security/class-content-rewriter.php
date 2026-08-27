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
 * gets cached. Each subclass gets its own independent buffer; none of this
 * plugin's own rewriters touch the same element types, so which one
 * rewrites first never matters -- but PHP's buffer stack is strictly LIFO,
 * so CLOSING them still has to happen in the exact reverse of open order.
 * self::$open_stack (below) is what makes that safe when more than one of
 * this plugin's own rewriters is active on the same request, without ever
 * forcing closed a buffer this plugin doesn't own.
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

	/**
	 * Every Content_Rewriter instance with a currently open buffer, in the
	 * exact order they opened -- shared across every instance (there are two
	 * concrete subclasses today, Reverse_Tabnabbing_Builder and
	 * Dependency_Governance_Builder, both unconditionally instantiated and
	 * both able to be active on the same request) rather than each
	 * instance's own shutdown callback acting independently. PHP's output
	 * buffer stack is strictly LIFO, but WordPress fires same-priority
	 * 'shutdown' callbacks in registration order -- the OPPOSITE of the
	 * order correct LIFO closure needs. Routing every instance's close
	 * through this shared stack means whichever instance's callback
	 * actually fires first does all of the closing that is currently safe
	 * (see unwind_open_stack()); every other instance's callback then finds
	 * its own buffer_started already false and no-ops.
	 *
	 * @var Content_Rewriter[]
	 */
	private static array $open_stack = array();

	/** Test-only: clears the shared open-buffer stack between test cases. */
	public static function reset_open_stack_for_tests(): void {
		self::$open_stack = array();
	}

	// ── Bootstrap ─────────────────────────────────────────────────────────────

	public function register(): void {
		add_action( 'template_redirect', array( $this, 'maybe_start_buffer' ) );
		// shutdown is the ONLY closure point -- not a fallback alongside an
		// earlier hook. A theme commonly echoes a small amount of markup
		// (at minimum closing </body></html> tags) after its wp_footer()
		// call returns, which is still part of the same template's normal
		// output; closing at wp_footer itself would hand rewrite() an
		// incomplete document and let that trailing markup bypass
		// rewriting entirely. By the time WordPress's 'shutdown' action
		// fires, every line of the template that echoes anything has
		// already executed -- PHP runs the request script to completion
		// (queuing shutdown functions, but not invoking them) before any
		// shutdown callback runs, so this buffer has already captured the
		// complete response by then. This is WP-controlled dispatch
		// (do_action('shutdown')), not PHP's own implicit end-of-script
		// buffer flush, which happens only after every registered shutdown
		// callback (including this one) has already run. Priority
		// PHP_INT_MAX so this runs after every other plugin's own
		// shutdown-time output (if any) has already happened.
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

		// This buffer is always closed -- by unwind_open_stack(), called from
		// maybe_end_buffer(), registered on `shutdown` at PHP_INT_MAX priority
		// (see register()). It's intentionally opened on `template_redirect`
		// and closed on a later, separate hook rather than in this same
		// method, because that's what lets multiple Content_Rewriter
		// instances close in true LIFO order regardless of which instance's
		// hook callback WordPress happens to fire first -- see
		// unwind_open_stack()'s own docblock. Exercised directly by
		// test/unit/Security/ContentRewriterTest.php, including the case
		// where something else already closed it and the case where a
		// third-party buffer is nested above and must never be force-closed.
		if ( ob_start( array( $this, 'filter_output' ), 0 ) ) {
			$this->buffer_started = true;
			$this->buffer_level   = ob_get_level();
			self::$open_stack[]   = $this;
		}
	}

	/**
	 * Entry point registered on `shutdown` (see register()). Never acts on
	 * this instance alone -- delegates to the shared unwind so multiple
	 * Content_Rewriter buffers close in true LIFO order regardless of which
	 * instance's callback WordPress happens to fire first.
	 */
	public function maybe_end_buffer(): void {
		if ( ! $this->buffer_started ) {
			return;
		}

		self::unwind_open_stack();
	}

	/**
	 * Closes every Content_Rewriter buffer reachable from the current top of
	 * the real PHP output buffer stack, in strict LIFO order via
	 * self::$open_stack, using ob_end_flush() (never ob_end_clean()) so
	 * content is always preserved. Stops the instant the next entry's
	 * recorded level no longer matches the real stack -- meaning something
	 * this class does not own (a theme, a page-cache plugin, another
	 * component entirely) is nested above it. That buffer, and every entry
	 * still below it in self::$open_stack, is left completely untouched:
	 * neither closed nor forced, and nothing above it is discarded.
	 *
	 * If an unidentified buffer remains above this plugin's buffer at
	 * shutdown, this method leaves both buffers untouched. PHP will
	 * subsequently finalise the remaining output-buffer stack. This
	 * exceptional path does not provide the plugin's normal
	 * explicit-closure guarantee -- filter_output() is still registered as
	 * this buffer's handler, so PHP's later implicit closure may still
	 * invoke it and rewrite the content, but this method makes no claim
	 * either way about whether that happens; only that nothing this class
	 * does not own is ever force-closed here (see class docblock's
	 * fail-open philosophy).
	 */
	private static function unwind_open_stack(): void {
		while ( array() !== self::$open_stack ) {
			$top = end( self::$open_stack );

			if ( ! $top->buffer_started || null === $top->buffer_level ) {
				// Already closed by an earlier iteration of this same
				// unwind, or never actually opened -- drop the stale
				// entry and keep going.
				array_pop( self::$open_stack );
				continue;
			}

			if ( ob_get_level() < $top->buffer_level ) {
				// Something else (e.g. an aggressive page-cache plugin)
				// already closed this buffer for us. Nothing to flush;
				// just stop tracking it.
				$top->buffer_started = false;
				array_pop( self::$open_stack );
				continue;
			}

			if ( ob_get_level() > $top->buffer_level ) {
				// A buffer this class does not own is nested above the
				// next one it would close. Stop entirely -- forcing it
				// closed here would act on content that isn't ours.
				return;
			}

			ob_end_flush();
			$top->buffer_started = false;
			array_pop( self::$open_stack );
		}
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
