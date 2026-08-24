<?php
/**
 * Unit tests for WP_SAM\Security\Content_Rewriter's buffer lifecycle.
 *
 * Content_Rewriter::maybe_start_buffer() gates on request_exclusion_reason(),
 * which (among other checks) excludes any request running under the CLI or
 * phpdbg SAPI -- exactly what PHPUnit itself runs under, so that guard can
 * never be satisfied by simply running these tests. The concrete test
 * subclass below overrides request_exclusion_reason() to bypass it: what's
 * under test here is the buffer-open/close mechanics themselves (ownership,
 * nesting, closing only at shutdown), not request-eligibility detection,
 * which is unrelated and untouched by this file.
 *
 * Every test opens its OWN outer capture buffer BEFORE the rewriter opens
 * its buffer (nested inside the capture buffer), matching the real-world
 * scenario this class's own docblock describes -- nested inside any buffer
 * a page-cache plugin opened earlier in the request. Opening the capture
 * buffer AFTER the rewriter's own start would put it on the wrong side of
 * the stack: the rewriter's own unwind loop would then treat the capture
 * buffer itself as unowned nested content and refuse to touch it.
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;
use WP_SAM\Security\Content_Rewriter;

class ContentRewriterTest extends TestCase {

	protected function setUp(): void {
		wp_test_reset_globals();
		Content_Rewriter::reset_open_stack_for_tests();
	}

	private function make_rewriter(): Content_Rewriter {
		return new class() extends Content_Rewriter {
			protected function request_exclusion_reason(): ?string {
				return null;
			}
			protected function is_active( string $surface ): bool {
				return true;
			}
			protected function rewrite( string $html, string $surface ): string {
				return str_replace( 'ORIGINAL', 'REWRITTEN', $html );
			}
		};
	}

	// ── register() wiring ────────────────────────────────────────────────────

	public function test_register_does_not_install_a_wp_footer_hook(): void {
		$rewriter = $this->make_rewriter();
		$rewriter->register();

		$registrations = array_filter(
			$GLOBALS['_wp_actions']['wp_footer'] ?? array(),
			static function ( array $registration ): bool {
				return is_array( $registration[0] ) && 'maybe_end_buffer' === ( $registration[0][1] ?? '' );
			}
		);

		$this->assertEmpty( $registrations, 'maybe_end_buffer must not be registered on wp_footer -- closing there would hand rewrite() an incomplete document whenever a theme echoes trailing markup after its own wp_footer() call returns.' );
	}

	public function test_register_installs_shutdown_as_the_only_closure_point(): void {
		$rewriter = $this->make_rewriter();
		$rewriter->register();

		$registrations = array_filter(
			$GLOBALS['_wp_actions']['shutdown'] ?? array(),
			static function ( array $registration ): bool {
				return is_array( $registration[0] ) && 'maybe_end_buffer' === ( $registration[0][1] ?? '' );
			}
		);

		$this->assertNotEmpty( $registrations, 'maybe_end_buffer is not registered on shutdown.' );
	}

	// ── Closure captures the complete response, including trailing markup ────

	public function test_captures_trailing_theme_output_emitted_after_the_normal_footer_point(): void {
		$baseline = ob_get_level();
		$rewriter = $this->make_rewriter();

		ob_start(); // outer capture buffer
		$rewriter->maybe_start_buffer();
		echo '<html>ORIGINAL content'; // e.g. everything up to and including wp_footer()'s own output
		// A theme's own trailing markup, echoed directly after its
		// wp_footer() call returns (at minimum, closing </body></html>
		// tags) -- still executes before the request script finishes, so
		// it must still land inside this buffer and be passed through
		// rewrite() along with everything else, not bypass it.
		echo '</html>';

		$rewriter->maybe_end_buffer(); // simulates the shutdown callback
		$output = ob_get_clean();

		$this->assertSame( '<html>REWRITTEN content</html>', $output, 'trailing theme markup emitted after wp_footer must still be captured and rewritten, not bypassed.' );
		$this->assertSame( $baseline, ob_get_level() );
	}

	public function test_maybe_end_buffer_is_a_no_op_when_never_started(): void {
		$baseline = ob_get_level();
		$rewriter = $this->make_rewriter();

		// maybe_start_buffer() never called -- must not throw, must not
		// touch any buffer.
		ob_start();
		$rewriter->maybe_end_buffer();
		$output = ob_get_clean();

		$this->assertSame( '', $output );
		$this->assertSame( $baseline, ob_get_level() );
	}

	public function test_maybe_end_buffer_is_a_no_op_when_something_else_already_closed_it(): void {
		$baseline = ob_get_level();
		$rewriter = $this->make_rewriter();
		$rewriter->maybe_start_buffer();
		// Simulate another plugin (or PHP itself) already having closed our
		// buffer before shutdown got a chance to run.
		ob_end_clean();

		// Must not throw, and must not act on whatever the current buffer
		// level now is (there may be none, or a completely unrelated one
		// this class does not own).
		$rewriter->maybe_end_buffer();

		$this->assertSame( $baseline, ob_get_level() );
	}

	// ── Buffer ownership: never force-close a buffer this class doesn't own ──

	public function test_third_party_buffer_nested_above_is_never_forcibly_closed(): void {
		$baseline = ob_get_level();
		$rewriter = $this->make_rewriter();

		ob_start(); // outer capture buffer
		$rewriter->maybe_start_buffer();
		echo '<html>ORIGINAL content</html>';

		// Something else (another plugin, or a page-cache layer) nests its
		// own buffer inside ours and has not closed it by the time
		// shutdown fires.
		ob_start();
		echo '<!-- nested third-party buffer -->';

		$rewriter->maybe_end_buffer();

		// Neither buffer is touched: forcing the third-party buffer closed
		// to reach our own would act on content this class does not own.
		// +3: the outer capture buffer, the rewriter's own buffer, and the
		// third-party buffer nested inside it -- all still open.
		$this->assertSame( $baseline + 3, ob_get_level(), 'a buffer this class does not own must never be force-closed.' );

		$third_party_output = ob_get_clean();
		$this->assertSame( '<!-- nested third-party buffer -->', $third_party_output, 'the third-party buffer must be left completely untouched.' );

		// Cleanup: discard the rewriter's own buffer, left open by design
		// (it fails open -- unrewritten, but never lost -- rather than
		// forcing a buffer it doesn't own), then this test's own outer
		// capture buffer.
		ob_end_clean();
		ob_end_clean();
		$this->assertSame( $baseline, ob_get_level() );
	}

	// ── Repeated hooks cannot open or close the same buffer twice ────────────

	public function test_maybe_start_buffer_does_not_open_a_second_buffer_if_called_twice(): void {
		$baseline = ob_get_level();
		$rewriter = $this->make_rewriter();

		ob_start(); // outer capture buffer
		$rewriter->maybe_start_buffer();
		$rewriter->maybe_start_buffer(); // e.g. template_redirect firing twice
		echo '<html>ORIGINAL content</html>';
		$rewriter->maybe_end_buffer();
		$output = ob_get_clean();

		// If the second maybe_start_buffer() call had opened another
		// nested buffer, closing would either leave a stray level open or
		// require more than one unwind step, and the captured output
		// would be wrapped in an extra, unrewritten layer.
		$this->assertSame( '<html>REWRITTEN content</html>', $output );
		$this->assertSame( $baseline, ob_get_level() );
	}

	// ── Multiple Content_Rewriter instances close in true LIFO order ─────────

	public function test_two_rewriters_close_in_lifo_order_regardless_of_callback_firing_order(): void {
		$baseline = ob_get_level();
		// $outer is instantiated (and so registered/opened) first, matching
		// Plugin::bootstrap()'s unconditional construction order of the two
		// real subclasses -- WordPress fires same-priority 'shutdown'
		// callbacks in that same registration order, so $outer's own
		// callback is what actually fires first in production, even though
		// $inner's buffer ends up on top of the real PHP stack.
		$outer = $this->make_rewriter();
		$inner = $this->make_rewriter();

		ob_start(); // outer capture buffer
		$outer->maybe_start_buffer();
		echo '<html>ORIGINAL from outer.';
		$inner->maybe_start_buffer();
		echo 'ORIGINAL from inner.</html>';

		// Simulates $outer's shutdown callback firing first: the shared
		// stack must still close $inner first (true LIFO), never force
		// $outer's buffer closed out from under it.
		$outer->maybe_end_buffer();
		$output = ob_get_clean();

		$this->assertSame( '<html>REWRITTEN from outer.REWRITTEN from inner.</html>', $output );
		$this->assertSame( $baseline, ob_get_level() );

		// $inner's own shutdown callback is still registered and fires
		// second in real WordPress dispatch; by then both buffers are
		// already closed via $outer's call above, so this must be a
		// genuine no-op.
		ob_start();
		$inner->maybe_end_buffer();
		$this->assertSame( '', ob_get_clean() );
	}
}
