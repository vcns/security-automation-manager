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
 * nesting, the wp_footer/shutdown split), not request-eligibility detection,
 * which is unrelated and untouched by this file.
 *
 * Every test opens its OWN outer capture buffer BEFORE the rewriter opens
 * its buffer (nested inside the capture buffer), matching the real-world
 * scenario this class's own docblock describes -- nested inside any buffer
 * a page-cache plugin opened earlier in the request. Opening the capture
 * buffer AFTER the rewriter's own start would put it on the wrong side of
 * the stack: the rewriter's own unwind loop would then treat the capture
 * buffer itself as unowned nested content and flush it away before the
 * rewriter's real content is ever captured.
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;
use WP_SAM\Security\Content_Rewriter;

class ContentRewriterTest extends TestCase {

	protected function setUp(): void {
		wp_test_reset_globals();
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

	public function test_register_installs_wp_footer_as_the_normal_closure_point(): void {
		$rewriter = $this->make_rewriter();
		$rewriter->register();

		$registrations = array_filter(
			$GLOBALS['_wp_actions']['wp_footer'] ?? array(),
			static function ( array $registration ): bool {
				return is_array( $registration[0] ) && 'maybe_end_buffer' === ( $registration[0][1] ?? '' );
			}
		);

		$this->assertNotEmpty( $registrations, 'maybe_end_buffer is not registered on wp_footer -- the normal closure point, not just a shutdown fallback.' );
	}

	public function test_register_installs_shutdown_as_a_fallback_only(): void {
		$rewriter = $this->make_rewriter();
		$rewriter->register();

		$registrations = array_filter(
			$GLOBALS['_wp_actions']['shutdown'] ?? array(),
			static function ( array $registration ): bool {
				return is_array( $registration[0] ) && 'maybe_end_buffer' === ( $registration[0][1] ?? '' );
			}
		);

		$this->assertNotEmpty( $registrations, 'maybe_end_buffer is not registered on shutdown -- interrupted flows (redirect/exit()/fatal before wp_footer) need a fallback closer.' );
	}

	// ── Normal lifecycle: closes at wp_footer, shutdown never has to act ──────

	public function test_normal_lifecycle_closes_at_wp_footer_not_shutdown(): void {
		$baseline = ob_get_level();
		$rewriter = $this->make_rewriter();

		ob_start(); // outer capture buffer
		$rewriter->maybe_start_buffer();
		echo '<html>ORIGINAL content</html>';
		$rewriter->maybe_end_buffer(); // simulates the wp_footer call specifically
		$footer_output = ob_get_clean();

		$this->assertSame( '<html>REWRITTEN content</html>', $footer_output );
		$this->assertSame( $baseline, ob_get_level(), 'wp_footer must leave the buffer stack exactly as it found it.' );

		// shutdown firing afterwards (the fallback) must be a genuine no-op:
		// buffer_started is already false, so nothing is touched a second
		// time and nothing is re-emitted.
		ob_start();
		$rewriter->maybe_end_buffer(); // simulates the shutdown call
		$shutdown_output = ob_get_clean();

		$this->assertSame( '', $shutdown_output, 'the shutdown fallback must not act again after wp_footer already closed the buffer.' );
		$this->assertSame( $baseline, ob_get_level() );
	}

	public function test_shutdown_fallback_closes_a_buffer_wp_footer_never_reached(): void {
		// Simulates a redirect/exit() or fatal error between
		// template_redirect and wp_footer -- wp_footer never fires, so the
		// shutdown fallback is what actually closes the buffer.
		$baseline = ob_get_level();
		$rewriter = $this->make_rewriter();

		ob_start(); // outer capture buffer
		$rewriter->maybe_start_buffer();
		echo '<html>ORIGINAL content</html>';
		// wp_footer deliberately not simulated here.
		$rewriter->maybe_end_buffer(); // simulates the shutdown call
		$output = ob_get_clean();

		$this->assertSame( '<html>REWRITTEN content</html>', $output );
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
		// buffer before wp_footer or shutdown got a chance to run.
		ob_end_clean();

		// Must not throw, and must not act on whatever the current buffer
		// level now is (there may be none, or a completely unrelated one
		// this class does not own).
		$rewriter->maybe_end_buffer();

		$this->assertSame( $baseline, ob_get_level() );
	}

	public function test_nested_buffer_opened_by_something_else_is_preserved_not_discarded(): void {
		$baseline = ob_get_level();
		$rewriter = $this->make_rewriter();

		ob_start(); // outer capture buffer
		$rewriter->maybe_start_buffer();
		echo '<html>ORIGINAL content</html>';

		// Something else (another plugin, or a page-cache layer) nests its
		// own buffer inside ours without closing it before our own close
		// runs.
		ob_start();
		echo '<!-- nested third-party buffer -->';

		$rewriter->maybe_end_buffer();
		$output = ob_get_clean();

		// Our own buffer was rewritten; the nested buffer's content was
		// flushed through untouched (this class never calls rewrite() on
		// content it doesn't own) rather than discarded.
		$this->assertStringContainsString( '<html>REWRITTEN content</html>', $output );
		$this->assertStringContainsString( '<!-- nested third-party buffer -->', $output );
		$this->assertSame( $baseline, ob_get_level(), 'both buffers must be fully unwound.' );
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

		// A single ob_end_flush() (implicit in maybe_end_buffer()'s guard
		// comparison) fully unwinds the stack back to baseline -- if the
		// second maybe_start_buffer() call had opened another nested
		// buffer, closing would either leave a stray level open or require
		// more than one unwind step, and the captured output would be
		// wrapped in an extra, unrewritten layer.
		$this->assertSame( '<html>REWRITTEN content</html>', $output );
		$this->assertSame( $baseline, ob_get_level() );
	}
}
