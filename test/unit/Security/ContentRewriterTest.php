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
 * nesting, the shutdown fallback), not request-eligibility detection, which
 * is unrelated and untouched by this file.
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

	public function test_normal_lifecycle_rewrites_and_closes_its_own_buffer(): void {
		$baseline = ob_get_level();
		$rewriter = $this->make_rewriter();

		ob_start(); // outer capture buffer
		$rewriter->maybe_start_buffer();
		echo '<html>ORIGINAL content</html>';
		$rewriter->maybe_end_buffer();
		$output = ob_get_clean();

		$this->assertSame( '<html>REWRITTEN content</html>', $output );
		$this->assertSame( $baseline, ob_get_level(), 'maybe_end_buffer() must leave the buffer stack exactly as it found it.' );
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
		// Simulate another plugin (or an earlier shutdown callback) already
		// having closed this exact buffer level.
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
		// own buffer inside ours without closing it before shutdown.
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

	public function test_shutdown_action_is_registered_to_close_the_buffer_explicitly(): void {
		$rewriter = $this->make_rewriter();
		$rewriter->register();

		$registrations = array_filter(
			$GLOBALS['_wp_actions']['shutdown'] ?? array(),
			static function ( array $registration ): bool {
				return is_array( $registration[0] ) && 'maybe_end_buffer' === ( $registration[0][1] ?? '' );
			}
		);

		$this->assertNotEmpty( $registrations, 'maybe_end_buffer is not registered on shutdown -- closure must be explicit, not left to PHP\'s implicit end-of-script flush.' );
	}
}
