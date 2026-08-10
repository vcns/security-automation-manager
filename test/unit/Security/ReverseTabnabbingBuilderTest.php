<?php
/**
 * Unit tests for WP_SAM\Security\Reverse_Tabnabbing_Builder.
 *
 * add_noopener()'s actual rewrite behaviour depends on WP_HTML_Tag_Processor,
 * a WordPress core class this lightweight test environment does not load
 * (no real wp-includes checkout is vendored here -- see test/bootstrap.php).
 * The only thing verifiable here is the fail-open guard: when the class is
 * unavailable, the input is returned completely unchanged. The actual
 * rel="noopener" injection is exercised on a real WordPress install (6.4+
 * guarantees the class exists), which is where this plugin's manual QA
 * pass covers it.
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;
use WP_SAM\Security\Reverse_Tabnabbing_Builder;

class ReverseTabnabbingBuilderTest extends TestCase {

	protected function setUp(): void {
		wp_test_reset_globals();
	}

	public function test_add_noopener_fails_open_when_tag_processor_unavailable(): void {
		if ( class_exists( 'WP_HTML_Tag_Processor' ) ) {
			$this->markTestSkipped( 'WP_HTML_Tag_Processor is available in this environment; fail-open path is not exercised.' );
		}

		$html = '<a href="https://example.com" target="_blank">Link</a>';
		$this->assertSame( $html, Reverse_Tabnabbing_Builder::add_noopener( $html ) );
	}

	public function test_add_noopener_returns_original_for_empty_string(): void {
		$this->assertSame( '', Reverse_Tabnabbing_Builder::add_noopener( '' ) );
	}
}
