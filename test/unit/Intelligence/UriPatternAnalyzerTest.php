<?php
/**
 * Unit tests for WP_SAM\Intelligence\Uri_Pattern_Analyzer.
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;
use WP_SAM\Intelligence\Uri_Pattern_Analyzer;

class UriPatternAnalyzerTest extends TestCase {

	private Uri_Pattern_Analyzer $analyzer;

	protected function setUp(): void {
		wp_test_reset_globals();
		$this->analyzer = new Uri_Pattern_Analyzer();
	}

	public function test_ascending_sequential_ids_are_enumerating(): void {
		$paths = array( '/product/101', '/product/102', '/product/103', '/product/104' );

		$this->assertTrue( $this->analyzer->is_enumerating( $paths ) );
	}

	public function test_descending_sequential_ids_are_enumerating(): void {
		$paths = array( '/product/50', '/product/49', '/product/48', '/product/47' );

		$this->assertTrue( $this->analyzer->is_enumerating( $paths ) );
	}

	public function test_a_fixed_non_unit_step_is_still_enumerating(): void {
		$paths = array( '/product/10', '/product/20', '/product/30', '/product/40' );

		$this->assertTrue( $this->analyzer->is_enumerating( $paths ) );
	}

	public function test_fewer_than_the_minimum_sequence_length_is_not_enumerating(): void {
		// Only 3 consecutive hits -- too short to assert a pattern confidently.
		$paths = array( '/product/101', '/product/102', '/product/103' );

		$this->assertFalse( $this->analyzer->is_enumerating( $paths ) );
	}

	public function test_repeated_identical_ids_are_not_enumerating(): void {
		// Step of 0 -- reloading the same page repeatedly isn't enumeration.
		$paths = array( '/product/5', '/product/5', '/product/5', '/product/5' );

		$this->assertFalse( $this->analyzer->is_enumerating( $paths ) );
	}

	public function test_an_inconsistent_step_is_not_enumerating(): void {
		$paths = array( '/product/1', '/product/2', '/product/4', '/product/9' );

		$this->assertFalse( $this->analyzer->is_enumerating( $paths ) );
	}

	public function test_a_non_numeric_path_in_the_run_breaks_the_sequence(): void {
		$paths = array( '/product/101', '/product/102', '/about-us', '/product/103', '/product/104' );

		$this->assertFalse( $this->analyzer->is_enumerating( $paths ) );
	}

	public function test_ordinary_unrelated_browsing_is_not_enumerating(): void {
		$paths = array( '/', '/about', '/contact', '/blog/hello-world' );

		$this->assertFalse( $this->analyzer->is_enumerating( $paths ) );
	}

	public function test_empty_history_is_not_enumerating(): void {
		$this->assertFalse( $this->analyzer->is_enumerating( array() ) );
	}

	public function test_uses_the_last_number_in_a_path_with_several(): void {
		// /wp-json/wp/v2/posts/101 -- the trailing "101" (the actual post
		// ID) is what should drive the sequence, not the "2" from "v2".
		$paths = array(
			'/wp-json/wp/v2/posts/101',
			'/wp-json/wp/v2/posts/102',
			'/wp-json/wp/v2/posts/103',
			'/wp-json/wp/v2/posts/104',
		);

		$this->assertTrue( $this->analyzer->is_enumerating( $paths ) );
	}
}
