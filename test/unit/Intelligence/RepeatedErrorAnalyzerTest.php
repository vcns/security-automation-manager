<?php
/**
 * Unit tests for WP_SAM\Intelligence\Repeated_Error_Analyzer.
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;
use WP_SAM\Intelligence\Repeated_Error_Analyzer;

class RepeatedErrorAnalyzerTest extends TestCase {

	private Repeated_Error_Analyzer $analyzer;

	protected function setUp(): void {
		wp_test_reset_globals();
		$this->analyzer = new Repeated_Error_Analyzer();
	}

	public function test_mostly_errors_is_error_probing(): void {
		$this->assertTrue( $this->analyzer->is_error_probing( array( 1, 1, 1, 0 ) ) );
	}

	public function test_all_errors_is_error_probing(): void {
		$this->assertTrue( $this->analyzer->is_error_probing( array( 1, 1, 1, 1 ) ) );
	}

	public function test_mostly_successful_requests_is_not_error_probing(): void {
		$this->assertFalse( $this->analyzer->is_error_probing( array( 0, 0, 0, 1 ) ) );
	}

	public function test_an_even_split_is_not_error_probing(): void {
		// 50% is below the 70% threshold -- an ordinary visitor occasionally
		// hitting a stale link isn't a scanner.
		$this->assertFalse( $this->analyzer->is_error_probing( array( 1, 0, 1, 0 ) ) );
	}

	public function test_fewer_than_the_minimum_sample_size_is_not_error_probing(): void {
		// Only 3 requests, all errors -- too short a run to assert confidently.
		$this->assertFalse( $this->analyzer->is_error_probing( array( 1, 1, 1 ) ) );
	}

	public function test_empty_history_is_not_error_probing(): void {
		$this->assertFalse( $this->analyzer->is_error_probing( array() ) );
	}

	public function test_boolean_entries_work_the_same_as_ints(): void {
		$this->assertTrue( $this->analyzer->is_error_probing( array( true, true, true, false ) ) );
	}
}
