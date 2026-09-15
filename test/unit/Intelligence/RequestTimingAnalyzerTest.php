<?php
/**
 * Unit tests for WP_SAM\Intelligence\Request_Timing_Analyzer.
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;
use WP_SAM\Intelligence\Request_Timing_Analyzer;

class RequestTimingAnalyzerTest extends TestCase {

	private Request_Timing_Analyzer $analyzer;

	protected function setUp(): void {
		wp_test_reset_globals();
		$this->analyzer = new Request_Timing_Analyzer();
	}

	/** @return array<int, string> */
	private function timestamps_at_fixed_interval( int $count, int $interval_seconds, int $start_epoch = 1_700_000_000 ): array {
		$timestamps = array();
		for ( $i = 0; $i < $count; $i++ ) {
			$timestamps[] = gmdate( 'Y-m-d H:i:s', $start_epoch + ( $i * $interval_seconds ) );
		}
		return $timestamps;
	}

	public function test_a_fixed_interval_across_five_requests_is_scripted_timing(): void {
		$timestamps = $this->timestamps_at_fixed_interval( 5, 30 );

		$this->assertTrue( $this->analyzer->is_scripted_timing( $timestamps ) );
	}

	public function test_fewer_than_the_minimum_interval_count_is_not_scripted_timing(): void {
		// 4 timestamps -- only 3 intervals, one short of the minimum.
		$timestamps = $this->timestamps_at_fixed_interval( 4, 30 );

		$this->assertFalse( $this->analyzer->is_scripted_timing( $timestamps ) );
	}

	public function test_naturally_irregular_intervals_are_not_scripted_timing(): void {
		$timestamps = array(
			gmdate( 'Y-m-d H:i:s', 1_700_000_000 ),
			gmdate( 'Y-m-d H:i:s', 1_700_000_012 ), // +12s
			gmdate( 'Y-m-d H:i:s', 1_700_000_071 ), // +59s
			gmdate( 'Y-m-d H:i:s', 1_700_000_083 ), // +12s
			gmdate( 'Y-m-d H:i:s', 1_700_000_190 ), // +107s
		);

		$this->assertFalse( $this->analyzer->is_scripted_timing( $timestamps ) );
	}

	public function test_a_long_average_interval_is_not_scripted_timing_even_if_uniform(): void {
		// Uniform, but a 20-minute cadence is ordinary infrequent traffic,
		// not something worth flagging -- see MAX_MEAN_INTERVAL_SECONDS.
		$timestamps = $this->timestamps_at_fixed_interval( 5, 1200 );

		$this->assertFalse( $this->analyzer->is_scripted_timing( $timestamps ) );
	}

	public function test_multiple_requests_in_the_same_second_every_time_is_not_scripted_timing(): void {
		// Mean interval of 0 is inconclusive, not a "timed" pattern.
		$timestamps = array_fill( 0, 5, gmdate( 'Y-m-d H:i:s', 1_700_000_000 ) );

		$this->assertFalse( $this->analyzer->is_scripted_timing( $timestamps ) );
	}

	public function test_empty_history_is_not_scripted_timing(): void {
		$this->assertFalse( $this->analyzer->is_scripted_timing( array() ) );
	}

	public function test_malformed_timestamp_is_not_scripted_timing(): void {
		$timestamps   = $this->timestamps_at_fixed_interval( 5, 30 );
		$timestamps[] = 'not-a-real-date';

		$this->assertFalse( $this->analyzer->is_scripted_timing( $timestamps ) );
	}

	public function test_a_slightly_jittered_fixed_interval_is_still_scripted_timing(): void {
		// A real scripted client rarely sleeps the exact same millisecond
		// every time -- a few seconds of jitter around a ~60s baseline
		// should still read as scripted (well within the CV threshold).
		$base       = 1_700_000_000;
		$timestamps = array(
			gmdate( 'Y-m-d H:i:s', $base ),
			gmdate( 'Y-m-d H:i:s', $base + 60 ),
			gmdate( 'Y-m-d H:i:s', $base + 121 ),
			gmdate( 'Y-m-d H:i:s', $base + 179 ),
			gmdate( 'Y-m-d H:i:s', $base + 240 ),
		);

		$this->assertTrue( $this->analyzer->is_scripted_timing( $timestamps ) );
	}
}
