<?php
/**
 * Unit tests for WP_SAM\Intelligence\Rate_Limiter.
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;
use WP_SAM\Intelligence\Rate_Limiter;

class RateLimiterTest extends TestCase {

	private Rate_Limiter $limiter;

	protected function setUp(): void {
		wp_test_reset_globals();
		$this->limiter = new Rate_Limiter();
	}

	public function test_hit_returns_zero_for_an_empty_ip(): void {
		$this->assertSame( 0, $this->limiter->hit( '', 'frontend', 60 ) );
	}

	public function test_hit_counts_up_across_calls_for_the_same_key(): void {
		$this->assertSame( 1, $this->limiter->hit( '203.0.113.42', 'frontend', 60 ) );
		$this->assertSame( 2, $this->limiter->hit( '203.0.113.42', 'frontend', 60 ) );
		$this->assertSame( 3, $this->limiter->hit( '203.0.113.42', 'frontend', 60 ) );
	}

	public function test_hit_keeps_separate_counters_per_surface(): void {
		$this->limiter->hit( '203.0.113.42', 'frontend', 60 );
		$this->limiter->hit( '203.0.113.42', 'frontend', 60 );

		$this->assertSame( 1, $this->limiter->hit( '203.0.113.42', 'admin', 60 ) );
	}

	public function test_hit_keeps_separate_counters_per_ip(): void {
		$this->limiter->hit( '203.0.113.42', 'frontend', 60 );

		$this->assertSame( 1, $this->limiter->hit( '198.51.100.7', 'frontend', 60 ) );
	}

	public function test_exceeded_is_false_at_or_below_the_max(): void {
		$this->assertFalse( $this->limiter->exceeded( '203.0.113.42', 'frontend', 3, 60 ) ); // 1
		$this->assertFalse( $this->limiter->exceeded( '203.0.113.42', 'frontend', 3, 60 ) ); // 2
		$this->assertFalse( $this->limiter->exceeded( '203.0.113.42', 'frontend', 3, 60 ) ); // 3
	}

	public function test_exceeded_is_true_once_past_the_max(): void {
		for ( $i = 0; $i < 3; $i++ ) {
			$this->limiter->exceeded( '203.0.113.42', 'frontend', 3, 60 );
		}

		$this->assertTrue( $this->limiter->exceeded( '203.0.113.42', 'frontend', 3, 60 ) ); // 4th hit.
	}

	public function test_a_new_window_starts_once_the_first_hits_window_has_ended(): void {
		$now     = 1_000_000;
		$limiter = new Rate_Limiter( static function () use ( &$now ): int {
			return $now;
		} );

		$this->assertSame( 1, $limiter->hit( '203.0.113.42', 'frontend', 60 ) );
		$now += 59;
		$this->assertSame( 2, $limiter->hit( '203.0.113.42', 'frontend', 60 ) );
		$now += 1; // 60s after the first hit.
		$this->assertSame( 1, $limiter->hit( '203.0.113.42', 'frontend', 60 ) );
	}

	/**
	 * The regression: one request every 30 seconds never left a full idle
	 * minute, so the old counter climbed past a limit of 3 per minute on
	 * the 4th request.
	 */
	public function test_a_slow_steady_source_never_exceeds_a_per_minute_limit(): void {
		$now     = 1_000_000;
		$limiter = new Rate_Limiter( static function () use ( &$now ): int {
			return $now;
		} );

		for ( $i = 0; $i < 120; $i++ ) {
			$this->assertFalse( $limiter->exceeded( '203.0.113.42', 'frontend', 3, 60 ), "request {$i}" );
			$now += 30;
		}
	}

	public function test_the_transient_expires_when_the_window_ends_not_after_the_latest_hit(): void {
		$now     = 1_000_000;
		$limiter = new Rate_Limiter( static function () use ( &$now ): int {
			return $now;
		} );

		$limiter->hit( '203.0.113.42', 'frontend', 60 );
		$now += 45;
		$limiter->hit( '203.0.113.42', 'frontend', 60 );

		$state = $GLOBALS['_wp_transients'][ 'wp_sam_rate_frontend_' . md5( '203.0.113.42' ) ];
		$this->assertSame( array( 'start' => 1_000_000, 'count' => 2 ), $state );
	}

	public function test_a_bare_count_from_the_old_format_starts_a_fresh_window(): void {
		$GLOBALS['_wp_transients'][ 'wp_sam_rate_frontend_' . md5( '203.0.113.42' ) ] = 500;

		$this->assertSame( 1, $this->limiter->hit( '203.0.113.42', 'frontend', 60 ) );
	}
}
