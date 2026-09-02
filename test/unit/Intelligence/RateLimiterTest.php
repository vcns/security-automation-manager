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
}
