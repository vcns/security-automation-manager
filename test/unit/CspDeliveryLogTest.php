<?php
/**
 * Unit tests for WP_SAM\CSP\Csp_Delivery_Log.
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;
use WP_SAM\CSP\Csp_Delivery_Log;

class CspDeliveryLogTest extends TestCase {

	private const NOW = 1_800_000_000;

	protected function setUp(): void {
		wp_test_reset_globals();
	}

	public function test_an_unknown_surface_has_no_record(): void {
		$this->assertSame( array(), Csp_Delivery_Log::get( 'frontend' ) );
	}

	public function test_the_first_send_sets_both_first_and_last_sent(): void {
		Csp_Delivery_Log::record_sent( 'admin', self::NOW );

		$this->assertSame(
			array(
				'first_sent' => self::NOW,
				'last_sent'  => self::NOW,
			),
			Csp_Delivery_Log::get( 'admin' )
		);
	}

	public function test_sends_within_the_hour_are_not_written_again(): void {
		Csp_Delivery_Log::record_sent( 'admin', self::NOW );
		Csp_Delivery_Log::record_sent( 'admin', self::NOW + 1800 );

		$this->assertSame( self::NOW, Csp_Delivery_Log::get( 'admin' )['last_sent'] );
	}

	public function test_a_later_send_moves_last_sent_and_keeps_first_sent(): void {
		Csp_Delivery_Log::record_sent( 'admin', self::NOW );
		Csp_Delivery_Log::record_sent( 'admin', self::NOW + 2 * DAY_IN_SECONDS );

		$entry = Csp_Delivery_Log::get( 'admin' );
		$this->assertSame( self::NOW, $entry['first_sent'] );
		$this->assertSame( self::NOW + 2 * DAY_IN_SECONDS, $entry['last_sent'] );
	}

	public function test_a_gap_longer_than_the_maximum_restarts_first_sent(): void {
		Csp_Delivery_Log::record_sent( 'admin', self::NOW );
		$later = self::NOW + Csp_Delivery_Log::MAX_GAP_SECONDS + DAY_IN_SECONDS;
		Csp_Delivery_Log::record_sent( 'admin', $later );

		$this->assertSame( $later, Csp_Delivery_Log::get( 'admin' )['first_sent'] );
	}

	public function test_trimming_is_recorded_and_throttled_without_touching_delivery(): void {
		Csp_Delivery_Log::record_sent( 'frontend', self::NOW );
		Csp_Delivery_Log::record_trimmed( 'frontend', self::NOW + 60 );
		Csp_Delivery_Log::record_trimmed( 'frontend', self::NOW + 120 );

		$entry = Csp_Delivery_Log::get( 'frontend' );
		$this->assertSame( self::NOW + 60, $entry['last_trimmed'] );
		$this->assertSame( self::NOW, $entry['first_sent'] );
	}

	public function test_surfaces_are_stored_separately(): void {
		Csp_Delivery_Log::record_sent( 'frontend', self::NOW );
		Csp_Delivery_Log::record_sent( 'admin', self::NOW + 10 );

		$this->assertSame( self::NOW, Csp_Delivery_Log::get( 'frontend' )['last_sent'] );
		$this->assertSame( self::NOW + 10, Csp_Delivery_Log::get( 'admin' )['last_sent'] );
	}

	public function test_throttling_is_recorded_and_throttled_without_touching_delivery(): void {
		Csp_Delivery_Log::record_throttled( 'admin', 1000 );
		Csp_Delivery_Log::record_throttled( 'admin', 1000 + 60 );

		$this->assertSame( array( 'last_throttled' => 1000 ), Csp_Delivery_Log::get( 'admin' ) );

		Csp_Delivery_Log::record_throttled( 'admin', 1000 + 301 );
		$this->assertSame( 1301, Csp_Delivery_Log::get( 'admin' )['last_throttled'] );
	}
}
