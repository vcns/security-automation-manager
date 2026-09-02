<?php
/**
 * Unit tests for WP_SAM\Intelligence\Campaign_Store.
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;
use WP_SAM\Intelligence\Campaign_Store;

class CampaignStoreTest extends TestCase {

	private Campaign_Store $store;

	protected function setUp(): void {
		wp_test_reset_globals();
		$this->store = new Campaign_Store();
	}

	public function test_record_inserts_a_new_row_when_none_exists(): void {
		$GLOBALS['_wpdb_get_var'] = null;

		$this->store->record( 'sqli-probe', 'injection', 'frontend', 12, 12 );

		$this->assertCount( 1, $GLOBALS['_wpdb_inserted_rows'] );
		$inserted = $GLOBALS['_wpdb_inserted_rows'][0]['data'];
		$this->assertSame( 'detected', $inserted['status'] );
		$this->assertSame( 12, $inserted['participant_count'] );
	}

	public function test_record_updates_existing_row_instead_of_inserting(): void {
		$GLOBALS['_wpdb_get_var'] = 7;

		$this->store->record( 'sqli-probe', 'injection', 'frontend', 15, 20 );

		$this->assertSame( array(), $GLOBALS['_wpdb_inserted_rows'] );
		$this->assertCount( 1, $GLOBALS['_wpdb_updated_rows'] );
		$updated = $GLOBALS['_wpdb_updated_rows'][0];
		$this->assertSame( array( 'id' => 7 ), $updated['where'] );
		$this->assertSame( 15, $updated['data']['participant_count'] );
	}

	public function test_record_fingerprint_is_stable_for_the_same_detector_and_surface(): void {
		$GLOBALS['_wpdb_get_var'] = null;

		$this->store->record( 'sqli-probe', 'injection', 'frontend', 10, 10 );
		$first = $GLOBALS['_wpdb_inserted_rows'][0]['data']['fingerprint'];

		$GLOBALS['_wpdb_inserted_rows'] = array();
		$this->store->record( 'sqli-probe', 'injection', 'frontend', 20, 20 );
		$second = $GLOBALS['_wpdb_inserted_rows'][0]['data']['fingerprint'];

		$this->assertSame( $first, $second );
	}

	public function test_disposition_rejects_detected(): void {
		$this->assertFalse( $this->store->disposition( 1, 'detected', 5, 'x' ) );
		$this->assertSame( array(), $GLOBALS['_wpdb_updated_rows'] );
	}

	public function test_disposition_rejects_an_empty_note(): void {
		$this->assertFalse( $this->store->disposition( 1, 'dismissed', 5, '' ) );
		$this->assertFalse( $this->store->disposition( 1, 'dismissed', 5, '   ' ) );
	}

	public function test_disposition_accepts_acknowledged_dismissed_and_blocked(): void {
		foreach ( array( 'acknowledged', 'dismissed', 'blocked' ) as $status ) {
			$GLOBALS['_wpdb_updated_rows'] = array();
			$ok                            = $this->store->disposition( 1, $status, 5, 'Reviewed.' );

			$this->assertTrue( $ok );
			$this->assertSame( $status, $GLOBALS['_wpdb_updated_rows'][0]['data']['status'] );
		}
	}

	public function test_all_filters_by_status_when_valid(): void {
		$this->store->all( 'detected' );

		$this->assertStringContainsString( "WHERE status = 'detected'", $GLOBALS['_wpdb_last_get_results_query'] );
	}

	public function test_get_returns_null_when_not_found(): void {
		$GLOBALS['_wpdb_get_row'] = null;

		$this->assertNull( $this->store->get( 999 ) );
	}
}
