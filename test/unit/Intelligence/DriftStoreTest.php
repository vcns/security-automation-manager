<?php
/**
 * Unit tests for WP_SAM\Intelligence\Drift_Store.
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;
use WP_SAM\Intelligence\Drift_Store;

class DriftStoreTest extends TestCase {

	private Drift_Store $store;

	protected function setUp(): void {
		wp_test_reset_globals();
		$this->store = new Drift_Store();
	}

	public function test_record_inserts_a_new_row_when_none_exists(): void {
		$GLOBALS['_wpdb_get_var'] = null;

		$this->store->record( 'pillar', 'frontend', 'x-frame-options', 'SAMEORIGIN', 'DENY', 'medium', 'changed', '' );

		$this->assertCount( 1, $GLOBALS['_wpdb_inserted_rows'] );
		$inserted = $GLOBALS['_wpdb_inserted_rows'][0]['data'];
		$this->assertSame( 'unexplained', $inserted['disposition'] );
		$this->assertSame( 'SAMEORIGIN', $inserted['old_value'] );
		$this->assertSame( 'DENY', $inserted['new_value'] );
	}

	public function test_record_clamps_an_unrecognised_risk_level_to_unknown(): void {
		$GLOBALS['_wpdb_get_var'] = null;

		$this->store->record( 'pillar', 'frontend', 'x', 'a', 'b', 'catastrophic', '', '' );

		$this->assertSame( 'unknown', $GLOBALS['_wpdb_inserted_rows'][0]['data']['risk_level'] );
	}

	public function test_record_updates_new_value_on_an_existing_open_row_instead_of_inserting(): void {
		$GLOBALS['_wpdb_get_var'] = 42;

		$this->store->record( 'pillar', 'frontend', 'x-frame-options', 'SAMEORIGIN', 'DENY', 'medium', 'changed again', '' );

		$this->assertSame( array(), $GLOBALS['_wpdb_inserted_rows'] );
		$this->assertCount( 1, $GLOBALS['_wpdb_updated_rows'] );
		$updated = $GLOBALS['_wpdb_updated_rows'][0];
		$this->assertSame( array( 'id' => 42 ), $updated['where'] );
		$this->assertSame( 'DENY', $updated['data']['new_value'] );
		$this->assertArrayNotHasKey( 'old_value', $updated['data'] ); // old_value stays anchored to the original baseline value.
	}

	public function test_resolve_sets_disposition_to_resolved_by_fingerprint(): void {
		$this->store->resolve( 'pillar', 'frontend', 'x-frame-options' );

		$this->assertCount( 1, $GLOBALS['_wpdb_updated_rows'] );
		$this->assertSame( 'resolved', $GLOBALS['_wpdb_updated_rows'][0]['data']['disposition'] );
	}

	public function test_disposition_rejects_unexplained_and_resolved(): void {
		$this->assertFalse( $this->store->disposition( 1, 'unexplained', 5, 'x' ) );
		$this->assertFalse( $this->store->disposition( 1, 'resolved', 5, 'x' ) );
		$this->assertSame( array(), $GLOBALS['_wpdb_updated_rows'] );
	}

	public function test_disposition_rejects_an_empty_note(): void {
		$this->assertFalse( $this->store->disposition( 1, 'approved', 5, '' ) );
		$this->assertFalse( $this->store->disposition( 1, 'approved', 5, '   ' ) );
	}

	public function test_disposition_writes_approved_with_a_reason(): void {
		$ok = $this->store->disposition( 1, 'approved', 5, 'Confirmed intentional.' );

		$this->assertTrue( $ok );
		$row = $GLOBALS['_wpdb_updated_rows'][0];
		$this->assertSame( 'approved', $row['data']['disposition'] );
		$this->assertSame( 5, $row['data']['disposition_by'] );
		$this->assertSame( array( 'id' => 1 ), $row['where'] );
	}

	public function test_disposition_accepts_expected(): void {
		$ok = $this->store->disposition( 1, 'expected', 5, 'Planned change.' );

		$this->assertTrue( $ok );
		$this->assertSame( 'expected', $GLOBALS['_wpdb_updated_rows'][0]['data']['disposition'] );
	}

	public function test_all_filters_by_disposition_when_valid(): void {
		$this->store->all( 'unexplained' );

		$this->assertStringContainsString( "WHERE disposition = 'unexplained'", $GLOBALS['_wpdb_last_get_results_query'] );
	}

	public function test_all_ignores_an_invalid_disposition_filter(): void {
		$this->store->all( 'not-a-real-disposition' );

		$this->assertStringNotContainsString( 'WHERE disposition', (string) $GLOBALS['_wpdb_last_get_results_query'] );
	}
}
