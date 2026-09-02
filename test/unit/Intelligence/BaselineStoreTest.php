<?php
/**
 * Unit tests for WP_SAM\Intelligence\Baseline_Store.
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;
use WP_SAM\Intelligence\Baseline_Store;

class BaselineStoreTest extends TestCase {

	private Baseline_Store $store;

	protected function setUp(): void {
		wp_test_reset_globals();
		$this->store = new Baseline_Store();
	}

	public function test_get_current_returns_null_when_none_exists(): void {
		$GLOBALS['_wpdb_get_row'] = null;

		$this->assertNull( $this->store->get_current() );
	}

	public function test_get_current_returns_the_is_current_row(): void {
		$GLOBALS['_wpdb_get_row'] = array( 'id' => 1, 'version_number' => 3, 'is_current' => 1 );

		$current = $this->store->get_current();

		$this->assertSame( 3, $current['version_number'] );
	}

	public function test_approve_starts_at_version_one_when_no_prior_baseline(): void {
		$GLOBALS['_wpdb_get_var'] = null;

		$id = $this->store->approve( array( array( 'category' => 'x', 'surface' => '', 'item_key' => 'x', 'value' => 'y' ) ), 'hash123', 5, 'first baseline' );

		$this->assertCount( 1, $GLOBALS['_wpdb_inserted_rows'] );
		$this->assertSame( 1, $GLOBALS['_wpdb_inserted_rows'][0]['data']['version_number'] );
		$this->assertSame( 1, $GLOBALS['_wpdb_inserted_rows'][0]['data']['is_current'] );
		$this->assertSame( 5, $GLOBALS['_wpdb_inserted_rows'][0]['data']['approved_by'] );
	}

	public function test_approve_increments_the_version_number(): void {
		$GLOBALS['_wpdb_get_var'] = 4;

		$this->store->approve( array(), 'hash456', 5, 'second baseline' );

		$this->assertSame( 5, $GLOBALS['_wpdb_inserted_rows'][0]['data']['version_number'] );
	}

	public function test_approve_clears_is_current_on_prior_rows_before_inserting(): void {
		$GLOBALS['_wpdb_get_var'] = 1;

		$this->store->approve( array(), 'hash789', 5, '' );

		$this->assertCount( 1, $GLOBALS['_wpdb_queries'] );
		$this->assertStringContainsString( 'is_current = 0', $GLOBALS['_wpdb_queries'][0] );
	}

	public function test_all_returns_rows_without_the_full_state_json(): void {
		$GLOBALS['_wpdb_get_results'] = array( array( 'id' => 1, 'version_number' => 1 ) );

		$rows = $this->store->all();

		$this->assertCount( 1, $rows );
		$this->assertStringNotContainsString( 'state_json', $GLOBALS['_wpdb_last_get_results_query']);
	}
}
