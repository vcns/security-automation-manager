<?php
/**
 * Unit tests for WP_SAM\Intelligence\Change_Log_Store.
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;
use WP_SAM\Intelligence\Change_Log_Store;

class ChangeLogStoreTest extends TestCase {

	private Change_Log_Store $store;

	protected function setUp(): void {
		wp_test_reset_globals();
		$this->store = new Change_Log_Store();
	}

	public function test_record_rejects_an_unrecognised_change_type(): void {
		$this->store->record( 'server_rebooted', 'x', '', '' );

		$this->assertSame( array(), $GLOBALS['_wpdb_inserted_rows'] );
	}

	public function test_record_inserts_a_recognised_change_type(): void {
		$this->store->record( 'plugin_updated', 'akismet/akismet.php', '5.2', '5.3' );

		$this->assertCount( 1, $GLOBALS['_wpdb_inserted_rows'] );
		$data = $GLOBALS['_wpdb_inserted_rows'][0]['data'];
		$this->assertSame( 'plugin_updated', $data['change_type'] );
		$this->assertSame( 'akismet/akismet.php', $data['item_name'] );
		$this->assertSame( '5.2', $data['old_version'] );
		$this->assertSame( '5.3', $data['new_version'] );
	}

	public function test_recent_queries_with_a_since_bound(): void {
		$this->store->recent( 48 );

		$this->assertStringContainsString( 'occurred_at >=', $GLOBALS['_wpdb_last_get_results_query'] );
	}

	public function test_recent_floors_hours_at_one(): void {
		$this->store->recent( 0 );

		// No exception, and still produces a valid bounded query.
		$this->assertStringContainsString( 'occurred_at >=', $GLOBALS['_wpdb_last_get_results_query'] );
	}

	public function test_all_limits_and_orders_by_most_recent(): void {
		$this->store->all( 10 );

		$this->assertStringContainsString( 'ORDER BY occurred_at DESC', $GLOBALS['_wpdb_last_get_results_query'] );
		$this->assertStringContainsString( 'LIMIT 10', $GLOBALS['_wpdb_last_get_results_query'] );
	}
}
