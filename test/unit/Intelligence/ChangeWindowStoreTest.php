<?php
/**
 * Unit tests for WP_SAM\Intelligence\Change_Window_Store.
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;
use WP_SAM\Intelligence\Change_Window_Store;

class ChangeWindowStoreTest extends TestCase {

	private Change_Window_Store $store;

	protected function setUp(): void {
		wp_test_reset_globals();
		$this->store = new Change_Window_Store();
	}

	public function test_open_inserts_a_row_when_none_is_active(): void {
		$GLOBALS['_wpdb_get_row'] = null;

		$id = $this->store->open( 'Upgrading Elementor', 1, 4, 9 );

		$this->assertGreaterThan( 0, $id );
		$this->assertCount( 1, $GLOBALS['_wpdb_inserted_rows'] );
		$data = $GLOBALS['_wpdb_inserted_rows'][0]['data'];
		$this->assertSame( 'Upgrading Elementor', $data['description'] );
		$this->assertSame( 'open', $data['status'] );
		$this->assertSame( 9, $data['baseline_id_before'] );
		$this->assertNotNull( $data['closes_at'] );
	}

	public function test_open_leaves_closes_at_null_with_no_duration(): void {
		$GLOBALS['_wpdb_get_row'] = null;

		$this->store->open( 'Deploying', 1, null, null );

		$this->assertNull( $GLOBALS['_wpdb_inserted_rows'][0]['data']['closes_at'] );
	}

	public function test_open_refuses_a_second_window_while_one_is_active(): void {
		$GLOBALS['_wpdb_get_row'] = array(
			'id'     => 1,
			'status' => 'open',
		);

		$id = $this->store->open( 'Another change', 1, null, null );

		$this->assertSame( 0, $id );
		$this->assertSame( array(), $GLOBALS['_wpdb_inserted_rows'] );
	}

	public function test_open_refuses_a_blank_description(): void {
		$GLOBALS['_wpdb_get_row'] = null;

		$this->assertSame( 0, $this->store->open( '   ', 1, null, null ) );
	}

	public function test_get_active_returns_null_when_none_open(): void {
		$GLOBALS['_wpdb_get_row'] = null;

		$this->assertNull( $this->store->get_active() );
	}

	public function test_close_updates_the_row_and_returns_true(): void {
		$GLOBALS['_wpdb_update_result'] = 1;

		$ok = $this->store->close( 5, 1, 'Confirmed as expected.', 11 );

		$this->assertTrue( $ok );
		$updated = $GLOBALS['_wpdb_updated_rows'][0];
		$this->assertSame( 'closed', $updated['data']['status'] );
		$this->assertSame( 11, $updated['data']['baseline_id_after'] );
		$this->assertSame(
			array(
				'id'     => 5,
				'status' => 'open',
			),
			$updated['where']
		);
	}

	public function test_close_returns_false_when_nothing_matched(): void {
		$GLOBALS['_wpdb_update_result'] = 0;

		$this->assertFalse( $this->store->close( 5, 1, 'note', null ) );
	}
}
