<?php
/**
 * Unit tests for WP_SAM\Intelligence\Honeypath_Store.
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;
use WP_SAM\Intelligence\Honeypath_Store;

class HoneypathStoreTest extends TestCase {

	private Honeypath_Store $store;

	protected function setUp(): void {
		wp_test_reset_globals();
		$this->store = new Honeypath_Store();
	}

	public function test_add_normalises_a_leading_slash(): void {
		$GLOBALS['_wpdb_get_results'] = array();

		$this->store->add( 'wp-content/backup.zip', 'Fake backup', 1 );

		$this->assertCount( 1, $GLOBALS['_wpdb_inserted_rows'] );
		$this->assertSame( '/wp-content/backup.zip', $GLOBALS['_wpdb_inserted_rows'][0]['data']['path'] );
	}

	public function test_add_rejects_the_bare_root_path(): void {
		$GLOBALS['_wpdb_get_results'] = array();

		$this->assertFalse( $this->store->add( '/', '', 1 ) );
		$this->assertFalse( $this->store->add( '', '', 1 ) );
		$this->assertSame( array(), $GLOBALS['_wpdb_inserted_rows'] );
	}

	public function test_add_refuses_beyond_the_maximum_path_count(): void {
		$GLOBALS['_wpdb_get_results'] = array_fill(
			0,
			100,
			array(
				'id'   => 1,
				'path' => '/x',
			)
		);

		$this->assertFalse( $this->store->add( '/new-decoy', '', 1 ) );
		$this->assertSame( array(), $GLOBALS['_wpdb_inserted_rows'] );
	}

	public function test_paths_returns_only_the_path_strings(): void {
		$GLOBALS['_wpdb_get_results'] = array(
			array(
				'id'   => 1,
				'path' => '/decoy-one',
			),
			array(
				'id'   => 2,
				'path' => '/decoy-two',
			),
		);

		$this->assertSame( array( '/decoy-one', '/decoy-two' ), $this->store->paths() );
	}

	public function test_paths_is_empty_by_default(): void {
		$GLOBALS['_wpdb_get_results'] = array();

		$this->assertSame( array(), $this->store->paths() );
	}

	public function test_delete_removes_a_row(): void {
		$GLOBALS['_wpdb_query_result'] = 1;

		$this->assertTrue( $this->store->delete( 3 ) );
		$this->assertStringContainsString( 'DELETE FROM', $GLOBALS['_wpdb_last_query'] );
	}
}
