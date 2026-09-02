<?php
/**
 * Unit tests for WP_SAM\Intelligence\Scanner_Vendor_Store.
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;
use WP_SAM\Intelligence\Scanner_Vendor_Store;

class ScannerVendorStoreTest extends TestCase {

	private Scanner_Vendor_Store $store;

	protected function setUp(): void {
		wp_test_reset_globals();
		$this->store = new Scanner_Vendor_Store();
	}

	public function test_all_hydrates_json_columns_and_builtin_flag(): void {
		$GLOBALS['_wpdb_get_results'] = array(
			array(
				'vendor_key'   => 'googlebot',
				'vendor_name'  => 'Googlebot',
				'category'     => 'known_crawler',
				'ua_pattern'   => 'Googlebot',
				'rdns_suffixes' => '["googlebot.com","google.com"]',
				'cidr_ranges'  => '[]',
				'source_url'   => 'https://example.test/verify',
				'is_builtin'   => 1,
			),
		);

		$vendors = $this->store->all();

		$this->assertCount( 1, $vendors );
		$this->assertSame( array( 'googlebot.com', 'google.com' ), $vendors[0]['rdns_suffixes'] );
		$this->assertSame( array(), $vendors[0]['cidr_ranges'] );
		$this->assertTrue( $vendors[0]['is_builtin'] );
	}

	public function test_get_returns_null_when_not_found(): void {
		$GLOBALS['_wpdb_get_row'] = null;

		$this->assertNull( $this->store->get( 'nonexistent' ) );
	}

	public function test_upsert_rejects_empty_key_or_name(): void {
		$this->assertFalse( $this->store->upsert( '', 'Name', 'custom', '', array(), array(), '', 'none', '' ) );
		$this->assertFalse( $this->store->upsert( 'key', '', 'custom', '', array(), array(), '', 'none', '' ) );
	}

	public function test_upsert_inserts_a_new_vendor(): void {
		$GLOBALS['_wpdb_get_row'] = null; // get() finds nothing -> insert path.

		$ok = $this->store->upsert(
			'qualys',
			'Qualys',
			'known_commercial_scanner',
			'QualysGuard',
			array( 'qualys.com' ),
			array( '64.39.96.0/20' ),
			'https://example.test/qualys',
			'cidr',
			'Verified 2026-09-02'
		);

		$this->assertTrue( $ok );
		$this->assertCount( 1, $GLOBALS['_wpdb_inserted_rows'] );
		$inserted = $GLOBALS['_wpdb_inserted_rows'][0]['data'];
		$this->assertSame( 'qualys', $inserted['vendor_key'] );
		$this->assertSame( 0, $inserted['is_builtin'] );
		$this->assertSame( '["qualys.com"]', $inserted['rdns_suffixes'] );
	}

	public function test_upsert_falls_back_to_custom_category_when_invalid(): void {
		$GLOBALS['_wpdb_get_row'] = null;

		$this->store->upsert( 'x', 'X', 'not-a-real-category', '', array(), array(), '', 'none', '' );

		$this->assertSame( 'custom', $GLOBALS['_wpdb_inserted_rows'][0]['data']['category'] );
	}

	public function test_upsert_updates_an_existing_vendor(): void {
		$GLOBALS['_wpdb_get_row'] = array(
			'vendor_key'   => 'qualys',
			'vendor_name'  => 'Qualys',
			'category'     => 'known_commercial_scanner',
			'ua_pattern'   => 'QualysGuard',
			'rdns_suffixes' => '[]',
			'cidr_ranges'  => '[]',
			'source_url'   => '',
			'is_builtin'   => 0,
		);

		$ok = $this->store->upsert( 'qualys', 'Qualys Inc', 'known_commercial_scanner', 'QualysGuard', array(), array(), '', 'none', '' );

		$this->assertTrue( $ok );
		$this->assertCount( 1, $GLOBALS['_wpdb_updated_rows'] );
		$this->assertSame( array( 'vendor_key' => 'qualys' ), $GLOBALS['_wpdb_updated_rows'][0]['where'] );
	}

	public function test_delete_refuses_a_builtin_vendor(): void {
		$GLOBALS['_wpdb_get_row'] = array(
			'vendor_key'  => 'googlebot',
			'vendor_name' => 'Googlebot',
			'category'    => 'known_crawler',
			'ua_pattern'  => 'Googlebot',
			'rdns_suffixes' => '[]',
			'cidr_ranges' => '[]',
			'source_url'  => '',
			'is_builtin'  => 1,
		);

		$this->assertFalse( $this->store->delete( 'googlebot' ) );
	}

	public function test_delete_removes_a_custom_vendor(): void {
		$GLOBALS['_wpdb_get_row'] = array(
			'vendor_key'  => 'qualys',
			'vendor_name' => 'Qualys',
			'category'    => 'known_commercial_scanner',
			'ua_pattern'  => 'QualysGuard',
			'rdns_suffixes' => '[]',
			'cidr_ranges' => '[]',
			'source_url'  => '',
			'is_builtin'  => 0,
		);

		$ok = $this->store->delete( 'qualys' );

		$this->assertTrue( $ok );
		$this->assertCount( 1, $GLOBALS['_wpdb_queries'] );
		$this->assertStringContainsString( 'DELETE FROM', $GLOBALS['_wpdb_queries'][0] );
		$this->assertStringContainsString( "'qualys'", $GLOBALS['_wpdb_queries'][0] );
	}

	public function test_delete_returns_false_when_vendor_does_not_exist(): void {
		$GLOBALS['_wpdb_get_row'] = null;

		$this->assertFalse( $this->store->delete( 'ghost' ) );
	}
}
