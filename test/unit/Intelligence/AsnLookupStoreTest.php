<?php
/**
 * Unit tests for WP_SAM\Intelligence\Asn_Lookup_Store.
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;
use WP_SAM\Intelligence\Asn_Lookup_Store;

class AsnLookupStoreTest extends TestCase {

	protected function setUp(): void {
		wp_test_reset_globals();
	}

	private function store( array $txt_responses ): Asn_Lookup_Store {
		$calls = array();
		return new Asn_Lookup_Store(
			static function ( string $hostname ) use ( &$calls, $txt_responses ): array {
				$calls[] = $hostname;
				return $txt_responses[ $hostname ] ?? array();
			}
		);
	}

	public function test_resolve_returns_nulls_for_empty_ip(): void {
		$store = new Asn_Lookup_Store( static fn( string $h ): array => array() );

		$result = $store->resolve( '' );

		$this->assertSame( array( 'asn' => null, 'asn_org' => null ), $result );
	}

	public function test_resolve_returns_nulls_for_a_non_ipv4_address(): void {
		$store = new Asn_Lookup_Store( static fn( string $h ): array => array() );

		$result = $store->resolve( '2001:db8::1' );

		$this->assertSame( array( 'asn' => null, 'asn_org' => null ), $result );
	}

	public function test_resolve_returns_cached_result_without_a_live_lookup(): void {
		$GLOBALS['_wpdb_get_row'] = array(
			'asn'     => 15169,
			'asn_org' => 'GOOGLE, US',
		);
		$lookup_ran = false;
		$store      = new Asn_Lookup_Store(
			static function () use ( &$lookup_ran ): array {
				$lookup_ran = true;
				return array();
			}
		);

		$result = $store->resolve( '8.8.8.8' );

		$this->assertSame( 15169, $result['asn'] );
		$this->assertSame( 'GOOGLE, US', $result['asn_org'] );
		$this->assertFalse( $lookup_ran );
	}

	public function test_resolve_performs_a_live_lookup_on_cache_miss(): void {
		$GLOBALS['_wpdb_get_row'] = null;
		$store                    = $this->store(
			array(
				'8.8.8.8.origin.asn.cymru.com' => array( '15169 | 8.8.8.0/24 | US | arin | 2023-12-28' ),
				'AS15169.asn.cymru.com'        => array( '15169 | US | arin | 2000-03-30 | GOOGLE, US' ),
			)
		);

		$result = $store->resolve( '8.8.8.8' );

		$this->assertSame( 15169, $result['asn'] );
		$this->assertSame( 'GOOGLE, US', $result['asn_org'] );
	}

	public function test_resolve_reverses_octets_for_the_origin_query(): void {
		$GLOBALS['_wpdb_get_row'] = null;
		$seen_hostnames           = array();
		$store                    = new Asn_Lookup_Store(
			static function ( string $hostname ) use ( &$seen_hostnames ): array {
				$seen_hostnames[] = $hostname;
				return array();
			}
		);

		$store->resolve( '203.0.113.42' );

		$this->assertSame( '42.113.0.203.origin.asn.cymru.com', $seen_hostnames[0] );
	}

	public function test_resolve_caches_a_negative_result_on_lookup_failure(): void {
		$GLOBALS['_wpdb_get_row'] = null;
		$store                    = $this->store( array() );

		$result = $store->resolve( '203.0.113.42' );

		$this->assertNull( $result['asn'] );
		$this->assertNull( $result['asn_org'] );
		$this->assertCount( 1, $GLOBALS['_wpdb_inserted_rows'] );
		$this->assertNull( $GLOBALS['_wpdb_inserted_rows'][0]['data']['asn'] );
	}

	public function test_resolve_handles_a_malformed_origin_record_gracefully(): void {
		$GLOBALS['_wpdb_get_row'] = null;
		$store                    = $this->store(
			array(
				'203.0.113.42.origin.asn.cymru.com' => array( 'not a valid record' ),
			)
		);

		$result = $store->resolve( '203.0.113.42' );

		$this->assertNull( $result['asn'] );
	}

	public function test_resolve_writes_to_cache_after_a_live_lookup(): void {
		$GLOBALS['_wpdb_get_row'] = null;
		$store                    = $this->store(
			array(
				'8.8.8.8.origin.asn.cymru.com' => array( '15169 | 8.8.8.0/24 | US | arin | 2023-12-28' ),
				'AS15169.asn.cymru.com'        => array( '15169 | US | arin | 2000-03-30 | GOOGLE, US' ),
			)
		);

		$store->resolve( '8.8.8.8' );

		$this->assertCount( 1, $GLOBALS['_wpdb_inserted_rows'] );
		$inserted = $GLOBALS['_wpdb_inserted_rows'][0]['data'];
		$this->assertSame( '8.8.8.8', $inserted['ip'] );
		$this->assertSame( 15169, $inserted['asn'] );
		$this->assertSame( 'GOOGLE, US', $inserted['asn_org'] );
	}

	public function test_resolve_updates_an_existing_cache_row_instead_of_inserting(): void {
		$GLOBALS['_wpdb_get_row']     = null;
		$GLOBALS['_wpdb_get_var']     = 7;
		$store                        = $this->store(
			array(
				'8.8.8.8.origin.asn.cymru.com' => array( '15169 | 8.8.8.0/24 | US | arin | 2023-12-28' ),
				'AS15169.asn.cymru.com'        => array( '15169 | US | arin | 2000-03-30 | GOOGLE, US' ),
			)
		);

		$store->resolve( '8.8.8.8' );

		$this->assertSame( array(), $GLOBALS['_wpdb_inserted_rows'] );
		$this->assertCount( 1, $GLOBALS['_wpdb_updated_rows'] );
		$this->assertSame( array( 'id' => 7 ), $GLOBALS['_wpdb_updated_rows'][0]['where'] );
	}
}
