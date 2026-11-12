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

	// ── network_range() and describe(), for the ASN Lookup page ──────────

	/** @param array<int, string> $hostnames Every hostname queried, appended to. */
	private function counting_store( array $txt_responses, array &$hostnames ): Asn_Lookup_Store {
		return new Asn_Lookup_Store(
			static function ( string $hostname ) use ( &$hostnames, $txt_responses ): array {
				$hostnames[] = $hostname;
				return $txt_responses[ $hostname ] ?? array();
			}
		);
	}

	public function test_network_range_is_the_prefix_from_the_origin_record_and_is_kept_for_a_day(): void {
		$hostnames = array();
		$store     = $this->counting_store( array( '135.72.125.91.origin.asn.cymru.com' => array( '6871 | 91.125.0.0/16 | GB | ripencc | 2006-10-09' ) ), $hostnames );

		$this->assertSame( '91.125.0.0/16', $store->network_range( '91.125.72.135' ) );
		$this->assertSame( '91.125.0.0/16', $store->network_range( '91.125.72.135' ) );
		$this->assertSame( array( '135.72.125.91.origin.asn.cymru.com' ), $hostnames, 'The second call is answered from the transient.' );
	}

	public function test_network_range_is_null_for_no_record_a_malformed_one_or_a_non_ipv4_address(): void {
		$hostnames = array();
		$store     = $this->counting_store(
			array(
				'1.0.0.10.origin.asn.cymru.com' => array( '64500 | <b>10.0.0.0/8</b> | ZZ' ),
			),
			$hostnames
		);

		$this->assertNull( $store->network_range( '203.0.113.9' ) );
		$this->assertNull( $store->network_range( '10.0.0.1' ) );
		$this->assertNull( $store->network_range( '2001:db8::1' ) );
		$this->assertNull( $store->network_range( 'nonsense' ) );
		$this->assertCount( 2, $hostnames, 'Nothing is queried for an address that is not IPv4.' );
		$this->assertNull( $store->network_range( '203.0.113.9' ) );
		$this->assertCount( 2, $hostnames, 'A miss is kept too.' );
	}

	public function test_describe_reads_the_registry_record_and_keeps_it_for_a_day(): void {
		$hostnames = array();
		$store     = $this->counting_store( array( 'AS6871.asn.cymru.com' => array( '6871 | GB | ripencc | 1996-12-13 | Plusnet - British Telecommunications Limited, GB' ) ), $hostnames );

		$expected = array(
			'asn'       => 6871,
			'name'      => 'Plusnet - British Telecommunications Limited, GB',
			'country'   => 'GB',
			'registry'  => 'ripencc',
			'allocated' => '1996-12-13',
		);
		$this->assertSame( $expected, $store->describe( 6871 ) );
		$this->assertSame( $expected, $store->describe( 6871 ) );
		$this->assertCount( 1, $hostnames );
	}

	public function test_describe_leaves_out_anything_that_does_not_look_like_its_field(): void {
		$store = $this->store( array( 'AS64500.asn.cymru.com' => array( '64500 | Great Britain | RIPE NCC | last year |  ' ) ) );

		$this->assertSame(
			array(
				'asn'       => 64500,
				'name'      => null,
				'country'   => null,
				'registry'  => null,
				'allocated' => null,
			),
			$store->describe( 64500 )
		);
	}

	public function test_describe_ignores_a_record_for_a_different_as_and_queries_nothing_for_zero(): void {
		$hostnames = array();
		$store     = $this->counting_store( array( 'AS64500.asn.cymru.com' => array( '15169 | US | arin | 2000-03-30 | GOOGLE, US' ) ), $hostnames );

		$this->assertNull( $store->describe( 64500 )['name'] );
		$this->assertNull( $store->describe( 0 )['name'] );
		$this->assertSame( array( 'AS64500.asn.cymru.com' ), $hostnames );
	}
}
