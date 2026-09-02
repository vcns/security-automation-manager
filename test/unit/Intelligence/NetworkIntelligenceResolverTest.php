<?php
/**
 * Unit tests for WP_SAM\Intelligence\Network_Intelligence_Resolver.
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;
use WP_SAM\Intelligence\Asn_Lookup_Store;
use WP_SAM\Intelligence\Geo_Ip_Store;
use WP_SAM\Intelligence\Network_Intelligence_Resolver;
use WP_SAM\Intelligence\Tor_Exit_List_Store;

class NetworkIntelligenceResolverTest extends TestCase {

	protected function setUp(): void {
		wp_test_reset_globals();
	}

	private function resolver(): Network_Intelligence_Resolver {
		return new Network_Intelligence_Resolver(
			new Tor_Exit_List_Store(),
			new Asn_Lookup_Store( static fn( string $h ): array => array() ),
			new Geo_Ip_Store()
		);
	}

	public function test_resolve_returns_defaults_for_empty_ip_without_querying(): void {
		$resolver = $this->resolver();

		$result = $resolver->resolve( '' );

		$this->assertSame(
			array(
				'is_tor_exit' => false,
				'asn'         => null,
				'asn_org'     => null,
				'country'     => null,
				'region'      => null,
				'city'        => null,
			),
			$result
		);
		$this->assertNull( $GLOBALS['_wpdb_last_operation'] ?? null );
	}

	public function test_resolve_reports_a_known_exit_node(): void {
		$GLOBALS['_wpdb_get_var'] = '1';

		$result = $this->resolver()->resolve( '203.0.113.42' );

		$this->assertTrue( $result['is_tor_exit'] );
	}

	public function test_resolve_reports_a_non_exit_ip(): void {
		$GLOBALS['_wpdb_get_var'] = null;

		$result = $this->resolver()->resolve( '203.0.113.42' );

		$this->assertFalse( $result['is_tor_exit'] );
	}

	public function test_resolve_merges_asn_data_alongside_tor_status(): void {
		$GLOBALS['_wpdb_get_var'] = null;
		$GLOBALS['_wpdb_get_row'] = array(
			'asn'     => 15169,
			'asn_org' => 'GOOGLE, US',
		);

		$result = $this->resolver()->resolve( '8.8.8.8' );

		$this->assertFalse( $result['is_tor_exit'] );
		$this->assertSame( 15169, $result['asn'] );
		$this->assertSame( 'GOOGLE, US', $result['asn_org'] );
	}

	public function test_resolve_leaves_geo_fields_null_when_geoip_is_not_configured(): void {
		$GLOBALS['_wpdb_get_var'] = null;
		$GLOBALS['_wpdb_get_row'] = array(
			'asn'     => 15169,
			'asn_org' => 'GOOGLE, US',
		);

		$result = $this->resolver()->resolve( '8.8.8.8' );

		$this->assertNull( $result['country'] );
		$this->assertNull( $result['region'] );
		$this->assertNull( $result['city'] );
	}
}
