<?php
/**
 * Unit tests for WP_SAM\Intelligence\Geo_Ip_Store.
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;
use WP_SAM\Intelligence\Geo_Ip_Store;

class GeoIpStoreTest extends TestCase {

	protected function setUp(): void {
		wp_test_reset_globals();
	}

	private function http_response( array $body, int $code = 200 ): array {
		return array(
			'response' => array( 'code' => $code ),
			'body'     => wp_json_encode( $body ),
		);
	}

	public function test_is_configured_is_false_with_no_token(): void {
		$this->assertFalse( ( new Geo_Ip_Store() )->is_configured() );
	}

	public function test_save_token_seals_the_value(): void {
		$store = new Geo_Ip_Store();

		$store->save_token( 'plain-text-token' );

		$saved = (string) get_option( 'wp_sam_geoip_ipinfo_token' );
		$this->assertNotSame( 'plain-text-token', $saved );
		$this->assertStringStartsWith( 'sam-v1:', $saved );
	}

	public function test_is_configured_is_true_after_saving_a_token(): void {
		$store = new Geo_Ip_Store();
		$store->save_token( 'a-real-token' );

		$this->assertTrue( $store->is_configured() );
	}

	public function test_save_empty_token_clears_configuration(): void {
		$store = new Geo_Ip_Store();
		$store->save_token( 'a-real-token' );
		$store->save_token( '' );

		$this->assertFalse( $store->is_configured() );
	}

	public function test_resolve_returns_nulls_when_not_configured_without_any_http_call(): void {
		$called = false;
		$store  = new Geo_Ip_Store(
			static function () use ( &$called ): array {
				$called = true;
				return array();
			}
		);

		$result = $store->resolve( '8.8.8.8' );

		$this->assertSame( array( 'country' => null, 'region' => null, 'city' => null ), $result );
		$this->assertFalse( $called );
	}

	public function test_resolve_returns_nulls_for_an_invalid_ip(): void {
		$store = new Geo_Ip_Store();
		$store->save_token( 'a-real-token' );

		$result = $store->resolve( 'not-an-ip' );

		$this->assertSame( array( 'country' => null, 'region' => null, 'city' => null ), $result );
	}

	public function test_resolve_returns_cached_result_without_a_live_call(): void {
		$GLOBALS['_wpdb_get_row'] = array(
			'country' => 'US',
			'region'  => 'California',
			'city'    => 'Mountain View',
		);
		$called = false;
		$store  = new Geo_Ip_Store(
			static function () use ( &$called ): array {
				$called = true;
				return array();
			}
		);
		$store->save_token( 'a-real-token' );

		$result = $store->resolve( '8.8.8.8' );

		$this->assertSame( 'US', $result['country'] );
		$this->assertFalse( $called );
	}

	public function test_resolve_performs_a_live_lookup_on_cache_miss(): void {
		$GLOBALS['_wpdb_get_row'] = null;
		$store                    = new Geo_Ip_Store(
			fn( string $url ) => $this->http_response(
				array(
					'ip'      => '8.8.8.8',
					'country' => 'US',
					'region'  => 'California',
					'city'    => 'Mountain View',
				)
			)
		);
		$store->save_token( 'a-real-token' );

		$result = $store->resolve( '8.8.8.8' );

		$this->assertSame( 'US', $result['country'] );
		$this->assertSame( 'California', $result['region'] );
		$this->assertSame( 'Mountain View', $result['city'] );
	}

	public function test_resolve_returns_nulls_on_a_wp_error_response(): void {
		$GLOBALS['_wpdb_get_row'] = null;
		$store                    = new Geo_Ip_Store( static fn( string $url ) => new WP_Error( 'http_request_failed', 'timeout' ) );
		$store->save_token( 'a-real-token' );

		$result = $store->resolve( '8.8.8.8' );

		$this->assertNull( $result['country'] );
	}

	public function test_resolve_returns_nulls_on_a_non_200_response(): void {
		$GLOBALS['_wpdb_get_row'] = null;
		$store                    = new Geo_Ip_Store( fn( string $url ) => $this->http_response( array(), 401 ) );
		$store->save_token( 'a-bad-token' );

		$result = $store->resolve( '8.8.8.8' );

		$this->assertNull( $result['country'] );
	}

	public function test_resolve_writes_to_cache_after_a_live_lookup(): void {
		$GLOBALS['_wpdb_get_row'] = null;
		$store                    = new Geo_Ip_Store(
			fn( string $url ) => $this->http_response(
				array(
					'country' => 'US',
					'region'  => 'California',
					'city'    => 'Mountain View',
				)
			)
		);
		$store->save_token( 'a-real-token' );

		$store->resolve( '8.8.8.8' );

		$this->assertCount( 1, $GLOBALS['_wpdb_inserted_rows'] );
		$inserted = $GLOBALS['_wpdb_inserted_rows'][0]['data'];
		$this->assertSame( '8.8.8.8', $inserted['ip'] );
		$this->assertSame( 'US', $inserted['country'] );
	}

	public function test_resolve_never_leaks_the_token_into_the_stored_url_of_the_request_log(): void {
		// The injected http_get receives the full URL (token included, by
		// design -- IPinfo's API takes it as a query param) -- this test
		// exists to document that expectation explicitly rather than leave
		// it implicit, since a future refactor moving to a header-based
		// auth scheme should update this alongside the implementation.
		$GLOBALS['_wpdb_get_row'] = null;
		$seen_url                 = null;
		$store                    = new Geo_Ip_Store(
			function ( string $url ) use ( &$seen_url ) {
				$seen_url = $url;
				return $this->http_response( array( 'country' => 'US' ) );
			}
		);
		$store->save_token( 'secret-token-123' );

		$store->resolve( '8.8.8.8' );

		$this->assertStringContainsString( 'secret-token-123', $seen_url );
		$this->assertStringContainsString( 'ipinfo.io/8.8.8.8', $seen_url );
	}

	public function test_token_undecryptable_is_false_when_nothing_saved(): void {
		$this->assertFalse( ( new Geo_Ip_Store() )->token_undecryptable() );
	}

	public function test_token_undecryptable_is_true_for_tampered_ciphertext(): void {
		update_option( 'wp_sam_geoip_ipinfo_token', 'sam-v1:not-valid-ciphertext' );

		$this->assertTrue( ( new Geo_Ip_Store() )->token_undecryptable() );
	}
}
