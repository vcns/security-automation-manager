<?php
/**
 * Unit tests for WP_SAM\Intelligence\App_Ads_Txt_Store -- mirrors
 * AdsTxtStoreTest since the two classes share the same IAB record format
 * and fetch/cache shape, each with its own options.
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;
use WP_SAM\Intelligence\App_Ads_Txt_Store;

class AppAdsTxtStoreTest extends TestCase {

	protected function setUp(): void {
		wp_test_reset_globals();
	}

	private function http_response( string $body, int $code = 200 ): array {
		return array(
			'response' => array( 'code' => $code ),
			'body'     => $body,
		);
	}

	private function seed_one_record(): void {
		update_option( 'wp_sam_app_ads_txt_records', array( array( 'domain' => 'example.com', 'publisher_id' => 'pub-1', 'relationship' => 'DIRECT', 'certification_id' => null ) ) );
		update_option( 'wp_sam_app_ads_txt_last_fetch_status', 'success' );
	}

	public function test_refresh_fetches_app_ads_txt_and_parses_seller_records(): void {
		$calls = array();
		$store = new App_Ads_Txt_Store(
			function ( string $url ) use ( &$calls ) {
				$calls[] = $url;
				return $this->http_response( "# comment\nCONTACT=adops@example.com\nexample.com, pub-1, reseller\n" );
			}
		);

		$result = $store->refresh();

		$this->assertSame( 'refreshed', $result['status'] );
		$this->assertStringEndsWith( '/app-ads.txt', $calls[0] );
		$this->assertCount( 1, $store->records() );
		$this->assertSame( 'RESELLER', $store->records()[0]['relationship'] );
		$this->assertTrue( $store->is_present() );
		$this->assertNotNull( $store->last_refreshed_at() );
	}

	public function test_is_present_is_false_before_any_refresh(): void {
		$this->assertFalse( ( new App_Ads_Txt_Store() )->is_present() );
	}

	public function test_refresh_treats_a_404_as_absent_and_clears_cached_records(): void {
		$this->seed_one_record();
		$store = new App_Ads_Txt_Store( fn( string $url ) => $this->http_response( '', 404 ) );

		$result = $store->refresh();

		$this->assertSame( 'absent', $result['status'] );
		$this->assertSame( 'No /app-ads.txt on this site (HTTP 404).', $result['message'] );
		$this->assertSame( array(), $store->records() );
		$this->assertFalse( $store->is_present() );
		$this->assertSame( 'absent', $store->last_fetch_status() );
	}

	public function test_refresh_keeps_existing_records_on_a_500_response(): void {
		$this->seed_one_record();
		$store = new App_Ads_Txt_Store( fn( string $url ) => $this->http_response( '', 500 ) );

		$result = $store->refresh();

		$this->assertSame( 'failed', $result['status'] );
		$this->assertCount( 1, $store->records() );
		$this->assertSame( 'failed', $store->last_fetch_status() );
	}

	public function test_refresh_keeps_existing_records_on_a_wp_error_response(): void {
		$this->seed_one_record();
		$store = new App_Ads_Txt_Store( static fn( string $url ) => new WP_Error( 'http_request_failed', 'timeout' ) );

		$result = $store->refresh();

		$this->assertSame( 'failed', $result['status'] );
		$this->assertSame( 'Fetch failed: timeout', $result['message'] );
		$this->assertCount( 1, $store->records() );
	}
}
