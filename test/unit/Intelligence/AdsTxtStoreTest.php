<?php
/**
 * Unit tests for WP_SAM\Intelligence\Ads_Txt_Store -- focuses on the IAB
 * record-format parsing (the behaviour specific to this store beyond the
 * generic fetch/cache pattern already covered by RobotsRulesStoreTest),
 * in particular that variable assignments (CONTACT=, SUBDOMAIN=, etc.) are
 * skipped rather than mis-parsed into bogus seller records.
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;
use WP_SAM\Intelligence\Ads_Txt_Store;

class AdsTxtStoreTest extends TestCase {

	protected function setUp(): void {
		wp_test_reset_globals();
	}

	private function http_response( string $body, int $code = 200 ): array {
		return array(
			'response' => array( 'code' => $code ),
			'body'     => $body,
		);
	}

	public function test_refresh_parses_seller_records(): void {
		$body  = "example.com, pub-1234567, DIRECT, f08c47fec0942fa0\n";
		$store = new Ads_Txt_Store( fn( string $url ) => $this->http_response( $body ) );

		$result = $store->refresh();

		$this->assertSame( 'refreshed', $result['status'] );
		$this->assertSame(
			array(
				array(
					'domain'           => 'example.com',
					'publisher_id'     => 'pub-1234567',
					'relationship'     => 'DIRECT',
					'certification_id' => 'f08c47fec0942fa0',
				),
			),
			$store->records()
		);
	}

	public function test_refresh_ignores_variable_assignments_and_comments(): void {
		$body  = "# a comment\nCONTACT=adops@example.com\nSUBDOMAIN=divisionA.example.com\nexample.com, pub-1, RESELLER\n";
		$store = new Ads_Txt_Store( fn( string $url ) => $this->http_response( $body ) );

		$store->refresh();

		$this->assertCount( 1, $store->records() );
		$this->assertSame( 'RESELLER', $store->records()[0]['relationship'] );
	}

	public function test_refresh_treats_a_missing_certification_id_as_null(): void {
		$store = new Ads_Txt_Store( fn( string $url ) => $this->http_response( "example.com, pub-1, DIRECT\n" ) );

		$store->refresh();

		$this->assertNull( $store->records()[0]['certification_id'] );
	}

	public function test_is_present_is_false_before_any_refresh(): void {
		$this->assertFalse( ( new Ads_Txt_Store() )->is_present() );
	}

	public function test_is_present_is_true_after_a_successful_fetch_with_zero_records(): void {
		// A 200 response containing only comments/variable assignments is
		// still a successfully-fetched file -- and the class's own docblock
		// frames a drop to zero records as a tampering signal worth
		// distinguishing from "never fetched".
		$store = new Ads_Txt_Store( fn( string $url ) => $this->http_response( "CONTACT=adops@example.com\n" ) );

		$store->refresh();

		$this->assertTrue( $store->is_present() );
		$this->assertSame( array(), $store->records() );
	}

	public function test_refresh_keeps_existing_records_on_a_non_200_response(): void {
		update_option( 'wp_sam_ads_txt_records', array( array( 'domain' => 'example.com', 'publisher_id' => 'pub-1', 'relationship' => 'DIRECT', 'certification_id' => null ) ) );
		$store = new Ads_Txt_Store( fn( string $url ) => $this->http_response( '', 404 ) );

		$result = $store->refresh();

		$this->assertSame( 'failed', $result['status'] );
		$this->assertCount( 1, $store->records() );
	}
}
