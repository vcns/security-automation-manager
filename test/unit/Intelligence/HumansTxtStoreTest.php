<?php
/**
 * Unit tests for WP_SAM\Intelligence\Humans_Txt_Store.
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;
use WP_SAM\Intelligence\Humans_Txt_Store;

class HumansTxtStoreTest extends TestCase {

	protected function setUp(): void {
		wp_test_reset_globals();
	}

	private function http_response( string $body, int $code = 200 ): array {
		return array(
			'response' => array( 'code' => $code ),
			'body'     => $body,
		);
	}

	public function test_is_present_is_false_before_any_refresh(): void {
		$this->assertFalse( ( new Humans_Txt_Store() )->is_present() );
	}

	public function test_is_present_is_true_after_a_successful_fetch_even_with_an_empty_body(): void {
		// A 0-byte humans.txt is a legitimate, successfully-fetched file --
		// "present" must not be indistinguishable from "never fetched".
		$store = new Humans_Txt_Store( fn( string $url ) => $this->http_response( '' ) );

		$store->refresh();

		$this->assertTrue( $store->is_present() );
		$this->assertSame( 'success', $store->last_fetch_status() );
	}

	public function test_refresh_stores_the_fetched_content(): void {
		$store = new Humans_Txt_Store( fn( string $url ) => $this->http_response( "/* TEAM */\nDeveloper: Someone\n" ) );

		$store->refresh();

		$this->assertStringContainsString( 'Developer: Someone', $store->content() );
	}

	public function test_refresh_keeps_existing_content_on_a_non_200_response(): void {
		update_option( 'wp_sam_humans_txt_content', 'previous content' );
		$store = new Humans_Txt_Store( fn( string $url ) => $this->http_response( '', 404 ) );

		$result = $store->refresh();

		$this->assertSame( 'failed', $result['status'] );
		$this->assertSame( 'previous content', $store->content() );
	}
}
