<?php
/**
 * Unit tests for WP_SAM\Intelligence\Security_Txt_Store -- focuses on the
 * canonical/legacy fallback fetch order and the is_expired() staleness
 * check, the two behaviours specific to this store beyond the generic
 * fetch/cache pattern already covered by RobotsRulesStoreTest.
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;
use WP_SAM\Intelligence\Security_Txt_Store;

class SecurityTxtStoreTest extends TestCase {

	protected function setUp(): void {
		wp_test_reset_globals();
	}

	private function http_response( string $body, int $code = 200 ): array {
		return array(
			'response' => array( 'code' => $code ),
			'body'     => $body,
		);
	}

	public function test_refresh_uses_the_well_known_location_when_it_succeeds(): void {
		$calls = array();
		$store = new Security_Txt_Store(
			function ( string $url ) use ( &$calls ) {
				$calls[] = $url;
				return $this->http_response( "Contact: mailto:security@example.com\nExpires: 2099-01-01T00:00:00.000Z\n" );
			}
		);

		$result = $store->refresh();

		$this->assertSame( 'refreshed', $result['status'] );
		$this->assertCount( 1, $calls );
		$this->assertStringContainsString( '/.well-known/security.txt', $calls[0] );
		$this->assertSame( array( 'mailto:security@example.com' ), $store->fields()['Contact'] );
	}

	public function test_refresh_falls_back_to_the_legacy_root_location(): void {
		$calls = array();
		$store = new Security_Txt_Store(
			function ( string $url ) use ( &$calls ) {
				$calls[] = $url;
				if ( str_contains( $url, '.well-known' ) ) {
					return $this->http_response( '', 404 );
				}
				return $this->http_response( "Contact: mailto:security@example.com\n" );
			}
		);

		$result = $store->refresh();

		$this->assertSame( 'refreshed', $result['status'] );
		$this->assertCount( 2, $calls );
		$this->assertTrue( $store->is_present() );
	}

	public function test_is_present_is_false_before_any_refresh(): void {
		$this->assertFalse( ( new Security_Txt_Store() )->is_present() );
	}

	public function test_is_present_is_true_after_a_successful_fetch_even_with_no_parseable_fields(): void {
		// A 200 response that is comment-only (or doesn't match the field
		// regex) is still a successfully-fetched file -- "present" must not
		// be indistinguishable from "never fetched".
		$store = new Security_Txt_Store( fn( string $url ) => $this->http_response( "# nothing else here\n" ) );

		$store->refresh();

		$this->assertTrue( $store->is_present() );
		$this->assertSame( array(), $store->fields() );
	}

	public function test_is_expired_is_false_with_no_expires_field(): void {
		$store = new Security_Txt_Store( fn( string $url ) => $this->http_response( "Contact: mailto:security@example.com\n" ) );
		$store->refresh();

		$this->assertFalse( $store->is_expired() );
	}

	public function test_is_expired_is_true_once_the_expires_date_has_passed(): void {
		$store = new Security_Txt_Store( fn( string $url ) => $this->http_response( "Expires: 2000-01-01T00:00:00.000Z\n" ) );
		$store->refresh();

		$this->assertTrue( $store->is_expired() );
	}

	public function test_is_expired_is_false_for_a_future_expires_date(): void {
		$store = new Security_Txt_Store( fn( string $url ) => $this->http_response( "Expires: 2099-01-01T00:00:00.000Z\n" ) );
		$store->refresh();

		$this->assertFalse( $store->is_expired() );
	}

	public function test_refresh_keeps_existing_fields_when_both_locations_fail(): void {
		update_option( 'wp_sam_security_txt_fields', array( 'Contact' => array( 'mailto:old@example.com' ) ) );
		$store = new Security_Txt_Store( static fn( string $url ) => new WP_Error( 'http_request_failed', 'timeout' ) );

		$result = $store->refresh();

		$this->assertSame( 'failed', $result['status'] );
		$this->assertSame( array( 'Contact' => array( 'mailto:old@example.com' ) ), $store->fields() );
	}
}
