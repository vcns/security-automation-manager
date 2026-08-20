<?php
/**
 * Phase 6C, Batch 1 ("Cloudflare clones, no record ID"): request-level
 * contract coverage for WP_SAM\Certificates\Providers\Provider_Godaddy.
 *
 * Shape: shared Dns_Provider::request() (JSON), two-part "sso-key" auth
 * header (api_key:api_secret, not Bearer), zone discovery by try/catch
 * around a per-candidate GET (same pattern as deSEC/Gandi -- see
 * ProviderContractDesecTest's docblock for the shared "no body ever
 * parsed" finding). Notably: create_txt_record()'s PATCH body is a
 * top-level JSON *array*, not an object -- decoded_body() therefore
 * returns an indexed array here, not an associative one. delete_txt_record()
 * removes ALL TXT records at that name (no per-value targeting), which is
 * safe only because ACME challenge names are exclusively owned by this
 * plugin -- documented in the driver's own docblock, not a defect.
 */

declare( strict_types=1 );

use WP_SAM\Certificates\Providers\Provider_Godaddy;

class ProviderContractGodaddyTest extends Dns_Provider_Contract_TestCase {

	private function wp_response( int $code, array $body = array() ): array {
		return array(
			'response' => array( 'code' => $code ),
			'body'     => (string) wp_json_encode( $body ),
		);
	}

	protected function make_provider(): Provider_Godaddy {
		return new Provider_Godaddy(
			array(
				'api_key'    => 'fixture-key',
				'api_secret' => 'fixture-secret',
			)
		);
	}

	protected function fqdn(): string {
		return '_acme-challenge.www.example.com';
	}

	protected function record_value(): string {
		return 'fixture-challenge-digest-value';
	}

	protected function queue_successful_create(): void {
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->wp_response( 404 ),
			$this->wp_response( 404 ),
			$this->wp_response( 200 ),
			$this->wp_response( 200 ), // PATCH create
		);
	}

	protected function queue_successful_delete(): void {
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->wp_response( 404 ),
			$this->wp_response( 404 ),
			$this->wp_response( 200 ),
			$this->wp_response( 200 ), // DELETE
		);
	}

	protected function queue_authentication_failure(): void {
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->wp_response( 200 ), // zone found on the first candidate
			$this->wp_response( 401 ), // the PATCH create itself is rejected
		);
	}

	protected function queue_zone_not_found(): void {
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->wp_response( 404 ),
			$this->wp_response( 404 ),
			$this->wp_response( 404 ),
		);
	}

	protected function queue_malformed_response(): void {
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			array( 'response' => array( 'code' => 502 ), 'body' => 'not json at all {{{' ),
			array( 'response' => array( 'code' => 502 ), 'body' => 'not json at all {{{' ),
			array( 'response' => array( 'code' => 502 ), 'body' => 'not json at all {{{' ),
		);
	}

	protected function queue_http_failure(): void {
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->wp_response( 200 ),
			$this->wp_response( 500 ),
		);
	}

	protected function assert_authenticated_correctly( array $request ): void {
		$this->assertSame( 'sso-key fixture-key:fixture-secret', $request['args']['headers']['Authorization'] ?? null );
	}

	protected function assert_record_naming_correct( array $create_request ): void {
		$this->assertStringContainsString( '/domains/example.com/records', $create_request['url'] );
		$body = $this->decoded_body( $create_request );
		$this->assertIsArray( $body );
		$this->assertArrayHasKey( 0, $body, 'GoDaddy\'s PATCH body is a top-level JSON array, not an object' );
		$this->assertSame( '_acme-challenge.www', $body[0]['name'] ?? null );
		$this->assertSame( 'TXT', $body[0]['type'] ?? null );
		$this->assertSame( $this->record_value(), $body[0]['data'] ?? null );
	}

	// ── Provider-specific: delete removes ALL TXT records at that name ───────

	public function test_delete_targets_the_type_and_name_endpoint_not_a_single_record(): void {
		$provider = $this->make_provider();
		$this->queue_successful_delete();
		$provider->delete_txt_record( $this->fqdn(), $this->record_value() );

		$requests = $this->captured_requests();
		$last     = end( $requests );
		$this->assertSame( 'DELETE', $last['args']['method'] ?? null );
		$this->assertStringContainsString( '/domains/example.com/records/TXT/_acme-challenge.www', $last['url'] );
	}
}
