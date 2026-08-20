<?php
/**
 * Phase 6C, Batch 1 ("Cloudflare clones, no record ID"): request-level
 * contract coverage for WP_SAM\Certificates\Providers\Provider_Ns1.
 *
 * Shape: shared Dns_Provider::request() (JSON), a non-standard
 * "X-NSONE-Key" header rather than Authorization, zone discovery by
 * try/catch around a per-candidate GET (same pattern as deSEC/Gandi/
 * GoDaddy -- no response body is ever parsed, see ProviderContractDesecTest's
 * docblock). Unlike those three, create/delete address the record by the
 * *full* fqdn in the URL path, not a zone-relative name.
 */

declare( strict_types=1 );

use WP_SAM\Certificates\Providers\Provider_Ns1;

class ProviderContractNs1Test extends Dns_Provider_Contract_TestCase {

	private function wp_response( int $code, array $body = array() ): array {
		return array(
			'response' => array( 'code' => $code ),
			'body'     => (string) wp_json_encode( $body ),
		);
	}

	protected function make_provider(): Provider_Ns1 {
		return new Provider_Ns1( array( 'api_key' => 'fixture-ns1-key' ) );
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
			$this->wp_response( 200 ), // PUT create
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
			$this->wp_response( 401 ), // the PUT create itself is rejected
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
		$this->assertSame( 'fixture-ns1-key', $request['args']['headers']['X-NSONE-Key'] ?? null );
		$this->assertArrayNotHasKey( 'Authorization', $request['args']['headers'] ?? array() );
	}

	protected function assert_record_naming_correct( array $create_request ): void {
		$this->assertStringContainsString( '/zones/example.com/' . $this->fqdn() . '/TXT', $create_request['url'], 'NS1 addresses records by the full fqdn in the URL, not a zone-relative name' );
		$body = $this->decoded_body( $create_request );
		$this->assertIsArray( $body );
		$this->assertSame( $this->fqdn(), $body['domain'] ?? null );
		$this->assertSame( array( array( 'answer' => array( $this->record_value() ) ) ), $body['answers'] ?? null );
	}
}
