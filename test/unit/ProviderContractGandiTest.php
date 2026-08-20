<?php
/**
 * Phase 6C, Batch 1 ("Cloudflare clones, no record ID"): request-level
 * contract coverage for WP_SAM\Certificates\Providers\Provider_Gandi.
 *
 * Shape: shared Dns_Provider::request() (JSON), static "Bearer" header
 * auth, zone discovery by try/catch around a per-candidate GET (same
 * shape as deSEC -- see that fixture's docblock for the two shared,
 * disclosed findings: zone()/create/delete never inspect response
 * bodies, only status; and a 401/403 during zone discovery is swallowed
 * identically to a genuine 404, misreporting as "no zone found"). Create
 * is PUT with a relative record name; delete is a real DELETE verb
 * (unlike deSEC's PUT-with-empty-list), also relative.
 */

declare( strict_types=1 );

use WP_SAM\Certificates\Providers\Provider_Gandi;

class ProviderContractGandiTest extends Dns_Provider_Contract_TestCase {

	private function wp_response( int $code, array $body = array() ): array {
		return array(
			'response' => array( 'code' => $code ),
			'body'     => (string) wp_json_encode( $body ),
		);
	}

	protected function make_provider(): Provider_Gandi {
		return new Provider_Gandi( array( 'api_token' => 'fixture-gandi-token' ) );
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
			$this->wp_response( 201 ), // PUT create
		);
	}

	protected function queue_successful_delete(): void {
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->wp_response( 404 ),
			$this->wp_response( 404 ),
			$this->wp_response( 200 ),
			$this->wp_response( 204 ), // DELETE
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
		// Genuine 2xx responses with an unparseable body -- see class
		// docblock and Provider_Desec fixture. This driver never reads the
		// body, so create_txt_record() is expected to complete successfully.
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			array( 'response' => array( 'code' => 200 ), 'body' => 'not json at all {{{' ),
			array( 'response' => array( 'code' => 200 ), 'body' => 'not json at all {{{' ),
		);
	}

	protected function response_body_is_validated_on_success(): bool {
		return false;
	}

	protected function queue_http_failure(): void {
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->wp_response( 200 ),
			$this->wp_response( 500 ),
		);
	}

	protected function assert_authenticated_correctly( array $request ): void {
		$this->assertSame( 'Bearer fixture-gandi-token', $request['args']['headers']['Authorization'] ?? null );
	}

	protected function assert_record_naming_correct( array $create_request ): void {
		$this->assertStringContainsString( '/domains/example.com/records/_acme-challenge.www/TXT', $create_request['url'] );
		$body = $this->decoded_body( $create_request );
		$this->assertIsArray( $body );
		$this->assertSame( array( '"' . $this->record_value() . '"' ), $body['rrset_values'] ?? null );
	}

	// ── Provider-specific: delete is a real DELETE, unlike deSEC's PUT ───────

	public function test_delete_issues_a_real_delete_request(): void {
		$provider = $this->make_provider();
		$this->queue_successful_delete();
		$provider->delete_txt_record( $this->fqdn(), $this->record_value() );

		$requests = $this->captured_requests();
		$last     = end( $requests );
		$this->assertSame( 'DELETE', $last['args']['method'] ?? null );
		$this->assertStringContainsString( '/domains/example.com/records/_acme-challenge.www/TXT', $last['url'] );
	}

	// ── Provider-specific: discovery-stage auth failure is misreported ───────

	public function test_authentication_failure_during_zone_discovery_is_misreported_as_zone_not_found(): void {
		$provider = $this->make_provider();
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->wp_response( 401 ),
			$this->wp_response( 401 ),
			$this->wp_response( 401 ),
		);

		try {
			$provider->create_txt_record( $this->fqdn(), $this->record_value() );
			$this->fail( 'expected an exception when every zone-discovery candidate is rejected with 401' );
		} catch ( \RuntimeException $e ) {
			$this->assertStringContainsString( 'no LiveDNS zone found', $e->getMessage() );
		}

		$this->assertCount( 3, $this->captured_requests(), 'an authentication failure during zone discovery must not proceed to a write request' );
	}
}
