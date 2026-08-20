<?php
/**
 * Phase 6C, Batch 2 ("Cloudflare clones, list-then-delete-by-ID"): request-
 * level contract coverage for WP_SAM\Certificates\Providers\Provider_Domeneshop.
 *
 * Shape: shared Dns_Provider::request() (JSON), HTTP Basic auth
 * (token:secret). Response bodies are top-level JSON *arrays*, not wrapped
 * in a named key ("domain_records"/"records"/etc.) -- decoded_body() and
 * the driver itself both operate on $list['body'] directly as an array of
 * objects. Zone discovery is a client-side filter (no try/catch), like
 * Hetzner/Bunny -- see ProviderContractHetznerTest's docblock for the
 * deliberate contrast with the try/catch providers' auth-during-discovery
 * misdiagnosis. delete_txt_record()'s list call is already server-side
 * filtered by type=TXT&host={relative}; only the "data" value is compared
 * client-side, so multiple records sharing that host and type but
 * different data can still collide on identifier selection -- tested
 * below.
 *
 * No pagination mechanism applicable (confirmed directly against
 * Domeneshop's published API docs, https://api.domeneshop.no/docs/): the
 * DNS records list endpoint documents only "host" and "type" filter
 * parameters -- no page, cursor, or limit parameter exists at all. The
 * absent-record test below therefore proves this driver's handling of a
 * record missing from a server-filtered query, not an ignored pagination
 * cursor, since none exists for this endpoint.
 */

declare( strict_types=1 );

use WP_SAM\Certificates\Providers\Provider_Domeneshop;

class ProviderContractDomeneshopTest extends Dns_Provider_Contract_TestCase {

	private function wp_response( int $code, array $body = array() ): array {
		return array(
			'response' => array( 'code' => $code ),
			'body'     => (string) wp_json_encode( $body ),
		);
	}

	protected function make_provider(): Provider_Domeneshop {
		return new Provider_Domeneshop(
			array(
				'token'  => 'fixture-domeneshop-token',
				'secret' => 'fixture-domeneshop-secret',
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
			$this->wp_response( 200, array() ),
			$this->wp_response( 200, array() ),
			$this->wp_response( 200, array( array( 'id' => 7, 'domain' => 'example.com' ) ) ),
			$this->wp_response( 201 ), // POST create
		);
	}

	protected function queue_successful_delete(): void {
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->wp_response( 200, array() ),
			$this->wp_response( 200, array() ),
			$this->wp_response( 200, array( array( 'id' => 7, 'domain' => 'example.com' ) ) ),
			$this->wp_response( 200, array( array( 'id' => 55, 'data' => $this->record_value() ) ) ),
			$this->wp_response( 200 ), // DELETE
		);
	}

	protected function queue_authentication_failure(): void {
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->wp_response( 200, array( array( 'id' => 7, 'domain' => $this->fqdn() ) ) ),
			$this->wp_response( 401 ),
		);
	}

	protected function queue_zone_not_found(): void {
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->wp_response( 200, array() ),
			$this->wp_response( 200, array() ),
			$this->wp_response( 200, array() ),
		);
	}

	protected function queue_malformed_response(): void {
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			array( 'response' => array( 'code' => 200 ), 'body' => 'not json at all {{{' ),
			array( 'response' => array( 'code' => 200 ), 'body' => 'not json at all {{{' ),
			array( 'response' => array( 'code' => 200 ), 'body' => 'not json at all {{{' ),
		);
	}

	protected function queue_http_failure(): void {
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->wp_response( 200, array( array( 'id' => 7, 'domain' => $this->fqdn() ) ) ),
			$this->wp_response( 500 ),
		);
	}

	protected function assert_authenticated_correctly( array $request ): void {
		$this->assertSame( 'Basic ' . base64_encode( 'fixture-domeneshop-token:fixture-domeneshop-secret' ), $request['args']['headers']['Authorization'] ?? null );
	}

	protected function assert_record_naming_correct( array $create_request ): void {
		$this->assertStringContainsString( '/domains/7/dns', $create_request['url'] );
		$body = $this->decoded_body( $create_request );
		$this->assertIsArray( $body );
		$this->assertSame( '_acme-challenge.www', $body['host'] ?? null );
		$this->assertSame( 'TXT', $body['type'] ?? null );
		$this->assertSame( $this->record_value(), $body['data'] ?? null );
	}

	// ── Provider-specific: record identifier extracted from the list ─────────

	public function test_delete_uses_the_server_assigned_record_id_from_the_list_response(): void {
		$provider = $this->make_provider();
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->wp_response( 200, array() ),
			$this->wp_response( 200, array() ),
			$this->wp_response( 200, array( array( 'id' => 7, 'domain' => 'example.com' ) ) ),
			$this->wp_response(
				200,
				array(
					// list is already server-filtered by type=TXT&host=relative;
					// only "data" distinguishes these two entries.
					array( 'id' => 55, 'data' => 'not-the-value' ),
					array( 'id' => 66, 'data' => $this->record_value() ),
				)
			),
			$this->wp_response( 200 ),
		);

		$provider->delete_txt_record( $this->fqdn(), $this->record_value() );

		$requests = $this->captured_requests();
		$last     = end( $requests );
		$this->assertSame( 'DELETE', $last['args']['method'] ?? null );
		$this->assertStringContainsString( '/domains/7/dns/66', $last['url'] );
	}

	// ── Provider-specific: a record absent from the filtered list is a no-op ─

	public function test_a_record_absent_from_the_filtered_list_is_not_deleted_and_does_not_throw(): void {
		$provider = $this->make_provider();
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->wp_response( 200, array() ),
			$this->wp_response( 200, array() ),
			$this->wp_response( 200, array( array( 'id' => 7, 'domain' => 'example.com' ) ) ),
			$this->wp_response( 200, array( array( 'id' => 55, 'data' => 'some-other-value' ) ) ),
		);

		$provider->delete_txt_record( $this->fqdn(), $this->record_value() );

		$requests = $this->captured_requests();
		$this->assertCount( 4, $requests, 'a record absent from the fetched (server-filtered) list must not cause a DELETE request, and must not throw' );
	}

	// ── Provider-specific: discovery-stage auth failure is NOT misreported ───

	public function test_authentication_failure_during_zone_discovery_surfaces_distinctly_not_as_zone_not_found(): void {
		$provider = $this->make_provider();
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->wp_response( 401 ),
		);

		try {
			$provider->create_txt_record( $this->fqdn(), $this->record_value() );
			$this->fail( 'expected an exception when the first zone-discovery candidate is rejected with 401' );
		} catch ( \RuntimeException $e ) {
			$this->assertStringNotContainsString( 'no domain found', $e->getMessage() );
			$this->assertStringContainsString( 'HTTP 401', $e->getMessage() );
		}

		$this->assertCount( 1, $this->captured_requests(), 'with no try/catch around zone(), a rejected first candidate must not be retried against further candidates' );
	}
}
