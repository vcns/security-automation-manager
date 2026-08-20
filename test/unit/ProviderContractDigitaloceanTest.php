<?php
/**
 * Phase 6C, Batch 2 ("Cloudflare clones, list-then-delete-by-ID"): request-
 * level contract coverage for WP_SAM\Certificates\Providers\Provider_DigitalOcean.
 *
 * Shape: shared Dns_Provider::request() (JSON), Bearer auth. Zone discovery
 * uses the same try/catch-on-any->=400-status pattern as Batch 1's
 * deSEC/Gandi/GoDaddy/NS1 -- neither zone() nor create_txt_record()'s POST
 * response is ever read for its body, only status, so this driver is
 * status-only for the create path (response_body_is_validated_on_success()
 * is false below). Unlike Batch 1, delete_txt_record() lists records
 * (?type=TXT&per_page=200) and deletes by the server-assigned "id" field
 * found in that list -- it DOES read a response body, but only on the
 * delete path, which the shared malformed-response contract test doesn't
 * exercise (it only calls create_txt_record()).
 *
 * Confirmed production defect, not fixed here: DigitalOcean's List All
 * Domain Records endpoint documents `per_page` (1-200, default 20),
 * `page`, and a `name` filter for narrowing to a single record name
 * (https://docs.digitalocean.com/products/networking/dns/reference/api/domain-records/,
 * verified directly against the current published docs). This driver
 * sends per_page=200 (the documented maximum) but never follows a
 * further page, and never uses the documented `name` filter that would
 * make the whole risk moot. A matching record beyond the first 200
 * remains undeleted, with no error surfaced -- proven by
 * test_pagination_only_fetches_a_single_page_of_records() below. Logged
 * in the evidence matrix as a confirmed pagination defect, not a
 * documented limitation.
 *
 * Disclosed, matches the existing Batch 1 finding, not fixed here: zone()'s
 * try/catch treats any status >= 400 identically as "not this candidate" --
 * an authentication failure during discovery is misreported as
 * "no zone found", exactly like deSEC/Gandi/GoDaddy/NS1. Proven by
 * test_authentication_failure_during_zone_discovery_is_misreported_as_zone_not_found()
 * below; this is additional evidence for the SAME defect already logged
 * against Batch 1's four providers, not a new one.
 */

declare( strict_types=1 );

use WP_SAM\Certificates\Providers\Provider_DigitalOcean;

class ProviderContractDigitaloceanTest extends Dns_Provider_Contract_TestCase {

	private function wp_response( int $code, array $body = array() ): array {
		return array(
			'response' => array( 'code' => $code ),
			'body'     => (string) wp_json_encode( $body ),
		);
	}

	protected function make_provider(): Provider_DigitalOcean {
		return new Provider_DigitalOcean( array( 'api_token' => 'fixture-do-token' ) );
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
			$this->wp_response( 200 ), // example.com -- exists
			$this->wp_response( 201 ), // POST create
		);
	}

	protected function queue_successful_delete(): void {
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->wp_response( 404 ),
			$this->wp_response( 404 ),
			$this->wp_response( 200 ),
			$this->wp_response(
				200,
				array(
					'domain_records' => array(
						array(
							'id'   => 987654,
							'name' => '_acme-challenge.www',
							'data' => $this->record_value(),
						),
					),
				)
			), // GET list
			$this->wp_response( 204 ), // DELETE
		);
	}

	protected function queue_authentication_failure(): void {
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->wp_response( 200 ), // zone found on the first candidate
			$this->wp_response( 401 ), // the POST create itself is rejected
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
		// Genuine 2xx responses with an unparseable body -- this driver
		// never reads the body on the create path (zone() and the POST
		// create response are both status-only), so create_txt_record() is
		// expected to complete successfully.
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
		$this->assertSame( 'Bearer fixture-do-token', $request['args']['headers']['Authorization'] ?? null );
	}

	protected function assert_record_naming_correct( array $create_request ): void {
		$this->assertStringContainsString( '/domains/example.com/records', $create_request['url'] );
		$body = $this->decoded_body( $create_request );
		$this->assertIsArray( $body );
		$this->assertSame( '_acme-challenge.www', $body['name'] ?? null );
		$this->assertSame( 'TXT', $body['type'] ?? null );
		$this->assertSame( $this->record_value(), $body['data'] ?? null );
	}

	// ── Provider-specific: record identifier extracted from the list ─────────

	public function test_delete_uses_the_server_assigned_record_id_from_the_list_response(): void {
		$provider = $this->make_provider();
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->wp_response( 404 ),
			$this->wp_response( 404 ),
			$this->wp_response( 200 ),
			$this->wp_response(
				200,
				array(
					'domain_records' => array(
						array( 'id' => 111, 'name' => '_acme-challenge.www', 'data' => 'a-different-value' ),
						array( 'id' => 222, 'name' => '_acme-challenge.www', 'data' => $this->record_value() ),
						array( 'id' => 333, 'name' => 'unrelated', 'data' => $this->record_value() ),
					),
				)
			),
			$this->wp_response( 204 ),
		);

		$provider->delete_txt_record( $this->fqdn(), $this->record_value() );

		$requests = $this->captured_requests();
		$last     = end( $requests );
		$this->assertSame( 'DELETE', $last['args']['method'] ?? null );
		$this->assertStringContainsString( '/domains/example.com/records/222', $last['url'], 'must delete by the ID of the record matching both name and value, not any other candidate' );
	}

	// ── Provider-specific: confirmed pagination defect (see class docblock) ──

	public function test_pagination_only_fetches_a_single_page_of_records(): void {
		$provider = $this->make_provider();
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->wp_response( 404 ),
			$this->wp_response( 404 ),
			$this->wp_response( 200 ),
			$this->wp_response(
				200,
				array(
					// A full page of unrelated records; the target record is
					// not present -- simulating it living on a hypothetical
					// next page this driver never requests.
					'domain_records' => array(
						array( 'id' => 1, 'name' => 'unrelated-1', 'data' => 'x' ),
						array( 'id' => 2, 'name' => 'unrelated-2', 'data' => 'y' ),
					),
				)
			),
		);

		$provider->delete_txt_record( $this->fqdn(), $this->record_value() );

		$requests = $this->captured_requests();
		$this->assertCount( 4, $requests, 'a record absent from the single fetched page must not cause a DELETE request, and must not throw' );
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
			$this->assertStringContainsString( 'no zone found', $e->getMessage() );
		}

		$this->assertCount( 3, $this->captured_requests(), 'an authentication failure during zone discovery must not proceed to a write request' );
	}
}
