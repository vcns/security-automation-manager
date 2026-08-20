<?php
/**
 * Phase 6C, Batch 4 ("JSON transport, non-standard auth or a pre-step"):
 * request-level contract coverage for
 * WP_SAM\Certificates\Providers\Provider_Dnsmadeeasy.
 *
 * Shape: shared Dns_Provider::request() (JSON), custom HMAC-SHA1 request
 * signing -- three headers per request: "x-dnsme-apiKey" (the raw API
 * key), "x-dnsme-requestDate" (gmdate('r') at call time), and
 * "x-dnsme-hmac" (hash_hmac('sha1', $requestDate, $secret_key)). Tested
 * below by recomputing the expected HMAC from the *actual* captured
 * requestDate header, since the real clock can't be controlled from the
 * test.
 *
 * Zone discovery combines two failure paths in the SAME try block: a
 * try/catch around any response status >= 400 (the established Batch 1/2
 * pattern), AND an explicit `!empty($response['body']['id'])` check for a
 * genuinely-2xx "no matching domain" response -- both correctly fall
 * through to the next candidate. zone() reads the response body (the
 * `!empty(...)` check), so response_body_is_validated_on_success() stays
 * at its default true.
 *
 * Confirmed production defect (extends the established Batch 1/2
 * auth-during-discovery family, with direct code evidence -- the
 * try/catch shape is identical, wrapping the same per-candidate GET), not
 * fixed here: a genuine authentication failure (401) during zone
 * discovery is misreported as "no managed domain found for {fqdn}",
 * identically to deSEC et al. Proven by
 * test_authentication_failure_during_zone_discovery_is_misreported_as_zone_not_found()
 * below.
 *
 * [Unverified] -- not classified as a confirmed pagination defect:
 * delete_txt_record()'s GET /dns/managed/{id}/records call has no
 * page/rows parameter. api-docs.dnsmadeeasy.com did not render its
 * content for automated retrieval, so no accessible official primary
 * source could confirm this endpoint's pagination behaviour. A
 * third-party Go client library (github.com/john-k/dnsmadeeasy) defines
 * a RecordsResp struct with totalRecords/totalPages/page fields, which is
 * evidence a pagination mechanism likely exists, but a third-party
 * client's struct definitions reflect that library's own interpretation
 * of observed API responses, not a confirmed current provider contract --
 * the same standard applied to Name.com/easyDNS/Hetzner in Batches 2-3.
 * test_a_record_absent_from_the_fetched_list_is_not_deleted_and_does_not_throw()
 * below proves the observable behaviour without asserting a pagination
 * mechanism that isn't authoritatively confirmed; the totalRecords/
 * totalPages/page fields are retained in that test's queued response
 * purely as provisional contract evidence should an accessible primary
 * source surface later, not as proof pagination is confirmed now.
 */

declare( strict_types=1 );

use WP_SAM\Certificates\Providers\Provider_Dnsmadeeasy;

class ProviderContractDnsmadeeasyTest extends Dns_Provider_Contract_TestCase {

	private function wp_response( int $code, array $body = array() ): array {
		return array(
			'response' => array( 'code' => $code ),
			'body'     => (string) wp_json_encode( $body ),
		);
	}

	protected function make_provider(): Provider_Dnsmadeeasy {
		return new Provider_Dnsmadeeasy(
			array(
				'api_key'    => 'fixture-dnsme-key',
				'secret_key' => 'fixture-dnsme-secret',
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
			$this->wp_response( 404 ), // _acme-challenge.www.example.com -- HTTP failure path
			$this->wp_response( 200, array() ), // www.example.com -- 2xx but no "id" -- empty-check path
			$this->wp_response( 200, array( 'id' => 55 ) ), // example.com -- found
			$this->wp_response( 201 ), // POST create
		);
	}

	protected function queue_successful_delete(): void {
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->wp_response( 404 ),
			$this->wp_response( 200, array() ),
			$this->wp_response( 200, array( 'id' => 55 ) ),
			$this->wp_response(
				200,
				array( 'data' => array( array( 'id' => 777, 'value' => '"' . $this->record_value() . '"' ) ) )
			), // GET list
			$this->wp_response( 200 ), // DELETE
		);
	}

	protected function queue_authentication_failure(): void {
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->wp_response( 200, array( 'id' => 55 ) ), // zone found on the first candidate
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
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			array( 'response' => array( 'code' => 200 ), 'body' => 'not json at all {{{' ),
			array( 'response' => array( 'code' => 200 ), 'body' => 'not json at all {{{' ),
			array( 'response' => array( 'code' => 200 ), 'body' => 'not json at all {{{' ),
		);
	}

	protected function queue_http_failure(): void {
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->wp_response( 200, array( 'id' => 55 ) ),
			$this->wp_response( 500 ),
		);
	}

	protected function assert_authenticated_correctly( array $request ): void {
		$headers = $request['args']['headers'] ?? array();
		$this->assertSame( 'fixture-dnsme-key', $headers['x-dnsme-apiKey'] ?? null );
		$this->assertArrayHasKey( 'x-dnsme-requestDate', $headers );
		$expected_hmac = hash_hmac( 'sha1', (string) $headers['x-dnsme-requestDate'], 'fixture-dnsme-secret' );
		$this->assertSame( $expected_hmac, $headers['x-dnsme-hmac'] ?? null );
	}

	protected function assert_record_naming_correct( array $create_request ): void {
		$this->assertStringContainsString( '/dns/managed/55/records', $create_request['url'] );
		$body = $this->decoded_body( $create_request );
		$this->assertIsArray( $body );
		$this->assertSame( '_acme-challenge.www', $body['name'] ?? null );
		$this->assertSame( 'TXT', $body['type'] ?? null );
		$this->assertSame( '"' . $this->record_value() . '"', $body['value'] ?? null, 'DNS Made Easy quotes the TXT value' );
		$this->assertSame( 'DEFAULT', $body['gtdLocation'] ?? null, 'gtdLocation is required by DNS Made Easy\'s API even for simple records' );
	}

	// ── Provider-specific: record identifier extracted from the list ─────────

	public function test_delete_uses_the_server_assigned_record_id_from_the_list_response(): void {
		$provider = $this->make_provider();
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->wp_response( 404 ),
			$this->wp_response( 200, array() ),
			$this->wp_response( 200, array( 'id' => 55 ) ),
			$this->wp_response(
				200,
				array(
					'data' => array(
						array( 'id' => 1, 'value' => '"not-the-value"' ),
						array( 'id' => 2, 'value' => '"' . $this->record_value() . '"' ),
					),
				)
			),
			$this->wp_response( 200 ),
		);

		$provider->delete_txt_record( $this->fqdn(), $this->record_value() );

		$requests = $this->captured_requests();
		$last     = end( $requests );
		$this->assertSame( 'DELETE', $last['args']['method'] ?? null );
		$this->assertStringContainsString( '/dns/managed/55/records/2', $last['url'] );
	}

	// ── Provider-specific: a 2xx "no id" response is a silent continue ───────

	public function test_a_2xx_response_with_no_matching_domain_id_is_treated_as_not_found_without_throwing(): void {
		$provider = $this->make_provider();
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->wp_response( 200, array() ), // candidate 1 -- 2xx, no "id"
			$this->wp_response( 200, array() ), // candidate 2 -- same
			$this->wp_response( 200, array() ), // candidate 3 -- same
		);

		try {
			$provider->create_txt_record( $this->fqdn(), $this->record_value() );
			$this->fail( 'expected an exception when every candidate returns 2xx with no matching id' );
		} catch ( \RuntimeException $e ) {
			$this->assertStringContainsString( 'no managed domain found', $e->getMessage() );
		}

		$this->assertCount( 3, $this->captured_requests(), 'all three candidates are tried via the empty-check path, none via an exception' );
	}

	// ── Provider-specific: absent-record handling, pagination [Unverified] ───

	public function test_a_record_absent_from_the_fetched_list_is_not_deleted_and_does_not_throw(): void {
		$provider = $this->make_provider();
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->wp_response( 404 ),
			$this->wp_response( 200, array() ),
			$this->wp_response( 200, array( 'id' => 55 ) ),
			$this->wp_response(
				200,
				array(
					'data'         => array( array( 'id' => 1, 'value' => '"unrelated"' ) ),
					// totalRecords/totalPages/page are retained here as
					// provisional contract evidence (a third-party client
					// library's interpretation of DNS Made Easy's response
					// shape) should an accessible primary source confirm
					// pagination later -- see class docblock. Not proof
					// pagination is confirmed now.
					'totalRecords' => 31,
					'totalPages'   => 2,
					'page'         => 1,
				)
			),
		);

		$provider->delete_txt_record( $this->fqdn(), $this->record_value() );

		$requests = $this->captured_requests();
		$this->assertCount( 4, $requests, 'a record absent from the fetched list must not cause a DELETE request, and must not throw' );
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
			$this->assertStringContainsString( 'no managed domain found', $e->getMessage() );
		}

		$this->assertCount( 3, $this->captured_requests(), 'an authentication failure during zone discovery must not proceed to a write request' );
	}
}
