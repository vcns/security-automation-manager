<?php
/**
 * Phase 6C, Batch 3 ("Enumerate-all-zones and unusual discovery"): request-
 * level contract coverage for WP_SAM\Certificates\Providers\Provider_Ionos.
 *
 * Shape: shared Dns_Provider::request() (JSON), "X-API-Key" header auth.
 * Zone discovery is architecturally different from every prior batch:
 * zone() makes exactly ONE request (GET /zones, no candidate-specific
 * query) and then loops zone_candidates() against that single cached list
 * client-side -- not one request per candidate. There is no try/catch at
 * all, so a non-2xx on that one call propagates immediately and directly
 * (no auth-during-discovery misdiagnosis possible here, unlike Batches
 * 1/2's try/catch-shaped providers -- there's only ever one call to fail).
 * zone() reads the response body (client-side filter), so this driver
 * validates bodies on the create path (response_body_is_validated_on_success()
 * stays at its default true). create_txt_record() sends the FULL fqdn (not
 * relative) wrapped in a single-element top-level array (not a bare
 * object). delete_txt_record() re-fetches the zone but via a
 * recordName/recordType-filtered zone-detail call, not a separate records
 * endpoint.
 *
 * Confirmed production defect, not fixed here: IONOS's GET /zones
 * endpoint paginates via offset/limit (default limit=100, per IONOS's own
 * published Go SDK reference derived from their OpenAPI spec --
 * https://github.com/ionos-cloud/sdk-go-dns/blob/master/docs/api/ZonesApi.md).
 * zone() sends no offset/limit at all, so it silently uses the default
 * limit=100. An account with more than 100 DNS zones could have its
 * correct zone fall outside that first page, causing create_txt_record()
 * to throw "no zone found" even though the zone genuinely exists -- a
 * more severe failure mode than Batch 2's pagination findings (which only
 * left a cleanup record undeleted; this can break issuance entirely).
 * Proven by test_zone_discovery_pagination_can_silently_miss_the_correct_zone()
 * below.
 */

declare( strict_types=1 );

use WP_SAM\Certificates\Providers\Provider_Ionos;

class ProviderContractIonosTest extends Dns_Provider_Contract_TestCase {

	private function wp_response( int $code, array $body = array() ): array {
		return array(
			'response' => array( 'code' => $code ),
			'body'     => (string) wp_json_encode( $body ),
		);
	}

	protected function make_provider(): Provider_Ionos {
		return new Provider_Ionos( array( 'api_key' => 'fixture-ionos-key' ) );
	}

	protected function fqdn(): string {
		return '_acme-challenge.www.example.com';
	}

	protected function record_value(): string {
		return 'fixture-challenge-digest-value';
	}

	private function zone_list_matching(): array {
		return $this->wp_response( 200, array( array( 'id' => 'zone-1', 'name' => 'example.com' ) ) );
	}

	protected function queue_successful_create(): void {
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->zone_list_matching(),
			$this->wp_response( 201 ), // POST create
		);
	}

	protected function queue_successful_delete(): void {
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->zone_list_matching(),
			$this->wp_response(
				200,
				array(
					'records' => array(
						array( 'id' => 'rec-1', 'content' => '"' . $this->record_value() . '"' ),
					),
				)
			),
			$this->wp_response( 200 ), // DELETE
		);
	}

	protected function queue_authentication_failure(): void {
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->zone_list_matching(),
			$this->wp_response( 401 ), // the POST create itself is rejected
		);
	}

	protected function queue_zone_not_found(): void {
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->wp_response( 200, array() ), // single call, no zone matches any candidate
		);
	}

	protected function queue_malformed_response(): void {
		// zone() reads the body (client-side filter); a malformed body
		// coerces to an empty array, matching no candidate.
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			array( 'response' => array( 'code' => 200 ), 'body' => 'not json at all {{{' ),
		);
	}

	protected function queue_http_failure(): void {
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->zone_list_matching(),
			$this->wp_response( 500 ),
		);
	}

	protected function assert_authenticated_correctly( array $request ): void {
		$this->assertSame( 'fixture-ionos-key', $request['args']['headers']['X-API-Key'] ?? null );
	}

	protected function assert_record_naming_correct( array $create_request ): void {
		$this->assertStringContainsString( '/zones/zone-1/records', $create_request['url'] );
		$body = $this->decoded_body( $create_request );
		$this->assertIsArray( $body );
		$this->assertArrayHasKey( 0, $body, 'IONOS wraps the single new record in a top-level array' );
		$this->assertSame( $this->fqdn(), $body[0]['name'] ?? null, 'IONOS sends the full fqdn, not a zone-relative name' );
		$this->assertSame( 'TXT', $body[0]['type'] ?? null );
		$this->assertSame( $this->record_value(), $body[0]['content'] ?? null );
	}

	// ── Provider-specific: only one request is ever made for zone lookup ─────

	public function test_zone_discovery_makes_exactly_one_request_regardless_of_candidate_count(): void {
		$provider = $this->make_provider();
		$this->queue_successful_create();

		$provider->create_txt_record( $this->fqdn(), $this->record_value() );

		// 2 requests total: the single zone list + the create -- not one
		// zone request per zone_candidates() entry, unlike every prior
		// batch's try/catch or per-candidate client-filter shape.
		$this->assertCount( 2, $this->captured_requests() );
	}

	// ── Provider-specific: record identifier extracted from the filtered detail ──

	public function test_delete_uses_the_server_assigned_record_id_from_the_filtered_zone_detail(): void {
		$provider = $this->make_provider();
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->zone_list_matching(),
			$this->wp_response(
				200,
				array(
					'records' => array(
						array( 'id' => 'rec-a', 'content' => '"not-the-value"' ),
						array( 'id' => 'rec-b', 'content' => '"' . $this->record_value() . '"' ),
					),
				)
			),
			$this->wp_response( 200 ),
		);

		$provider->delete_txt_record( $this->fqdn(), $this->record_value() );

		$requests = $this->captured_requests();
		$last     = end( $requests );
		$this->assertSame( 'DELETE', $last['args']['method'] ?? null );
		$this->assertStringContainsString( '/zones/zone-1/records/rec-b', $last['url'] );
	}

	// ── Provider-specific: a record absent from the filtered detail is a no-op ──

	public function test_a_record_absent_from_the_filtered_zone_detail_is_not_deleted_and_does_not_throw(): void {
		$provider = $this->make_provider();
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->zone_list_matching(),
			$this->wp_response(
				200,
				array(
					'records' => array(
						array( 'id' => 'rec-a', 'content' => '"some-other-value"' ),
					),
				)
			),
		);

		$provider->delete_txt_record( $this->fqdn(), $this->record_value() );

		$requests = $this->captured_requests();
		$this->assertCount( 2, $requests, 'a record absent from the filtered zone detail must not cause a DELETE request, and must not throw' );
	}

	// ── Provider-specific: confirmed zone-discovery pagination defect ────────

	public function test_zone_discovery_pagination_can_silently_miss_the_correct_zone(): void {
		$provider = $this->make_provider();
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			// A single page of zones that does not include example.com --
			// simulating an account with more zones than the default
			// limit=100, where the correct zone lives beyond this response.
			$this->wp_response(
				200,
				array(
					array( 'id' => 'zone-other-1', 'name' => 'unrelated-1.com' ),
					array( 'id' => 'zone-other-2', 'name' => 'unrelated-2.com' ),
				)
			),
		);

		try {
			$provider->create_txt_record( $this->fqdn(), $this->record_value() );
			$this->fail( 'expected an exception when the correct zone is absent from the single unpaginated response' );
		} catch ( \RuntimeException $e ) {
			$this->assertStringContainsString( 'no zone found', $e->getMessage(), 'a zone that genuinely exists, but beyond the default page, is misreported identically to a zone that does not exist at all' );
		}

		$this->assertCount( 1, $this->captured_requests(), 'no offset/limit is ever sent to request further pages' );
	}

	// ── Provider-specific: discovery-stage auth failure is NOT misreported ───

	public function test_authentication_failure_during_zone_discovery_surfaces_distinctly_not_as_zone_not_found(): void {
		$provider = $this->make_provider();
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->wp_response( 401 ),
		);

		try {
			$provider->create_txt_record( $this->fqdn(), $this->record_value() );
			$this->fail( 'expected an exception when the single zone-list request is rejected with 401' );
		} catch ( \RuntimeException $e ) {
			$this->assertStringNotContainsString( 'no zone found', $e->getMessage() );
			$this->assertStringContainsString( 'HTTP 401', $e->getMessage() );
		}

		$this->assertCount( 1, $this->captured_requests() );
	}
}
