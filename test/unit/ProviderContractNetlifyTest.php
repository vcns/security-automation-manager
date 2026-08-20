<?php
/**
 * Phase 6C, Batch 3 ("Enumerate-all-zones and unusual discovery"): request-
 * level contract coverage for WP_SAM\Certificates\Providers\Provider_Netlify.
 *
 * Shape: shared Dns_Provider::request() (JSON), Bearer auth. Zone discovery
 * makes exactly ONE request (GET /dns_zones) and loops zone_candidates()
 * against that single cached list client-side -- same "enumerate once,
 * filter locally" shape as IONOS/Linode (see ProviderContractIonosTest's
 * docblock). No try/catch, so a non-2xx on that one call propagates
 * immediately and distinctly (no auth-during-discovery misdiagnosis).
 * zone() reads the response body, so this driver validates bodies on the
 * create path (response_body_is_validated_on_success() stays at its
 * default true). Both create and delete address records by the FULL fqdn
 * (the "hostname" field), not a zone-relative name -- unlike most of this
 * batch's siblings.
 *
 * [Unverified] -- not classified as a confirmed pagination defect:
 * delete_txt_record()'s GET /dns_zones/{id}/dns_records call has no
 * page/per_page parameter. Netlify's general API documentation states
 * "automatic pagination is applied to all API requests that return over
 * 100 items" (page/per_page, Link headers), but the operation-specific
 * OpenAPI spec for this exact endpoint (open-api.netlify.com,
 * getGetDnsRecords) documents no pagination parameters for it at all --
 * a genuine inconsistency between the general platform documentation and
 * this endpoint's own specification that could not be resolved with
 * confidence either way.
 * test_a_record_absent_from_the_fetched_list_is_not_deleted_and_does_not_throw()
 * below proves the observable behaviour without asserting a pagination
 * mechanism that couldn't be confirmed.
 */

declare( strict_types=1 );

use WP_SAM\Certificates\Providers\Provider_Netlify;

class ProviderContractNetlifyTest extends Dns_Provider_Contract_TestCase {

	private function wp_response( int $code, array $body = array() ): array {
		return array(
			'response' => array( 'code' => $code ),
			'body'     => (string) wp_json_encode( $body ),
		);
	}

	private function zones_list_matching(): array {
		return $this->wp_response( 200, array( array( 'id' => 'zone-xyz', 'name' => 'example.com' ) ) );
	}

	protected function make_provider(): Provider_Netlify {
		return new Provider_Netlify( array( 'api_token' => 'fixture-netlify-token' ) );
	}

	protected function fqdn(): string {
		return '_acme-challenge.www.example.com';
	}

	protected function record_value(): string {
		return 'fixture-challenge-digest-value';
	}

	protected function queue_successful_create(): void {
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->zones_list_matching(),
			$this->wp_response( 201 ), // POST create
		);
	}

	protected function queue_successful_delete(): void {
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->zones_list_matching(),
			$this->wp_response(
				200,
				array(
					array( 'id' => 'rec-1', 'type' => 'TXT', 'hostname' => $this->fqdn(), 'value' => $this->record_value() ),
				)
			),
			$this->wp_response( 200 ), // DELETE
		);
	}

	protected function queue_authentication_failure(): void {
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->zones_list_matching(),
			$this->wp_response( 401 ),
		);
	}

	protected function queue_zone_not_found(): void {
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->wp_response( 200, array() ),
		);
	}

	protected function queue_malformed_response(): void {
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			array( 'response' => array( 'code' => 200 ), 'body' => 'not json at all {{{' ),
		);
	}

	protected function queue_http_failure(): void {
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->zones_list_matching(),
			$this->wp_response( 500 ),
		);
	}

	protected function assert_authenticated_correctly( array $request ): void {
		$this->assertSame( 'Bearer fixture-netlify-token', $request['args']['headers']['Authorization'] ?? null );
	}

	protected function assert_record_naming_correct( array $create_request ): void {
		$this->assertStringContainsString( '/dns_zones/zone-xyz/dns_records', $create_request['url'] );
		$body = $this->decoded_body( $create_request );
		$this->assertIsArray( $body );
		$this->assertSame( $this->fqdn(), $body['hostname'] ?? null, 'Netlify addresses records by the full fqdn, not a zone-relative name' );
		$this->assertSame( 'TXT', $body['type'] ?? null );
		$this->assertSame( $this->record_value(), $body['value'] ?? null );
	}

	// ── Provider-specific: record identifier extracted from the list ─────────

	public function test_delete_uses_the_server_assigned_record_id_from_the_list_response(): void {
		$provider = $this->make_provider();
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->zones_list_matching(),
			$this->wp_response(
				200,
				array(
					array( 'id' => 'rec-a', 'type' => 'TXT', 'hostname' => $this->fqdn(), 'value' => 'not-the-value' ),
					array( 'id' => 'rec-b', 'type' => 'TXT', 'hostname' => $this->fqdn(), 'value' => $this->record_value() ),
				)
			),
			$this->wp_response( 200 ),
		);

		$provider->delete_txt_record( $this->fqdn(), $this->record_value() );

		$requests = $this->captured_requests();
		$last     = end( $requests );
		$this->assertSame( 'DELETE', $last['args']['method'] ?? null );
		$this->assertStringContainsString( '/dns_zones/zone-xyz/dns_records/rec-b', $last['url'] );
	}

	// ── Provider-specific: absent-record handling, pagination [Unverified] ───

	public function test_a_record_absent_from_the_fetched_list_is_not_deleted_and_does_not_throw(): void {
		$provider = $this->make_provider();
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->zones_list_matching(),
			$this->wp_response(
				200,
				array(
					array( 'id' => 'rec-a', 'type' => 'TXT', 'hostname' => 'unrelated.example.com', 'value' => 'x' ),
				)
			),
		);

		$provider->delete_txt_record( $this->fqdn(), $this->record_value() );

		$requests = $this->captured_requests();
		$this->assertCount( 2, $requests, 'a record absent from the fetched list must not cause a DELETE request, and must not throw' );
	}

	// ── Provider-specific: discovery-stage auth failure is NOT misreported ───

	public function test_authentication_failure_during_zone_discovery_surfaces_distinctly_not_as_zone_not_found(): void {
		$provider = $this->make_provider();
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->wp_response( 401 ),
		);

		try {
			$provider->create_txt_record( $this->fqdn(), $this->record_value() );
			$this->fail( 'expected an exception when the single zones-list request is rejected with 401' );
		} catch ( \RuntimeException $e ) {
			$this->assertStringNotContainsString( 'no zone found', $e->getMessage() );
			$this->assertStringContainsString( 'HTTP 401', $e->getMessage() );
		}

		$this->assertCount( 1, $this->captured_requests() );
	}
}
