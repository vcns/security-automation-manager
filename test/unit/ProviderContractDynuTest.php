<?php
/**
 * Phase 6C, Batch 3 ("Enumerate-all-zones and unusual discovery"): request-
 * level contract coverage for WP_SAM\Certificates\Providers\Provider_Dynu.
 *
 * Shape: shared Dns_Provider::request() (JSON), "API-Key" header auth
 * (not Authorization). The most architecturally distinct discovery
 * mechanism in the whole registry: zone() never calls
 * Dns_Provider::zone_candidates() or relative_name() at all -- it makes a
 * single call to a specialised getroot endpoint
 * (GET /dns/getroot/{fqdn}) that resolves BOTH the domain ID and the
 * "node" (Dynu's own relative-label resolution) server-side in one
 * response, replacing the candidate-walk pattern every other provider in
 * this registry uses. Tested explicitly below as the batch's
 * "asynchronous or multi-step operations" dimension: this is a genuinely
 * different single delegated resolution step, not a multi-request walk.
 * No try/catch around that one call, so a non-2xx propagates immediately
 * and distinctly (no auth-during-discovery misdiagnosis). zone() reads
 * the response body directly (id/node fields), so
 * response_body_is_validated_on_success() stays at its default true --
 * and a malformed body collapses to the *same* "no root domain found"
 * diagnosis as a genuine empty result, since both hit the identical
 * `0 === $id` check.
 *
 * [Unverified] -- not classified as a confirmed pagination defect:
 * delete_txt_record()'s GET /dns/{id}/record call has no page/limit
 * parameter. No authoritative Dynu v2 API documentation for this specific
 * endpoint's pagination behaviour could be located; the only reachable
 * Dynu API documentation page described a different (v1) endpoint path,
 * giving no confidence it was even the correct reference for the v2
 * endpoint this driver calls.
 * test_a_record_absent_from_the_fetched_list_is_not_deleted_and_does_not_throw()
 * below proves the observable behaviour without asserting a pagination
 * mechanism that couldn't be confirmed.
 */

declare( strict_types=1 );

use WP_SAM\Certificates\Providers\Provider_Dynu;

class ProviderContractDynuTest extends Dns_Provider_Contract_TestCase {

	private function wp_response( int $code, array $body = array() ): array {
		return array(
			'response' => array( 'code' => $code ),
			'body'     => (string) wp_json_encode( $body ),
		);
	}

	private function getroot_matching(): array {
		return $this->wp_response( 200, array( 'id' => 99, 'node' => '_acme-challenge.www' ) );
	}

	protected function make_provider(): Provider_Dynu {
		return new Provider_Dynu( array( 'api_key' => 'fixture-dynu-key' ) );
	}

	protected function fqdn(): string {
		return '_acme-challenge.www.example.com';
	}

	protected function record_value(): string {
		return 'fixture-challenge-digest-value';
	}

	protected function queue_successful_create(): void {
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->getroot_matching(),
			$this->wp_response( 201 ), // POST create
		);
	}

	protected function queue_successful_delete(): void {
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->getroot_matching(),
			$this->wp_response(
				200,
				array(
					'dnsRecords' => array(
						array( 'id' => 555, 'recordType' => 'TXT', 'nodeName' => '_acme-challenge.www', 'textData' => $this->record_value() ),
					),
				)
			),
			$this->wp_response( 200 ), // DELETE
		);
	}

	protected function queue_authentication_failure(): void {
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->getroot_matching(),
			$this->wp_response( 401 ),
		);
	}

	protected function queue_zone_not_found(): void {
		// A successful (200) but empty getroot response -- id defaults to 0.
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->wp_response( 200, array() ),
		);
	}

	protected function queue_malformed_response(): void {
		// Collapses to the identical id===0 branch as queue_zone_not_found() --
		// see class docblock.
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			array( 'response' => array( 'code' => 200 ), 'body' => 'not json at all {{{' ),
		);
	}

	protected function queue_http_failure(): void {
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->getroot_matching(),
			$this->wp_response( 500 ),
		);
	}

	protected function assert_authenticated_correctly( array $request ): void {
		$this->assertSame( 'fixture-dynu-key', $request['args']['headers']['API-Key'] ?? null );
		$this->assertArrayNotHasKey( 'Authorization', $request['args']['headers'] ?? array() );
	}

	protected function assert_record_naming_correct( array $create_request ): void {
		$this->assertStringContainsString( '/dns/99/record', $create_request['url'] );
		$body = $this->decoded_body( $create_request );
		$this->assertIsArray( $body );
		$this->assertSame( '_acme-challenge.www', $body['nodeName'] ?? null, 'the "node" comes from getroot()\'s own server-side resolution, not relative_name()' );
		$this->assertSame( 'TXT', $body['recordType'] ?? null );
		$this->assertSame( $this->record_value(), $body['textData'] ?? null );
	}

	// ── Provider-specific: record identifier extracted from the list ─────────

	public function test_delete_uses_the_server_assigned_record_id_from_the_list_response(): void {
		$provider = $this->make_provider();
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->getroot_matching(),
			$this->wp_response(
				200,
				array(
					'dnsRecords' => array(
						array( 'id' => 1, 'recordType' => 'TXT', 'nodeName' => '_acme-challenge.www', 'textData' => 'not-the-value' ),
						array( 'id' => 2, 'recordType' => 'TXT', 'nodeName' => '_acme-challenge.www', 'textData' => $this->record_value() ),
					),
				)
			),
			$this->wp_response( 200 ),
		);

		$provider->delete_txt_record( $this->fqdn(), $this->record_value() );

		$requests = $this->captured_requests();
		$last     = end( $requests );
		$this->assertSame( 'DELETE', $last['args']['method'] ?? null );
		$this->assertStringContainsString( '/dns/99/record/2', $last['url'] );
	}

	// ── Provider-specific: absent-record handling, pagination [Unverified] ───

	public function test_a_record_absent_from_the_fetched_list_is_not_deleted_and_does_not_throw(): void {
		$provider = $this->make_provider();
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->getroot_matching(),
			$this->wp_response(
				200,
				array(
					'dnsRecords' => array(
						array( 'id' => 1, 'recordType' => 'TXT', 'nodeName' => 'unrelated-node', 'textData' => 'x' ),
					),
				)
			),
		);

		$provider->delete_txt_record( $this->fqdn(), $this->record_value() );

		$requests = $this->captured_requests();
		$this->assertCount( 2, $requests, 'a record absent from the fetched list must not cause a DELETE request, and must not throw' );
	}

	// ── Provider-specific: getroot replaces the multi-candidate walk ─────────

	public function test_getroot_resolves_zone_and_node_in_a_single_call_regardless_of_label_depth(): void {
		$provider           = $this->make_provider();
		$deeply_nested_fqdn = '_acme-challenge.a.b.c.d.example.com';
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->wp_response( 200, array( 'id' => 99, 'node' => '_acme-challenge.a.b.c.d' ) ),
			$this->wp_response( 201 ),
		);

		$provider->create_txt_record( $deeply_nested_fqdn, $this->record_value() );

		$requests = $this->captured_requests();
		$this->assertCount( 2, $requests, 'exactly one getroot call plus the write -- no candidate-walk request count grows with label depth, unlike every other provider in the registry' );
		$this->assertStringContainsString( '/dns/getroot/' . rawurlencode( $deeply_nested_fqdn ), $requests[0]['url'] );
	}

	// ── Provider-specific: discovery-stage auth failure is NOT misreported ───

	public function test_authentication_failure_during_zone_discovery_surfaces_distinctly_not_as_zone_not_found(): void {
		$provider = $this->make_provider();
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->wp_response( 401 ),
		);

		try {
			$provider->create_txt_record( $this->fqdn(), $this->record_value() );
			$this->fail( 'expected an exception when the single getroot request is rejected with 401' );
		} catch ( \RuntimeException $e ) {
			$this->assertStringNotContainsString( 'no root domain found', $e->getMessage() );
			$this->assertStringContainsString( 'HTTP 401', $e->getMessage() );
		}

		$this->assertCount( 1, $this->captured_requests() );
	}
}
