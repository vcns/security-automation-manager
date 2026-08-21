<?php
/**
 * Phase 6C, Batch 6 ("Raw transport, JSON/RPC envelopes"): request-level
 * contract coverage for WP_SAM\Certificates\Providers\Provider_Njalla.
 *
 * Shape: Dns_Provider::request_raw() (JSON-RPC-style envelope --
 * {"method":..., "params":...}), "Njalla {token}" Authorization header.
 * Zone discovery makes exactly ONE request (list-domains) and matches
 * candidates against the cached name list client-side -- the
 * "enumerate-once" shape from Batch 3, with no try/catch around it.
 *
 * Well-designed, immune to the auth-misdiagnosis defect regardless of
 * failure representation: call()'s own code explicitly checks for a
 * JSON-RPC "error" key in the decoded body and throws a distinct
 * RuntimeException if present -- `if ( isset( $decoded['error'] ) ) {
 * throw ...; }` -- BEFORE zone() or any caller ever sees the result. This
 * means a body-encoded authentication failure (matching Njalla's own
 * JSON-RPC-style error convention) is converted into a genuine thrown
 * exception at the call() layer itself, and since zone()'s single
 * list-domains call has no try/catch around it, that exception
 * propagates immediately and distinctly -- confirmed by direct code
 * inspection to be immune regardless of whether the real API represents
 * failures via HTTP status or an in-band "error" field, unlike
 * ClouDNS/NameSilo/DNSPod which required checking the *specific* failure
 * representation before concluding immunity (see that correction in the
 * evidence matrix). response_body_is_validated_on_success() therefore
 * stays at its default true.
 *
 * [Unverified] -- pagination: Njalla's list-records documentation
 * requires an authenticated account to access in full and no accessible
 * public source could confirm or rule out a pagination mechanism for
 * this endpoint.
 */

declare( strict_types=1 );

use WP_SAM\Certificates\Providers\Provider_Njalla;

class ProviderContractNjallaTest extends Dns_Provider_Contract_TestCase {

	private function rpc_response( int $code, ?array $result = null, ?array $error = null ): array {
		$body = array();
		if ( null !== $result ) {
			$body['result'] = $result;
		}
		if ( null !== $error ) {
			$body['error'] = $error;
		}

		return array(
			'response' => array( 'code' => $code ),
			'body'     => (string) wp_json_encode( $body ),
		);
	}

	protected function make_provider(): Provider_Njalla {
		return new Provider_Njalla( array( 'api_token' => 'fixture-njalla-token' ) );
	}

	protected function fqdn(): string {
		return '_acme-challenge.www.example.com';
	}

	protected function record_value(): string {
		return 'fixture-challenge-digest-value';
	}

	protected function queue_successful_create(): void {
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->rpc_response( 200, array( 'domains' => array( array( 'name' => 'example.com' ) ) ) ),
			$this->rpc_response( 200, array() ), // add-record
		);
	}

	protected function queue_successful_delete(): void {
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->rpc_response( 200, array( 'domains' => array( array( 'name' => 'example.com' ) ) ) ),
			$this->rpc_response( 200, array( 'records' => array( array( 'id' => 555, 'type' => 'TXT', 'name' => '_acme-challenge.www', 'content' => $this->record_value() ) ) ) ), // list-records
			$this->rpc_response( 200, array() ), // remove-record
		);
	}

	protected function queue_authentication_failure(): void {
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->rpc_response( 200, array( 'domains' => array( array( 'name' => 'example.com' ) ) ) ),
			$this->rpc_response( 200, null, array( 'code' => -32000, 'message' => 'invalid token' ) ), // add-record rejected
		);
	}

	protected function queue_zone_not_found(): void {
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->rpc_response( 200, array( 'domains' => array( array( 'name' => 'unrelated.org' ) ) ) ),
		);
	}

	protected function queue_malformed_response(): void {
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			array( 'response' => array( 'code' => 200 ), 'body' => 'not json at all {{{' ),
		);
	}

	protected function queue_http_failure(): void {
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->rpc_response( 200, array( 'domains' => array( array( 'name' => 'example.com' ) ) ) ),
			array( 'response' => array( 'code' => 500 ), 'body' => 'Internal Server Error' ),
		);
	}

	protected function assert_authenticated_correctly( array $request ): void {
		$this->assertSame( 'Njalla fixture-njalla-token', $request['args']['headers']['Authorization'] ?? null );
	}

	protected function assert_record_naming_correct( array $create_request ): void {
		$body = $this->decoded_body( $create_request );
		$this->assertIsArray( $body );
		$this->assertSame( 'add-record', $body['method'] ?? null );
		$this->assertSame( 'example.com', $body['params']['domain'] ?? null );
		$this->assertSame( '_acme-challenge.www', $body['params']['name'] ?? null );
		$this->assertSame( 'TXT', $body['params']['type'] ?? null );
		$this->assertSame( $this->record_value(), $body['params']['content'] ?? null );
	}

	// ── Provider-specific: record identifier extracted from the list ─────────

	public function test_delete_uses_the_server_assigned_record_id_from_the_list_response(): void {
		$provider = $this->make_provider();
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->rpc_response( 200, array( 'domains' => array( array( 'name' => 'example.com' ) ) ) ),
			$this->rpc_response(
				200,
				array(
					'records' => array(
						array( 'id' => 1, 'type' => 'TXT', 'name' => '_acme-challenge.www', 'content' => 'not-the-value' ),
						array( 'id' => 2, 'type' => 'TXT', 'name' => '_acme-challenge.www', 'content' => $this->record_value() ),
					),
				)
			),
			$this->rpc_response( 200, array() ),
		);

		$provider->delete_txt_record( $this->fqdn(), $this->record_value() );

		$requests = $this->captured_requests();
		$last     = end( $requests );
		$body     = $this->decoded_body( $last );
		$this->assertSame( 'remove-record', $body['method'] ?? null );
		$this->assertSame( 2, $body['params']['id'] ?? null );
	}

	// ── Provider-specific: zone discovery is a single upfront enumeration ────

	public function test_zone_discovery_makes_exactly_one_request_regardless_of_candidate_count(): void {
		$provider = $this->make_provider();
		$this->queue_successful_create();

		$provider->create_txt_record( $this->fqdn(), $this->record_value() );

		$this->assertCount( 2, $this->captured_requests(), 'a single list-domains call plus the write -- not one request per zone_candidates() entry' );
	}

	// ── Provider-specific: an in-band JSON-RPC error is caught and rethrown,
	// so discovery-stage auth failure is NOT misreported, regardless of shape ─

	public function test_an_in_band_json_rpc_error_during_zone_discovery_is_not_misreported(): void {
		$provider = $this->make_provider();
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->rpc_response( 200, null, array( 'code' => -32001, 'message' => 'invalid token' ) ),
		);

		try {
			$provider->create_txt_record( $this->fqdn(), $this->record_value() );
			$this->fail( 'expected an exception when the single list-domains request reports a JSON-RPC error' );
		} catch ( \RuntimeException $e ) {
			$this->assertStringNotContainsString( 'no domain found', $e->getMessage() );
			$this->assertStringContainsString( 'invalid token', $e->getMessage() );
		}

		$this->assertCount( 1, $this->captured_requests() );
	}
}
