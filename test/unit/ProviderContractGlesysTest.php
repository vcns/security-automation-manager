<?php
/**
 * Phase 6C, Batch 6 ("Raw transport, JSON/RPC envelopes"): request-level
 * contract coverage for WP_SAM\Certificates\Providers\Provider_Glesys.
 *
 * Shape: Dns_Provider::request_raw() (JSON body, HTTP Basic auth --
 * account:api_key), try/catch zone discovery identical in shape to
 * deSEC's. Confirmed via GleSYS's own official Go client
 * (github.com/glesys/glesys-go, client.go: `if response.StatusCode !=
 * http.StatusOK { return handleResponseError(response) }`) that GleSYS's
 * API signals failure via real HTTP status codes, not a 200-status
 * body-encoded field -- so this driver's reliance on request_raw()'s own
 * HTTP-status throw is sufficient to detect failures, and the established
 * auth-misdiagnosis defect applies via the standard try/catch mechanism
 * (not the ClouDNS/NameSilo/DNSPod in-band-failure variant).
 * response_body_is_validated_on_success() is false: create/delete/zone
 * all rely purely on request_raw()'s HTTP-status check, never reading
 * response body content to determine success.
 *
 * Confirmed production defect (extends the established Batch 1/2/4/5
 * auth-during-discovery family, with direct code evidence -- the
 * try/catch shape is identical, wrapping the same per-candidate call),
 * not fixed here: a genuine authentication failure (401/403) during zone
 * discovery is misreported as "no domain found for {fqdn}", identically
 * to deSEC et al. Proven by
 * test_authentication_failure_during_zone_discovery_is_misreported_as_zone_not_found()
 * below.
 *
 * No pagination mechanism applicable, confirmed directly against
 * GleSYS's own API documentation (github.com/GleSYS/API-docs wiki):
 * domain/listrecords documents no page parameter or pagination metadata
 * at all, unlike other GleSYS endpoints (e.g. email/overview) which
 * explicitly document a "page" parameter and "meta" pagination info.
 */

declare( strict_types=1 );

use WP_SAM\Certificates\Providers\Provider_Glesys;

class ProviderContractGlesysTest extends Dns_Provider_Contract_TestCase {

	private function raw_response( int $code, array $body = array() ): array {
		return array(
			'response' => array( 'code' => $code ),
			'body'     => (string) wp_json_encode( $body ),
		);
	}

	protected function make_provider(): Provider_Glesys {
		return new Provider_Glesys(
			array(
				'account' => 'CL12345',
				'api_key' => 'fixture-glesys-key',
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
			$this->raw_response( 404 ),
			$this->raw_response( 404 ),
			$this->raw_response( 200 ),
			$this->raw_response( 200 ), // addrecord
		);
	}

	protected function queue_successful_delete(): void {
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->raw_response( 404 ),
			$this->raw_response( 404 ),
			$this->raw_response( 200 ),
			$this->raw_response( 200, array( 'response' => array( 'records' => array( array( 'recordid' => 9001, 'type' => 'TXT', 'host' => '_acme-challenge.www', 'data' => $this->record_value() ) ) ) ) ), // listrecords
			$this->raw_response( 200 ), // deleterecord
		);
	}

	protected function queue_authentication_failure(): void {
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->raw_response( 200 ), // zone found on the first candidate
			$this->raw_response( 401 ), // addrecord rejected
		);
	}

	protected function queue_zone_not_found(): void {
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->raw_response( 404 ),
			$this->raw_response( 404 ),
			$this->raw_response( 404 ),
		);
	}

	protected function queue_malformed_response(): void {
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
			$this->raw_response( 200 ),
			$this->raw_response( 500 ),
		);
	}

	protected function assert_authenticated_correctly( array $request ): void {
		$this->assertSame( 'Basic ' . base64_encode( 'CL12345:fixture-glesys-key' ), $request['args']['headers']['Authorization'] ?? null );
	}

	protected function assert_record_naming_correct( array $create_request ): void {
		$this->assertStringContainsString( '/domain/addrecord', $create_request['url'] );
		$body = $this->decoded_body( $create_request );
		$this->assertIsArray( $body );
		$this->assertSame( 'example.com', $body['domainname'] ?? null );
		$this->assertSame( '_acme-challenge.www', $body['host'] ?? null );
		$this->assertSame( 'TXT', $body['type'] ?? null );
		$this->assertSame( $this->record_value(), $body['data'] ?? null );
	}

	// ── Provider-specific: record identifier extracted from the list ─────────

	public function test_delete_uses_the_server_assigned_record_id_from_the_list_response(): void {
		$provider = $this->make_provider();
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->raw_response( 404 ),
			$this->raw_response( 404 ),
			$this->raw_response( 200 ),
			$this->raw_response(
				200,
				array(
					'response' => array(
						'records' => array(
							array( 'recordid' => 1, 'type' => 'TXT', 'host' => '_acme-challenge.www', 'data' => 'not-the-value' ),
							array( 'recordid' => 2, 'type' => 'TXT', 'host' => '_acme-challenge.www', 'data' => $this->record_value() ),
						),
					),
				)
			),
			$this->raw_response( 200 ),
		);

		$provider->delete_txt_record( $this->fqdn(), $this->record_value() );

		$requests = $this->captured_requests();
		$last     = end( $requests );
		$this->assertStringContainsString( '/domain/deleterecord', $last['url'] );
		$body = $this->decoded_body( $last );
		$this->assertSame( 2, $body['recordid'] ?? null );
	}

	// ── Provider-specific: discovery-stage auth failure is misreported ───────

	public function test_authentication_failure_during_zone_discovery_is_misreported_as_zone_not_found(): void {
		$provider = $this->make_provider();
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->raw_response( 401 ),
			$this->raw_response( 401 ),
			$this->raw_response( 401 ),
		);

		try {
			$provider->create_txt_record( $this->fqdn(), $this->record_value() );
			$this->fail( 'expected an exception when every zone-discovery candidate is rejected with 401' );
		} catch ( \RuntimeException $e ) {
			$this->assertStringContainsString( 'no domain found', $e->getMessage() );
		}

		$this->assertCount( 3, $this->captured_requests(), 'an authentication failure during zone discovery must not proceed to a write request' );
	}
}
