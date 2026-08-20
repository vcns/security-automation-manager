<?php
/**
 * Phase 6C, Batch 2 ("Cloudflare clones, list-then-delete-by-ID"): request-
 * level contract coverage for WP_SAM\Certificates\Providers\Provider_Hetzner.
 *
 * Shape: shared Dns_Provider::request() (JSON), custom "Auth-API-Token"
 * header (not Authorization). Zone discovery is a client-side filter over
 * a 200 response's "zones" array (like Scaleway/Cloudflare), NOT a
 * try/catch over per-candidate error status like the other four fixtures
 * in this batch -- zone() has no try/catch at all, so a non-2xx response
 * on ANY candidate propagates immediately and directly from the shared
 * request() helper. This means Hetzner does NOT share the Batch-1-style
 * auth-during-discovery misdiagnosis: an authentication failure surfaces
 * as Hetzner's own distinct "API error (HTTP 401)" message on the very
 * first candidate, not a generic "no zone found" after exhausting all
 * three -- proven below as a deliberate contrast with
 * ProviderContractDigitaloceanTest's confirmed defect. zone() DOES read
 * the response body (to find the matching zone), so this driver validates
 * bodies on the create path (response_body_is_validated_on_success() stays
 * at its default true) -- unlike DigitalOcean/Vultr/Name.com/easyDNS.
 */

declare( strict_types=1 );

use WP_SAM\Certificates\Providers\Provider_Hetzner;

class ProviderContractHetznerTest extends Dns_Provider_Contract_TestCase {

	private function wp_response( int $code, array $body = array() ): array {
		return array(
			'response' => array( 'code' => $code ),
			'body'     => (string) wp_json_encode( $body ),
		);
	}

	protected function make_provider(): Provider_Hetzner {
		return new Provider_Hetzner( array( 'api_token' => 'fixture-hetzner-token' ) );
	}

	protected function fqdn(): string {
		return '_acme-challenge.www.example.com';
	}

	protected function record_value(): string {
		return 'fixture-challenge-digest-value';
	}

	protected function queue_successful_create(): void {
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->wp_response( 200, array( 'zones' => array() ) ),
			$this->wp_response( 200, array( 'zones' => array() ) ),
			$this->wp_response( 200, array( 'zones' => array( array( 'id' => 'zone-1', 'name' => 'example.com' ) ) ) ),
			$this->wp_response( 201 ), // POST create
		);
	}

	protected function queue_successful_delete(): void {
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->wp_response( 200, array( 'zones' => array() ) ),
			$this->wp_response( 200, array( 'zones' => array() ) ),
			$this->wp_response( 200, array( 'zones' => array( array( 'id' => 'zone-1', 'name' => 'example.com' ) ) ) ),
			$this->wp_response(
				200,
				array(
					'records' => array(
						array(
							'id'    => 'rec-777',
							'type'  => 'TXT',
							'name'  => '_acme-challenge.www',
							'value' => $this->record_value(),
						),
					),
				)
			),
			$this->wp_response( 200 ), // DELETE
		);
	}

	protected function queue_authentication_failure(): void {
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->wp_response( 200, array( 'zones' => array( array( 'id' => 'zone-1', 'name' => 'example.com' ) ) ) ),
			$this->wp_response( 401 ), // the POST create itself is rejected
		);
	}

	protected function queue_zone_not_found(): void {
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->wp_response( 200, array( 'zones' => array() ) ),
			$this->wp_response( 200, array( 'zones' => array() ) ),
			$this->wp_response( 200, array( 'zones' => array() ) ),
		);
	}

	protected function queue_malformed_response(): void {
		// zone() reads the body (client-side filter over "zones"), so a
		// malformed body here behaves like an empty result -- exhausting all
		// three candidates and throwing, exactly like Cloudflare/Scaleway.
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			array( 'response' => array( 'code' => 200 ), 'body' => 'not json at all {{{' ),
			array( 'response' => array( 'code' => 200 ), 'body' => 'not json at all {{{' ),
			array( 'response' => array( 'code' => 200 ), 'body' => 'not json at all {{{' ),
		);
	}

	protected function queue_http_failure(): void {
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->wp_response( 200, array( 'zones' => array( array( 'id' => 'zone-1', 'name' => 'example.com' ) ) ) ),
			$this->wp_response( 500 ),
		);
	}

	protected function assert_authenticated_correctly( array $request ): void {
		$this->assertSame( 'fixture-hetzner-token', $request['args']['headers']['Auth-API-Token'] ?? null );
		$this->assertArrayNotHasKey( 'Authorization', $request['args']['headers'] ?? array() );
	}

	protected function assert_record_naming_correct( array $create_request ): void {
		$this->assertStringContainsString( '/records', $create_request['url'] );
		$body = $this->decoded_body( $create_request );
		$this->assertIsArray( $body );
		$this->assertSame( 'zone-1', $body['zone_id'] ?? null, 'the zone ID discovered during zone() must be sent in the create body' );
		$this->assertSame( '_acme-challenge.www', $body['name'] ?? null );
		$this->assertSame( 'TXT', $body['type'] ?? null );
		$this->assertSame( $this->record_value(), $body['value'] ?? null );
	}

	// ── Provider-specific: record identifier extracted from the list ─────────

	public function test_delete_uses_the_server_assigned_record_id_from_the_list_response(): void {
		$provider = $this->make_provider();
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->wp_response( 200, array( 'zones' => array() ) ),
			$this->wp_response( 200, array( 'zones' => array() ) ),
			$this->wp_response( 200, array( 'zones' => array( array( 'id' => 'zone-1', 'name' => 'example.com' ) ) ) ),
			$this->wp_response(
				200,
				array(
					'records' => array(
						array( 'id' => 'rec-a', 'type' => 'TXT', 'name' => '_acme-challenge.www', 'value' => 'not-the-value' ),
						array( 'id' => 'rec-b', 'type' => 'TXT', 'name' => '_acme-challenge.www', 'value' => $this->record_value() ),
					),
				)
			),
			$this->wp_response( 200 ),
		);

		$provider->delete_txt_record( $this->fqdn(), $this->record_value() );

		$requests = $this->captured_requests();
		$last     = end( $requests );
		$this->assertSame( 'DELETE', $last['args']['method'] ?? null );
		$this->assertStringContainsString( '/records/rec-b', $last['url'] );
	}

	// ── Provider-specific: single-page fetch, documented limitation ──────────

	public function test_pagination_only_fetches_a_single_page_of_records(): void {
		$provider = $this->make_provider();
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->wp_response( 200, array( 'zones' => array() ) ),
			$this->wp_response( 200, array( 'zones' => array() ) ),
			$this->wp_response( 200, array( 'zones' => array( array( 'id' => 'zone-1', 'name' => 'example.com' ) ) ) ),
			$this->wp_response(
				200,
				array(
					'records' => array(
						array( 'id' => 'rec-x', 'type' => 'TXT', 'name' => 'unrelated', 'value' => 'x' ),
					),
				)
			),
		);

		$provider->delete_txt_record( $this->fqdn(), $this->record_value() );

		$requests = $this->captured_requests();
		$this->assertCount( 4, $requests, 'a record absent from the single fetched page must not cause a DELETE request, and must not throw' );
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
			$this->assertStringNotContainsString( 'no zone found', $e->getMessage(), 'unlike the try/catch-shaped providers, Hetzner must not mask an auth failure as zone-not-found' );
			$this->assertStringContainsString( 'HTTP 401', $e->getMessage(), 'the real HTTP status must be visible in the diagnostic' );
		}

		$this->assertCount( 1, $this->captured_requests(), 'with no try/catch around zone(), a rejected first candidate must not be retried against further candidates' );
	}
}
