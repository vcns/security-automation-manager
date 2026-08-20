<?php
/**
 * Phase 6C, Batch 2 ("Cloudflare clones, list-then-delete-by-ID"): request-
 * level contract coverage for WP_SAM\Certificates\Providers\Provider_Vultr.
 *
 * Shape: shared Dns_Provider::request() (JSON), Bearer auth, try/catch zone
 * discovery (same as DigitalOcean -- see that fixture's docblock for the
 * shared status-only-on-create finding and the recurring, already-logged
 * auth-during-discovery misdiagnosis). Vultr quotes the TXT value in its
 * "data" field (`"value"`) on create, and delete_txt_record() strips the
 * quotes with trim() before comparing -- create/delete asymmetry, tested
 * below. delete lists with ?per_page=500, single page only (same
 * documented limitation as DigitalOcean).
 */

declare( strict_types=1 );

use WP_SAM\Certificates\Providers\Provider_Vultr;

class ProviderContractVultrTest extends Dns_Provider_Contract_TestCase {

	private function wp_response( int $code, array $body = array() ): array {
		return array(
			'response' => array( 'code' => $code ),
			'body'     => (string) wp_json_encode( $body ),
		);
	}

	protected function make_provider(): Provider_Vultr {
		return new Provider_Vultr( array( 'api_key' => 'fixture-vultr-key' ) );
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
					'records' => array(
						array(
							'id'   => 'rec-987',
							'type' => 'TXT',
							'name' => '_acme-challenge.www',
							'data' => '"' . $this->record_value() . '"',
						),
					),
				)
			),
			$this->wp_response( 204 ), // DELETE
		);
	}

	protected function queue_authentication_failure(): void {
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->wp_response( 200 ),
			$this->wp_response( 401 ),
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
		$this->assertSame( 'Bearer fixture-vultr-key', $request['args']['headers']['Authorization'] ?? null );
	}

	protected function assert_record_naming_correct( array $create_request ): void {
		$this->assertStringContainsString( '/domains/example.com/records', $create_request['url'] );
		$body = $this->decoded_body( $create_request );
		$this->assertIsArray( $body );
		$this->assertSame( '_acme-challenge.www', $body['name'] ?? null );
		$this->assertSame( 'TXT', $body['type'] ?? null );
		$this->assertSame( '"' . $this->record_value() . '"', $body['data'] ?? null, 'Vultr quotes the TXT value on create' );
	}

	// ── Provider-specific: create quotes, delete compares unquoted ───────────

	public function test_delete_matches_by_trimming_quotes_from_the_listed_data_field(): void {
		$provider = $this->make_provider();
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->wp_response( 404 ),
			$this->wp_response( 404 ),
			$this->wp_response( 200 ),
			$this->wp_response(
				200,
				array(
					'records' => array(
						array( 'id' => 'rec-1', 'type' => 'TXT', 'name' => '_acme-challenge.www', 'data' => 'not-the-value' ),
						array( 'id' => 'rec-2', 'type' => 'TXT', 'name' => '_acme-challenge.www', 'data' => '"' . $this->record_value() . '"' ),
						array( 'id' => 'rec-3', 'type' => 'A', 'name' => '_acme-challenge.www', 'data' => '"' . $this->record_value() . '"' ),
					),
				)
			),
			$this->wp_response( 204 ),
		);

		$provider->delete_txt_record( $this->fqdn(), $this->record_value() );

		$requests = $this->captured_requests();
		$last     = end( $requests );
		$this->assertSame( 'DELETE', $last['args']['method'] ?? null );
		$this->assertStringContainsString( '/domains/example.com/records/rec-2', $last['url'], 'must match the unquoted value and TXT type, ignoring the A record with the same quoted data' );
	}

	// ── Provider-specific: single-page fetch, documented limitation ──────────

	public function test_pagination_only_fetches_a_single_page_of_records(): void {
		$provider = $this->make_provider();
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->wp_response( 404 ),
			$this->wp_response( 404 ),
			$this->wp_response( 200 ),
			$this->wp_response(
				200,
				array(
					'records' => array(
						array( 'id' => 'rec-1', 'type' => 'TXT', 'name' => 'unrelated-1', 'data' => '"x"' ),
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
			$this->assertStringContainsString( 'no domain found', $e->getMessage() );
		}

		$this->assertCount( 3, $this->captured_requests(), 'an authentication failure during zone discovery must not proceed to a write request' );
	}
}
