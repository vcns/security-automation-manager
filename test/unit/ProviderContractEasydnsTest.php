<?php
/**
 * Phase 6C, Batch 2 ("Cloudflare clones, list-then-delete-by-ID"): request-
 * level contract coverage for WP_SAM\Certificates\Providers\Provider_Easydns.
 *
 * Shape: shared Dns_Provider::request() (JSON), HTTP Basic auth
 * (token:key). Create uses PUT (not POST) to
 * /zones/records/add/{zone}/TXT. Zone discovery re-uses the exact same
 * "list all records" endpoint delete uses (/zones/records/all/{candidate})
 * wrapped in the same try/catch-on-any->=400 pattern as
 * DigitalOcean/Vultr/Name.com -- the response body from that discovery GET
 * is never read, only status, so this driver is status-only for the create
 * path (see ProviderContractDigitaloceanTest's docblock for the shared
 * finding and the recurring auth-during-discovery misdiagnosis). Records
 * are wrapped in "data" (not "records"/"domain_records"), fields
 * host/rdata/id, and the type comparison is case-insensitive
 * (strtoupper()) on the way out but sent as literal "TXT" on the way in.
 */

declare( strict_types=1 );

use WP_SAM\Certificates\Providers\Provider_Easydns;

class ProviderContractEasydnsTest extends Dns_Provider_Contract_TestCase {

	private function wp_response( int $code, array $body = array() ): array {
		return array(
			'response' => array( 'code' => $code ),
			'body'     => (string) wp_json_encode( $body ),
		);
	}

	protected function make_provider(): Provider_Easydns {
		return new Provider_Easydns(
			array(
				'token' => 'fixture-easydns-token',
				'key'   => 'fixture-easydns-key',
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
			$this->wp_response( 404 ),
			$this->wp_response( 404 ),
			$this->wp_response( 200 ),
			$this->wp_response( 200 ), // PUT create
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
					'data' => array(
						array(
							'id'    => 'rec-321',
							'type'  => 'TXT',
							'host'  => '_acme-challenge.www',
							'rdata' => $this->record_value(),
						),
					),
				)
			),
			$this->wp_response( 200 ), // DELETE
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
		$this->assertSame( 'Basic ' . base64_encode( 'fixture-easydns-token:fixture-easydns-key' ), $request['args']['headers']['Authorization'] ?? null );
	}

	protected function assert_record_naming_correct( array $create_request ): void {
		$this->assertSame( 'PUT', $create_request['args']['method'] ?? null, 'easyDNS creates records with PUT, not POST' );
		$this->assertStringContainsString( '/zones/records/add/example.com/TXT', $create_request['url'] );
		$body = $this->decoded_body( $create_request );
		$this->assertIsArray( $body );
		$this->assertSame( '_acme-challenge.www', $body['host'] ?? null );
		$this->assertSame( $this->record_value(), $body['rdata'] ?? null, 'easyDNS uses "rdata", not "data"' );
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
					'data' => array(
						array( 'id' => 'rec-1', 'type' => 'txt', 'host' => '_acme-challenge.www', 'rdata' => 'not-the-value' ),
						array( 'id' => 'rec-2', 'type' => 'txt', 'host' => '_acme-challenge.www', 'rdata' => $this->record_value() ),
					),
				)
			),
			$this->wp_response( 200 ),
		);

		$provider->delete_txt_record( $this->fqdn(), $this->record_value() );

		$requests = $this->captured_requests();
		$last     = end( $requests );
		$this->assertSame( 'DELETE', $last['args']['method'] ?? null );
		$this->assertStringContainsString( '/zones/records/example.com/rec-2', $last['url'] );
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
					'data' => array(
						array( 'id' => 'rec-1', 'type' => 'txt', 'host' => 'unrelated', 'rdata' => 'x' ),
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
