<?php
/**
 * Phase 6C, Batch 2 ("Cloudflare clones, list-then-delete-by-ID"): request-
 * level contract coverage for WP_SAM\Certificates\Providers\Provider_Bunny.
 *
 * Shape: shared Dns_Provider::request() (JSON), custom "AccessKey" header
 * (not Authorization). Zone discovery is a client-side filter over a 200
 * response's "Items" array, no try/catch -- same shape as Hetzner (see
 * ProviderContractHetznerTest's docblock for the deliberate contrast with
 * the try/catch providers' auth-during-discovery misdiagnosis). Bunny uses
 * PascalCase field names throughout (Type/Name/Value/Ttl/Id) and a numeric
 * TXT type (3) rather than a string. delete_txt_record() fetches the
 * zone's own detail object (GET /dnszone/{id}, a single-resource fetch, not
 * a classic paginated list endpoint) and reads its nested "Records" array
 * -- a record absent from that array is still silently not found/not
 * deleted, same observable behaviour as the other batch members' list
 * endpoints, tested below for consistency even though the underlying risk
 * (a genuinely paginated list) doesn't apply the same way here.
 */

declare( strict_types=1 );

use WP_SAM\Certificates\Providers\Provider_Bunny;

class ProviderContractBunnyTest extends Dns_Provider_Contract_TestCase {

	private function wp_response( int $code, array $body = array() ): array {
		return array(
			'response' => array( 'code' => $code ),
			'body'     => (string) wp_json_encode( $body ),
		);
	}

	protected function make_provider(): Provider_Bunny {
		return new Provider_Bunny( array( 'api_key' => 'fixture-bunny-key' ) );
	}

	protected function fqdn(): string {
		return '_acme-challenge.www.example.com';
	}

	protected function record_value(): string {
		return 'fixture-challenge-digest-value';
	}

	protected function queue_successful_create(): void {
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->wp_response( 200, array( 'Items' => array() ) ),
			$this->wp_response( 200, array( 'Items' => array() ) ),
			$this->wp_response( 200, array( 'Items' => array( array( 'Id' => 42, 'Domain' => 'example.com' ) ) ) ),
			$this->wp_response( 201 ), // PUT create
		);
	}

	protected function queue_successful_delete(): void {
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->wp_response( 200, array( 'Items' => array() ) ),
			$this->wp_response( 200, array( 'Items' => array() ) ),
			$this->wp_response( 200, array( 'Items' => array( array( 'Id' => 42, 'Domain' => 'example.com' ) ) ) ),
			$this->wp_response(
				200,
				array(
					'Records' => array(
						array(
							'Id'    => 999,
							'Type'  => 3,
							'Name'  => '_acme-challenge.www',
							'Value' => $this->record_value(),
						),
					),
				)
			),
			$this->wp_response( 200 ), // DELETE
		);
	}

	protected function queue_authentication_failure(): void {
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->wp_response( 200, array( 'Items' => array( array( 'Id' => 42, 'Domain' => 'example.com' ) ) ) ),
			$this->wp_response( 401 ),
		);
	}

	protected function queue_zone_not_found(): void {
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->wp_response( 200, array( 'Items' => array() ) ),
			$this->wp_response( 200, array( 'Items' => array() ) ),
			$this->wp_response( 200, array( 'Items' => array() ) ),
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
			$this->wp_response( 200, array( 'Items' => array( array( 'Id' => 42, 'Domain' => 'example.com' ) ) ) ),
			$this->wp_response( 500 ),
		);
	}

	protected function assert_authenticated_correctly( array $request ): void {
		$this->assertSame( 'fixture-bunny-key', $request['args']['headers']['AccessKey'] ?? null );
		$this->assertArrayNotHasKey( 'Authorization', $request['args']['headers'] ?? array() );
	}

	protected function assert_record_naming_correct( array $create_request ): void {
		$this->assertSame( 'PUT', $create_request['args']['method'] ?? null );
		$this->assertStringContainsString( '/dnszone/42/records', $create_request['url'] );
		$body = $this->decoded_body( $create_request );
		$this->assertIsArray( $body );
		$this->assertSame( 3, $body['Type'] ?? null, 'Bunny uses numeric TXT type 3' );
		$this->assertSame( '_acme-challenge.www', $body['Name'] ?? null );
		$this->assertSame( $this->record_value(), $body['Value'] ?? null );
	}

	// ── Provider-specific: record identifier extracted from the zone detail ──

	public function test_delete_uses_the_server_assigned_record_id_from_the_zone_detail(): void {
		$provider = $this->make_provider();
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->wp_response( 200, array( 'Items' => array() ) ),
			$this->wp_response( 200, array( 'Items' => array() ) ),
			$this->wp_response( 200, array( 'Items' => array( array( 'Id' => 42, 'Domain' => 'example.com' ) ) ) ),
			$this->wp_response(
				200,
				array(
					'Records' => array(
						array( 'Id' => 1, 'Type' => 3, 'Name' => '_acme-challenge.www', 'Value' => 'not-the-value' ),
						array( 'Id' => 2, 'Type' => 3, 'Name' => '_acme-challenge.www', 'Value' => $this->record_value() ),
						array( 'Id' => 3, 'Type' => 1, 'Name' => '_acme-challenge.www', 'Value' => $this->record_value() ), // A record, same value
					),
				)
			),
			$this->wp_response( 200 ),
		);

		$provider->delete_txt_record( $this->fqdn(), $this->record_value() );

		$requests = $this->captured_requests();
		$last     = end( $requests );
		$this->assertSame( 'DELETE', $last['args']['method'] ?? null );
		$this->assertStringContainsString( '/dnszone/42/records/2', $last['url'], 'must match by numeric type 3, name, and value -- not the A record sharing the same value' );
	}

	// ── Provider-specific: a record absent from the zone detail is a no-op ───

	public function test_a_record_absent_from_the_zone_detail_is_not_deleted_and_does_not_throw(): void {
		$provider = $this->make_provider();
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->wp_response( 200, array( 'Items' => array() ) ),
			$this->wp_response( 200, array( 'Items' => array() ) ),
			$this->wp_response( 200, array( 'Items' => array( array( 'Id' => 42, 'Domain' => 'example.com' ) ) ) ),
			$this->wp_response(
				200,
				array(
					'Records' => array(
						array( 'Id' => 1, 'Type' => 3, 'Name' => 'unrelated', 'Value' => 'x' ),
					),
				)
			),
		);

		$provider->delete_txt_record( $this->fqdn(), $this->record_value() );

		$requests = $this->captured_requests();
		$this->assertCount( 4, $requests, 'a record absent from the fetched zone detail must not cause a DELETE request, and must not throw' );
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
			$this->assertStringNotContainsString( 'no DNS zone found', $e->getMessage() );
			$this->assertStringContainsString( 'HTTP 401', $e->getMessage() );
		}

		$this->assertCount( 1, $this->captured_requests(), 'with no try/catch around zone(), a rejected first candidate must not be retried against further candidates' );
	}
}
