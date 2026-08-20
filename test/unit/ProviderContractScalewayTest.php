<?php
/**
 * Phase 6C, Batch 1 ("Cloudflare clones, no record ID"): request-level
 * contract coverage for WP_SAM\Certificates\Providers\Provider_Scaleway.
 *
 * Shape: shared Dns_Provider::request() (JSON), "X-Auth-Token" header
 * auth. Unlike the other four fixtures in this batch, zone discovery
 * does NOT rely on try/catch over per-candidate error statuses -- every
 * lookup returns 200 with a `dns_zones` array, and the driver filters
 * client-side by reconstructing `subdomain.domain` and comparing it to
 * the candidate. This means a malformed/unparseable body genuinely
 * changes behaviour here (falls through to "no zones", same as
 * Cloudflare), unlike deSEC/Gandi/GoDaddy/NS1 where it doesn't.
 * Create/delete both use a single PATCH endpoint with a nested
 * "changes[].add"/"changes[].delete" envelope, identified by
 * name+type+data rather than a record ID.
 */

declare( strict_types=1 );

use WP_SAM\Certificates\Providers\Provider_Scaleway;

class ProviderContractScalewayTest extends Dns_Provider_Contract_TestCase {

	private function wp_response( int $code, array $body = array() ): array {
		return array(
			'response' => array( 'code' => $code ),
			'body'     => (string) wp_json_encode( $body ),
		);
	}

	protected function make_provider(): Provider_Scaleway {
		return new Provider_Scaleway( array( 'secret_key' => 'fixture-scaleway-secret' ) );
	}

	protected function fqdn(): string {
		return '_acme-challenge.www.example.com';
	}

	protected function record_value(): string {
		return 'fixture-challenge-digest-value';
	}

	protected function queue_successful_create(): void {
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->wp_response( 200, array( 'dns_zones' => array() ) ), // _acme-challenge.www.example.com -- no match
			$this->wp_response( 200, array( 'dns_zones' => array() ) ), // www.example.com -- no match
			$this->wp_response( 200, array( 'dns_zones' => array( array( 'subdomain' => '', 'domain' => 'example.com' ) ) ) ), // example.com -- match
			$this->wp_response( 200, array() ), // PATCH create
		);
	}

	protected function queue_successful_delete(): void {
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->wp_response( 200, array( 'dns_zones' => array() ) ),
			$this->wp_response( 200, array( 'dns_zones' => array() ) ),
			$this->wp_response( 200, array( 'dns_zones' => array( array( 'subdomain' => '', 'domain' => 'example.com' ) ) ) ),
			$this->wp_response( 200, array() ), // PATCH delete
		);
	}

	protected function queue_authentication_failure(): void {
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->wp_response( 401, array( 'message' => 'invalid token' ) ),
		);
	}

	protected function queue_zone_not_found(): void {
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->wp_response( 200, array( 'dns_zones' => array() ) ),
			$this->wp_response( 200, array( 'dns_zones' => array() ) ),
			$this->wp_response( 200, array( 'dns_zones' => array() ) ),
		);
	}

	protected function queue_malformed_response(): void {
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			array( 'response' => array( 'code' => 200 ), 'body' => 'this is not json at all {{{' ),
			array( 'response' => array( 'code' => 200 ), 'body' => 'this is not json at all {{{' ),
			array( 'response' => array( 'code' => 200 ), 'body' => 'this is not json at all {{{' ),
		);
	}

	protected function queue_http_failure(): void {
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->wp_response( 500, array( 'message' => 'internal error' ) ),
		);
	}

	protected function assert_authenticated_correctly( array $request ): void {
		$this->assertSame( 'fixture-scaleway-secret', $request['args']['headers']['X-Auth-Token'] ?? null );
	}

	protected function assert_record_naming_correct( array $create_request ): void {
		$this->assertStringContainsString( '/dns-zones/example.com/records', $create_request['url'] );
		$body = $this->decoded_body( $create_request );
		$this->assertIsArray( $body );
		$record = $body['changes'][0]['add']['records'][0] ?? null;
		$this->assertIsArray( $record );
		$this->assertSame( '_acme-challenge.www', $record['name'] ?? null );
		$this->assertSame( 'TXT', $record['type'] ?? null );
		$this->assertSame( '"' . $this->record_value() . '"', $record['data'] ?? null );
	}

	// ── Provider-specific: client-side zone filtering (not try/catch) ────────

	public function test_zone_lookup_ignores_non_matching_zones_in_a_successful_response(): void {
		$provider = $this->make_provider();
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->wp_response(
				200,
				array(
					'dns_zones' => array(
						array( 'subdomain' => 'unrelated', 'domain' => 'example.com' ),
						array( 'subdomain' => 'also-unrelated', 'domain' => 'example.com' ),
					),
				)
			), // _acme-challenge.www.example.com -- zones present but none match by name
			$this->wp_response( 200, array( 'dns_zones' => array() ) ),
			$this->wp_response( 200, array( 'dns_zones' => array( array( 'subdomain' => '', 'domain' => 'example.com' ) ) ) ),
			$this->wp_response( 200, array() ),
		);

		$provider->create_txt_record( $this->fqdn(), $this->record_value() );

		$this->assertCount( 4, $this->captured_requests(), 'a 200 response with only non-matching zone entries must not be treated as a match' );
	}

	// ── Provider-specific: delete envelope uses "delete"/"id_fields" ─────────

	public function test_delete_uses_a_delete_envelope_identified_by_name_type_and_data(): void {
		$provider = $this->make_provider();
		$this->queue_successful_delete();
		$provider->delete_txt_record( $this->fqdn(), $this->record_value() );

		$requests = $this->captured_requests();
		$last     = end( $requests );
		$this->assertSame( 'PATCH', $last['args']['method'] ?? null );
		$body = $this->decoded_body( $last );
		$id_fields = $body['changes'][0]['delete']['id_fields'] ?? null;
		$this->assertIsArray( $id_fields );
		$this->assertSame( '_acme-challenge.www', $id_fields['name'] ?? null );
		$this->assertSame( 'TXT', $id_fields['type'] ?? null );
		$this->assertSame( '"' . $this->record_value() . '"', $id_fields['data'] ?? null );
	}
}
