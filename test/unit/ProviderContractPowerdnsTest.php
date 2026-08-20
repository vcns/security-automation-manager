<?php
/**
 * Phase 6C, Batch 3 ("Enumerate-all-zones and unusual discovery"): request-
 * level contract coverage for WP_SAM\Certificates\Providers\Provider_Powerdns.
 *
 * Shape: self-hosted PowerDNS Authoritative Server, base URL assembled
 * from a configurable api_url + server_id (defaulting to "localhost") --
 * the only provider in the registry whose API endpoint itself is
 * user-configured infrastructure rather than a fixed SaaS host, so base
 * URL assembly is tested explicitly below alongside authentication.
 * "X-API-Key" header auth. Zone discovery makes exactly ONE request
 * (GET /zones) and loops zone_candidates() against that single cached
 * list client-side, same "enumerate once, filter locally" shape as
 * IONOS/Linode/Netlify (see ProviderContractIonosTest's docblock). No
 * try/catch, so a non-2xx on that call propagates immediately and
 * distinctly. zone() reads the response body, so
 * response_body_is_validated_on_success() stays at its default true.
 *
 * Architecturally distinct from every other Batch 1-3 provider: create
 * and delete both go through a single PATCH replacing/removing the
 * WHOLE RRset (changetype REPLACE / DELETE) rather than listing records
 * and deleting one by server-assigned ID -- confirmed via
 * doc.powerdns.com's own Zone API reference (no separate records-listing
 * endpoint exists; "a Resource Record Set ... are all records for a
 * given name and type"). "No applicable mechanism" for both record
 * identifiers and pagination: there is no list-of-records response to
 * paginate or extract an ID from at all. delete_txt_record() therefore
 * also ignores the $value parameter entirely -- REPLACE's overwrite
 * semantics mean the RRset can only ever hold the one value this plugin
 * itself last wrote, so removing the whole set is equivalent to removing
 * that value; tested explicitly below as a disclosed architectural
 * characteristic, not a defect.
 */

declare( strict_types=1 );

use WP_SAM\Certificates\Providers\Provider_Powerdns;

class ProviderContractPowerdnsTest extends Dns_Provider_Contract_TestCase {

	private function wp_response( int $code, array $body = array() ): array {
		return array(
			'response' => array( 'code' => $code ),
			'body'     => (string) wp_json_encode( $body ),
		);
	}

	private function zones_list_matching(): array {
		return $this->wp_response( 200, array( array( 'name' => 'example.com.' ) ) );
	}

	protected function make_provider(): Provider_Powerdns {
		return new Provider_Powerdns(
			array(
				'api_url'   => 'http://fixture-pdns.test:8081',
				'api_key'   => 'fixture-pdns-key',
				'server_id' => '',
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
			$this->zones_list_matching(),
			$this->wp_response( 204 ), // PATCH create (REPLACE)
		);
	}

	protected function queue_successful_delete(): void {
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->zones_list_matching(),
			$this->wp_response( 204 ), // PATCH delete
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
		$this->assertSame( 'fixture-pdns-key', $request['args']['headers']['X-API-Key'] ?? null );
	}

	protected function assert_record_naming_correct( array $create_request ): void {
		$this->assertSame( 'PATCH', $create_request['args']['method'] ?? null );
		$this->assertStringContainsString( '/api/v1/servers/localhost/zones/example.com.', $create_request['url'], 'blank server_id must default to "localhost"' );
		$body  = $this->decoded_body( $create_request );
		$rrset = $body['rrsets'][0] ?? null;
		$this->assertIsArray( $rrset );
		$this->assertSame( $this->fqdn() . '.', $rrset['name'] ?? null, 'PowerDNS record names carry a trailing dot' );
		$this->assertSame( 'TXT', $rrset['type'] ?? null );
		$this->assertSame( 'REPLACE', $rrset['changetype'] ?? null );
		$this->assertSame( 60, $rrset['ttl'] ?? null );
		$this->assertSame( '"' . $this->record_value() . '"', $rrset['records'][0]['content'] ?? null, 'the TXT value is quoted' );
		$this->assertFalse( $rrset['records'][0]['disabled'] ?? null );
	}

	// ── Provider-specific: base URL assembly from api_url + server_id ────────

	public function test_custom_server_id_is_used_in_the_base_url(): void {
		$provider = new Provider_Powerdns(
			array(
				'api_url'   => 'http://fixture-pdns.test:8081',
				'api_key'   => 'fixture-pdns-key',
				'server_id' => 'my-custom-server',
			)
		);
		$this->queue_successful_create();

		$provider->create_txt_record( $this->fqdn(), $this->record_value() );

		foreach ( $this->captured_requests() as $request ) {
			$this->assertStringContainsString( '/api/v1/servers/my-custom-server/', $request['url'] );
			$this->assertStringNotContainsString( '/servers/localhost/', $request['url'] );
		}
	}

	// ── Provider-specific: no record-listing call, no record-ID mechanism ────

	public function test_delete_never_lists_records_and_uses_no_record_identifier(): void {
		$provider = $this->make_provider();
		$this->queue_successful_delete();

		$provider->delete_txt_record( $this->fqdn(), $this->record_value() );

		$requests = $this->captured_requests();
		$this->assertCount( 2, $requests, 'zone lookup + a single PATCH -- no separate records-list request exists for this provider' );
		$last = end( $requests );
		$this->assertSame( 'PATCH', $last['args']['method'] ?? null );
		$this->assertStringNotContainsString( 'records/', $last['url'], 'no server-assigned record ID is ever addressed in the URL' );
	}

	// ── Provider-specific: delete ignores $value, removes the whole RRset ────

	public function test_delete_uses_changetype_delete_and_ignores_the_provided_value(): void {
		$provider = $this->make_provider();
		$this->queue_successful_delete();

		// A value that was never created for this fqdn -- if $value were
		// used to target a specific record, this would find nothing.
		$provider->delete_txt_record( $this->fqdn(), 'a-value-that-was-never-created' );

		$requests = $this->captured_requests();
		$last     = end( $requests );
		$body     = $this->decoded_body( $last );
		$rrset    = $body['rrsets'][0] ?? null;
		$this->assertIsArray( $rrset );
		$this->assertSame( 'DELETE', $rrset['changetype'] ?? null );
		$this->assertArrayNotHasKey( 'records', $rrset, 'a DELETE changetype carries no records array' );
		$this->assertArrayNotHasKey( 'ttl', $rrset, 'a DELETE changetype carries no ttl' );
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
