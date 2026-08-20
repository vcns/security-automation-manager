<?php
/**
 * Phase 6C, Batch 4 ("JSON transport, non-standard auth or a pre-step"):
 * request-level contract coverage for
 * WP_SAM\Certificates\Providers\Provider_Porkbun.
 *
 * Shape: shared Dns_Provider::request() (JSON), but authentication travels
 * entirely in the JSON *body* ("apikey"/"secretapikey" merged into every
 * request via auth()) -- no Authorization header, no custom header at
 * all; every request (including read-only zone lookups) is a POST, since
 * Porkbun's API has no GET-with-credentials-in-headers concept. Zone
 * discovery is the established try/catch-per-candidate shape (direct code
 * evidence: identical structure to deSEC et al.) with no body read on
 * success, so response_body_is_validated_on_success() is false.
 *
 * Confirmed production defect (extends the established Batch 1/2
 * auth-during-discovery family, with direct code evidence), not fixed
 * here: an authentication failure during zone discovery is misreported as
 * "no zone found for {fqdn}", identically to deSEC et al. Proven by
 * test_authentication_failure_during_zone_discovery_is_misreported_as_zone_not_found()
 * below.
 *
 * Confirmed production defect (separate finding, NOT an extension of the
 * PowerDNS destructive-write family -- different provider, different root
 * cause, verified independently), not fixed here, avoidable: verified
 * directly against Porkbun's own published API documentation
 * (https://porkbun.com/api/json/v3/documentation and llms-full.txt).
 * delete_txt_record() calls POST /dns/deleteByNameType/{zone}/TXT/{name},
 * which deletes every TXT record at that name regardless of content --
 * the driver never inspects $value at all when deleting. Unlike PowerDNS
 * (whose API has no by-value mechanism below a version threshold),
 * Porkbun's own API documents BOTH "Delete DNS record by ID"
 * (POST /dns/delete/{domain}/{id}) and "Retrieve DNS records by name and
 * type" (POST /dns/retrieveByNameType/{domain}/{type}/{subdomain}, which
 * returns each matching record's ID) -- the safer list-then-delete-by-ID
 * pattern every sibling provider in this registry uses is directly
 * available in Porkbun's API and simply isn't used here. This makes the
 * defect avoidable, not merely an architectural limitation. "No
 * applicable mechanism" for record identifiers as currently implemented
 * (delete_txt_record() never lists records or extracts an ID at all) and
 * for pagination (Porkbun's retrieve endpoints document no
 * offset/limit/pagination parameters at all).
 */

declare( strict_types=1 );

use WP_SAM\Certificates\Providers\Provider_Porkbun;

class ProviderContractPorkbunTest extends Dns_Provider_Contract_TestCase {

	private function wp_response( int $code, array $body = array() ): array {
		return array(
			'response' => array( 'code' => $code ),
			'body'     => (string) wp_json_encode( $body ),
		);
	}

	protected function make_provider(): Provider_Porkbun {
		return new Provider_Porkbun(
			array(
				'api_key'    => 'fixture-porkbun-key',
				'api_secret' => 'fixture-porkbun-secret',
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
			$this->wp_response( 200 ), // example.com -- exists
			$this->wp_response( 200 ), // POST create
		);
	}

	protected function queue_successful_delete(): void {
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->wp_response( 404 ),
			$this->wp_response( 404 ),
			$this->wp_response( 200 ),
			$this->wp_response( 200 ), // POST deleteByNameType -- no prior list call at all
		);
	}

	protected function queue_authentication_failure(): void {
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->wp_response( 200 ), // zone found on the first candidate
			$this->wp_response( 401 ), // the POST create itself is rejected
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
		$headers = $request['args']['headers'] ?? array();
		$this->assertArrayNotHasKey( 'Authorization', $headers );
		$this->assertCount( 1, $headers, 'only the shared Content-Type header should be present -- Porkbun sends no auth header at all' );
		$body = $this->decoded_body( $request );
		$this->assertIsArray( $body );
		$this->assertSame( 'fixture-porkbun-key', $body['apikey'] ?? null );
		$this->assertSame( 'fixture-porkbun-secret', $body['secretapikey'] ?? null );
	}

	protected function assert_record_naming_correct( array $create_request ): void {
		$this->assertSame( 'POST', $create_request['args']['method'] ?? null );
		$this->assertStringContainsString( '/dns/create/example.com', $create_request['url'] );
		$body = $this->decoded_body( $create_request );
		$this->assertIsArray( $body );
		$this->assertSame( '_acme-challenge.www', $body['name'] ?? null );
		$this->assertSame( 'TXT', $body['type'] ?? null );
		$this->assertSame( $this->record_value(), $body['content'] ?? null );
		$this->assertSame( '600', $body['ttl'] ?? null, 'Porkbun\'s ttl is sent as a string, not an integer' );
	}

	// ── Provider-specific: confirmed avoidable destructive delete defect ─────

	public function test_delete_uses_delete_by_name_type_and_ignores_the_provided_value(): void {
		$provider = $this->make_provider();
		$this->queue_successful_delete();

		// A value that was never created for this fqdn -- if $value were
		// used to target a specific record, this would find nothing. It
		// isn't: deleteByNameType removes every TXT record at this name,
		// regardless of content, and no prior list/retrieve call happens
		// to check what's actually there.
		$provider->delete_txt_record( $this->fqdn(), 'a-value-that-was-never-created' );

		$requests = $this->captured_requests();
		$last     = end( $requests );
		$this->assertSame( 'POST', $last['args']['method'] ?? null );
		$this->assertStringContainsString( '/dns/deleteByNameType/example.com/TXT/_acme-challenge.www', $last['url'] );
		$body = $this->decoded_body( $last );
		$this->assertIsArray( $body );
		$this->assertArrayNotHasKey( 'content', $body, 'no value-identifying field is sent at all' );
		$this->assertCount( 2, $body, 'the delete body carries only apikey/secretapikey -- nothing else' );
	}

	public function test_delete_never_lists_or_retrieves_records_first(): void {
		$provider = $this->make_provider();
		$this->queue_successful_delete();

		$provider->delete_txt_record( $this->fqdn(), $this->record_value() );

		// zone()'s own existence probe legitimately calls /dns/retrieve/{zone}
		// (no name/type filter) -- the distinct finding is that
		// /dns/retrieveByNameType, which would return the matching records'
		// IDs for a safe by-ID delete, is never called.
		foreach ( $this->captured_requests() as $request ) {
			$this->assertStringNotContainsString( '/dns/retrieveByNameType', $request['url'], 'Porkbun\'s own API supports retrieving records by name and type (with their IDs), but this driver never calls it before deleting' );
		}
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
