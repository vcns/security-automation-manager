<?php
/**
 * Phase 6C, Batch 7 ("Signature and multi-step auth heavyweights"):
 * request-level contract coverage for WP_SAM\Certificates\Providers\Provider_Azure.
 *
 * Shape: shared Dns_Provider::request() (JSON, ARM REST API), with a
 * memoised OAuth2 client-credentials pre-step: private headers() calls
 * wp_remote_post() directly (not request()/request_raw()) against
 * login.microsoftonline.com once, caches the bearer token on $this->token,
 * and every subsequent ARM call reuses it. Because headers() is evaluated
 * as an argument expression to the surrounding request() call, the token
 * fetch is genuinely the FIRST request the driver ever makes for a fresh
 * instance -- unlike OVH's separate unauthenticated time pre-step, this
 * first request IS the authentication-construction step itself (an OAuth2
 * client-credentials POST), so assert_authenticated_correctly() inspects
 * it directly rather than needing to skip past it.
 *
 * Zone discovery is a single upfront GET (no try/catch), matching the
 * Batch 3/6/7 "enumerate-once" shape. Azure Resource Manager's common
 * error response schema is standard, official Microsoft documentation
 * (Azure REST API error responses use real HTTP 401/403 for authentication/
 * authorization failures, not an in-band 200 body) -- confirmed immune to
 * the auth-misdiagnosis defect for this dimension with high confidence.
 *
 * Confirmed production defects, bidirectional and avoidable -- the same
 * risk shape as PowerDNS's REPLACE/DELETE (Batch 3), though the API and
 * implementation differ:
 * - create_txt_record() PUTs the record set with only the single new
 *   challenge value -- no GET of the existing record set precedes it, so
 *   PUT (which replaces the whole record set, not merges into it) can
 *   silently overwrite an unrelated TXT value already present at the same
 *   name.
 * - delete_txt_record() issues an unconditional DELETE of the entire TXT
 *   recordset at the resolved name -- it never reads the recordset's
 *   current TXTRecords values, never compares against $value, and the
 *   DELETE request carries no body at all.
 * Both are avoidable, not architectural: Azure's Record Sets API documents
 * GET (returns the complete record set, including TXTRecords) and PUT
 * (updates the record set) as a pair, plus If-Match support using the
 * record set's ETag to guard against overwriting a concurrent change --
 * see https://learn.microsoft.com/en-us/rest/api/dns/record-sets/get?view=rest-dns-2018-05-01
 * and https://learn.microsoft.com/en-us/rest/api/dns/record-sets/create-or-update?view=rest-dns-2018-05-01.
 * A safe implementation could GET the record set, add/remove only the
 * matching TXT value from TXTRecords, PUT the revised collection with
 * If-Match set to the retrieved ETag, and fall back to a whole-recordset
 * DELETE only once no values remain. Proven by
 * test_create_replaces_the_entire_txt_recordset_without_reading_it_first()
 * and test_delete_removes_the_entire_txt_recordset_without_checking_the_value().
 */

declare( strict_types=1 );

use WP_SAM\Certificates\Providers\Provider_Azure;

class ProviderContractAzureTest extends Dns_Provider_Contract_TestCase {

	private function wp_response( int $code, array $body = array() ): array {
		return array(
			'response' => array( 'code' => $code ),
			'body'     => (string) wp_json_encode( $body ),
		);
	}

	private function token_response(): array {
		return $this->wp_response( 200, array( 'access_token' => 'fixture-bearer-token' ) );
	}

	protected function make_provider(): Provider_Azure {
		return new Provider_Azure(
			array(
				'tenant_id'       => 'fixture-tenant-id',
				'client_id'       => 'fixture-client-id',
				'client_secret'   => 'fixture-client-secret',
				'subscription_id' => 'fixture-subscription-id',
				'resource_group'  => 'fixture-resource-group',
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
		$GLOBALS['_wp_remote_post_response_queue']    = array( $this->token_response() );
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->wp_response( 200, array( 'value' => array( array( 'name' => 'example.com' ) ) ) ), // zone list
			$this->wp_response( 200 ), // PUT create
		);
	}

	protected function queue_successful_delete(): void {
		// $this->token is already cached from the preceding create_txt_record()
		// call on the same $provider instance -- no further OAuth2 POST.
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->wp_response( 200, array( 'value' => array( array( 'name' => 'example.com' ) ) ) ),
			$this->wp_response( 200 ), // DELETE
		);
	}

	protected function queue_authentication_failure(): void {
		$GLOBALS['_wp_remote_post_response_queue']    = array( $this->token_response() );
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->wp_response( 200, array( 'value' => array( array( 'name' => 'example.com' ) ) ) ),
			$this->wp_response( 401, array( 'error' => array( 'code' => 'AuthorizationFailed', 'message' => 'The client does not have authorization to perform this action.' ) ) ),
		);
	}

	protected function queue_zone_not_found(): void {
		$GLOBALS['_wp_remote_post_response_queue']    = array( $this->token_response() );
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->wp_response( 200, array( 'value' => array( array( 'name' => 'unrelated-1.com' ), array( 'name' => 'unrelated-2.com' ) ) ) ),
		);
	}

	protected function queue_malformed_response(): void {
		$GLOBALS['_wp_remote_post_response_queue']    = array( $this->token_response() );
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			array( 'response' => array( 'code' => 200 ), 'body' => 'not json at all {{{' ), // zone list
		);
	}

	protected function queue_http_failure(): void {
		$GLOBALS['_wp_remote_post_response_queue']    = array( $this->token_response() );
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->wp_response( 200, array( 'value' => array( array( 'name' => 'example.com' ) ) ) ),
			$this->wp_response( 500, array( 'error' => array( 'code' => 'InternalServerError' ) ) ),
		);
	}

	protected function assert_authenticated_correctly( array $request ): void {
		// requests[0] for a fresh instance genuinely is the OAuth2
		// client-credentials POST itself (headers() is evaluated before the
		// surrounding request() call fires) -- assert on that directly.
		$body = $request['args']['body'] ?? array();
		$this->assertSame( 'client_credentials', $body['grant_type'] ?? null );
		$this->assertSame( 'fixture-client-id', $body['client_id'] ?? null );
		$this->assertSame( 'fixture-client-secret', $body['client_secret'] ?? null );
		$this->assertSame( 'https://management.azure.com/.default', $body['scope'] ?? null );
		$this->assertStringContainsString( 'fixture-tenant-id', $request['url'] );
	}

	protected function assert_record_naming_correct( array $create_request ): void {
		$this->assertStringContainsString( '/dnsZones/example.com/TXT/_acme-challenge.www', $create_request['url'] );
		$body = $this->decoded_body( $create_request );
		$this->assertIsArray( $body );
		$this->assertSame( array( $this->record_value() ), $body['properties']['TXTRecords'][0]['value'] ?? null );
	}

	// ── Provider-specific: OAuth2 token is fetched once and cached ───────────

	public function test_oauth_token_is_fetched_once_and_cached_across_create_and_delete(): void {
		$provider = $this->make_provider();
		$this->queue_successful_create();
		$provider->create_txt_record( $this->fqdn(), $this->record_value() );

		$this->queue_successful_delete();
		$provider->delete_txt_record( $this->fqdn(), $this->record_value() );

		$token_calls = array_filter(
			$this->captured_requests(),
			static fn( array $r ): bool => str_contains( (string) ( $r['url'] ?? '' ), 'login.microsoftonline.com' )
		);
		$this->assertCount( 1, $token_calls, 'the OAuth2 client-credentials pre-step must resolve once and be cached for the rest of this provider instance\'s lifetime' );
	}

	public function test_oauth_token_failure_is_not_silently_accepted(): void {
		$provider = $this->make_provider();
		$GLOBALS['_wp_remote_post_response_queue'] = array(
			$this->wp_response( 400, array( 'error' => 'invalid_client', 'error_description' => 'Invalid client secret provided.' ) ),
		);

		$this->expectException( \RuntimeException::class );
		$this->expectExceptionMessageMatches( '/Azure token request failed/' );

		$provider->create_txt_record( $this->fqdn(), $this->record_value() );
	}

	// ── Provider-specific: confirmed destructive whole-recordset create/delete ──

	public function test_create_replaces_the_entire_txt_recordset_without_reading_it_first(): void {
		$provider = $this->make_provider();
		$this->queue_successful_create();

		$provider->create_txt_record( $this->fqdn(), $this->record_value() );

		$requests = $this->captured_requests();
		// Three requests total: the OAuth2 token POST, the zone list, then
		// the PUT itself -- no GET of the specific TXT record set precedes
		// the write.
		$this->assertCount( 3, $requests );
		$record_set_reads = array_filter(
			$requests,
			static fn( array $r ): bool => 'GET' === ( $r['args']['method'] ?? null ) && str_contains( (string) ( $r['url'] ?? '' ), '/TXT/_acme-challenge.www' )
		);
		$this->assertCount( 0, $record_set_reads, 'no GET of the existing TXT record set precedes the PUT -- an unrelated value already present there would never be seen, let alone preserved' );

		$put_request = end( $requests );
		$this->assertSame( 'PUT', $put_request['args']['method'] ?? null );
		$body = $this->decoded_body( $put_request );
		$this->assertSame(
			array( array( 'value' => array( $this->record_value() ) ) ),
			$body['properties']['TXTRecords'] ?? null,
			'the PUT body contains only the new ACME value -- any pre-existing TXT value at this name is replaced, not merged with'
		);
	}

	// ── Provider-specific: confirmed destructive whole-recordset delete ─────

	public function test_delete_removes_the_entire_txt_recordset_without_checking_the_value(): void {
		$provider = $this->make_provider();
		$this->queue_successful_create();
		$provider->create_txt_record( $this->fqdn(), $this->record_value() );

		$this->queue_successful_delete();
		$provider->delete_txt_record( $this->fqdn(), 'a-completely-different-value-that-was-never-created' );

		$requests = $this->captured_requests();
		$delete_request = end( $requests );
		$this->assertSame( 'DELETE', $delete_request['args']['method'] ?? null );
		$this->assertArrayNotHasKey( 'body', $delete_request['args'] ?? array(), 'the DELETE carries no body -- it cannot possibly discriminate by value' );
		$this->assertStringNotContainsString( 'a-completely-different-value', $delete_request['url'], 'the value plays no part in the DELETE request at all' );
	}

	// ── Provider-specific: discovery-stage auth failure is NOT misreported ───

	public function test_authentication_failure_during_zone_discovery_surfaces_distinctly_not_as_zone_not_found(): void {
		$provider = $this->make_provider();
		$GLOBALS['_wp_remote_post_response_queue']    = array( $this->token_response() );
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->wp_response( 403, array( 'error' => array( 'code' => 'AuthorizationFailed', 'message' => 'not authorized' ) ) ),
		);

		try {
			$provider->create_txt_record( $this->fqdn(), $this->record_value() );
			$this->fail( 'expected an exception when the zone-list request is rejected with 403' );
		} catch ( \RuntimeException $e ) {
			$this->assertStringNotContainsString( 'no zone found', $e->getMessage() );
			$this->assertStringContainsString( 'HTTP 403', $e->getMessage() );
		}
	}
}
