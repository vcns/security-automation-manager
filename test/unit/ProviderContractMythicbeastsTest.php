<?php
/**
 * Phase 6C, Batch 7 ("Signature and multi-step auth heavyweights"):
 * request-level contract coverage for
 * WP_SAM\Certificates\Providers\Provider_Mythicbeasts.
 *
 * Shape: shared Dns_Provider::request() (JSON), with the same memoised
 * OAuth2 client-credentials pre-step shape as Azure -- private headers()
 * calls wp_remote_post() directly (not request()/request_raw()) against
 * auth.mythic-beasts.com once, caches the bearer token on $this->token,
 * using HTTP Basic auth (key_id:secret) for the token exchange itself
 * rather than a client_secret POST field. Because headers() is evaluated
 * as an argument expression to the surrounding request() call, the token
 * fetch is the first request a fresh instance ever makes, and is itself
 * the authentication-construction step assert_authenticated_correctly()
 * inspects.
 *
 * Zone discovery is a single upfront GET (no try/catch) against a plain
 * array of zone name strings, matching the Batch 3/6/7 "enumerate-once"
 * shape. This is a Bearer-token OAuth2 API (RFC 6750), for which rejecting
 * an invalid/expired token via genuine HTTP 401 is the standard, universal
 * convention -- confirmed immune to the auth-misdiagnosis defect for this
 * dimension.
 *
 * Contrast finding, not a defect: delete_txt_record() is a genuinely
 * well-designed exact-match deletion -- host, record type, and the TXT
 * value itself are all passed as path/query parameters to a single DELETE
 * call, and the API documents this endpoint as deleting only the record(s)
 * matching all three, not the whole recordset at that host. No client-side
 * list-then-verify step exists (or is needed) because the match is already
 * exact server-side.
 */

declare( strict_types=1 );

use WP_SAM\Certificates\Providers\Provider_Mythicbeasts;

class ProviderContractMythicbeastsTest extends Dns_Provider_Contract_TestCase {

	private function wp_response( int $code, array $body = array() ): array {
		return array(
			'response' => array( 'code' => $code ),
			'body'     => (string) wp_json_encode( $body ),
		);
	}

	private function token_response(): array {
		return $this->wp_response( 200, array( 'access_token' => 'fixture-bearer-token' ) );
	}

	protected function make_provider(): Provider_Mythicbeasts {
		return new Provider_Mythicbeasts(
			array(
				'key_id' => 'fixture-key-id',
				'secret' => 'fixture-secret',
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
			$this->wp_response( 200, array( 'zones' => array( 'example.com' ) ) ), // zone list
			$this->wp_response( 200 ), // POST create
		);
	}

	protected function queue_successful_delete(): void {
		// $this->token is already cached from the preceding create_txt_record()
		// call on the same $provider instance -- no further token POST.
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->wp_response( 200, array( 'zones' => array( 'example.com' ) ) ),
			$this->wp_response( 200 ), // DELETE
		);
	}

	protected function queue_authentication_failure(): void {
		$GLOBALS['_wp_remote_post_response_queue']    = array( $this->token_response() );
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->wp_response( 200, array( 'zones' => array( 'example.com' ) ) ),
			$this->wp_response( 401, array( 'error' => 'invalid_token' ) ),
		);
	}

	protected function queue_zone_not_found(): void {
		$GLOBALS['_wp_remote_post_response_queue']    = array( $this->token_response() );
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->wp_response( 200, array( 'zones' => array( 'unrelated-1.com', 'unrelated-2.com' ) ) ),
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
			$this->wp_response( 200, array( 'zones' => array( 'example.com' ) ) ),
			$this->wp_response( 500, array( 'error' => 'internal_error' ) ),
		);
	}

	protected function assert_authenticated_correctly( array $request ): void {
		// requests[0] for a fresh instance genuinely is the OAuth2 token POST
		// itself (headers() is evaluated before the surrounding request()
		// call fires) -- assert on that directly.
		$headers = $request['args']['headers'] ?? array();
		$this->assertSame( 'Basic ' . base64_encode( 'fixture-key-id:fixture-secret' ), $headers['Authorization'] ?? null );
		$body = $request['args']['body'] ?? array();
		$this->assertSame( 'client_credentials', $body['grant_type'] ?? null );
		$this->assertStringContainsString( 'auth.mythic-beasts.com', $request['url'] );
	}

	protected function assert_record_naming_correct( array $create_request ): void {
		$this->assertStringContainsString( '/zones/example.com/records', $create_request['url'] );
		$body = $this->decoded_body( $create_request );
		$this->assertIsArray( $body );
		$this->assertSame( '_acme-challenge.www', $body['records'][0]['host'] ?? null );
		$this->assertSame( 'TXT', $body['records'][0]['type'] ?? null );
		$this->assertSame( $this->record_value(), $body['records'][0]['data'] ?? null );
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
			static fn( array $r ): bool => str_contains( (string) ( $r['url'] ?? '' ), 'auth.mythic-beasts.com' )
		);
		$this->assertCount( 1, $token_calls, 'the OAuth2 pre-step must resolve once and be cached for the rest of this provider instance\'s lifetime' );
	}

	public function test_oauth_token_failure_is_not_silently_accepted(): void {
		$provider = $this->make_provider();
		$GLOBALS['_wp_remote_post_response_queue'] = array(
			$this->wp_response( 401, array( 'error' => 'invalid_client' ) ),
		);

		$this->expectException( \RuntimeException::class );
		$this->expectExceptionMessage( 'Mythic Beasts authentication failed.' );

		$provider->create_txt_record( $this->fqdn(), $this->record_value() );
	}

	// ── Provider-specific: well-designed exact-match delete (contrast) ───────

	public function test_delete_targets_the_exact_host_type_and_value_not_the_whole_recordset(): void {
		$provider = $this->make_provider();
		$this->queue_successful_create();
		$provider->create_txt_record( $this->fqdn(), $this->record_value() );

		$this->queue_successful_delete();
		$provider->delete_txt_record( $this->fqdn(), $this->record_value() );

		$requests       = $this->captured_requests();
		$delete_request = end( $requests );
		$this->assertSame( 'DELETE', $delete_request['args']['method'] ?? null );
		$this->assertStringContainsString( '/records/_acme-challenge.www/TXT', $delete_request['url'] );
		$this->assertStringContainsString( 'data=' . rawurlencode( $this->record_value() ), $delete_request['url'] );
	}

	// ── Provider-specific: discovery-stage auth failure is NOT misreported ───

	public function test_authentication_failure_during_zone_discovery_surfaces_distinctly_not_as_zone_not_found(): void {
		$provider = $this->make_provider();
		$GLOBALS['_wp_remote_post_response_queue']    = array( $this->token_response() );
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->wp_response( 401, array( 'error' => 'invalid_token' ) ),
		);

		try {
			$provider->create_txt_record( $this->fqdn(), $this->record_value() );
			$this->fail( 'expected an exception when the zone-list request is rejected with 401' );
		} catch ( \RuntimeException $e ) {
			$this->assertStringNotContainsString( 'no zone found', $e->getMessage() );
			$this->assertStringContainsString( 'HTTP 401', $e->getMessage() );
		}
	}
}
