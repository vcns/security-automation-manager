<?php
/**
 * Representative fixture #3 for Dns_Provider_Contract_TestCase (Phase 6B):
 * a provider that performs a direct wp_remote_post() OAuth service-account
 * JWT token exchange, then all subsequent DNS operations through
 * wp_remote_request() (via the shared Dns_Provider::request() helper),
 * reusing the cached token across every call on the same instance.
 *
 * Cloudflare and Route53 (this file's siblings) each use exactly one
 * transport throughout. This fixture proves the framework's unified
 * _wp_remote_all_requests log correctly interleaves two *different* stub
 * functions in true call order, and that a provider's own token-caching
 * behaviour (headers() only exchanges once per instance) is observable
 * through it -- neither of which DeployerTest.php's wp_remote_post()
 * coverage (Phase 6A) or the single-transport fixtures above exercise.
 */

declare( strict_types=1 );

use WP_SAM\Certificates\Acme_Crypto;
use WP_SAM\Certificates\Providers\Provider_Google_Cloud;

class ProviderContractGoogleCloudTest extends Dns_Provider_Contract_TestCase {

	private static string $rsa_key;

	public static function setUpBeforeClass(): void {
		// Generated once for the whole file -- real RSA-2048 keygen, since
		// Provider_Google_Cloud's headers() signs a real JWT with
		// Acme_Crypto::sign(), which requires a key openssl can actually
		// load. Shared across every test method; nothing here is secret or
		// mutated, so reuse is safe and keeps the suite fast.
		self::$rsa_key = Acme_Crypto::generate_key( 'rsa-2048' );
	}

	private function service_account_json(): string {
		return (string) wp_json_encode(
			array(
				'client_email' => 'fixture@fixture-project.iam.gserviceaccount.com',
				'private_key'  => self::$rsa_key,
				'project_id'   => 'fixture-project',
			)
		);
	}

	private function json_response( int $code, array $body ): array {
		return array(
			'response' => array( 'code' => $code ),
			'body'     => (string) wp_json_encode( $body ),
		);
	}

	private function token_response( string $access_token = 'fixture-access-token-abc123' ): array {
		return $this->json_response( 200, array( 'access_token' => $access_token, 'expires_in' => 3600, 'token_type' => 'Bearer' ) );
	}

	protected function make_provider(): Provider_Google_Cloud {
		return new Provider_Google_Cloud( array( 'service_account_json' => $this->service_account_json() ) );
	}

	protected function fqdn(): string {
		// zone_candidates(): _acme-challenge.www.example.com, www.example.com,
		// example.com -- 3 candidates, zone found on the 3rd throughout.
		return '_acme-challenge.www.example.com';
	}

	protected function record_value(): string {
		return 'fixture-challenge-digest-value';
	}

	// ── Contract fixtures ─────────────────────────────────────────────────────
	// Every one queues the token exchange (wp_remote_post) once, then the DNS
	// operation(s) (wp_remote_request) -- matching how Provider_Google_Cloud
	// actually sequences a single create/delete call from a fresh instance.

	protected function queue_successful_create(): void {
		$GLOBALS['_wp_remote_post_response_queue'] = array( $this->token_response() );
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->json_response( 200, array( 'managedZones' => array() ) ), // _acme-challenge.www.example.com -- not found
			$this->json_response( 200, array( 'managedZones' => array() ) ), // www.example.com -- not found
			$this->json_response( 200, array( 'managedZones' => array( array( 'name' => 'example-com-zone' ) ) ) ), // example.com -- found
			$this->json_response( 200, array( 'id' => '1', 'status' => 'pending' ) ), // POST changes (create)
		);
	}

	protected function queue_successful_delete(): void {
		// No token response queued -- delete_txt_record() runs on the same
		// provider instance as the preceding create_txt_record() in the base
		// contract's own test_successful_txt_record_deletion(), so headers()
		// must reuse the already-cached token rather than exchange again.
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->json_response( 200, array( 'managedZones' => array() ) ),
			$this->json_response( 200, array( 'managedZones' => array() ) ),
			$this->json_response( 200, array( 'managedZones' => array( array( 'name' => 'example-com-zone' ) ) ) ),
			$this->json_response( 200, array( 'rrsets' => array( array( 'name' => $this->fqdn() . '.', 'type' => 'TXT', 'rrdatas' => array( '"' . $this->record_value() . '"' ) ) ) ) ), // GET existing rrsets
			$this->json_response( 200, array( 'id' => '2', 'status' => 'pending' ) ), // POST changes (delete)
		);
	}

	protected function queue_authentication_failure(): void {
		// Token exchange succeeds; the DNS API itself rejects the request --
		// matching how the Cloudflare/Route53 fixtures interpret this generic
		// contract item (an API-level auth rejection). Token-exchange-specific
		// failure modes get their own dedicated tests below, since they're a
		// behaviour only this provider's shape has.
		$GLOBALS['_wp_remote_post_response_queue'] = array( $this->token_response() );
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->json_response( 403, array( 'error' => array( 'code' => 403, 'message' => 'The caller does not have permission' ) ) ),
		);
	}

	protected function queue_zone_not_found(): void {
		$GLOBALS['_wp_remote_post_response_queue'] = array( $this->token_response() );
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->json_response( 200, array( 'managedZones' => array() ) ),
			$this->json_response( 200, array( 'managedZones' => array() ) ),
			$this->json_response( 200, array( 'managedZones' => array() ) ),
		);
	}

	protected function queue_malformed_response(): void {
		$GLOBALS['_wp_remote_post_response_queue'] = array( $this->token_response() );
		$malformed = array( 'response' => array( 'code' => 200 ), 'body' => 'not json at all {{{' );
		$GLOBALS['_wp_remote_request_response_queue'] = array( $malformed, $malformed, $malformed );
	}

	protected function queue_http_failure(): void {
		$GLOBALS['_wp_remote_post_response_queue'] = array( $this->token_response() );
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->json_response( 500, array( 'error' => array( 'code' => 500, 'message' => 'Internal error' ) ) ),
		);
	}

	protected function assert_authenticated_correctly( array $request ): void {
		// The *first* captured request is the token exchange itself -- it
		// carries no Authorization header (that's what it's requesting).
		// "Correct authentication construction" for this shape means the JWT
		// assertion was built correctly, not a header on this specific call.
		$this->assertSame( 'post', $request['transport'] );
		$this->assertStringContainsString( 'oauth2.googleapis.com/token', $request['url'] );

		$body = $request['args']['body'] ?? null;
		$this->assertIsArray( $body, 'Provider_Google_Cloud sends the token request body as a plain array (form-encoded), not JSON' );
		$this->assertSame( 'urn:ietf:params:oauth:grant-type:jwt-bearer', $body['grant_type'] ?? null );
		$assertion = (string) ( $body['assertion'] ?? '' );
		$this->assertSame( 2, substr_count( $assertion, '.' ), 'a JWT assertion must have exactly three dot-separated parts (header.claims.signature)' );
	}

	protected function assert_record_naming_correct( array $create_request ): void {
		$body = $this->decoded_body( $create_request );
		$this->assertIsArray( $body );
		$this->assertSame(
			$this->fqdn() . '.',
			$body['additions'][0]['name'] ?? null,
			'Google Cloud DNS requires a trailing dot on the full fqdn, not a zone-relative name'
		);
		$this->assertSame( 'TXT', $body['additions'][0]['type'] ?? null );
	}

	// ── Mixed-transport-specific coverage (beyond the base 10-item contract) ──

	public function test_token_request_uses_post_and_dns_operations_use_request(): void {
		$provider = $this->make_provider();
		$this->queue_successful_create();

		$provider->create_txt_record( $this->fqdn(), $this->record_value() );

		$all = $this->captured_requests();
		$this->assertSame( 'post', $all[0]['transport'], 'the token exchange must go through wp_remote_post()' );
		for ( $i = 1; $i < count( $all ); $i++ ) {
			$this->assertSame( 'request', $all[ $i ]['transport'], "request #{$i} (the DNS operations) must go through wp_remote_request()" );
		}
	}

	public function test_chronological_order_in_the_unified_request_log(): void {
		$provider = $this->make_provider();
		$this->queue_successful_create();

		$provider->create_txt_record( $this->fqdn(), $this->record_value() );

		$transports = array_column( $this->captured_requests(), 'transport' );
		$this->assertSame(
			array( 'post', 'request', 'request', 'request', 'request' ),
			$transports,
			'the token exchange must be first, and every DNS operation strictly after it, in true call order'
		);
	}

	public function test_token_is_extracted_and_used_as_bearer_auth_on_every_dns_request(): void {
		$provider = $this->make_provider();
		$this->queue_successful_create();

		$provider->create_txt_record( $this->fqdn(), $this->record_value() );

		$dns_requests = array_filter( $this->captured_requests(), static fn( array $r ): bool => 'request' === $r['transport'] );
		$this->assertNotEmpty( $dns_requests );
		foreach ( $dns_requests as $request ) {
			$this->assertSame( 'Bearer fixture-access-token-abc123', $request['args']['headers']['Authorization'] ?? null );
		}
	}

	public function test_token_is_cached_and_reused_across_a_second_operation_on_the_same_instance(): void {
		$provider = $this->make_provider();
		$this->queue_successful_create();
		$provider->create_txt_record( $this->fqdn(), $this->record_value() );

		$this->queue_successful_delete();
		$provider->delete_txt_record( $this->fqdn(), $this->record_value() );

		$token_requests = array_filter( $this->captured_requests(), static fn( array $r ): bool => 'post' === $r['transport'] );
		$this->assertCount( 1, $token_requests, 'a second operation on the same provider instance must reuse the cached token, not exchange a new one' );
	}

	public function test_token_exchange_transport_failure_is_a_clear_error(): void {
		$provider = $this->make_provider();
		$GLOBALS['_wp_remote_post_response'] = new WP_Error( 'http_request_failed', 'Connection timed out' );

		try {
			$provider->create_txt_record( $this->fqdn(), $this->record_value() );
			$this->fail( 'Expected RuntimeException was not thrown.' );
		} catch ( \RuntimeException $e ) {
			$this->assertStringContainsString( 'Google token transport error', $e->getMessage() );
		}
		$this->assertEmpty(
			array_filter( $this->captured_requests(), static fn( array $r ): bool => 'request' === $r['transport'] ),
			'no DNS operation may be attempted when the token exchange itself fails transport-level'
		);
	}

	public function test_malformed_token_response_body_is_rejected(): void {
		$provider = $this->make_provider();
		$GLOBALS['_wp_remote_post_response'] = array( 'response' => array( 'code' => 200 ), 'body' => 'not json at all {{{' );

		try {
			$provider->create_txt_record( $this->fqdn(), $this->record_value() );
			$this->fail( 'Expected RuntimeException was not thrown.' );
		} catch ( \RuntimeException $e ) {
			$this->assertStringContainsString( 'Google token request failed', $e->getMessage() );
		}
	}

	public function test_a_well_formed_token_response_missing_access_token_is_also_rejected(): void {
		// Distinct from the invalid-JSON case above: valid JSON, but not
		// shaped as a token response at all (e.g. an OAuth error body) --
		// both must be rejected the same way, not just outright-unparseable JSON.
		$provider = $this->make_provider();
		$GLOBALS['_wp_remote_post_response'] = $this->json_response( 200, array( 'error' => 'invalid_grant', 'error_description' => 'Invalid JWT Signature.' ) );

		try {
			$provider->create_txt_record( $this->fqdn(), $this->record_value() );
			$this->fail( 'Expected RuntimeException was not thrown.' );
		} catch ( \RuntimeException $e ) {
			$this->assertStringContainsString( 'Google token request failed', $e->getMessage() );
			$this->assertStringContainsString( 'invalid_grant', $e->getMessage() );
		}
	}

	public function test_dns_operation_failure_after_successful_authentication_is_distinguishable_from_a_token_failure(): void {
		$provider = $this->make_provider();
		$this->queue_http_failure(); // token succeeds; first DNS lookup returns 500

		try {
			$provider->create_txt_record( $this->fqdn(), $this->record_value() );
			$this->fail( 'Expected RuntimeException was not thrown.' );
		} catch ( \RuntimeException $e ) {
			$this->assertStringContainsString( 'API error (HTTP 500)', $e->getMessage() );
			$this->assertStringNotContainsString( 'token', strtolower( $e->getMessage() ), 'a post-authentication DNS failure must not be reported as a token/auth problem' );
		}

		$token_requests = array_filter( $this->captured_requests(), static fn( array $r ): bool => 'post' === $r['transport'] );
		$this->assertCount( 1, $token_requests, 'the token exchange must have completed successfully before the DNS operation was even attempted' );
	}
}
