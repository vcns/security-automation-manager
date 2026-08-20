<?php
/**
 * Unit tests for WP_SAM\Certificates\Acme_Client.
 *
 * All wp_remote_* calls are intercepted by test/bootstrap.php's stubs -- no
 * request ever leaves the process. Acme_Client itself does not poll or wait;
 * order/authorization polling is Certificate_Manager's responsibility (see
 * CertificateManagerTest.php), so "authorisation polling" scenarios here
 * exercise Acme_Client::fetch(), the single-fetch primitive polling is built
 * from, not a poll loop.
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;
use WP_SAM\Certificates\Acme_Client;
use WP_SAM\Certificates\Acme_Crypto;

class AcmeClientTest extends TestCase {

	private string $account_key;

	protected function setUp(): void {
		wp_test_reset_globals();
		$this->account_key = Acme_Crypto::generate_key( 'ec-256' );
	}

	private function directory_response(): array {
		return array(
			'response' => array( 'code' => 200 ),
			'body'     => (string) wp_json_encode(
				array(
					'newNonce'   => 'https://acme.test/new-nonce',
					'newAccount' => 'https://acme.test/new-account',
					'newOrder'   => 'https://acme.test/new-order',
				)
			),
		);
	}

	private function nonce_response( string $nonce = 'nonce-1' ): array {
		return array(
			'response' => array( 'code' => 200 ),
			'headers'  => array( 'replay-nonce' => $nonce ),
		);
	}

	/** Queues a directory fetch (wp_remote_get) then a nonce fetch (wp_remote_head). */
	private function prime_directory_and_nonce( string $nonce = 'nonce-1' ): void {
		$GLOBALS['_wp_remote_get_response']  = $this->directory_response();
		$GLOBALS['_wp_remote_head_response'] = $this->nonce_response( $nonce );
	}

	// ── Staging / production endpoint separation ─────────────────────────────

	public function test_directory_constants_point_at_distinct_endpoints(): void {
		$this->assertStringContainsString( 'acme-v02.api.letsencrypt.org', Acme_Client::DIRECTORY_PRODUCTION );
		$this->assertStringContainsString( 'acme-staging-v02.api.letsencrypt.org', Acme_Client::DIRECTORY_STAGING );
		$this->assertNotSame( Acme_Client::DIRECTORY_PRODUCTION, Acme_Client::DIRECTORY_STAGING );
	}

	public function test_client_fetches_directory_from_the_url_it_was_constructed_with(): void {
		$this->prime_directory_and_nonce();
		$GLOBALS['_wp_remote_post_response'] = array(
			'response' => array( 'code' => 201 ),
			'headers'  => array( 'location' => 'https://acme.test/acct/1' ),
			'body'     => '{}',
		);

		( new Acme_Client( Acme_Client::DIRECTORY_STAGING, $this->account_key ) )->register_account();

		$this->assertSame( Acme_Client::DIRECTORY_STAGING, $GLOBALS['_wp_remote_get_requests'][0]['url'] );
	}

	// ── Nonce handling ────────────────────────────────────────────────────────

	public function test_nonce_is_fetched_once_via_head_then_reused_from_the_next_response(): void {
		$this->prime_directory_and_nonce( 'first-nonce' );
		$GLOBALS['_wp_remote_post_response_queue'] = array(
			array(
				'response' => array( 'code' => 201 ),
				'headers'  => array(
					'location'     => 'https://acme.test/acct/1',
					'replay-nonce' => 'second-nonce',
				),
				'body'     => '{}',
			),
		);

		$client = new Acme_Client( Acme_Client::DIRECTORY_STAGING, $this->account_key );
		$client->register_account();

		// One HEAD for the initial nonce; the POST response's own replay-nonce
		// header is cached for the *next* signed request instead of another HEAD.
		$this->assertCount( 1, $GLOBALS['_wp_remote_head_requests'] );

		$GLOBALS['_wp_remote_post_response'] = array(
			'response' => array( 'code' => 201 ),
			'headers'  => array( 'location' => 'https://acme.test/order/1' ),
			'body'     => '{}',
		);
		$client->new_order( array( 'example.com' ) );

		$this->assertCount( 1, $GLOBALS['_wp_remote_head_requests'], 'the cached nonce from the previous response must be reused, not re-fetched' );
	}

	public function test_missing_replay_nonce_header_throws(): void {
		$GLOBALS['_wp_remote_get_response']  = $this->directory_response();
		$GLOBALS['_wp_remote_head_response'] = array( 'response' => array( 'code' => 200 ), 'headers' => array() );

		$this->expectException( RuntimeException::class );
		$this->expectExceptionMessage( 'no Replay-Nonce header' );

		( new Acme_Client( Acme_Client::DIRECTORY_STAGING, $this->account_key ) )->register_account();
	}

	// ── badNonce retry ────────────────────────────────────────────────────────

	public function test_bad_nonce_is_retried_with_the_fresh_nonce_from_the_error_response(): void {
		$this->prime_directory_and_nonce( 'stale-nonce' );
		$GLOBALS['_wp_remote_post_response_queue'] = array(
			array(
				'response' => array( 'code' => 400 ),
				'headers'  => array( 'replay-nonce' => 'fresh-nonce' ),
				'body'     => (string) wp_json_encode( array( 'type' => 'urn:ietf:params:acme:error:badNonce', 'detail' => 'stale' ) ),
			),
			array(
				'response' => array( 'code' => 201 ),
				'headers'  => array( 'location' => 'https://acme.test/acct/1' ),
				'body'     => '{}',
			),
		);

		$kid = ( new Acme_Client( Acme_Client::DIRECTORY_STAGING, $this->account_key ) )->register_account();

		$this->assertSame( 'https://acme.test/acct/1', $kid );
		$this->assertCount( 2, $GLOBALS['_wp_remote_post_requests'], 'badNonce must trigger exactly one retry' );
		// Only one HEAD: the retry reuses the nonce carried on the badNonce
		// error response itself, per RFC 8555 §6.5, rather than fetching again.
		$this->assertCount( 1, $GLOBALS['_wp_remote_head_requests'] );
	}

	public function test_bad_nonce_gives_up_after_three_attempts(): void {
		$this->prime_directory_and_nonce();
		$bad_nonce_response = array(
			'response' => array( 'code' => 400 ),
			'headers'  => array( 'replay-nonce' => 'still-bad' ),
			'body'     => (string) wp_json_encode( array( 'type' => 'urn:ietf:params:acme:error:badNonce' ) ),
		);
		// do-while: 3 attempts happen; the 3rd is not retried, so the final
		// response returned is still the 3rd badNonce -- no 4th call is made.
		$GLOBALS['_wp_remote_post_response_queue'] = array( $bad_nonce_response, $bad_nonce_response, $bad_nonce_response );

		$this->expectException( RuntimeException::class );

		( new Acme_Client( Acme_Client::DIRECTORY_STAGING, $this->account_key ) )->register_account();
	}

	// ── Account registration ──────────────────────────────────────────────────

	public function test_register_account_returns_the_location_header_as_kid(): void {
		$this->prime_directory_and_nonce();
		$GLOBALS['_wp_remote_post_response'] = array(
			'response' => array( 'code' => 201 ),
			'headers'  => array( 'location' => 'https://acme.test/acct/42' ),
			'body'     => '{}',
		);

		$kid = ( new Acme_Client( Acme_Client::DIRECTORY_STAGING, $this->account_key ) )->register_account( 'admin@example.com' );

		$this->assertSame( 'https://acme.test/acct/42', $kid );
		$sent_body = json_decode( (string) $GLOBALS['_wp_remote_post_requests'][0]['args']['body'], true );
		$payload   = json_decode( (string) base64_decode( strtr( $sent_body['payload'], '-_', '+/' ), true ), true );
		$this->assertSame( array( 'mailto:admin@example.com' ), $payload['contact'] );
		$this->assertTrue( $payload['termsOfServiceAgreed'] );
	}

	public function test_account_registration_embeds_jwk_not_kid_even_when_kid_is_set(): void {
		$this->prime_directory_and_nonce();
		$GLOBALS['_wp_remote_post_response'] = array(
			'response' => array( 'code' => 200 ),
			'headers'  => array( 'location' => 'https://acme.test/acct/1' ),
			'body'     => '{}',
		);

		$client = new Acme_Client( Acme_Client::DIRECTORY_STAGING, $this->account_key );
		$client->set_kid( 'https://acme.test/acct/preexisting' );
		$client->register_account();

		$sent_body = json_decode( (string) $GLOBALS['_wp_remote_post_requests'][0]['args']['body'], true );
		$protected = json_decode( (string) base64_decode( strtr( $sent_body['protected'], '-_', '+/' ), true ), true );
		$this->assertArrayHasKey( 'jwk', $protected, 'newAccount must always embed the full JWK, per RFC 8555 §7.3, never kid' );
		$this->assertArrayNotHasKey( 'kid', $protected );
	}

	public function test_registration_rejects_a_non_2xx_status(): void {
		$this->prime_directory_and_nonce();
		$GLOBALS['_wp_remote_post_response'] = array(
			'response' => array( 'code' => 400 ),
			'body'     => (string) wp_json_encode( array( 'detail' => 'invalid contact' ) ),
		);

		$this->expectException( RuntimeException::class );
		$this->expectExceptionMessage( 'invalid contact' );

		( new Acme_Client( Acme_Client::DIRECTORY_STAGING, $this->account_key ) )->register_account();
	}

	public function test_registration_without_location_header_throws(): void {
		$this->prime_directory_and_nonce();
		$GLOBALS['_wp_remote_post_response'] = array(
			'response' => array( 'code' => 201 ),
			'body'     => '{}',
		);

		$this->expectException( RuntimeException::class );
		$this->expectExceptionMessage( 'no Location header' );

		( new Acme_Client( Acme_Client::DIRECTORY_STAGING, $this->account_key ) )->register_account();
	}

	// ── Order creation ────────────────────────────────────────────────────────

	public function test_new_order_returns_url_and_decoded_body(): void {
		$this->prime_directory_and_nonce();
		$GLOBALS['_wp_remote_post_response'] = array(
			'response' => array( 'code' => 201 ),
			'headers'  => array( 'location' => 'https://acme.test/order/7' ),
			'body'     => (string) wp_json_encode( array( 'status' => 'pending', 'authorizations' => array( 'https://acme.test/authz/1' ) ) ),
		);

		$client = new Acme_Client( Acme_Client::DIRECTORY_STAGING, $this->account_key );
		$client->set_kid( 'https://acme.test/acct/1' );
		$order = $client->new_order( array( 'example.com', 'www.example.com' ) );

		$this->assertSame( 'https://acme.test/order/7', $order['url'] );
		$this->assertSame( array( 'https://acme.test/authz/1' ), $order['body']['authorizations'] );

		$sent_body   = json_decode( (string) $GLOBALS['_wp_remote_post_requests'][0]['args']['body'], true );
		$payload     = json_decode( (string) base64_decode( strtr( $sent_body['payload'], '-_', '+/' ), true ), true );
		$this->assertSame(
			array(
				array( 'type' => 'dns', 'value' => 'example.com' ),
				array( 'type' => 'dns', 'value' => 'www.example.com' ),
			),
			$payload['identifiers']
		);
	}

	public function test_new_order_rejects_a_non_201_status(): void {
		$this->prime_directory_and_nonce();
		$GLOBALS['_wp_remote_post_response'] = array(
			'response' => array( 'code' => 400 ),
			'body'     => (string) wp_json_encode( array( 'detail' => 'malformed identifier' ) ),
		);

		$client = new Acme_Client( Acme_Client::DIRECTORY_STAGING, $this->account_key );
		$client->set_kid( 'https://acme.test/acct/1' );

		$this->expectException( RuntimeException::class );
		$this->expectExceptionMessage( 'malformed identifier' );

		$client->new_order( array( 'example.com' ) );
	}

	// ── fetch() -- the primitive Certificate_Manager's poll loop is built on ──

	public function test_fetch_returns_decoded_body_on_success(): void {
		$this->prime_directory_and_nonce();
		$GLOBALS['_wp_remote_post_response'] = array(
			'response' => array( 'code' => 200 ),
			'body'     => (string) wp_json_encode( array( 'status' => 'valid' ) ),
		);

		$client = new Acme_Client( Acme_Client::DIRECTORY_STAGING, $this->account_key );
		$client->set_kid( 'https://acme.test/acct/1' );

		$this->assertSame( array( 'status' => 'valid' ), $client->fetch( 'https://acme.test/authz/1' ) );
	}

	public function test_fetch_throws_on_4xx_or_5xx(): void {
		$this->prime_directory_and_nonce();
		$GLOBALS['_wp_remote_post_response'] = array(
			'response' => array( 'code' => 500 ),
			'body'     => 'Internal Server Error',
		);

		$client = new Acme_Client( Acme_Client::DIRECTORY_STAGING, $this->account_key );
		$client->set_kid( 'https://acme.test/acct/1' );

		$this->expectException( RuntimeException::class );
		$this->expectExceptionMessage( 'ACME fetch failed' );

		$client->fetch( 'https://acme.test/authz/1' );
	}

	// ── Challenge completion ──────────────────────────────────────────────────

	public function test_respond_challenge_posts_an_empty_object_payload(): void {
		$this->prime_directory_and_nonce();
		$GLOBALS['_wp_remote_post_response'] = array(
			'response' => array( 'code' => 200 ),
			'body'     => (string) wp_json_encode( array( 'status' => 'pending' ) ),
		);

		$client = new Acme_Client( Acme_Client::DIRECTORY_STAGING, $this->account_key );
		$client->set_kid( 'https://acme.test/acct/1' );
		$client->respond_challenge( 'https://acme.test/challenge/1' );

		$sent_body = json_decode( (string) $GLOBALS['_wp_remote_post_requests'][0]['args']['body'], true );
		$decoded_payload = base64_decode( strtr( $sent_body['payload'], '-_', '+/' ), true );
		$this->assertSame( '{}', $decoded_payload, 'RFC 8555 §7.5.1: the challenge-ready POST carries an empty JSON object payload, distinct from POST-as-GET\'s empty string' );
	}

	public function test_respond_challenge_throws_on_error_status(): void {
		$this->prime_directory_and_nonce();
		$GLOBALS['_wp_remote_post_response'] = array(
			'response' => array( 'code' => 403 ),
			'body'     => (string) wp_json_encode( array( 'detail' => 'unauthorized' ) ),
		);

		$client = new Acme_Client( Acme_Client::DIRECTORY_STAGING, $this->account_key );
		$client->set_kid( 'https://acme.test/acct/1' );

		$this->expectException( RuntimeException::class );
		$this->expectExceptionMessage( 'unauthorized' );

		$client->respond_challenge( 'https://acme.test/challenge/1' );
	}

	// ── Certificate retrieval / finalize ──────────────────────────────────────

	public function test_finalize_sends_base64url_encoded_csr(): void {
		$this->prime_directory_and_nonce();
		$GLOBALS['_wp_remote_post_response'] = array(
			'response' => array( 'code' => 200 ),
			'body'     => (string) wp_json_encode( array( 'status' => 'valid' ) ),
		);

		$client = new Acme_Client( Acme_Client::DIRECTORY_STAGING, $this->account_key );
		$client->set_kid( 'https://acme.test/acct/1' );
		$client->finalize( 'https://acme.test/finalize/1', "der-bytes\x00\xff" );

		$sent_body = json_decode( (string) $GLOBALS['_wp_remote_post_requests'][0]['args']['body'], true );
		$payload   = json_decode( (string) base64_decode( strtr( $sent_body['payload'], '-_', '+/' ), true ), true );
		$this->assertSame( Acme_Crypto::base64url( "der-bytes\x00\xff" ), $payload['csr'] );
	}

	public function test_finalize_throws_on_error_status(): void {
		$this->prime_directory_and_nonce();
		$GLOBALS['_wp_remote_post_response'] = array(
			'response' => array( 'code' => 400 ),
			'body'     => (string) wp_json_encode( array( 'detail' => 'CSR rejected' ) ),
		);

		$client = new Acme_Client( Acme_Client::DIRECTORY_STAGING, $this->account_key );
		$client->set_kid( 'https://acme.test/acct/1' );

		$this->expectException( RuntimeException::class );
		$this->expectExceptionMessage( 'CSR rejected' );

		$client->finalize( 'https://acme.test/finalize/1', 'der-bytes' );
	}

	public function test_download_certificate_returns_raw_pem_body(): void {
		$this->prime_directory_and_nonce();
		$pem = "-----BEGIN CERTIFICATE-----\nfakecertdata\n-----END CERTIFICATE-----\n";
		$GLOBALS['_wp_remote_post_response'] = array(
			'response' => array( 'code' => 200 ),
			'body'     => $pem,
		);

		$client = new Acme_Client( Acme_Client::DIRECTORY_STAGING, $this->account_key );
		$client->set_kid( 'https://acme.test/acct/1' );

		$this->assertSame( $pem, $client->download_certificate( 'https://acme.test/cert/1' ) );
	}

	public function test_download_certificate_rejects_a_non_200_status(): void {
		$this->prime_directory_and_nonce();
		$GLOBALS['_wp_remote_post_response'] = array(
			'response' => array( 'code' => 404 ),
			'body'     => (string) wp_json_encode( array( 'detail' => 'not found' ) ),
		);

		$client = new Acme_Client( Acme_Client::DIRECTORY_STAGING, $this->account_key );
		$client->set_kid( 'https://acme.test/acct/1' );

		$this->expectException( RuntimeException::class );
		$this->expectExceptionMessage( 'certificate download failed' );

		$client->download_certificate( 'https://acme.test/cert/1' );
	}

	// ── Terminal failure states ───────────────────────────────────────────────

	public function test_transport_error_on_the_signed_post_itself_throws(): void {
		$this->prime_directory_and_nonce();
		$GLOBALS['_wp_remote_post_response'] = new WP_Error( 'http_request_failed', 'Connection timed out' );

		$this->expectException( RuntimeException::class );
		$this->expectExceptionMessage( 'ACME request transport error' );

		( new Acme_Client( Acme_Client::DIRECTORY_STAGING, $this->account_key ) )->register_account();
	}

	public function test_transport_error_fetching_the_directory_throws(): void {
		$GLOBALS['_wp_remote_get_response'] = new WP_Error( 'http_request_failed', 'DNS resolution failed' );

		$this->expectException( RuntimeException::class );
		$this->expectExceptionMessage( 'Unable to fetch ACME directory' );

		( new Acme_Client( Acme_Client::DIRECTORY_STAGING, $this->account_key ) )->register_account();
	}

	public function test_transport_error_fetching_the_nonce_throws(): void {
		$GLOBALS['_wp_remote_get_response']  = $this->directory_response();
		$GLOBALS['_wp_remote_head_response'] = new WP_Error( 'http_request_failed', 'Connection refused' );

		$this->expectException( RuntimeException::class );
		$this->expectExceptionMessage( 'Unable to fetch ACME nonce' );

		( new Acme_Client( Acme_Client::DIRECTORY_STAGING, $this->account_key ) )->register_account();
	}

	// ── Malformed / unexpected responses ──────────────────────────────────────

	public function test_directory_missing_a_required_key_throws(): void {
		$GLOBALS['_wp_remote_get_response'] = array(
			'response' => array( 'code' => 200 ),
			// No 'newAccount' key.
			'body'     => (string) wp_json_encode( array( 'newNonce' => 'https://acme.test/new-nonce' ) ),
		);
		$GLOBALS['_wp_remote_head_response'] = $this->nonce_response();

		$this->expectException( RuntimeException::class );
		$this->expectExceptionMessage( "missing 'newAccount'" );

		( new Acme_Client( Acme_Client::DIRECTORY_STAGING, $this->account_key ) )->register_account();
	}

	public function test_non_json_directory_body_is_treated_as_an_empty_directory(): void {
		$GLOBALS['_wp_remote_get_response'] = array(
			'response' => array( 'code' => 200 ),
			'body'     => 'not json at all {{{',
		);
		$GLOBALS['_wp_remote_head_response'] = $this->nonce_response();

		// json_decode() of malformed JSON yields null -> json() coerces to [] ->
		// every directory key is "missing", surfaced as the same clear error
		// as a genuinely incomplete directory, not a fatal or a silent no-op.
		$this->expectException( RuntimeException::class );
		$this->expectExceptionMessage( "missing 'newAccount'" );

		( new Acme_Client( Acme_Client::DIRECTORY_STAGING, $this->account_key ) )->register_account();
	}

	public function test_error_detail_falls_back_to_a_body_excerpt_when_no_json_detail_field_exists(): void {
		$this->prime_directory_and_nonce();
		$GLOBALS['_wp_remote_post_response'] = array(
			'response' => array( 'code' => 502 ),
			'body'     => str_repeat( 'x', 300 ), // Not JSON; no 'detail' key.
		);

		try {
			( new Acme_Client( Acme_Client::DIRECTORY_STAGING, $this->account_key ) )->register_account();
			$this->fail( 'Expected RuntimeException was not thrown.' );
		} catch ( RuntimeException $e ) {
			$this->assertStringContainsString( 'HTTP 502', $e->getMessage() );
			$this->assertStringContainsString( str_repeat( 'x', 200 ), $e->getMessage() );
			$this->assertStringNotContainsString( str_repeat( 'x', 300 ), $e->getMessage(), 'the excerpt must be truncated to 200 characters' );
		}
	}

	// ── Thumbprint ────────────────────────────────────────────────────────────

	public function test_thumbprint_is_deterministic_for_the_same_key(): void {
		$client = new Acme_Client( Acme_Client::DIRECTORY_STAGING, $this->account_key );
		$this->assertSame( $client->thumbprint(), $client->thumbprint() );
		$this->assertNotSame(
			$client->thumbprint(),
			( new Acme_Client( Acme_Client::DIRECTORY_STAGING, Acme_Crypto::generate_key( 'ec-256' ) ) )->thumbprint()
		);
	}
}
