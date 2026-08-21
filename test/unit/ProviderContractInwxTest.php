<?php
/**
 * Phase 6C, Batch 7 ("Signature and multi-step auth heavyweights"):
 * request-level contract coverage for
 * WP_SAM\Certificates\Providers\Provider_Inwx.
 *
 * Shape: JSON-RPC over wp_remote_post() (single transport, no
 * request()/request_raw() shared helper -- every call, including login,
 * always returns HTTP 200 and encodes success/failure entirely in an
 * in-band `code` field, 1000-1999 meaning success per INWX's own
 * documented convention). A memoised session-cookie pre-step: private
 * rpc() calls login() once (a sentinel empty string is assigned to
 * $cookie first so login()'s own nested rpc('account.login', ...) call
 * does not recurse), then caches whatever Set-Cookie header the login
 * response carries.
 *
 * Contrast finding, not a defect: a genuine bad-credentials login failure
 * (a `code` outside 1000-1999) makes login()'s own rpc() call throw
 * *before* zone()'s per-candidate loop -- which has no try/catch at all --
 * ever runs, so the failure propagates directly and distinctly, not
 * misreported as "no zone found". Proven by
 * test_authentication_failure_at_login_propagates_directly_not_misreported_as_zone_not_found().
 *
 * Confirmed production defect, a distinct code-level gap from the above:
 * login()'s cookie is only ever overwritten when the login response
 * actually carries a Set-Cookie header (`if ( ! empty( $set_cookie ) )`).
 * A login response with a genuine success `code` (1000) but no Set-Cookie
 * header leaves $cookie at its permanently-cached empty-string sentinel --
 * not null -- so login() is never retried for the rest of this instance's
 * lifetime, and every subsequent request carries an empty `Cookie` header.
 * [Unverified]: whether INWX's real API can actually produce this
 * combination (a documented success code with no session cookie attached)
 * for any real request path; no operation-specific authoritative evidence
 * currently confirms or rules this out. Proven at the code level by
 * test_a_cookieless_successful_login_response_permanently_disables_authentication().
 */

declare( strict_types=1 );

use WP_SAM\Certificates\Providers\Provider_Inwx;

class ProviderContractInwxTest extends Dns_Provider_Contract_TestCase {

	private function rpc_response( int $code, array $extra = array(), ?string $set_cookie = null ): array {
		$response = array(
			'response' => array( 'code' => 200 ),
			'body'     => (string) wp_json_encode( array_merge( array( 'code' => $code ), $extra ) ),
		);
		if ( null !== $set_cookie ) {
			$response['headers'] = array( 'set-cookie' => $set_cookie );
		}
		return $response;
	}

	private function login_response(): array {
		return $this->rpc_response( 1000, array(), 'inwx-session=fixture-session-id; path=/' );
	}

	protected function make_provider(): Provider_Inwx {
		return new Provider_Inwx(
			array(
				'username' => 'fixture-username',
				'password' => 'fixture-password',
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
		$GLOBALS['_wp_remote_post_response_queue'] = array(
			$this->login_response(),
			$this->rpc_response( 2303 ), // _acme-challenge.www.example.com -- not found
			$this->rpc_response( 2303 ), // www.example.com -- not found
			$this->rpc_response( 1000 ), // example.com -- found
			$this->rpc_response( 1000 ), // createRecord
		);
	}

	protected function queue_successful_delete(): void {
		// $this->cookie is already cached from the preceding create_txt_record()
		// call on the same $provider instance -- no further login request.
		$GLOBALS['_wp_remote_post_response_queue'] = array(
			$this->rpc_response( 2303 ),
			$this->rpc_response( 2303 ),
			$this->rpc_response( 1000 ),
			$this->rpc_response(
				1000,
				array( 'resData' => array( 'record' => array( array( 'id' => 9001, 'content' => $this->record_value() ) ) ) )
			), // nameserver.info
			$this->rpc_response( 1000 ), // deleteRecord
		);
	}

	protected function queue_authentication_failure(): void {
		$GLOBALS['_wp_remote_post_response_queue'] = array(
			$this->rpc_response( 2200, array( 'msg' => 'Authentication error' ) ), // account.login rejected
		);
	}

	protected function queue_zone_not_found(): void {
		$GLOBALS['_wp_remote_post_response_queue'] = array(
			$this->login_response(),
			$this->rpc_response( 2303 ),
			$this->rpc_response( 2303 ),
			$this->rpc_response( 2303 ),
		);
	}

	protected function queue_malformed_response(): void {
		$GLOBALS['_wp_remote_post_response_queue'] = array(
			$this->login_response(),
			array( 'response' => array( 'code' => 200 ), 'body' => 'not json at all {{{' ), // candidate 1
			array( 'response' => array( 'code' => 200 ), 'body' => 'not json at all {{{' ), // candidate 2
			array( 'response' => array( 'code' => 200 ), 'body' => 'not json at all {{{' ), // candidate 3
		);
	}

	protected function queue_http_failure(): void {
		$GLOBALS['_wp_remote_post_response_queue'] = array(
			$this->login_response(),
			$this->rpc_response( 2303 ),
			$this->rpc_response( 2303 ),
			$this->rpc_response( 1000 ),
			array( 'response' => array( 'code' => 500 ), 'body' => 'Internal Server Error' ), // createRecord
		);
	}

	protected function assert_authenticated_correctly( array $request ): void {
		// requests[0] for a fresh instance genuinely is the account.login
		// call itself, triggered as a side effect of the very first rpc().
		$body = json_decode( (string) ( $request['args']['body'] ?? '' ), true );
		$this->assertIsArray( $body );
		$this->assertSame( 'account.login', $body['method'] ?? null );
		$this->assertSame( 'fixture-username', $body['params']['user'] ?? null );
		$this->assertSame( 'fixture-password', $body['params']['pass'] ?? null );
	}

	protected function assert_record_naming_correct( array $create_request ): void {
		// INWX's nameserver.createRecord documents "name" as the full
		// record name (including subdomain), not a zone-relative name.
		$body = json_decode( (string) ( $create_request['args']['body'] ?? '' ), true );
		$this->assertIsArray( $body );
		$this->assertSame( 'nameserver.createRecord', $body['method'] ?? null );
		$this->assertSame( 'example.com', $body['params']['domain'] ?? null );
		$this->assertSame( $this->fqdn(), $body['params']['name'] ?? null );
		$this->assertSame( 'TXT', $body['params']['type'] ?? null );
		$this->assertSame( $this->record_value(), $body['params']['content'] ?? null );
	}

	// ── Provider-specific: session cookie is fetched once and cached ────────

	public function test_login_is_performed_once_and_cached_across_create_and_delete(): void {
		$provider = $this->make_provider();
		$this->queue_successful_create();
		$provider->create_txt_record( $this->fqdn(), $this->record_value() );

		$this->queue_successful_delete();
		$provider->delete_txt_record( $this->fqdn(), $this->record_value() );

		$login_calls = array_filter(
			$this->captured_requests(),
			function ( array $r ): bool {
				$body = json_decode( (string) ( $r['args']['body'] ?? '' ), true );
				return 'account.login' === ( $body['method'] ?? null );
			}
		);
		$this->assertCount( 1, $login_calls, 'the session-cookie pre-step must resolve once and be cached for the rest of this provider instance\'s lifetime' );
	}

	// ── Provider-specific: genuine login failure is NOT misreported (contrast) ──

	public function test_authentication_failure_at_login_propagates_directly_not_misreported_as_zone_not_found(): void {
		$provider = $this->make_provider();
		$this->queue_authentication_failure();

		try {
			$provider->create_txt_record( $this->fqdn(), $this->record_value() );
			$this->fail( 'expected an exception when account.login itself is rejected' );
		} catch ( \RuntimeException $e ) {
			$this->assertStringContainsString( 'account.login failed', $e->getMessage() );
			$this->assertStringNotContainsString( 'no zone found', $e->getMessage() );
		}

		$this->assertCount( 1, $this->captured_requests(), 'zone() never even begins -- login() throws before the first candidate is checked' );
	}

	// ── Provider-specific: confirmed cookieless-success degrades permanently ──

	public function test_a_cookieless_successful_login_response_permanently_disables_authentication(): void {
		$provider = $this->make_provider();
		$GLOBALS['_wp_remote_post_response_queue'] = array(
			$this->rpc_response( 1000 ), // login succeeds (code 1000) but carries no Set-Cookie header at all
			$this->rpc_response( 2200 ), // candidate 1 -- server sees no valid session, rejects
			$this->rpc_response( 2200 ), // candidate 2
			$this->rpc_response( 2200 ), // candidate 3
		);

		try {
			$provider->create_txt_record( $this->fqdn(), $this->record_value() );
			$this->fail( 'expected "no zone found" once every candidate is silently treated as unauthenticated' );
		} catch ( \RuntimeException $e ) {
			$this->assertStringContainsString( 'no zone found', $e->getMessage(), 'a cookieless-but-successful login degrades to the same misdiagnosis as a genuine not-found' );
		}

		// A second call on the same instance never retries login() -- the
		// empty-string sentinel is never null, so it looks "already resolved".
		$GLOBALS['_wp_remote_post_response_queue'] = array(
			$this->rpc_response( 2200 ),
			$this->rpc_response( 2200 ),
			$this->rpc_response( 2200 ),
		);
		try {
			$provider->create_txt_record( $this->fqdn(), $this->record_value() );
			$this->fail( 'expected "no zone found" again, still with no login retry' );
		} catch ( \RuntimeException $e ) {
			$this->assertStringContainsString( 'no zone found', $e->getMessage() );
		}

		$login_calls = array_filter(
			$this->captured_requests(),
			function ( array $r ): bool {
				$body = json_decode( (string) ( $r['args']['body'] ?? '' ), true );
				return 'account.login' === ( $body['method'] ?? null );
			}
		);
		$this->assertCount( 1, $login_calls, 'login() is permanently believed resolved once $cookie is any non-null value, including the empty sentinel' );
	}

	// ── Provider-specific: well-designed delete only removes the matching record ──

	public function test_delete_only_removes_the_record_whose_content_matches_the_value(): void {
		$provider = $this->make_provider();
		$this->queue_successful_create();
		$provider->create_txt_record( $this->fqdn(), $this->record_value() );

		$GLOBALS['_wp_remote_post_response_queue'] = array(
			$this->rpc_response( 2303 ),
			$this->rpc_response( 2303 ),
			$this->rpc_response( 1000 ),
			$this->rpc_response(
				1000,
				array(
					'resData' => array(
						'record' => array(
							array( 'id' => 1, 'content' => 'not-the-value' ),
							array( 'id' => 2, 'content' => $this->record_value() ),
						),
					),
				)
			),
			$this->rpc_response( 1000 ), // deleteRecord for id 2 only
		);

		$provider->delete_txt_record( $this->fqdn(), $this->record_value() );

		$requests = $this->captured_requests();
		$last     = end( $requests );
		$body     = json_decode( (string) ( $last['args']['body'] ?? '' ), true );
		$this->assertSame( 'nameserver.deleteRecord', $body['method'] ?? null );
		$this->assertSame( 2, $body['params']['id'] ?? null );
	}
}
