<?php
/**
 * Unit tests for WP_SAM\Certificates\Certificate_Manager.
 *
 * Certificate_Manager instantiates Acme_Client internally (not injected), so
 * these tests drive the full ACME wire protocol through wp_remote_* stubs --
 * they are integration-flavoured unit tests of the real orchestration, not
 * mocks of Acme_Client's behaviour. Certificate_Store, Challenge_Http, and
 * Deployer are real objects backed by the same option/$wpdb stubs the rest
 * of the suite uses ('download' deployment mode avoids any filesystem/HTTP
 * side effect from Deployer itself).
 *
 * poll()'s loop sleeps 10 real seconds between non-terminal polls (18
 * attempts max) and satisfy_authorization()'s dns-01 branch sleeps a further
 * unconditional 30 seconds for propagation. Every scenario below is built so
 * the relevant poll's *first* check already satisfies the terminal condition
 * -- except the one dns-01 lifecycle test, which is deliberately slow (~30s)
 * because proving the create-TXT -> settle -> validate -> delete-in-finally
 * sequence, including cleanup on a failed validation, is worth that cost
 * once. No test here exercises poll() actually exhausting its 18 attempts
 * (18 x 10s = 180s) or DNS_SETTLE_SECONDS repeated across scenarios --
 * poll()'s timeout path is Certificate_Manager's own "authorisation
 * polling"/timeout scope per the roadmap, but is not practical to cover in
 * a suite meant to run on every PR; see the Phase 6A report for this
 * explicitly-scoped gap.
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;
use WP_SAM\Certificates\Acme_Crypto;
use WP_SAM\Certificates\Certificate_Manager;
use WP_SAM\Certificates\Certificate_Store;
use WP_SAM\Certificates\Challenge_Http;
use WP_SAM\Certificates\Credential_Vault;
use WP_SAM\Certificates\Deployer;
use WP_SAM\Modules\Audit_Log;

class CertificateManagerTest extends TestCase {

	private Certificate_Store $store;
	private Challenge_Http $http_challenge;
	private Deployer $deployer;
	private Certificate_Manager $manager;

	protected function setUp(): void {
		wp_test_reset_globals();
		$GLOBALS['_wpdb_get_var'] = $GLOBALS['wpdb']->prefix . 'sam_audit_log'; // Audit_Log::write_to_db()'s table-exists guard.

		$this->store          = new Certificate_Store();
		$this->http_challenge = new Challenge_Http();
		$this->deployer       = new Deployer( new Audit_Log() );
		$this->manager         = new Certificate_Manager( $this->store, $this->http_challenge, $this->deployer, new Audit_Log() );
	}

	private function base_config( array $overrides = array() ): array {
		return array_merge(
			array(
				'domains'        => array( 'example.com' ),
				'contact_email'  => '',
				'provider'       => '',
				'challenge'      => 'http-01',
				'key_type'       => 'ec-256',
				'staging'        => true,
				'deployment'     => 'download',
				'custom_key_pem' => '',
				'dns_credentials' => array(),
			),
			$overrides
		);
	}

	private function json_response( int $code, array $body, array $extra_headers = array() ): array {
		return array(
			'response' => array( 'code' => $code ),
			'headers'  => array_merge( array( 'replay-nonce' => 'n-' . bin2hex( random_bytes( 4 ) ) ), $extra_headers ),
			'body'     => (string) wp_json_encode( $body ),
		);
	}

	/**
	 * Queues the full happy-path ACME response sequence for one order:
	 * (optionally) newAccount, newOrder, fetch authz, respond challenge,
	 * poll authz (valid on first check), poll order (ready on first check),
	 * finalize, poll order again (valid on first check), download.
	 */
	private function queue_happy_path( string $challenge_type = 'http-01', bool $needs_account = true ): void {
		$GLOBALS['_wp_remote_get_response'] = array(
			'response' => array( 'code' => 200 ),
			'body'     => (string) wp_json_encode(
				array(
					'newNonce'   => 'https://acme.test/new-nonce',
					'newAccount' => 'https://acme.test/new-account',
					'newOrder'   => 'https://acme.test/new-order',
				)
			),
		);
		$GLOBALS['_wp_remote_head_response'] = array(
			'response' => array( 'code' => 200 ),
			'headers'  => array( 'replay-nonce' => 'first-nonce' ),
		);

		$challenge = 'dns-01' === $challenge_type
			? array( 'type' => 'dns-01', 'token' => 'chal-token', 'url' => 'https://acme.test/chal/1' )
			: array( 'type' => 'http-01', 'token' => 'chal-token', 'url' => 'https://acme.test/chal/1' );

		$queue = array();
		if ( $needs_account ) {
			$queue[] = $this->json_response( 201, array(), array( 'location' => 'https://acme.test/acct/1' ) );
		}
		$queue[] = $this->json_response( 201, array( 'authorizations' => array( 'https://acme.test/authz/1' ) ), array( 'location' => 'https://acme.test/order/1' ) );
		$queue[] = $this->json_response( 200, array( 'status' => 'pending', 'identifier' => array( 'value' => 'example.com' ), 'challenges' => array( $challenge ) ) ); // fetch authz
		$queue[] = $this->json_response( 200, array() ); // respond_challenge
		$queue[] = $this->json_response( 200, array( 'status' => 'valid' ) ); // poll authz (validate_challenge)
		$queue[] = $this->json_response( 200, array( 'status' => 'ready', 'finalize' => 'https://acme.test/finalize/1' ) ); // poll order (pre-finalize)
		$queue[] = $this->json_response( 200, array() ); // finalize
		$queue[] = $this->json_response( 200, array( 'status' => 'valid', 'certificate' => 'https://acme.test/cert/1' ) ); // poll order (post-finalize)
		$queue[] = array(
			'response' => array( 'code' => 200 ),
			'headers'  => array( 'replay-nonce' => 'n-final' ),
			'body'     => "-----BEGIN CERTIFICATE-----\nfakeleafcertdata\n-----END CERTIFICATE-----\n",
		); // download_certificate

		$GLOBALS['_wp_remote_post_response_queue'] = $queue;
	}

	// ── No domains configured ─────────────────────────────────────────────────

	public function test_issue_with_no_domains_records_failure_and_makes_no_requests(): void {
		$this->store->save_config( $this->base_config( array( 'domains' => array() ) ) );

		$this->manager->issue();

		$this->assertSame( 'failed', $this->manager->last_run()['status'] );
		$this->assertSame( 'No domains configured.', $this->manager->last_run()['detail'] );
		$this->assertEmpty( $GLOBALS['_wp_remote_get_requests'] );
		$this->assertEmpty( $GLOBALS['_wp_remote_post_requests'] );
	}

	// ── Successful issuance orchestration ─────────────────────────────────────

	public function test_successful_issuance_records_success_and_stores_the_certificate(): void {
		$this->store->save_config( $this->base_config() );
		$this->queue_happy_path( 'http-01', true );

		$this->manager->issue();

		$this->assertSame( 'success', $this->manager->last_run()['status'] );
		$this->assertStringContainsString( 'example.com', $this->manager->last_run()['detail'] );

		// The stub $wpdb doesn't correlate insert() with a later get_row() --
		// they're independent canned calls -- so inspect what was actually
		// passed to insert() rather than reading it back through a second,
		// disconnected stub call.
		$inserted = array_values(
			array_filter(
				$GLOBALS['_wpdb_inserted_rows'],
				static fn( array $row ): bool => str_contains( $row['table'], 'sam_certificates' )
			)
		);
		$this->assertCount( 1, $inserted );
		$this->assertSame( '["example.com"]', $inserted[0]['data']['domains'] );
		$this->assertStringContainsString( 'fakeleafcertdata', $inserted[0]['data']['fullchain_pem'] );
		$this->assertTrue( Credential_Vault::is_sealed( $inserted[0]['data']['key_pem'] ), 'the generated private key must be sealed before storage' );
	}

	public function test_successful_issuance_logs_to_the_audit_log(): void {
		$this->store->save_config( $this->base_config() );
		$this->queue_happy_path( 'http-01', true );

		$this->manager->issue();

		$logged = array_filter(
			$GLOBALS['_wpdb_inserted_rows'],
			static fn( array $row ): bool => str_contains( $row['table'], 'sam_audit_log' ) && 'cert_issued' === $row['data']['event']
		);
		$this->assertNotEmpty( $logged );
	}

	// ── Certificate and account-key handling ──────────────────────────────────

	public function test_an_existing_account_kid_is_reused_without_re_registering(): void {
		// Seed an account with a kid already set, as if a previous run registered it.
		$this->store->get_account( 'staging' );
		$this->store->save_account_kid( 'staging', 'https://acme.test/acct/existing' );

		$this->store->save_config( $this->base_config() );
		$this->queue_happy_path( 'http-01', false ); // no newAccount step queued

		$this->manager->issue();

		$this->assertSame( 'success', $this->manager->last_run()['status'] );
		// Every queued response was consumed in order with no extra newAccount
		// call inserted -- if register_account() had run anyway, the queue
		// would have been misaligned and a later step would have failed
		// against the wrong canned response, so 'success' here already proves
		// it. Assert explicitly for clarity.
		$this->assertEmpty( $GLOBALS['_wp_remote_post_response_queue'], 'exactly the queued happy-path responses, no more, no fewer, must have been consumed' );
	}

	public function test_a_custom_private_key_is_used_instead_of_generating_one(): void {
		$custom_key = Acme_Crypto::generate_key( 'ec-256' );

		$this->store->save_config( $this->base_config( array( 'custom_key_pem' => $custom_key ) ) );
		$this->queue_happy_path( 'http-01', true );

		$this->manager->issue();

		$this->assertSame( 'success', $this->manager->last_run()['status'] );
		$inserted = array_values(
			array_filter(
				$GLOBALS['_wpdb_inserted_rows'],
				static fn( array $row ): bool => str_contains( $row['table'], 'sam_certificates' )
			)
		);
		// run_order() trims the configured key before use, so compare against
		// the trimmed form -- confirmed correct, not a bug, since Deployer/
		// Certificate_Store treat PEM content, not exact whitespace, as what
		// matters.
		$this->assertSame( trim( $custom_key ), Credential_Vault::open( $inserted[0]['data']['key_pem'] ), 'the configured custom key, not a freshly generated one, must be what was sealed and stored' );
	}

	public function test_an_invalid_custom_private_key_fails_before_any_order_is_finalized(): void {
		$this->store->save_config( $this->base_config( array( 'custom_key_pem' => 'not a real PEM key at all' ) ) );
		$this->queue_happy_path( 'http-01', true );

		$this->manager->issue();

		$this->assertSame( 'failed', $this->manager->last_run()['status'] );
		$this->assertStringContainsString( 'could not be loaded', $this->manager->last_run()['detail'] );
	}

	// ── Failure recording / exception-to-diagnostic mapping ──────────────────

	public function test_a_rejected_order_records_the_acme_error_detail_as_the_failure(): void {
		$this->store->save_config( $this->base_config() );

		$GLOBALS['_wp_remote_get_response']  = array(
			'response' => array( 'code' => 200 ),
			'body'     => (string) wp_json_encode( array( 'newNonce' => 'https://acme.test/new-nonce', 'newAccount' => 'https://acme.test/new-account', 'newOrder' => 'https://acme.test/new-order' ) ),
		);
		$GLOBALS['_wp_remote_head_response'] = array( 'response' => array( 'code' => 200 ), 'headers' => array( 'replay-nonce' => 'n' ) );
		$GLOBALS['_wp_remote_post_response_queue'] = array(
			$this->json_response( 201, array(), array( 'location' => 'https://acme.test/acct/1' ) ), // register_account
			$this->json_response( 400, array( 'detail' => 'too many certificates already issued for this domain' ) ), // newOrder rejected
		);

		$this->manager->issue();

		$this->assertSame( 'failed', $this->manager->last_run()['status'] );
		$this->assertStringContainsString( 'too many certificates already issued', $this->manager->last_run()['detail'] );
	}

	public function test_a_transport_error_is_recorded_as_a_failure_not_an_uncaught_exception(): void {
		$this->store->save_config( $this->base_config() );
		$GLOBALS['_wp_remote_get_response'] = new WP_Error( 'http_request_failed', 'Could not resolve host' );

		// issue() must never let a Throwable escape -- it's called from a cron
		// context with no request to report a fatal error to.
		$this->manager->issue();

		$this->assertSame( 'failed', $this->manager->last_run()['status'] );
		$this->assertStringContainsString( 'Could not resolve host', $this->manager->last_run()['detail'] );
	}

	public function test_no_usable_challenge_for_a_wildcard_without_a_dns_provider_fails_clearly(): void {
		$this->store->save_config( $this->base_config( array( 'domains' => array( '*.example.com' ), 'challenge' => 'http-01', 'provider' => '' ) ) );

		$GLOBALS['_wp_remote_get_response']  = array(
			'response' => array( 'code' => 200 ),
			'body'     => (string) wp_json_encode( array( 'newNonce' => 'https://acme.test/new-nonce', 'newAccount' => 'https://acme.test/new-account', 'newOrder' => 'https://acme.test/new-order' ) ),
		);
		$GLOBALS['_wp_remote_head_response'] = array( 'response' => array( 'code' => 200 ), 'headers' => array( 'replay-nonce' => 'n' ) );
		$GLOBALS['_wp_remote_post_response_queue'] = array(
			$this->json_response( 201, array(), array( 'location' => 'https://acme.test/acct/1' ) ),
			$this->json_response( 201, array( 'authorizations' => array( 'https://acme.test/authz/1' ) ), array( 'location' => 'https://acme.test/order/1' ) ),
			$this->json_response(
				200,
				array(
					'status'     => 'pending',
					'identifier' => array( 'value' => '*.example.com' ),
					'wildcard'   => true,
					'challenges' => array( array( 'type' => 'http-01', 'token' => 't', 'url' => 'https://acme.test/chal/1' ) ),
				)
			),
		);

		$this->manager->issue();

		$this->assertSame( 'failed', $this->manager->last_run()['status'] );
		$this->assertStringContainsString( 'No usable challenge', $this->manager->last_run()['detail'] );
		$this->assertStringContainsString( 'Wildcards require a DNS provider', $this->manager->last_run()['detail'] );
	}

	public function test_an_unconfigured_dns_provider_fails_clearly(): void {
		$this->store->save_config( $this->base_config( array( 'challenge' => 'dns-01', 'provider' => 'not-a-real-provider' ) ) );

		$GLOBALS['_wp_remote_get_response']  = array(
			'response' => array( 'code' => 200 ),
			'body'     => (string) wp_json_encode( array( 'newNonce' => 'https://acme.test/new-nonce', 'newAccount' => 'https://acme.test/new-account', 'newOrder' => 'https://acme.test/new-order' ) ),
		);
		$GLOBALS['_wp_remote_head_response'] = array( 'response' => array( 'code' => 200 ), 'headers' => array( 'replay-nonce' => 'n' ) );
		$GLOBALS['_wp_remote_post_response_queue'] = array(
			$this->json_response( 201, array(), array( 'location' => 'https://acme.test/acct/1' ) ),
			$this->json_response( 201, array( 'authorizations' => array( 'https://acme.test/authz/1' ) ), array( 'location' => 'https://acme.test/order/1' ) ),
			$this->json_response(
				200,
				array(
					'status'     => 'pending',
					'identifier' => array( 'value' => 'example.com' ),
					'challenges' => array( array( 'type' => 'dns-01', 'token' => 't', 'url' => 'https://acme.test/chal/1' ) ),
				)
			),
		);

		$this->manager->issue();

		$this->assertSame( 'failed', $this->manager->last_run()['status'] );
		$this->assertStringContainsString( 'Configured DNS provider is not available', $this->manager->last_run()['detail'] );
	}

	// ── Cleanup after partially completed operations ──────────────────────────

	public function test_http_challenge_token_is_deleted_even_when_validation_fails(): void {
		$this->store->save_config( $this->base_config() );

		$GLOBALS['_wp_remote_get_response']  = array(
			'response' => array( 'code' => 200 ),
			'body'     => (string) wp_json_encode( array( 'newNonce' => 'https://acme.test/new-nonce', 'newAccount' => 'https://acme.test/new-account', 'newOrder' => 'https://acme.test/new-order' ) ),
		);
		$GLOBALS['_wp_remote_head_response'] = array( 'response' => array( 'code' => 200 ), 'headers' => array( 'replay-nonce' => 'n' ) );
		$GLOBALS['_wp_remote_post_response_queue'] = array(
			$this->json_response( 201, array(), array( 'location' => 'https://acme.test/acct/1' ) ),
			$this->json_response( 201, array( 'authorizations' => array( 'https://acme.test/authz/1' ) ), array( 'location' => 'https://acme.test/order/1' ) ),
			$this->json_response(
				200,
				array(
					'status'     => 'pending',
					'identifier' => array( 'value' => 'example.com' ),
					'challenges' => array( array( 'type' => 'http-01', 'token' => 'chal-token', 'url' => 'https://acme.test/chal/1' ) ),
				)
			),
			$this->json_response( 200, array() ), // respond_challenge succeeds
			$this->json_response( 200, array( 'status' => 'invalid', 'challenges' => array( array( 'error' => array( 'detail' => 'CA could not reach the token' ) ) ) ) ), // poll authz: invalid
		);

		$this->manager->issue();

		$this->assertSame( 'failed', $this->manager->last_run()['status'] );
		$this->assertStringContainsString( 'CA could not reach the token', $this->manager->last_run()['detail'] );
		$this->assertArrayNotHasKey(
			'chal-token',
			$GLOBALS['_wp_options']['wp_sam_acme_http_tokens'] ?? array(),
			'the token must be deleted in the finally block even though validation failed'
		);
	}

	// ── maybe_renew() ─────────────────────────────────────────────────────────

	public function test_maybe_renew_skips_staging_certificates(): void {
		$this->store->save_config( $this->base_config( array( 'staging' => true ) ) );

		$this->manager->maybe_renew();

		$this->assertSame( 'never', $this->manager->last_run()['status'], 'staging certificates are never auto-renewed' );
		$this->assertEmpty( $GLOBALS['_wp_remote_get_requests'] );
	}

	public function test_maybe_renew_skips_when_no_domains_are_configured(): void {
		$this->store->save_config( $this->base_config( array( 'staging' => false, 'domains' => array() ) ) );

		$this->manager->maybe_renew();

		$this->assertSame( 'never', $this->manager->last_run()['status'] );
	}

	public function test_maybe_renew_does_nothing_when_outside_the_renewal_window(): void {
		$this->store->save_config( $this->base_config( array( 'staging' => false ) ) );
		// A production certificate that expires in 60 days -- outside the 30-day window.
		$GLOBALS['_wpdb_get_row'] = array(
			'id'            => 1,
			'domains'       => (string) wp_json_encode( array( 'example.com' ) ),
			'environment'   => 'production',
			'key_pem'       => '',
			'fullchain_pem' => 'x',
			'not_before'    => gmdate( 'Y-m-d H:i:s', time() - DAY_IN_SECONDS ),
			'not_after'     => gmdate( 'Y-m-d H:i:s', time() + ( 60 * DAY_IN_SECONDS ) ),
		);

		$this->manager->maybe_renew();

		$this->assertSame( 'never', $this->manager->last_run()['status'] );
		$this->assertEmpty( $GLOBALS['_wp_remote_get_requests'] );
	}

	public function test_maybe_renew_issues_when_inside_the_renewal_window(): void {
		$this->store->save_config( $this->base_config( array( 'staging' => false ) ) );
		// A production certificate that expires in 10 days -- inside the 30-day window.
		$GLOBALS['_wpdb_get_row'] = array(
			'id'            => 1,
			'domains'       => (string) wp_json_encode( array( 'example.com' ) ),
			'environment'   => 'production',
			'key_pem'       => '',
			'fullchain_pem' => 'x',
			'not_before'    => gmdate( 'Y-m-d H:i:s', time() - ( 80 * DAY_IN_SECONDS ) ),
			'not_after'     => gmdate( 'Y-m-d H:i:s', time() + ( 10 * DAY_IN_SECONDS ) ),
		);
		$this->queue_happy_path( 'http-01', true );

		$this->manager->maybe_renew();

		$this->assertSame( 'success', $this->manager->last_run()['status'] );
	}

	// ── DNS-01: provider transport failure ────────────────────────────────────

	/**
	 * Uses the real RFC 2136 driver specifically to prove a DNS provider that
	 * is configured but genuinely unreachable is recorded as a failed run,
	 * via Certificate_Manager's normal exception-to-diagnostic path -- no
	 * seam or fake needed for this one, since the failure happens before any
	 * TXT record is created.
	 *
	 * This test performs one real, local TCP connection attempt to
	 * 127.0.0.1:1 (a reserved/unassigned port). The OS refuses it
	 * immediately (no listener); no DNS query is ever sent or received, and
	 * nothing leaves the local machine. See the Phase 6A report for why this
	 * one call isn't intercepted the way wp_remote_* calls are: RFC 2136
	 * speaks raw DNS over a socket, not HTTP.
	 *
	 * The full create -> settle -> validate -> delete-in-finally lifecycle,
	 * including cleanup after both successful and failed validation and
	 * cleanup-itself-failing, is covered separately below using a fake,
	 * in-memory Dns_Provider double via resolve_dns_provider() -- not this
	 * real driver, and with no network calls of any kind.
	 */
	public function test_dns_provider_transport_failure_is_recorded_as_a_failed_run(): void {
		$this->store->save_config(
			$this->base_config(
				array(
					'challenge'       => 'dns-01',
					'provider'        => 'rfc2136',
					'dns_credentials' => array(
						'server'    => '127.0.0.1:1', // Reserved/unassigned port -- connection refused immediately, no real DNS traffic.
						'zone'      => 'example.com',
						'key_name'  => 'k',
						'secret'    => base64_encode( 'x' ),
						'algorithm' => 'hmac-sha256',
					),
				)
			)
		);

		$GLOBALS['_wp_remote_get_response']  = array(
			'response' => array( 'code' => 200 ),
			'body'     => (string) wp_json_encode( array( 'newNonce' => 'https://acme.test/new-nonce', 'newAccount' => 'https://acme.test/new-account', 'newOrder' => 'https://acme.test/new-order' ) ),
		);
		$GLOBALS['_wp_remote_head_response'] = array( 'response' => array( 'code' => 200 ), 'headers' => array( 'replay-nonce' => 'n' ) );
		$GLOBALS['_wp_remote_post_response_queue'] = array(
			$this->json_response( 201, array(), array( 'location' => 'https://acme.test/acct/1' ) ),
			$this->json_response( 201, array( 'authorizations' => array( 'https://acme.test/authz/1' ) ), array( 'location' => 'https://acme.test/order/1' ) ),
			$this->json_response(
				200,
				array(
					'status'     => 'pending',
					'identifier' => array( 'value' => 'example.com' ),
					'challenges' => array( array( 'type' => 'dns-01', 'token' => 'dns-chal-token', 'url' => 'https://acme.test/chal/1' ) ),
				)
			),
		);

		$this->manager->issue();

		$this->assertSame( 'failed', $this->manager->last_run()['status'] );
		$this->assertStringContainsString( 'RFC 2136', $this->manager->last_run()['detail'] );
	}

	// ── Production defaults, unchanged by the testability seam ────────────────

	public function test_production_polling_and_settlement_defaults_are_unchanged(): void {
		$reflection = new ReflectionClass( Certificate_Manager::class );

		$this->assertSame( 18, $reflection->getConstant( 'MAX_POLLS' ) );
		$this->assertSame( 30, $reflection->getConstant( 'DNS_SETTLE_SECONDS' ) );

		// The un-overridden protected methods must still report exactly the
		// production defaults -- proves the seam is a pure pass-through, not
		// a behaviour change, for any caller that doesn't subclass.
		$plain = new Certificate_Manager( $this->store, $this->http_challenge, $this->deployer, new Audit_Log() );
		$exposed = new class( $this->store, $this->http_challenge, $this->deployer, new Audit_Log() ) extends Certificate_Manager {
			public function expose_poll_max_attempts(): int {
				return $this->poll_max_attempts();
			}
		};
		$this->assertSame( 18, $exposed->expose_poll_max_attempts() );
	}

	// ── Genuine polling timeout (fast: attempts/interval overridden) ─────────

	public function test_polling_stops_after_the_configured_maximum_attempts_and_records_the_timeout(): void {
		$manager = new Certificate_Manager_Test_Double( $this->store, $this->http_challenge, $this->deployer, new Audit_Log() );
		$manager->poll_max_attempts_override = 3;

		$this->store->save_config( $this->base_config() );

		$GLOBALS['_wp_remote_get_response'] = array(
			'response' => array( 'code' => 200 ),
			'body'     => (string) wp_json_encode( array( 'newNonce' => 'https://acme.test/new-nonce', 'newAccount' => 'https://acme.test/new-account', 'newOrder' => 'https://acme.test/new-order' ) ),
		);
		$GLOBALS['_wp_remote_head_response'] = array( 'response' => array( 'code' => 200 ), 'headers' => array( 'replay-nonce' => 'n' ) );

		$pending_authz = $this->json_response(
			200,
			array(
				'status'     => 'pending',
				'identifier' => array( 'value' => 'example.com' ),
				'challenges' => array( array( 'type' => 'http-01', 'token' => 'chal-token', 'url' => 'https://acme.test/chal/1' ) ),
			)
		);
		$queue = array(
			$this->json_response( 201, array(), array( 'location' => 'https://acme.test/acct/1' ) ), // register
			$this->json_response( 201, array( 'authorizations' => array( 'https://acme.test/authz/1' ) ), array( 'location' => 'https://acme.test/order/1' ) ), // new_order
			$pending_authz, // satisfy_authorization's own fetch
			$this->json_response( 200, array() ), // respond_challenge
		);
		// poll_max_attempts_override attempts, every one still 'pending' -- the
		// loop must never see a terminal status, so it genuinely exhausts.
		for ( $i = 0; $i < 3; $i++ ) {
			$queue[] = $pending_authz;
		}
		$GLOBALS['_wp_remote_post_response_queue'] = $queue;

		$manager->issue();

		$this->assertSame( 'failed', $manager->last_run()['status'] );
		$this->assertStringContainsString( 'ACME polling timed out', $manager->last_run()['detail'] );
		$this->assertStringContainsString( 'validation for example.com timed out', $manager->last_run()['detail'] );

		// 3 "fetch" calls total for the poll loop itself: register + new_order
		// + satisfy_authorization's own fetch + respond_challenge = 4 prior
		// POSTs, then exactly 3 more poll fetches, then stop -- no 4th poll
		// fetch, i.e. no request beyond what was queued.
		$this->assertCount( 7, $GLOBALS['_wp_remote_post_requests'], 'no fetch beyond the configured maximum attempts may occur' );
		$this->assertSame( 3, $manager->wait_between_polls_calls, 'a wait must happen after each non-terminal poll, and not after the final, still-failing one is followed by giving up' );
	}

	// ── DNS-01 cleanup lifecycle (fake provider; settlement wait suppressed) ──

	private function queue_up_to_dns_challenge_response(): void {
		$GLOBALS['_wp_remote_get_response'] = array(
			'response' => array( 'code' => 200 ),
			'body'     => (string) wp_json_encode( array( 'newNonce' => 'https://acme.test/new-nonce', 'newAccount' => 'https://acme.test/new-account', 'newOrder' => 'https://acme.test/new-order' ) ),
		);
		$GLOBALS['_wp_remote_head_response'] = array( 'response' => array( 'code' => 200 ), 'headers' => array( 'replay-nonce' => 'n' ) );
		$GLOBALS['_wp_remote_post_response_queue'] = array(
			$this->json_response( 201, array(), array( 'location' => 'https://acme.test/acct/1' ) ),
			$this->json_response( 201, array( 'authorizations' => array( 'https://acme.test/authz/1' ) ), array( 'location' => 'https://acme.test/order/1' ) ),
			$this->json_response(
				200,
				array(
					'status'     => 'pending',
					'identifier' => array( 'value' => 'example.com' ),
					'challenges' => array( array( 'type' => 'dns-01', 'token' => 'dns-chal-token', 'url' => 'https://acme.test/chal/1' ) ),
				)
			),
			$this->json_response( 200, array() ), // respond_challenge
		);
	}

	public function test_dns_record_is_created_then_deleted_after_successful_validation(): void {
		$manager = new Certificate_Manager_Test_Double( $this->store, $this->http_challenge, $this->deployer, new Audit_Log() );
		$fake    = new Fake_Dns_Provider( array() );
		$manager->fake_dns_provider = $fake;

		$this->store->save_config( $this->base_config( array( 'challenge' => 'dns-01', 'provider' => 'fake' ) ) );
		$this->queue_up_to_dns_challenge_response();
		// poll authz -> valid on first check; poll order (ready) -> finalize -> poll order (valid) -> download.
		$GLOBALS['_wp_remote_post_response_queue'] = array_merge(
			$GLOBALS['_wp_remote_post_response_queue'],
			array(
				$this->json_response( 200, array( 'status' => 'valid' ) ),
				$this->json_response( 200, array( 'status' => 'ready', 'finalize' => 'https://acme.test/finalize/1' ) ),
				$this->json_response( 200, array() ),
				$this->json_response( 200, array( 'status' => 'valid', 'certificate' => 'https://acme.test/cert/1' ) ),
				array( 'response' => array( 'code' => 200 ), 'headers' => array( 'replay-nonce' => 'n-final' ), 'body' => "-----BEGIN CERTIFICATE-----\nfakecert\n-----END CERTIFICATE-----\n" ),
			)
		);

		$manager->issue();

		$this->assertSame( 'success', $manager->last_run()['status'] );
		$this->assertCount( 1, $fake->created );
		$this->assertSame( '_acme-challenge.example.com', $fake->created[0]['fqdn'] );
		$this->assertCount( 1, $fake->deleted, 'the record must be deleted once validation succeeds' );
		$this->assertSame( $fake->created[0]['value'], $fake->deleted[0]['value'], 'the same value that was created must be what gets deleted' );
		$this->assertSame( 1, $manager->wait_for_dns_settle_calls, 'the settlement wait must still be invoked once (suppressed, not skipped)' );
	}

	public function test_dns_record_is_deleted_from_finally_even_when_validation_fails(): void {
		$manager = new Certificate_Manager_Test_Double( $this->store, $this->http_challenge, $this->deployer, new Audit_Log() );
		$fake    = new Fake_Dns_Provider( array() );
		$manager->fake_dns_provider = $fake;

		$this->store->save_config( $this->base_config( array( 'challenge' => 'dns-01', 'provider' => 'fake' ) ) );
		$this->queue_up_to_dns_challenge_response();
		$GLOBALS['_wp_remote_post_response_queue'][] = $this->json_response(
			200,
			array( 'status' => 'invalid', 'challenges' => array( array( 'error' => array( 'detail' => 'incorrect TXT record' ) ) ) )
		);

		$manager->issue();

		$this->assertSame( 'failed', $manager->last_run()['status'] );
		$this->assertStringContainsString( 'incorrect TXT record', $manager->last_run()['detail'], 'the primary issuance failure must be recorded, not hidden or replaced' );
		$this->assertCount( 1, $fake->created );
		$this->assertCount( 1, $fake->deleted, 'cleanup must still run from the finally block on a failed validation' );
	}

	public function test_a_cleanup_failure_does_not_hide_the_primary_validation_failure(): void {
		$manager = new Certificate_Manager_Test_Double( $this->store, $this->http_challenge, $this->deployer, new Audit_Log() );
		$fake    = new Fake_Dns_Provider( array() );
		$fake->throw_on_delete = true;
		$manager->fake_dns_provider = $fake;

		$this->store->save_config( $this->base_config( array( 'challenge' => 'dns-01', 'provider' => 'fake' ) ) );
		$this->queue_up_to_dns_challenge_response();
		$GLOBALS['_wp_remote_post_response_queue'][] = $this->json_response(
			200,
			array( 'status' => 'invalid', 'challenges' => array( array( 'error' => array( 'detail' => 'incorrect TXT record' ) ) ) )
		);

		$manager->issue();

		// Documented, deliberate diagnostic policy (satisfy_authorization()'s
		// own comment: "Cleanup failure must not mask the validation outcome;
		// a stale TXT record is cosmetic") -- the *validation* failure is
		// what gets recorded, and a delete_txt_record() failure on top of it
		// is silently absorbed rather than overwriting or appending to that
		// message. This test exists to catch a future change to that policy,
		// not to argue for a different one.
		$this->assertSame( 'failed', $manager->last_run()['status'] );
		$this->assertSame( 'incorrect TXT record', $manager->last_run()['detail'], 'a cleanup failure on top of a validation failure must not change the recorded diagnostic' );
	}

	public function test_a_cleanup_failure_after_a_successful_validation_does_not_turn_success_into_failure(): void {
		$manager = new Certificate_Manager_Test_Double( $this->store, $this->http_challenge, $this->deployer, new Audit_Log() );
		$fake    = new Fake_Dns_Provider( array() );
		$fake->throw_on_delete = true;
		$manager->fake_dns_provider = $fake;

		$this->store->save_config( $this->base_config( array( 'challenge' => 'dns-01', 'provider' => 'fake' ) ) );
		$this->queue_up_to_dns_challenge_response();
		$GLOBALS['_wp_remote_post_response_queue'] = array_merge(
			$GLOBALS['_wp_remote_post_response_queue'],
			array(
				$this->json_response( 200, array( 'status' => 'valid' ) ),
				$this->json_response( 200, array( 'status' => 'ready', 'finalize' => 'https://acme.test/finalize/1' ) ),
				$this->json_response( 200, array() ),
				$this->json_response( 200, array( 'status' => 'valid', 'certificate' => 'https://acme.test/cert/1' ) ),
				array( 'response' => array( 'code' => 200 ), 'headers' => array( 'replay-nonce' => 'n-final' ), 'body' => "-----BEGIN CERTIFICATE-----\nfakecert\n-----END CERTIFICATE-----\n" ),
			)
		);

		$manager->issue();

		$this->assertSame( 'success', $manager->last_run()['status'], 'a cosmetic cleanup failure after real success must not be recorded as a failed issuance' );
		$this->assertCount( 0, $fake->deleted, 'delete was attempted but threw, so nothing was recorded as deleted' );
	}
}

/**
 * In-memory Dns_Provider double for the DNS-01 cleanup-lifecycle tests --
 * makes no network call of any kind. Injected via
 * Certificate_Manager_Test_Double::$fake_dns_provider.
 */
final class Fake_Dns_Provider extends WP_SAM\Certificates\Dns_Provider {

	/** @var array<int,array{fqdn:string,value:string}> */
	public array $created = array();

	/** @var array<int,array{fqdn:string,value:string}> */
	public array $deleted = array();

	public bool $throw_on_delete = false;

	public static function label(): string {
		return 'Fake (test double)';
	}

	public static function fields(): array {
		return array();
	}

	public function create_txt_record( string $fqdn, string $value ): void {
		$this->created[] = array(
			'fqdn'  => $fqdn,
			'value' => $value,
		);
	}

	public function delete_txt_record( string $fqdn, string $value ): void {
		if ( $this->throw_on_delete ) {
			throw new \RuntimeException( 'Fake provider: delete_txt_record failed (simulated).' );
		}
		$this->deleted[] = array(
			'fqdn'  => $fqdn,
			'value' => $value,
		);
	}
}

/**
 * Certificate_Manager subclass exposing its real-time-waiting and DNS-
 * provider-resolution seams for tests. Every overridden method defaults to
 * calling straight through to the parent's production behaviour when the
 * corresponding override property is left unset -- only tests that
 * explicitly opt in (by setting $poll_max_attempts_override or
 * $fake_dns_provider) get different behaviour.
 */
final class Certificate_Manager_Test_Double extends WP_SAM\Certificates\Certificate_Manager {

	public ?int $poll_max_attempts_override = null;
	public ?WP_SAM\Certificates\Dns_Provider $fake_dns_provider = null;
	public int $wait_between_polls_calls = 0;
	public int $wait_for_dns_settle_calls = 0;

	protected function poll_max_attempts(): int {
		return $this->poll_max_attempts_override ?? parent::poll_max_attempts();
	}

	protected function wait_between_polls(): void {
		++$this->wait_between_polls_calls;
		// No sleep() -- this is exactly what makes the timeout test fast.
	}

	protected function wait_for_dns_settle(): void {
		++$this->wait_for_dns_settle_calls;
		// No sleep() -- this is exactly what makes the DNS lifecycle tests fast.
	}

	protected function resolve_dns_provider( string $slug, array $credentials ): ?WP_SAM\Certificates\Dns_Provider {
		return $this->fake_dns_provider ?? parent::resolve_dns_provider( $slug, $credentials );
	}
}
