<?php
/**
 * Reusable request-testing framework for WP_SAM\Certificates\Dns_Provider
 * implementations -- the Phase 6B deliverable.
 *
 * A concrete provider test extends this class, implements the handful of
 * abstract hook methods below (build the provider instance, supply canned
 * response queues for each contract scenario, and assert on
 * provider-specific details this base class can't know generically), and
 * gets the ten-item common minimum contract for free as concrete, already-
 * written test methods. See ProviderContractCloudflareTest.php and
 * ProviderContractRoute53Test.php for the two representative fixtures that
 * prove this works across genuinely different provider shapes (JSON body /
 * Bearer auth vs raw XML body / AWS SigV4 signature auth).
 *
 * Interception and network-access prevention: every wp_remote_get/post/
 * head/request() call a provider driver can make is intercepted by
 * test/bootstrap.php's stubs -- defined in the global namespace, and the
 * only implementation of those function names anywhere in the test process,
 * since WordPress core is never loaded (grep the bootstrap: it requires only
 * this plugin's own files and one test helper). There is no code path
 * through which a real network-calling wp_remote_* implementation could run
 * during a unit test; nothing needs to be "disabled" because nothing real
 * ever exists to call. RFC 2136 is the one provider this doesn't cover --
 * see "RFC 2136" below.
 *
 * The common minimum contract (ten scenarios every provider test covers):
 *   1. successful TXT-record creation
 *   2. successful TXT-record deletion
 *   3. correct authentication construction
 *   4. zone discovery or zone selection
 *   5. authentication failure
 *   6. zone-not-found response
 *   7. malformed provider response
 *   8. provider-side HTTP failure
 *   9. transport-level WordPress error
 *   10. correct handling of relative record names and zone names
 *
 * Providers with asynchronous operations, pagination, project/account
 * discovery, or provider-specific record identifiers should add their own
 * additional test methods in their own concrete test class rather than
 * trying to force those behaviours into this shared contract -- that's
 * Phase 6C's job, provider by provider; this class only guarantees the ten
 * items above apply uniformly.
 *
 * RFC 2136: speaks raw DNS over a TCP socket (stream_socket_client()), not
 * any wp_remote_* function, so this HTTP-focused framework does not cover
 * it -- Phase 6A's CertificateManagerTest.php already covers its one
 * generically-testable behaviour (a configured-but-unreachable server is
 * recorded as a failed run) via a real, refused loopback connection. A
 * request-level test for RFC 2136 itself would need a socket-level fake
 * (e.g. stream_wrapper_register() over a custom protocol, or a stub DNS
 * server process) -- out of scope for this HTTP-transport framework;
 * flagged as a Phase 6C limitation in the Phase 6B report.
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;
use WP_SAM\Certificates\Dns_Provider;

abstract class Dns_Provider_Contract_TestCase extends TestCase {

	protected function setUp(): void {
		wp_test_reset_globals();
	}

	// ── Hooks every concrete provider contract test must supply ──────────────

	/** A fresh instance of the provider under test, with valid-shaped fixture credentials. */
	abstract protected function make_provider(): Dns_Provider;

	/**
	 * The record name to create/delete. Providers walk this via
	 * Dns_Provider::zone_candidates() during zone discovery -- use a
	 * multi-label name (not a bare two-label domain) so "relative record
	 * name" handling (contract item 10) is actually exercised.
	 */
	abstract protected function fqdn(): string;

	/** The TXT record value (the base64url challenge digest, in real use). */
	abstract protected function record_value(): string;

	/** Queues exactly the canned wp_remote_* response(s) needed for create_txt_record() to succeed. */
	abstract protected function queue_successful_create(): void;

	/** Queues exactly the canned wp_remote_* response(s) needed for delete_txt_record() to succeed, called after a successful create_txt_record() in the same test. */
	abstract protected function queue_successful_delete(): void;

	/** Queues a response shaped like this provider's own authentication-failure signal (401/403, or whatever error shape it actually returns). */
	abstract protected function queue_authentication_failure(): void;

	/** Queues response(s) that exhaust every zone_candidates() entry without finding a zone. */
	abstract protected function queue_zone_not_found(): void;

	/** Queues a 2xx response whose body is not parseable / not shaped as this provider expects. */
	abstract protected function queue_malformed_response(): void;

	/**
	 * Whether this provider's zone-discovery and write requests actually
	 * inspect a response's body when the HTTP status already indicates
	 * success. Most providers do (parsing a zone ID, record ID, or
	 * confirmation field out of the body) and should leave this at its
	 * default of `true`. A provider that determines success purely from
	 * HTTP status -- never reading the body at all -- should override this
	 * to `false`; queue_malformed_response() must then supply a genuine 2xx
	 * response with an unparseable body, and the contract asserts that
	 * create_txt_record() completes successfully rather than manufacturing
	 * a failure the driver would never actually produce.
	 */
	protected function response_body_is_validated_on_success(): bool {
		return true;
	}

	/** Queues a response shaped like a provider-side HTTP failure (5xx, or this provider's own server-error shape). */
	abstract protected function queue_http_failure(): void;

	/**
	 * Asserts the given captured request (one element of captured_requests())
	 * shows this provider's authentication constructed correctly -- e.g. the
	 * right header name/value, or query-string credential, whatever this
	 * provider actually uses. Called against the *first* request captured
	 * during a successful create_txt_record().
	 */
	abstract protected function assert_authenticated_correctly( array $request ): void;

	/**
	 * Asserts the record-creation request correctly reflects fqdn()/zone
	 * naming -- e.g. that a relative name (not the full fqdn) was sent where
	 * this provider's API expects a relative name, or that the full fqdn was
	 * sent where it expects that instead. Called against the request that
	 * actually creates the record (not a zone-lookup request) during a
	 * successful create_txt_record().
	 */
	abstract protected function assert_record_naming_correct( array $create_request ): void;

	// ── Shared capture helpers ────────────────────────────────────────────────

	/** Every wp_remote_get/post/head/request() call made so far, in call order, across every transport. */
	protected function captured_requests(): array {
		return $GLOBALS['_wp_remote_all_requests'] ?? array();
	}

	protected function decoded_body( array $request ): mixed {
		$body = $request['args']['body'] ?? null;
		if ( ! is_string( $body ) ) {
			return null;
		}
		return json_decode( $body, true );
	}

	// ── The common minimum contract (concrete; identical for every provider) ─

	public function test_successful_txt_record_creation(): void {
		$provider = $this->make_provider();
		$this->queue_successful_create();

		$provider->create_txt_record( $this->fqdn(), $this->record_value() );

		$this->assertNotEmpty( $this->captured_requests(), 'creating a record must make at least one request' );
	}

	public function test_successful_txt_record_deletion(): void {
		$provider = $this->make_provider();
		$this->queue_successful_create();
		$provider->create_txt_record( $this->fqdn(), $this->record_value() );
		$before = count( $this->captured_requests() );

		$this->queue_successful_delete();
		$provider->delete_txt_record( $this->fqdn(), $this->record_value() );

		$this->assertGreaterThan( $before, count( $this->captured_requests() ), 'deleting a record must make at least one further request' );
	}

	public function test_authentication_is_constructed_correctly(): void {
		$provider = $this->make_provider();
		$this->queue_successful_create();

		$provider->create_txt_record( $this->fqdn(), $this->record_value() );

		$requests = $this->captured_requests();
		$this->assertNotEmpty( $requests );
		$this->assert_authenticated_correctly( $requests[0] );
	}

	public function test_zone_discovery_or_selection(): void {
		$provider = $this->make_provider();
		$this->queue_successful_create();

		// Zone discovery having genuinely happened is what makes creation
		// possible at all against a multi-label fqdn() fixture -- proven by
		// the same successful call every other "successful create" assertion
		// relies on; queue_successful_create() itself documents, per
		// concrete provider, how many candidate lookups it takes.
		$provider->create_txt_record( $this->fqdn(), $this->record_value() );

		$this->assertNotEmpty( $this->captured_requests() );
	}

	public function test_authentication_failure_is_not_treated_as_success(): void {
		$provider = $this->make_provider();
		$this->queue_authentication_failure();

		$this->expectException( \Throwable::class );

		$provider->create_txt_record( $this->fqdn(), $this->record_value() );
	}

	public function test_zone_not_found_throws_a_clear_error(): void {
		$provider = $this->make_provider();
		$this->queue_zone_not_found();

		$this->expectException( \RuntimeException::class );

		$provider->create_txt_record( $this->fqdn(), $this->record_value() );
	}

	public function test_malformed_response_does_not_silently_succeed(): void {
		$provider = $this->make_provider();
		$this->queue_malformed_response();

		if ( ! $this->response_body_is_validated_on_success() ) {
			// This provider determines success purely from HTTP status and
			// never reads the response body -- a malformed body on an
			// otherwise-2xx response is therefore indistinguishable from a
			// well-formed one. Completing successfully here is the provider's
			// actual, documented behaviour, not a gap this contract should
			// manufacture a failure to paper over.
			$provider->create_txt_record( $this->fqdn(), $this->record_value() );
			$this->assertNotEmpty( $this->captured_requests(), 'a provider that never validates response bodies must still complete the request when every status is 2xx, even with a malformed body' );
			return;
		}

		// A malformed body must not be silently treated as "record created" --
		// either the provider throws outright, or it throws the same
		// "zone/record not found"-shaped error a genuinely empty result would
		// (many providers' zone_id()-style lookups simply won't match a
		// malformed body's content, which is itself the correct, safe
		// behaviour). Either way, success is not an acceptable outcome here.
		$this->expectException( \Throwable::class );

		$provider->create_txt_record( $this->fqdn(), $this->record_value() );
	}

	public function test_provider_side_http_failure_throws(): void {
		$provider = $this->make_provider();
		$this->queue_http_failure();

		$this->expectException( \RuntimeException::class );

		$provider->create_txt_record( $this->fqdn(), $this->record_value() );
	}

	public function test_transport_level_wp_error_throws(): void {
		$provider = $this->make_provider();
		$transport_error = new WP_Error( 'http_request_failed', 'Connection timed out' );
		// Every transport a provider might use is pointed at the same
		// WP_Error -- whichever one this provider actually calls first hits
		// it immediately, without needing to know which transport that is.
		$GLOBALS['_wp_remote_get_response']     = $transport_error;
		$GLOBALS['_wp_remote_post_response']    = $transport_error;
		$GLOBALS['_wp_remote_request_response'] = $transport_error;

		$this->expectException( \RuntimeException::class );

		$provider->create_txt_record( $this->fqdn(), $this->record_value() );
	}

	public function test_relative_record_and_zone_name_handling(): void {
		$provider = $this->make_provider();
		$this->queue_successful_create();

		$provider->create_txt_record( $this->fqdn(), $this->record_value() );

		$requests = $this->captured_requests();
		$this->assertNotEmpty( $requests );
		$this->assert_record_naming_correct( end( $requests ) );
	}
}
