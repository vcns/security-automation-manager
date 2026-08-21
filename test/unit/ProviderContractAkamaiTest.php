<?php
/**
 * Phase 6C, Batch 7 ("Signature and multi-step auth heavyweights"):
 * request-level contract coverage for
 * WP_SAM\Certificates\Providers\Provider_Akamai.
 *
 * Shape: Dns_Provider::request_raw() (EdgeGrid EG1-HMAC-SHA256 request
 * signing, computed per-call with no memoised pre-step -- unlike OVH/Azure/
 * Mythic Beasts, every single request is independently signed from
 * scratch). Zone discovery is the classic deSEC-style per-candidate
 * try/catch that swallows *any* \RuntimeException -- including a genuine
 * HTTP-status auth failure (401/403) *and* a transport-level WP_Error,
 * since request_raw() throws \RuntimeException for both -- as "try the
 * next candidate," collapsing into a generic "no zone found" once every
 * candidate is exhausted.
 *
 * Confirmed production defect (the established auth-misdiagnosis family):
 * an authentication failure during zone discovery is misreported as
 * "no zone found for {fqdn}", identically to deSEC et al. Proven by
 * test_authentication_failure_during_zone_discovery_is_misreported_as_zone_not_found()
 * below.
 *
 * response_body_is_validated_on_success() is false: neither zone()'s
 * per-candidate success check nor create_txt_record()'s PUT nor
 * delete_txt_record()'s DELETE ever read signed()'s return value -- every
 * one of these calls discards the response body entirely and determines
 * success purely from request_raw() not having thrown (i.e. HTTP status
 * alone). Proven directly by test_write_operations_never_read_the_response_body().
 *
 * Confirmed production defect: delete_txt_record() issues an unconditional
 * DELETE of the entire TXT recordset at {zone}/names/{fqdn}/types/TXT --
 * $value plays no part in the request at all, identical in shape to
 * Azure's whole-recordset delete. The class's own comment ("ACME names are
 * exclusively ours") argues this is lower-risk in the common case where
 * nothing else shares that exact `_acme-challenge.*` name, but the defect
 * is the same: a coexisting, unrelated TXT value at that exact name would
 * still be destroyed.
 * [Unverified]: whether Akamai's Config DNS v2 API offers a per-rdata-value
 * removal mechanism (rather than whole-recordset PUT/DELETE) that this
 * driver could have used instead.
 */

declare( strict_types=1 );

use WP_SAM\Certificates\Providers\Provider_Akamai;

class ProviderContractAkamaiTest extends Dns_Provider_Contract_TestCase {

	private function raw_response( int $code, string $body = '' ): array {
		return array(
			'response' => array( 'code' => $code ),
			'body'     => $body,
		);
	}

	protected function make_provider(): Provider_Akamai {
		return new Provider_Akamai(
			array(
				'host'          => 'akab-fixture.luna.akamaiapis.net',
				'client_token'  => 'fixture-client-token',
				'client_secret' => 'fixture-client-secret',
				'access_token'  => 'fixture-access-token',
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
			$this->raw_response( 404, '{"detail":"not found"}' ), // _acme-challenge.www.example.com
			$this->raw_response( 404, '{"detail":"not found"}' ), // www.example.com
			$this->raw_response( 200, '{"zone":"example.com"}' ), // example.com -- found
			$this->raw_response( 200, '{}' ), // PUT create
		);
	}

	protected function queue_successful_delete(): void {
		// Akamai caches nothing across calls -- delete_txt_record() re-walks
		// zone discovery from scratch, identically to create_txt_record().
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->raw_response( 404, '{"detail":"not found"}' ),
			$this->raw_response( 404, '{"detail":"not found"}' ),
			$this->raw_response( 200, '{"zone":"example.com"}' ),
			$this->raw_response( 200, '{}' ), // DELETE
		);
	}

	protected function queue_authentication_failure(): void {
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->raw_response( 404, '{"detail":"not found"}' ),
			$this->raw_response( 404, '{"detail":"not found"}' ),
			$this->raw_response( 200, '{"zone":"example.com"}' ),
			$this->raw_response( 401, '{"detail":"Signature does not match"}' ), // PUT create rejected
		);
	}

	protected function queue_zone_not_found(): void {
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->raw_response( 404, '{"detail":"not found"}' ),
			$this->raw_response( 404, '{"detail":"not found"}' ),
			$this->raw_response( 404, '{"detail":"not found"}' ),
		);
	}

	protected function queue_malformed_response(): void {
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->raw_response( 404, '{"detail":"not found"}' ),
			$this->raw_response( 404, '{"detail":"not found"}' ),
			$this->raw_response( 200, 'not json at all {{{' ), // found candidate -- malformed body, status alone decides
			$this->raw_response( 200, '{}' ), // PUT create
		);
	}

	protected function response_body_is_validated_on_success(): bool {
		return false;
	}

	protected function queue_http_failure(): void {
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->raw_response( 404, '{"detail":"not found"}' ),
			$this->raw_response( 404, '{"detail":"not found"}' ),
			$this->raw_response( 200, '{"zone":"example.com"}' ),
			$this->raw_response( 500, 'Internal Server Error' ), // PUT create
		);
	}

	protected function assert_authenticated_correctly( array $request ): void {
		$auth = (string) ( $request['args']['headers']['Authorization'] ?? '' );
		$this->assertStringStartsWith( 'EG1-HMAC-SHA256 ', $auth );
		$this->assertStringContainsString( 'client_token=fixture-client-token;', $auth );
		$this->assertStringContainsString( 'access_token=fixture-access-token;', $auth );
		$this->assertStringContainsString( 'signature=', $auth );
	}

	protected function assert_record_naming_correct( array $create_request ): void {
		// Akamai's Edge DNS API documents record names as fully-qualified --
		// unlike almost every other provider in this suite, the correct
		// behaviour here is to send the FULL fqdn, not a zone-relative name.
		$this->assertStringContainsString( '/names/' . $this->fqdn() . '/types/TXT', $create_request['url'] );
		$body = json_decode( (string) ( $create_request['args']['body'] ?? '' ), true );
		$this->assertIsArray( $body );
		$this->assertSame( $this->fqdn(), $body['name'] ?? null );
		$this->assertSame( 'TXT', $body['type'] ?? null );
		$this->assertSame( array( '"' . $this->record_value() . '"' ), $body['rdata'] ?? null, 'rdata must be quoted per TXT master-file convention' );
	}

	// ── Provider-specific: neither write operation reads its response body ──

	public function test_write_operations_never_read_the_response_body(): void {
		$provider = $this->make_provider();
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->raw_response( 404, '{"detail":"not found"}' ),
			$this->raw_response( 404, '{"detail":"not found"}' ),
			$this->raw_response( 200, '{"zone":"example.com"}' ),
			$this->raw_response( 200, 'not json at all {{{' ), // PUT create -- malformed but 2xx
		);

		// No exception: the malformed create response is never inspected.
		$provider->create_txt_record( $this->fqdn(), $this->record_value() );
		$this->assertCount( 4, $this->captured_requests() );
	}

	// ── Provider-specific: confirmed whole-recordset delete ignores $value ───

	public function test_delete_removes_the_entire_txt_recordset_without_checking_the_value(): void {
		$provider = $this->make_provider();
		$this->queue_successful_create();
		$provider->create_txt_record( $this->fqdn(), $this->record_value() );

		$this->queue_successful_delete();
		$provider->delete_txt_record( $this->fqdn(), 'a-completely-different-value-that-was-never-created' );

		$requests       = $this->captured_requests();
		$delete_request = end( $requests );
		$this->assertSame( 'DELETE', $delete_request['args']['method'] ?? null );
		$this->assertArrayNotHasKey( 'body', $delete_request['args'] ?? array(), 'the DELETE carries no body -- it cannot possibly discriminate by value' );
		$this->assertStringNotContainsString( 'a-completely-different-value', $delete_request['url'] );
	}

	// ── Provider-specific: discovery-stage auth failure is misreported ───────

	public function test_authentication_failure_during_zone_discovery_is_misreported_as_zone_not_found(): void {
		$provider = $this->make_provider();
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->raw_response( 401, '{"detail":"Signature does not match"}' ), // candidate 1
			$this->raw_response( 401, '{"detail":"Signature does not match"}' ), // candidate 2
			$this->raw_response( 401, '{"detail":"Signature does not match"}' ), // candidate 3
		);

		try {
			$provider->create_txt_record( $this->fqdn(), $this->record_value() );
			$this->fail( 'expected an exception when every candidate is rejected with 401' );
		} catch ( \RuntimeException $e ) {
			$this->assertStringContainsString( 'no zone found', $e->getMessage() );
		}

		$this->assertCount( 3, $this->captured_requests(), 'each candidate is retried once, since a caught auth failure looks identical to a genuine not-found' );
	}
}
