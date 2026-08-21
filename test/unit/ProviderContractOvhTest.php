<?php
/**
 * Phase 6C, Batch 7 ("Signature and multi-step auth heavyweights"):
 * request-level contract coverage for WP_SAM\Certificates\Providers\Provider_Ovh.
 *
 * Shape: Dns_Provider::request_raw() (custom OVH request-signing scheme).
 * A memoised time-drift pre-step -- signed() fetches /auth/time once and
 * caches the delta on $this->time_delta, needed because OVH's signature
 * includes a timestamp the API validates against clock skew. Zone
 * discovery makes exactly ONE request (GET /domain/zone, a top-level JSON
 * array of zone name strings) and matches candidates client-side, with no
 * try/catch -- the Batch 3/6 "enumerate-once" shape. OVH's own API is
 * confirmed (via multiple independent reports of real HTTP 401/403/400
 * responses for signature/consumer-key failures, e.g. ovh/php-ovh#56/#62)
 * to represent authentication failures via genuine HTTP status codes, so
 * this driver is immune to the auth-misdiagnosis defect for this
 * dimension -- confirmed by direct code inspection (no try/catch to
 * swallow it) combined with OVH's own documented error convention.
 * zone() reads the response body (the in_array check), so
 * response_body_is_validated_on_success() stays at its default true.
 *
 * delete_txt_record() is a genuinely well-designed list-then-verify-then-
 * delete-by-ID pattern: it lists candidate IDs filtered by fieldType/
 * subDomain, then fetches each candidate record individually and checks
 * its "target" field against $value before deleting -- real per-value
 * discrimination, not a destructive whole-recordset delete.
 *
 * [Unverified] -- pagination: no accessible authoritative documentation
 * for the legacy v1.0 `/domain/zone/{zone}/record` endpoint's pagination
 * behaviour could be located (OVH's newer v2 API documents cursor
 * pagination via response headers, but this endpoint is part of the
 * older, still-current v1.0 API family this driver calls).
 */

declare( strict_types=1 );

use WP_SAM\Certificates\Providers\Provider_Ovh;

class ProviderContractOvhTest extends Dns_Provider_Contract_TestCase {

	private function raw_response( int $code, string $body ): array {
		return array(
			'response' => array( 'code' => $code ),
			'body'     => $body,
		);
	}

	private function time_response(): array {
		return $this->raw_response( 200, '1750000000' );
	}

	protected function make_provider(): Provider_Ovh {
		return new Provider_Ovh(
			array(
				'endpoint'           => 'ovh-eu',
				'application_key'    => 'fixture-app-key',
				'application_secret' => 'fixture-app-secret',
				'consumer_key'       => 'fixture-consumer-key',
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
			$this->time_response(),
			$this->raw_response( 200, '["example.com"]' ), // /domain/zone
			$this->raw_response( 200, '{"id":42}' ), // POST record
			$this->raw_response( 200, '{}' ), // POST refresh
		);
	}

	protected function queue_successful_delete(): void {
		// time_delta is already cached from the preceding create_txt_record()
		// call on the same $provider instance -- no further /auth/time request.
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->raw_response( 200, '["example.com"]' ),
			$this->raw_response( 200, '[9001]' ), // filtered ID list
			$this->raw_response( 200, '{"target":"' . $this->record_value() . '"}' ), // record detail
			$this->raw_response( 200, '{}' ), // DELETE
			$this->raw_response( 200, '{}' ), // refresh
		);
	}

	protected function queue_authentication_failure(): void {
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->time_response(),
			$this->raw_response( 200, '["example.com"]' ),
			$this->raw_response( 401, '{"message":"Invalid signature"}' ), // POST record rejected
		);
	}

	protected function queue_zone_not_found(): void {
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->time_response(),
			$this->raw_response( 200, '["unrelated-1.com","unrelated-2.com"]' ),
		);
	}

	protected function queue_malformed_response(): void {
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->time_response(),
			$this->raw_response( 200, 'not json at all {{{' ),
		);
	}

	protected function queue_http_failure(): void {
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->time_response(),
			$this->raw_response( 200, '["example.com"]' ),
			$this->raw_response( 500, 'Internal Server Error' ),
		);
	}

	protected function assert_authenticated_correctly( array $request ): void {
		// The base contract passes captured_requests()[0], but for a fresh
		// OVH instance that is always the unauthenticated /auth/time
		// pre-step (OVH's real API deliberately doesn't sign that endpoint --
		// it exists precisely so a client can bootstrap the clock delta
		// needed to compute every other request's signature). The first
		// genuinely-signed request is the very next one -- the zone-list
		// call -- so inspect that instead of the passed-in parameter.
		$signed_request = $this->captured_requests()[1] ?? null;
		$this->assertNotNull( $signed_request );
		$headers = $signed_request['args']['headers'] ?? array();
		$this->assertSame( 'fixture-app-key', $headers['X-Ovh-Application'] ?? null );
		$this->assertSame( 'fixture-consumer-key', $headers['X-Ovh-Consumer'] ?? null );
		$this->assertArrayHasKey( 'X-Ovh-Timestamp', $headers );
		$this->assertArrayHasKey( 'X-Ovh-Signature', $headers );
		$this->assertStringStartsWith( '$1$', (string) ( $headers['X-Ovh-Signature'] ?? '' ) );
	}

	protected function assert_record_naming_correct( array $create_request ): void {
		// The last request captured after a successful create is the POST
		// refresh call, not the record-creation call itself -- inspect the
		// specific record request directly.
		$requests = $this->captured_requests();
		$record_request = $requests[2] ?? null;
		$this->assertNotNull( $record_request );
		$this->assertSame( 'POST', $record_request['args']['method'] ?? null );
		$this->assertStringContainsString( '/domain/zone/example.com/record', $record_request['url'] );
		$body = json_decode( (string) ( $record_request['args']['body'] ?? '' ), true );
		$this->assertIsArray( $body );
		$this->assertSame( 'TXT', $body['fieldType'] ?? null );
		$this->assertSame( '_acme-challenge.www', $body['subDomain'] ?? null );
		$this->assertSame( $this->record_value(), $body['target'] ?? null );
	}

	// ── Provider-specific: time-drift pre-step is fetched once and cached ────

	public function test_time_drift_is_fetched_once_and_cached_across_create_and_delete(): void {
		$provider = $this->make_provider();
		$this->queue_successful_create();
		$provider->create_txt_record( $this->fqdn(), $this->record_value() );

		$this->queue_successful_delete();
		$provider->delete_txt_record( $this->fqdn(), $this->record_value() );

		$time_calls = array_filter(
			$this->captured_requests(),
			static fn( array $r ): bool => str_contains( (string) ( $r['url'] ?? '' ), '/auth/time' )
		);
		$this->assertCount( 1, $time_calls, 'the time-drift pre-step must resolve once and be cached for the rest of this provider instance\'s lifetime' );
	}

	public function test_the_time_pre_step_itself_carries_no_signature_unlike_every_other_request(): void {
		$provider = $this->make_provider();
		$this->queue_successful_create();
		$provider->create_txt_record( $this->fqdn(), $this->record_value() );

		$requests = $this->captured_requests();
		$time_headers = $requests[0]['args']['headers'] ?? array();
		$this->assertArrayNotHasKey( 'X-Ovh-Signature', $time_headers, 'the /auth/time endpoint is deliberately unauthenticated in OVH\'s real API -- it exists to bootstrap the clock delta a signature needs' );

		$zone_headers = $requests[1]['args']['headers'] ?? array();
		$this->assertArrayHasKey( 'X-Ovh-Signature', $zone_headers, 'every request other than the time pre-step must be signed' );
	}

	public function test_a_time_endpoint_failure_propagates_directly(): void {
		$provider = $this->make_provider();
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->raw_response( 500, 'Internal Server Error' ),
		);

		$this->expectException( \RuntimeException::class );
		$provider->create_txt_record( $this->fqdn(), $this->record_value() );
	}

	// ── Provider-specific: record identifier extracted via list-then-verify ──

	public function test_delete_verifies_the_target_value_before_deleting_by_id(): void {
		$provider = $this->make_provider();
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->time_response(), // fresh instance -- time_delta not yet cached
			$this->raw_response( 200, '["example.com"]' ),
			$this->raw_response( 200, '[1,2]' ), // two candidate IDs sharing the filtered name+type
			$this->raw_response( 200, '{"target":"not-the-value"}' ), // record 1 -- doesn't match
			$this->raw_response( 200, '{"target":"' . $this->record_value() . '"}' ), // record 2 -- matches
			$this->raw_response( 200, '{}' ), // DELETE for record 2 only
			$this->raw_response( 200, '{}' ), // refresh
		);

		$provider->delete_txt_record( $this->fqdn(), $this->record_value() );

		$requests = $this->captured_requests();
		// record/1 must never be DELETEd -- 7 requests total (time, zone,
		// ids, detail-1, detail-2, delete-2, refresh), no delete for id 1.
		$this->assertCount( 7, $requests );
		$this->assertSame( 'DELETE', $requests[5]['args']['method'] ?? null );
		$this->assertStringContainsString( '/record/2', $requests[5]['url'] );
	}

	// ── Provider-specific: discovery-stage auth failure is NOT misreported ───

	public function test_authentication_failure_during_zone_discovery_surfaces_distinctly_not_as_zone_not_found(): void {
		$provider = $this->make_provider();
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->time_response(),
			$this->raw_response( 403, '{"message":"Invalid consumer key"}' ),
		);

		try {
			$provider->create_txt_record( $this->fqdn(), $this->record_value() );
			$this->fail( 'expected an exception when the zone-list request is rejected with 403' );
		} catch ( \RuntimeException $e ) {
			$this->assertStringNotContainsString( 'no zone found', $e->getMessage() );
			$this->assertStringContainsString( 'HTTP 403', $e->getMessage() );
		}

		$this->assertCount( 2, $this->captured_requests() );
	}
}
