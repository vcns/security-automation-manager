<?php
/**
 * Phase 6C, Batch 6 ("Raw transport, JSON/RPC envelopes"): request-level
 * contract coverage for WP_SAM\Certificates\Providers\Provider_Netcup.
 *
 * Shape: Dns_Provider::request_raw() (JSON body, action+param envelope).
 * call() itself explicitly checks `'success' !== strtolower($decoded['status']
 * ?? '')` and throws with the API's own longmessage/shortmessage on ANY
 * failure -- a robust, body-content-based validation applied uniformly to
 * every operation, so response_body_is_validated_on_success() stays at
 * its default true.
 *
 * A memoised session pre-step -- structurally close to DNSimple's
 * whoami() (Batch 4): call() logs in once (caching `$this->session` from
 * the login response's apisessionid) if no session exists yet and the
 * requested action isn't itself "login". zone()'s try/catch wraps
 * call(), so this pre-step is evaluated *inside* the same try block.
 *
 * Confirmed production defect (extends the established Batch 1/2/4/5
 * auth-during-discovery family, with direct code evidence -- the same
 * nested-pre-step-inside-try/catch shape DNSimple's account() has), not
 * fixed here: a login failure that genuinely throws (call()'s own
 * "success" check failing for the login request itself) is never cached
 * -- `$this->session` stays null -- so it is retried once per zone
 * candidate and, once every candidate is exhausted, misreported as
 * "no DNS zone found for {fqdn}", identically to deSEC et al. Distinctly,
 * not the same code path: if login itself reports "success" but the
 * response is missing `apisessionid`, `$this->session` is assigned the
 * empty string *before* the empty-value check runs (identical to
 * DNSimple's account_id quirk) -- so login is NOT retried again; every
 * subsequent candidate instead attempts the real DNS-zone lookup with an
 * empty session ID, which independently fails and is independently
 * caught. Proven by
 * test_authentication_failure_during_zone_discovery_is_misreported_as_zone_not_found()
 * below.
 *
 * No pagination mechanism applicable, confirmed reasonably: netcup's own
 * documentation describes infoDnsRecords as "Obtain all DNS records of a
 * zone" (netcup.com/en/helpcenter/documentation/domain/our-api) with no
 * page/limit parameter documented anywhere.
 */

declare( strict_types=1 );

use WP_SAM\Certificates\Providers\Provider_Netcup;

class ProviderContractNetcupTest extends Dns_Provider_Contract_TestCase {

	private function raw_response( int $code, array $body ): array {
		return array(
			'response' => array( 'code' => $code ),
			'body'     => (string) wp_json_encode( $body ),
		);
	}

	private function success( array $responsedata = array() ): array {
		return $this->raw_response( 200, array( 'status' => 'success', 'responsedata' => $responsedata ) );
	}

	private function error( string $message = 'unknown error' ): array {
		return $this->raw_response( 200, array( 'status' => 'error', 'shortmessage' => $message ) );
	}

	private function login_success(): array {
		return $this->success( array( 'apisessionid' => 'fixture-session-id' ) );
	}

	protected function make_provider(): Provider_Netcup {
		return new Provider_Netcup(
			array(
				'customer_number' => '123456',
				'api_key'         => 'fixture-netcup-key',
				'api_password'    => 'fixture-netcup-password',
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
			$this->login_success(),
			$this->error( 'zone not found' ), // candidate 1
			$this->error( 'zone not found' ), // candidate 2
			$this->success(), // candidate 3 -- infoDnsZone succeeds
			$this->success(), // updateDnsRecords (create)
		);
	}

	protected function queue_successful_delete(): void {
		// Session is already cached from the preceding create_txt_record()
		// call on the same $provider instance -- no further login request.
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->error( 'zone not found' ),
			$this->error( 'zone not found' ),
			$this->success(),
			$this->success( array( 'dnsrecords' => array( array( 'id' => 777, 'type' => 'TXT', 'hostname' => '_acme-challenge.www', 'destination' => $this->record_value() ) ) ) ), // infoDnsRecords
			$this->success(), // updateDnsRecords (delete)
		);
	}

	protected function queue_authentication_failure(): void {
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->login_success(),
			$this->success(), // zone found on the first candidate
			$this->error( 'permission denied' ), // updateDnsRecords rejected
		);
	}

	protected function queue_zone_not_found(): void {
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->login_success(),
			$this->error(),
			$this->error(),
			$this->error(),
		);
	}

	protected function queue_malformed_response(): void {
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->login_success(),
			array( 'response' => array( 'code' => 200 ), 'body' => 'not json at all {{{' ),
			array( 'response' => array( 'code' => 200 ), 'body' => 'not json at all {{{' ),
			array( 'response' => array( 'code' => 200 ), 'body' => 'not json at all {{{' ),
		);
	}

	protected function queue_http_failure(): void {
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->login_success(),
			$this->success(),
			array( 'response' => array( 'code' => 500 ), 'body' => 'Internal Server Error' ),
		);
	}

	protected function assert_authenticated_correctly( array $request ): void {
		$body = $this->decoded_body( $request );
		$this->assertIsArray( $body );
		$this->assertSame( 'login', $body['action'] ?? null, 'the first request must be the login call' );
		$this->assertSame( 'fixture-netcup-key', $body['param']['apikey'] ?? null );
		$this->assertSame( 'fixture-netcup-password', $body['param']['apipassword'] ?? null );
		$this->assertSame( '123456', $body['param']['customernumber'] ?? null );
	}

	protected function assert_record_naming_correct( array $create_request ): void {
		$body = $this->decoded_body( $create_request );
		$this->assertIsArray( $body );
		$this->assertSame( 'updateDnsRecords', $body['action'] ?? null );
		$this->assertSame( 'example.com', $body['param']['domainname'] ?? null );
		$this->assertSame( 'fixture-session-id', $body['param']['apisessionid'] ?? null, 'the session ID cached from login must be sent on subsequent requests' );
		$record = $body['param']['dnsrecordset']['dnsrecords'][0] ?? null;
		$this->assertIsArray( $record );
		$this->assertSame( '_acme-challenge.www', $record['hostname'] ?? null );
		$this->assertSame( 'TXT', $record['type'] ?? null );
		$this->assertSame( $this->record_value(), $record['destination'] ?? null );
	}

	// ── Provider-specific: delete reuses updateDnsRecords with a delete flag ──

	public function test_delete_uses_update_dns_records_with_a_deleterecord_flag(): void {
		$provider = $this->make_provider();
		$this->queue_successful_create();
		$provider->create_txt_record( $this->fqdn(), $this->record_value() );

		$this->queue_successful_delete();
		$provider->delete_txt_record( $this->fqdn(), $this->record_value() );

		$requests = $this->captured_requests();
		$last     = end( $requests );
		$body     = $this->decoded_body( $last );
		$this->assertSame( 'updateDnsRecords', $body['action'] ?? null, 'netcup has no separate delete endpoint -- deletion reuses updateDnsRecords' );
		$record = $body['param']['dnsrecordset']['dnsrecords'][0] ?? null;
		$this->assertSame( '777', $record['id'] ?? null, 'the server-assigned record id from infoDnsRecords must be included' );
		$this->assertTrue( $record['deleterecord'] ?? null );
	}

	// ── Provider-specific: discovery-stage auth failure is misreported ───────

	public function test_authentication_failure_during_zone_discovery_is_misreported_as_zone_not_found(): void {
		$provider = $this->make_provider();
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->error( 'invalid credentials' ), // login, candidate 1 -- throws, never cached
			$this->error( 'invalid credentials' ), // login retried, candidate 2
			$this->error( 'invalid credentials' ), // login retried, candidate 3
		);

		try {
			$provider->create_txt_record( $this->fqdn(), $this->record_value() );
			$this->fail( 'expected an exception when login fails on every candidate' );
		} catch ( \RuntimeException $e ) {
			$this->assertStringContainsString( 'no DNS zone found', $e->getMessage() );
		}

		$this->assertCount( 3, $this->captured_requests(), 'a login failure that genuinely throws is never cached, so it is retried once per zone candidate' );
	}
}
