<?php
/**
 * Phase 6C, Batch 5 ("Raw transport, query/form encoded, little or no
 * discovery"): request-level contract coverage for
 * WP_SAM\Certificates\Providers\Provider_Dnspod.
 *
 * Shape: Dns_Provider::request_raw() (form-encoded POST body, JSON
 * response manually decoded in call()), "login_token" credential built as
 * "{token_id},{token}" in the body. Zone discovery via a per-candidate
 * call whose "found" determination checks a decoded `status.code` field
 * -- no try/catch anywhere in zone(). Since request_raw() throws directly
 * on any HTTP status >= 400, and nothing catches that exception here, a
 * genuine authentication failure during discovery propagates immediately
 * and distinctly -- confirmed by direct code inspection, joining the
 * established contrast group (Hetzner/Bunny/Domeneshop/IONOS/Linode/
 * Netlify/PowerDNS/Dynu/ClouDNS/NameSilo). zone() reads the decoded body
 * (the status.code check), so response_body_is_validated_on_success()
 * stays at its default true. call()'s own json_decode() coerces an
 * unparseable body to an empty array rather than throwing, so a malformed
 * response is indistinguishable from a "status.code missing" response --
 * both fall through to the next candidate identically.
 *
 * Confirmed production defect, not fixed here: DNSPod's Record.List
 * endpoint documents `offset`/`length` pagination, returning at most 500
 * records per call by default (https://docs.dnspod.com/api-legacy/records.html,
 * verified directly: "If there are more than 500 records, only the first
 * 500 will be responded. You may need to set 'offset' and 'length' to get
 * all the records with requests."). delete_txt_record()'s Record.List
 * call is already filtered by domain, sub_domain, and record_type,
 * narrowing results, but sends neither offset nor length, so the
 * pagination mechanism is confirmed to exist and go unused.
 */

declare( strict_types=1 );

use WP_SAM\Certificates\Providers\Provider_Dnspod;

class ProviderContractDnspodTest extends Dns_Provider_Contract_TestCase {

	private function raw_response( int $code, array $body ): array {
		return array(
			'response' => array( 'code' => $code ),
			'body'     => (string) wp_json_encode( $body ),
		);
	}

	private function dnspod_status( string $code, string $message = 'ok' ): array {
		return array( 'status' => array( 'code' => $code, 'message' => $message ) );
	}

	protected function make_provider(): Provider_Dnspod {
		return new Provider_Dnspod(
			array(
				'token_id' => '730060',
				'token'    => 'fixture-dnspod-token',
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
			$this->raw_response( 200, $this->dnspod_status( '-1', 'domain not found' ) ),
			$this->raw_response( 200, $this->dnspod_status( '-1', 'domain not found' ) ),
			$this->raw_response( 200, $this->dnspod_status( '1' ) ), // example.com -- found
			$this->raw_response( 200, $this->dnspod_status( '1' ) ), // Record.Create
		);
	}

	protected function queue_successful_delete(): void {
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->raw_response( 200, $this->dnspod_status( '-1' ) ),
			$this->raw_response( 200, $this->dnspod_status( '-1' ) ),
			$this->raw_response( 200, $this->dnspod_status( '1' ) ),
			$this->raw_response(
				200,
				array_merge(
					$this->dnspod_status( '1' ),
					array( 'records' => array( array( 'id' => 777, 'value' => $this->record_value() ) ) )
				)
			), // Record.List
			$this->raw_response( 200, $this->dnspod_status( '1' ) ), // Record.Remove
		);
	}

	protected function queue_authentication_failure(): void {
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->raw_response( 200, $this->dnspod_status( '1' ) ), // zone found on the first candidate
			$this->raw_response( 200, $this->dnspod_status( '-8', 'invalid token' ) ), // Record.Create rejected
		);
	}

	protected function queue_zone_not_found(): void {
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->raw_response( 200, $this->dnspod_status( '-1' ) ),
			$this->raw_response( 200, $this->dnspod_status( '-1' ) ),
			$this->raw_response( 200, $this->dnspod_status( '-1' ) ),
		);
	}

	protected function queue_malformed_response(): void {
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			array( 'response' => array( 'code' => 200 ), 'body' => 'not json at all {{{' ),
			array( 'response' => array( 'code' => 200 ), 'body' => 'not json at all {{{' ),
			array( 'response' => array( 'code' => 200 ), 'body' => 'not json at all {{{' ),
		);
	}

	protected function queue_http_failure(): void {
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->raw_response( 200, $this->dnspod_status( '1' ) ),
			array( 'response' => array( 'code' => 500 ), 'body' => 'Internal Server Error' ),
		);
	}

	protected function assert_authenticated_correctly( array $request ): void {
		parse_str( (string) ( $request['args']['body'] ?? '' ), $body );
		$this->assertSame( '730060,fixture-dnspod-token', $body['login_token'] ?? null );
	}

	protected function assert_record_naming_correct( array $create_request ): void {
		$this->assertStringContainsString( '/Record.Create', $create_request['url'] );
		parse_str( (string) ( $create_request['args']['body'] ?? '' ), $body );
		$this->assertSame( 'example.com', $body['domain'] ?? null );
		$this->assertSame( '_acme-challenge.www', $body['sub_domain'] ?? null );
		$this->assertSame( 'TXT', $body['record_type'] ?? null );
		$this->assertSame( $this->record_value(), $body['value'] ?? null );
	}

	// ── Provider-specific: record identifier extracted from the list ─────────

	public function test_delete_uses_the_server_assigned_record_id_from_the_list_response(): void {
		$provider = $this->make_provider();
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->raw_response( 200, $this->dnspod_status( '-1' ) ),
			$this->raw_response( 200, $this->dnspod_status( '-1' ) ),
			$this->raw_response( 200, $this->dnspod_status( '1' ) ),
			$this->raw_response(
				200,
				array_merge(
					$this->dnspod_status( '1' ),
					array(
						'records' => array(
							array( 'id' => 1, 'value' => 'not-the-value' ),
							array( 'id' => 2, 'value' => $this->record_value() ),
						),
					)
				)
			),
			$this->raw_response( 200, $this->dnspod_status( '1' ) ),
		);

		$provider->delete_txt_record( $this->fqdn(), $this->record_value() );

		$requests = $this->captured_requests();
		$last     = end( $requests );
		$this->assertStringContainsString( '/Record.Remove', $last['url'] );
		parse_str( (string) ( $last['args']['body'] ?? '' ), $body );
		$this->assertSame( '2', $body['record_id'] ?? null );
	}

	// ── Provider-specific: confirmed pagination defect on the records list ───

	public function test_records_list_pagination_can_leave_a_matching_record_undeleted(): void {
		$provider = $this->make_provider();
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->raw_response( 200, $this->dnspod_status( '-1' ) ),
			$this->raw_response( 200, $this->dnspod_status( '-1' ) ),
			$this->raw_response( 200, $this->dnspod_status( '1' ) ),
			$this->raw_response( 200, array_merge( $this->dnspod_status( '1' ), array( 'records' => array( array( 'id' => 1, 'value' => 'unrelated' ) ) ) ) ),
		);

		$provider->delete_txt_record( $this->fqdn(), $this->record_value() );

		$requests = $this->captured_requests();
		$this->assertCount( 4, $requests, 'the driver never sends offset/length, so a record beyond the default 500-record response is silently left undeleted' );
	}

	// ── Provider-specific: discovery-stage auth failure is NOT misreported ───

	public function test_authentication_failure_during_zone_discovery_surfaces_distinctly_not_as_zone_not_found(): void {
		$provider = $this->make_provider();
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			array( 'response' => array( 'code' => 401 ), 'body' => 'Unauthorized' ),
		);

		try {
			$provider->create_txt_record( $this->fqdn(), $this->record_value() );
			$this->fail( 'expected an exception when the first zone-discovery candidate is rejected with 401' );
		} catch ( \RuntimeException $e ) {
			$this->assertStringNotContainsString( 'no domain found', $e->getMessage() );
			$this->assertStringContainsString( 'HTTP 401', $e->getMessage() );
		}

		$this->assertCount( 1, $this->captured_requests(), 'with no try/catch around zone(), a rejected first candidate must not be retried against further candidates' );
	}
}
