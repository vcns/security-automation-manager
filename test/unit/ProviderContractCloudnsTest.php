<?php
/**
 * Phase 6C, Batch 5 ("Raw transport, query/form encoded, little or no
 * discovery"): request-level contract coverage for
 * WP_SAM\Certificates\Providers\Provider_Cloudns.
 *
 * Shape: Dns_Provider::request_raw() (raw text body, credentials as query
 * parameters -- auth-id/sub-auth-id + auth-password, not headers), zone
 * discovery via a per-candidate GET whose "found" determination is a
 * plain substring search (`str_contains($body, '"name"') &&
 * !str_contains($body, '"Failed"')`) with NO try/catch anywhere in
 * zone(). response_body_is_validated_on_success() stays at its default
 * true, since zone() reads the response body directly.
 *
 * CORRECTED classification (this file previously, incorrectly, called
 * ClouDNS immune to the auth-misdiagnosis defect): the absence of a
 * try/catch only means a genuine HTTP-level error (status >= 400)
 * propagates distinctly, since request_raw() throws before zone() ever
 * sees a body -- proven narrowly by
 * test_a_genuine_http_level_error_during_zone_discovery_surfaces_distinctly()
 * below. ClouDNS's own documented API convention represents an
 * authentication failure as an HTTP 200 response with
 * `{"status":"Failed",...}` in the body
 * (https://www.cloudns.net/wiki/article/57/), which is *exactly* the
 * shape zone()'s substring check treats as "not this candidate" --
 * falling through silently, with no exception at all, to the next
 * candidate. Once every candidate is exhausted this collapses into the
 * identical generic "no zone found for {fqdn}" diagnostic a real
 * zone-not-found would produce -- ClouDNS therefore DOES share the
 * established auth-misdiagnosis defect (deSEC et al.), just via a
 * different mechanism (silent fall-through rather than a caught
 * exception) than the try/catch-shaped family. Proven by
 * test_authentication_failure_during_zone_discovery_is_misreported_as_zone_not_found()
 * below.
 *
 * Confirmed production defect, not fixed here: ClouDNS's "List records"
 * endpoint (records.json) documents `rows-per-page` (10/20/30/50/100) and
 * `page` parameters (https://www.cloudns.net/wiki/article/57/, verified
 * directly). delete_txt_record()'s records.json call sends neither, so it
 * relies on ClouDNS's default page size. The call is already filtered by
 * domain-name, type, and host, narrowing results, but the pagination
 * mechanism is confirmed to exist and go unused.
 */

declare( strict_types=1 );

use WP_SAM\Certificates\Providers\Provider_Cloudns;

class ProviderContractCloudnsTest extends Dns_Provider_Contract_TestCase {

	private function raw_response( int $code, string $body ): array {
		return array(
			'response' => array( 'code' => $code ),
			'body'     => $body,
		);
	}

	private function zone_found_body(): string {
		return '{"name":"example.com","type":"master"}';
	}

	private function zone_not_found_body(): string {
		return '{"status":"Failed","statusDescription":"No zone found."}';
	}

	protected function make_provider(): Provider_Cloudns {
		return new Provider_Cloudns(
			array(
				'auth_id'       => '1234',
				'auth_password' => 'fixture-cloudns-password',
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
			$this->raw_response( 200, $this->zone_not_found_body() ),
			$this->raw_response( 200, $this->zone_not_found_body() ),
			$this->raw_response( 200, $this->zone_found_body() ),
			$this->raw_response( 200, '{"status":"Success","statusDescription":"Record added."}' ),
		);
	}

	protected function queue_successful_delete(): void {
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->raw_response( 200, $this->zone_not_found_body() ),
			$this->raw_response( 200, $this->zone_not_found_body() ),
			$this->raw_response( 200, $this->zone_found_body() ),
			$this->raw_response( 200, (string) wp_json_encode( array( '9001' => array( 'id' => '9001', 'type' => 'TXT', 'host' => '_acme-challenge.www', 'record' => $this->record_value() ) ) ) ),
			$this->raw_response( 200, '{"status":"Success"}' ),
		);
	}

	protected function queue_authentication_failure(): void {
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->raw_response( 200, $this->zone_found_body() ),
			$this->raw_response( 200, '{"status":"Failed","statusDescription":"Invalid login or password."}' ),
		);
	}

	protected function queue_zone_not_found(): void {
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->raw_response( 200, $this->zone_not_found_body() ),
			$this->raw_response( 200, $this->zone_not_found_body() ),
			$this->raw_response( 200, $this->zone_not_found_body() ),
		);
	}

	protected function queue_malformed_response(): void {
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->raw_response( 200, 'not json at all {{{' ),
			$this->raw_response( 200, 'not json at all {{{' ),
			$this->raw_response( 200, 'not json at all {{{' ),
		);
	}

	protected function queue_http_failure(): void {
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->raw_response( 200, $this->zone_found_body() ),
			$this->raw_response( 500, 'Internal Server Error' ),
		);
	}

	protected function assert_authenticated_correctly( array $request ): void {
		$query = array();
		parse_str( (string) parse_url( $request['url'], PHP_URL_QUERY ), $query );
		$this->assertSame( '1234', $query['auth-id'] ?? null );
		$this->assertSame( 'fixture-cloudns-password', $query['auth-password'] ?? null );
		$this->assertArrayNotHasKey( 'sub-auth-id', $query );
	}

	protected function assert_record_naming_correct( array $create_request ): void {
		$query = array();
		parse_str( (string) parse_url( $create_request['url'], PHP_URL_QUERY ), $query );
		$this->assertStringContainsString( '/add-record.json', $create_request['url'] );
		$this->assertSame( 'example.com', $query['domain-name'] ?? null );
		$this->assertSame( '_acme-challenge.www', $query['host'] ?? null );
		$this->assertSame( 'TXT', $query['record-type'] ?? null );
		$this->assertSame( $this->record_value(), $query['record'] ?? null );
	}

	// ── Provider-specific: sub-auth-id credential form ────────────────────────

	public function test_sub_auth_id_is_used_when_prefixed(): void {
		$provider = new Provider_Cloudns(
			array(
				'auth_id'       => 'sub:5678',
				'auth_password' => 'fixture-cloudns-password',
			)
		);
		$this->queue_successful_create();

		$provider->create_txt_record( $this->fqdn(), $this->record_value() );

		$query = array();
		parse_str( (string) parse_url( $this->captured_requests()[0]['url'], PHP_URL_QUERY ), $query );
		$this->assertSame( '5678', $query['sub-auth-id'] ?? null );
		$this->assertArrayNotHasKey( 'auth-id', $query );
	}

	// ── Provider-specific: record identifier extracted from the list ─────────

	public function test_delete_uses_the_server_assigned_record_id_from_the_list_response(): void {
		$provider = $this->make_provider();
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->raw_response( 200, $this->zone_not_found_body() ),
			$this->raw_response( 200, $this->zone_not_found_body() ),
			$this->raw_response( 200, $this->zone_found_body() ),
			$this->raw_response(
				200,
				(string) wp_json_encode(
					array(
						'1' => array( 'id' => '1', 'type' => 'TXT', 'host' => '_acme-challenge.www', 'record' => 'not-the-value' ),
						'2' => array( 'id' => '2', 'type' => 'TXT', 'host' => '_acme-challenge.www', 'record' => $this->record_value() ),
					)
				)
			),
			$this->raw_response( 200, '{"status":"Success"}' ),
		);

		$provider->delete_txt_record( $this->fqdn(), $this->record_value() );

		$requests = $this->captured_requests();
		$last     = end( $requests );
		$query    = array();
		parse_str( (string) parse_url( $last['url'], PHP_URL_QUERY ), $query );
		$this->assertStringContainsString( '/delete-record.json', $last['url'] );
		$this->assertSame( '2', $query['record-id'] ?? null );
	}

	// ── Provider-specific: confirmed pagination defect on the records list ───

	public function test_records_list_pagination_can_leave_a_matching_record_undeleted(): void {
		$provider = $this->make_provider();
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->raw_response( 200, $this->zone_not_found_body() ),
			$this->raw_response( 200, $this->zone_not_found_body() ),
			$this->raw_response( 200, $this->zone_found_body() ),
			$this->raw_response( 200, (string) wp_json_encode( array( '1' => array( 'id' => '1', 'type' => 'TXT', 'host' => 'unrelated', 'record' => 'x' ) ) ) ),
		);

		$provider->delete_txt_record( $this->fqdn(), $this->record_value() );

		$requests = $this->captured_requests();
		$this->assertCount( 4, $requests, 'the driver never requests rows-per-page/page, so a record beyond the default page is silently left undeleted' );
	}

	// ── Provider-specific: a genuine HTTP-level error is NOT misreported ─────
	// (a narrower finding than overall immunity -- see class docblock)

	public function test_a_genuine_http_level_error_during_zone_discovery_surfaces_distinctly(): void {
		$provider = $this->make_provider();
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->raw_response( 401, 'Unauthorized' ),
		);

		try {
			$provider->create_txt_record( $this->fqdn(), $this->record_value() );
			$this->fail( 'expected an exception when the first zone-discovery candidate is rejected with 401' );
		} catch ( \RuntimeException $e ) {
			$this->assertStringNotContainsString( 'no zone found', $e->getMessage() );
			$this->assertStringContainsString( 'HTTP 401', $e->getMessage() );
		}

		$this->assertCount( 1, $this->captured_requests(), 'with no try/catch around zone(), a rejected first candidate must not be retried against further candidates' );
	}

	// ── Provider-specific: confirmed auth-misdiagnosis defect (realistic) ────

	public function test_authentication_failure_during_zone_discovery_is_misreported_as_zone_not_found(): void {
		$provider          = $this->make_provider();
		$auth_failure_body = '{"status":"Failed","statusDescription":"Invalid login or password."}';
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->raw_response( 200, $auth_failure_body ),
			$this->raw_response( 200, $auth_failure_body ),
			$this->raw_response( 200, $auth_failure_body ),
		);

		try {
			$provider->create_txt_record( $this->fqdn(), $this->record_value() );
			$this->fail( 'expected an exception when every zone-discovery candidate reports an authentication failure' );
		} catch ( \RuntimeException $e ) {
			$this->assertStringContainsString( 'no zone found', $e->getMessage() );
		}

		$this->assertCount( 3, $this->captured_requests(), 'an authentication failure reported in-band (HTTP 200 with a "Failed" status) during zone discovery must not proceed to a write request' );
	}
}
