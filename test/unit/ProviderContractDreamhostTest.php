<?php
/**
 * Phase 6C, Batch 5 ("Raw transport, query/form encoded, little or no
 * discovery"): request-level contract coverage for
 * WP_SAM\Certificates\Providers\Provider_Dreamhost.
 *
 * Shape: no zone concept at all -- dns-add_record/dns-remove_record take
 * the full record name directly ($fqdn, unmodified), so there is no
 * zone_candidates() walk, no relative_name() call, and no "zone not
 * found"/"auth failure during discovery" phase to speak of; the base
 * contract's zone-discovery hooks are implemented as generic
 * general-failure-path simulations rather than a distinct discovery step,
 * disclosed here rather than left implicit. Uses Dns_Provider::request_raw()
 * (GET with query string, "key" credential as a plain query parameter, not
 * a header) against api.dreamhost.com's plaintext-JSON-in-body protocol.
 * The shared request_raw() helper throws on transport error or HTTP
 * status >= 400 before this driver ever sees the body; this driver's OWN
 * check is purely body-content-based ($decoded['result'] === 'success'),
 * so response_body_is_validated_on_success() stays at its default true.
 *
 * Distinctive, disclosed, not a defect: delete_txt_record() treats a
 * "no_such_record" failure reason as a successful no-op (the record is
 * already gone, which is the desired end state for a cleanup call) --
 * tested explicitly below, and only for the remove command, not create.
 */

declare( strict_types=1 );

use WP_SAM\Certificates\Providers\Provider_Dreamhost;

class ProviderContractDreamhostTest extends Dns_Provider_Contract_TestCase {

	private function raw_response( int $code, string $body ): array {
		return array(
			'response' => array( 'code' => $code ),
			'body'     => $body,
		);
	}

	private function success_body(): string {
		return (string) wp_json_encode( array( 'result' => 'success', 'data' => 'record_added' ) );
	}

	protected function make_provider(): Provider_Dreamhost {
		return new Provider_Dreamhost( array( 'api_key' => 'fixture-dreamhost-key' ) );
	}

	protected function fqdn(): string {
		return '_acme-challenge.www.example.com';
	}

	protected function record_value(): string {
		return 'fixture-challenge-digest-value';
	}

	protected function queue_successful_create(): void {
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->raw_response( 200, $this->success_body() ),
		);
	}

	protected function queue_successful_delete(): void {
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->raw_response( 200, $this->success_body() ),
		);
	}

	protected function queue_authentication_failure(): void {
		// DreamHost's simple key-based API returns 200 with the failure
		// encoded in the body, not a distinct HTTP status -- there is no
		// separate "discovery" phase to distinguish this from any other
		// body-encoded failure.
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->raw_response( 200, (string) wp_json_encode( array( 'result' => 'error', 'data' => 'invalid_api_key' ) ) ),
		);
	}

	protected function queue_zone_not_found(): void {
		// No zone concept exists for this provider (see class docblock) --
		// this simulates the general body-encoded failure path the shared
		// contract requires every fixture to supply.
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->raw_response( 200, (string) wp_json_encode( array( 'result' => 'error', 'data' => 'domain_doesnt_exist' ) ) ),
		);
	}

	protected function queue_malformed_response(): void {
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->raw_response( 200, 'not json at all {{{' ),
		);
	}

	protected function queue_http_failure(): void {
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->raw_response( 500, 'Internal Server Error' ),
		);
	}

	protected function assert_authenticated_correctly( array $request ): void {
		$query = array();
		parse_str( (string) parse_url( $request['url'], PHP_URL_QUERY ), $query );
		$this->assertSame( 'fixture-dreamhost-key', $query['key'] ?? null );
	}

	protected function assert_record_naming_correct( array $create_request ): void {
		$query = array();
		parse_str( (string) parse_url( $create_request['url'], PHP_URL_QUERY ), $query );
		$this->assertSame( 'dns-add_record', $query['cmd'] ?? null );
		$this->assertSame( $this->fqdn(), $query['record'] ?? null, 'DreamHost takes the full record name directly -- no zone resolution or relative naming' );
		$this->assertSame( 'TXT', $query['type'] ?? null );
		$this->assertSame( $this->record_value(), $query['value'] ?? null );
	}

	// ── Provider-specific: no_such_record on delete is a silent success ──────

	public function test_delete_treats_no_such_record_as_already_succeeded(): void {
		$provider = $this->make_provider();
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->raw_response( 200, (string) wp_json_encode( array( 'result' => 'error', 'data' => 'no_such_record' ) ) ),
		);

		// Must not throw -- a record that's already gone is the desired
		// end state for a cleanup call, not a failure.
		$provider->delete_txt_record( $this->fqdn(), $this->record_value() );

		$this->assertCount( 1, $this->captured_requests() );
	}

	public function test_create_does_not_special_case_no_such_record(): void {
		$provider = $this->make_provider();
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->raw_response( 200, (string) wp_json_encode( array( 'result' => 'error', 'data' => 'no_such_record' ) ) ),
		);

		$this->expectException( \RuntimeException::class );
		$provider->create_txt_record( $this->fqdn(), $this->record_value() );
	}
}
