<?php
/**
 * Phase 6C, Batch 1 ("Cloudflare clones, no record ID"): request-level
 * contract coverage for WP_SAM\Certificates\Providers\Provider_Desec.
 *
 * Shape: shared Dns_Provider::request() (JSON), static "Token" header auth,
 * zone discovery by try/catch around a per-candidate GET (a failed lookup
 * -- 404 or otherwise -- is indistinguishable from "not found", since
 * request() throws generically for any status >= 400 with no body
 * inspection at all in zone()). Create/delete are both PUT with a
 * relative (zone-stripped) record name; delete replaces with an empty
 * record list rather than issuing a DELETE.
 *
 * Finding disclosed, not a defect: zone(), create, and delete never parse
 * a response body -- success is determined purely by HTTP status. This
 * means a 2xx response with an unparseable body is indistinguishable from
 * a well-formed 2xx response for this driver; queue_malformed_response()
 * below therefore pairs a malformed body with a non-2xx status (the only
 * way "malformed" can matter here) rather than a genuinely 2xx-malformed
 * case, which this driver would treat as ordinary success. See the batch's
 * PR description for the same finding across deSEC/Gandi/GoDaddy/NS1.
 */

declare( strict_types=1 );

use WP_SAM\Certificates\Providers\Provider_Desec;

class ProviderContractDesecTest extends Dns_Provider_Contract_TestCase {

	private function wp_response( int $code, array $body = array() ): array {
		return array(
			'response' => array( 'code' => $code ),
			'body'     => (string) wp_json_encode( $body ),
		);
	}

	protected function make_provider(): Provider_Desec {
		return new Provider_Desec( array( 'api_token' => 'fixture-desec-token' ) );
	}

	protected function fqdn(): string {
		return '_acme-challenge.www.example.com';
	}

	protected function record_value(): string {
		return 'fixture-challenge-digest-value';
	}

	protected function queue_successful_create(): void {
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->wp_response( 404 ), // _acme-challenge.www.example.com -- not a domain
			$this->wp_response( 404 ), // www.example.com -- not a domain
			$this->wp_response( 200 ), // example.com -- exists
			$this->wp_response( 200 ), // PUT create
		);
	}

	protected function queue_successful_delete(): void {
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->wp_response( 404 ),
			$this->wp_response( 404 ),
			$this->wp_response( 200 ),
			$this->wp_response( 200 ), // PUT with empty records (the delete)
		);
	}

	protected function queue_authentication_failure(): void {
		// The zone-lookup try/catch can't distinguish "not found" from "auth
		// rejected" (both just throw a generic RuntimeException on any >=400
		// status) -- an auth failure only becomes visibly distinct once the
		// actual write request is attempted, since that call isn't wrapped
		// in zone()'s try/catch.
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->wp_response( 200 ), // zone found on the first candidate, for simplicity
			$this->wp_response( 401 ), // the PUT create itself is rejected
		);
	}

	protected function queue_zone_not_found(): void {
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->wp_response( 404 ),
			$this->wp_response( 404 ),
			$this->wp_response( 404 ),
		);
	}

	protected function queue_malformed_response(): void {
		// See class docblock: this driver never parses a response body, so a
		// malformed body only matters when paired with a failing status.
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			array( 'response' => array( 'code' => 502 ), 'body' => 'not json at all {{{' ),
			array( 'response' => array( 'code' => 502 ), 'body' => 'not json at all {{{' ),
			array( 'response' => array( 'code' => 502 ), 'body' => 'not json at all {{{' ),
		);
	}

	protected function queue_http_failure(): void {
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->wp_response( 200 ), // zone found
			$this->wp_response( 500 ), // the PUT create fails server-side
		);
	}

	protected function assert_authenticated_correctly( array $request ): void {
		$this->assertSame( 'Token fixture-desec-token', $request['args']['headers']['Authorization'] ?? null );
	}

	protected function assert_record_naming_correct( array $create_request ): void {
		// Zone found on the 3rd candidate (example.com); the record path
		// must carry the *relative* name (_acme-challenge.www), not the full
		// fqdn, and the zone in the URL path.
		$this->assertStringContainsString( '/domains/example.com/rrsets/_acme-challenge.www/TXT/', $create_request['url'] );
		$body = $this->decoded_body( $create_request );
		$this->assertIsArray( $body );
		$this->assertSame( array( '"' . $this->record_value() . '"' ), $body['records'] ?? null );
	}

	// ── Provider-specific: delete replaces with an empty record list ─────────

	public function test_delete_uses_put_with_an_empty_record_list_not_a_delete_verb(): void {
		$provider = $this->make_provider();
		$this->queue_successful_create();
		$provider->create_txt_record( $this->fqdn(), $this->record_value() );

		$this->queue_successful_delete();
		$provider->delete_txt_record( $this->fqdn(), $this->record_value() );

		$requests = $this->captured_requests();
		$last     = end( $requests );
		$this->assertSame( 'PUT', $last['args']['method'] ?? null, 'deSEC deletes an rrset by PUTting an empty records array, not by issuing a DELETE' );
		$body = $this->decoded_body( $last );
		$this->assertSame( array(), $body['records'] ?? null );
	}
}
