<?php
/**
 * Representative fixture #1 for Dns_Provider_Contract_TestCase (Phase 6B):
 * a provider built on the shared Dns_Provider::request() JSON helper, using
 * Bearer-token auth and a walk-the-zone-candidates-by-name lookup -- the
 * shape 36 of the other 40 providers share (everything except the 4 that
 * call wp_remote_post() directly and RFC 2136's raw socket).
 */

declare( strict_types=1 );

use WP_SAM\Certificates\Providers\Provider_Cloudflare;

class ProviderContractCloudflareTest extends Dns_Provider_Contract_TestCase {

	private function wp_response( int $code, array $body ): array {
		return array(
			'response' => array( 'code' => $code ),
			'body'     => (string) wp_json_encode( $body ),
		);
	}

	protected function make_provider(): Provider_Cloudflare {
		return new Provider_Cloudflare( array( 'api_token' => 'cf-fixture-token' ) );
	}

	protected function fqdn(): string {
		// Multi-label on purpose -- zone_candidates() walks 4 entries:
		// _acme-challenge.www.example.co.uk, www.example.co.uk,
		// example.co.uk, co.uk. The fixtures below assume the zone is found
		// on the 3rd candidate (example.co.uk), the realistic case for a
		// bare-domain Cloudflare zone.
		return '_acme-challenge.www.example.co.uk';
	}

	protected function record_value(): string {
		return 'fixture-challenge-digest-value';
	}

	protected function queue_successful_create(): void {
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->wp_response( 200, array( 'result' => array() ) ), // zone lookup: _acme-challenge.www.example.co.uk -- not found
			$this->wp_response( 200, array( 'result' => array() ) ), // zone lookup: www.example.co.uk -- not found
			$this->wp_response( 200, array( 'result' => array( array( 'id' => 'zone-abc123' ) ) ) ), // zone lookup: example.co.uk -- found
			$this->wp_response( 200, array( 'result' => array( 'id' => 'record-1' ) ) ), // POST create
		);
	}

	protected function queue_successful_delete(): void {
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->wp_response( 200, array( 'result' => array() ) ),
			$this->wp_response( 200, array( 'result' => array() ) ),
			$this->wp_response( 200, array( 'result' => array( array( 'id' => 'zone-abc123' ) ) ) ), // zone_id() re-resolved (delete_txt_record() looks it up again)
			$this->wp_response(
				200,
				array(
					'result' => array(
						array(
							'id'      => 'record-1',
							'content' => '"' . $this->record_value() . '"', // Cloudflare quotes TXT content; delete_txt_record() trims the quotes to compare.
						),
					),
				)
			), // GET list matching TXT records
			$this->wp_response( 200, array() ), // DELETE
		);
	}

	protected function queue_authentication_failure(): void {
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->wp_response( 401, array( 'success' => false, 'errors' => array( array( 'message' => 'Invalid API Token' ) ) ) ),
		);
	}

	protected function queue_zone_not_found(): void {
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->wp_response( 200, array( 'result' => array() ) ),
			$this->wp_response( 200, array( 'result' => array() ) ),
			$this->wp_response( 200, array( 'result' => array() ) ),
			$this->wp_response( 200, array( 'result' => array() ) ),
		);
	}

	protected function queue_malformed_response(): void {
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			array( 'response' => array( 'code' => 200 ), 'body' => 'this is not json {{{' ),
			array( 'response' => array( 'code' => 200 ), 'body' => 'this is not json {{{' ),
			array( 'response' => array( 'code' => 200 ), 'body' => 'this is not json {{{' ),
			array( 'response' => array( 'code' => 200 ), 'body' => 'this is not json {{{' ),
		);
	}

	protected function queue_http_failure(): void {
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->wp_response( 500, array( 'success' => false, 'errors' => array( array( 'message' => 'Internal Server Error' ) ) ) ),
		);
	}

	protected function assert_authenticated_correctly( array $request ): void {
		$this->assertSame( 'Bearer cf-fixture-token', $request['args']['headers']['Authorization'] ?? null );
	}

	protected function assert_record_naming_correct( array $create_request ): void {
		$body = $this->decoded_body( $create_request );
		$this->assertIsArray( $body );
		$this->assertSame( $this->fqdn(), $body['name'] ?? null, 'Cloudflare\'s API takes the full fqdn in "name", not a zone-relative name' );
		$this->assertSame( 'TXT', $body['type'] ?? null );
		$this->assertSame( $this->record_value(), $body['content'] ?? null );
	}
}
