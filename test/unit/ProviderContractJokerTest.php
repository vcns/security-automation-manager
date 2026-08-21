<?php
/**
 * Phase 6C, Batch 5 ("Raw transport, query/form encoded, little or no
 * discovery"): request-level contract coverage for
 * WP_SAM\Certificates\Providers\Provider_Joker.
 *
 * Shape: the zone is a trusted, statically-configured credential (the
 * "zone" field), never looked up or verified against any API call at
 * all -- there is no zone-discovery request, no zone_candidates() walk
 * beyond a single local string comparison to decide the label, and
 * therefore no "auth failure during discovery" phase can exist for this
 * provider (disclosed explicitly, not silently omitted -- "no applicable
 * mechanism"). Both create and delete route through the exact same
 * replace() call to Joker's single documented Dynamic-DNS-style TXT
 * endpoint: create sends the value, delete sends an empty string, which
 * Joker's API treats as "clear this label." There is no records list, no
 * record ID, and no per-value matching on delete at all -- a single TXT
 * slot per label, always overwritten wholesale, architecturally similar
 * in spirit to PowerDNS's RRSet REPLACE/DELETE (Batch 3) but via a
 * completely different, simpler, single-value protocol; "no applicable
 * mechanism" for record identifiers and pagination both, since no list
 * response of any kind exists to page through or extract an ID from.
 *
 * The response is raw plaintext (a DynDNS-protocol-style "good"/"OK"/error
 * line), not JSON or XML -- checked via a plain substring search, so
 * "malformed" and "failed" collapse to the same code path: any response
 * lacking the expected success markers throws identically, whether that's
 * because the text is garbled or because Joker's servers genuinely
 * rejected the request. response_body_is_validated_on_success() stays at
 * its default true, since the success/failure determination is entirely
 * body-content-based.
 */

declare( strict_types=1 );

use WP_SAM\Certificates\Providers\Provider_Joker;

class ProviderContractJokerTest extends Dns_Provider_Contract_TestCase {

	private function raw_response( int $code, string $body ): array {
		return array(
			'response' => array( 'code' => $code ),
			'body'     => $body,
		);
	}

	protected function make_provider(): Provider_Joker {
		return new Provider_Joker(
			array(
				'zone'     => 'example.com',
				'username' => 'fixture-joker-user',
				'password' => 'fixture-joker-pass',
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
			$this->raw_response( 200, "good\n" ),
		);
	}

	protected function queue_successful_delete(): void {
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->raw_response( 200, "good\n" ),
		);
	}

	protected function queue_authentication_failure(): void {
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->raw_response( 200, "badauth\n" ),
		);
	}

	protected function queue_zone_not_found(): void {
		// No zone-discovery request exists at all (see class docblock) --
		// this simulates the general text-response failure path the
		// shared contract requires every fixture to supply.
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->raw_response( 200, "nofqdn\n" ),
		);
	}

	protected function queue_malformed_response(): void {
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->raw_response( 200, "\x00\x01 garbled binary noise" ),
		);
	}

	protected function queue_http_failure(): void {
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->raw_response( 500, 'Internal Server Error' ),
		);
	}

	protected function assert_authenticated_correctly( array $request ): void {
		parse_str( (string) ( $request['args']['body'] ?? '' ), $body );
		$this->assertSame( 'fixture-joker-user', $body['username'] ?? null );
		$this->assertSame( 'fixture-joker-pass', $body['password'] ?? null );
	}

	protected function assert_record_naming_correct( array $create_request ): void {
		parse_str( (string) ( $create_request['args']['body'] ?? '' ), $body );
		$this->assertSame( 'example.com', $body['zone'] ?? null );
		$this->assertSame( '_acme-challenge.www', $body['label'] ?? null );
		$this->assertSame( 'TXT', $body['type'] ?? null );
		$this->assertSame( $this->record_value(), $body['value'] ?? null );
	}

	// ── Provider-specific: apex fqdn uses the fixed "_acme-challenge" label ───

	public function test_apex_fqdn_uses_the_fixed_acme_challenge_label(): void {
		$provider = new Provider_Joker(
			array(
				'zone'     => 'example.com',
				'username' => 'fixture-joker-user',
				'password' => 'fixture-joker-pass',
			)
		);
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->raw_response( 200, "good\n" ),
		);

		// fqdn === zone (the apex case) -- not a multi-label subdomain.
		$provider->create_txt_record( 'example.com', $this->record_value() );

		$requests = $this->captured_requests();
		parse_str( (string) ( $requests[0]['args']['body'] ?? '' ), $body );
		$this->assertSame( '_acme-challenge', $body['label'] ?? null );
	}

	// ── Provider-specific: delete sends an empty value to clear the label ────

	public function test_delete_sends_an_empty_value_to_clear_the_label(): void {
		$provider = $this->make_provider();
		$this->queue_successful_delete();

		// A value that was never created -- if $value mattered to Joker's
		// endpoint, this would be meaningless; it isn't used at all.
		$provider->delete_txt_record( $this->fqdn(), 'a-value-that-was-never-created' );

		$requests = $this->captured_requests();
		parse_str( (string) ( $requests[0]['args']['body'] ?? '' ), $body );
		$this->assertSame( '', $body['value'] ?? null, 'Joker\'s replace endpoint clears the label when given an empty value' );
	}

	// ── Provider-specific: no zone-discovery request exists at all ───────────

	public function test_no_zone_discovery_request_precedes_the_write(): void {
		$provider = $this->make_provider();
		$this->queue_successful_create();

		$provider->create_txt_record( $this->fqdn(), $this->record_value() );

		$this->assertCount( 1, $this->captured_requests(), 'the zone is a trusted static credential -- exactly one request (the write itself) is ever made' );
	}
}
