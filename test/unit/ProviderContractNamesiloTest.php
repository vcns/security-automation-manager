<?php
/**
 * Phase 6C, Batch 5 ("Raw transport, query/form encoded, little or no
 * discovery"): request-level contract coverage for
 * WP_SAM\Certificates\Providers\Provider_Namesilo.
 *
 * Shape: Dns_Provider::request_raw() (raw XML body, "key" credential as a
 * query parameter), zone discovery via a per-candidate GET whose "found"
 * determination is a substring search for `<code>300</code>` -- no
 * try/catch anywhere in zone(). response_body_is_validated_on_success()
 * stays at its default true, since zone() reads the response body
 * directly.
 *
 * CORRECTED classification (this file previously, incorrectly, called
 * NameSilo immune to the auth-misdiagnosis defect): the absence of a
 * try/catch only means a genuine HTTP-level error (status >= 400)
 * propagates distinctly, since request_raw() throws before zone() ever
 * sees a body -- proven narrowly by
 * test_a_genuine_http_level_error_during_zone_discovery_surfaces_distinctly()
 * below. NameSilo's own API represents an authentication failure as an
 * HTTP 200 response body containing a non-300 `<code>` (this fixture
 * already uses `<code>150</code>`, "Invalid API key," for the write-stage
 * auth-failure case below), which is *exactly* the shape zone()'s
 * substring check treats as "not this candidate" -- falling through
 * silently, with no exception at all, to the next candidate. Once every
 * candidate is exhausted this collapses into the identical generic
 * "no domain found for {fqdn}" diagnostic a real zone-not-found would
 * produce -- NameSilo therefore DOES share the established
 * auth-misdiagnosis defect (deSEC et al.), just via a different mechanism
 * (silent fall-through rather than a caught exception) than the
 * try/catch-shaped family. Proven by
 * test_authentication_failure_during_zone_discovery_is_misreported_as_zone_not_found()
 * below.
 *
 * INVESTIGATION -- the previously flagged create/delete naming asymmetry
 * (create_txt_record() sends relative_name() as "rrhost"; delete_txt_record()
 * matches "<host>{$fqdn}</host>" using the FULL fqdn) is CONFIRMED CORRECT,
 * not a production defect, verified against two independent pieces of
 * primary-source evidence from NameSilo's own official API
 * documentation:
 *   - dnsAddRecord's "rrhost" parameter is documented as accepting a
 *     RELATIVE hostname: "there is no need to include the '.DOMAIN'"
 *     (namesilo.com/api-reference, dns/dns-add-record) -- matches
 *     create_txt_record()'s use of relative_name().
 *   - dnsListRecords' own official example response shows the returned
 *     "<host>" field as a FULLY QUALIFIED name -- "<host>test.namesilo.com</host>"
 *     for a record under namesilo.com (namesilo.com/api-reference/pages?uid=dns/dns-list-records)
 *     -- matches delete_txt_record()'s use of the full $fqdn, not a
 *     relative name.
 * NameSilo's own API is therefore asymmetric BY DESIGN (relative on
 * write, fully-qualified on read-back), and this driver correctly
 * mirrors that asymmetry rather than being inconsistent. Proven precisely
 * by test_delete_matches_a_resource_record_whose_host_is_the_fully_qualified_name()
 * and its contrasting negative case below. No production defect is
 * logged for this finding.
 *
 * No pagination mechanism applicable, confirmed directly: dnsListRecords'
 * documented parameter list is exactly one entry, "domain" -- no page,
 * limit, or offset parameter exists (namesilo.com/api-reference/pages?uid=dns/dns-list-records).
 */

declare( strict_types=1 );

use WP_SAM\Certificates\Providers\Provider_Namesilo;

class ProviderContractNamesiloTest extends Dns_Provider_Contract_TestCase {

	private function xml_response( int $code, string $xml ): array {
		return array(
			'response' => array( 'code' => $code ),
			'body'     => $xml,
		);
	}

	private function reply( string $code, string $extra = '' ): string {
		return "<namesilo><reply><code>{$code}</code>{$extra}</reply></namesilo>";
	}

	protected function make_provider(): Provider_Namesilo {
		return new Provider_Namesilo( array( 'api_key' => 'fixture-namesilo-key' ) );
	}

	protected function fqdn(): string {
		return '_acme-challenge.www.example.com';
	}

	protected function record_value(): string {
		return 'fixture-challenge-digest-value';
	}

	protected function queue_successful_create(): void {
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->xml_response( 200, $this->reply( '280', '<detail>Domain not found</detail>' ) ),
			$this->xml_response( 200, $this->reply( '280', '<detail>Domain not found</detail>' ) ),
			$this->xml_response( 200, $this->reply( '300' ) ), // example.com -- exists
			$this->xml_response( 200, $this->reply( '300', '<detail>success</detail>' ) ), // dnsAddRecord
		);
	}

	protected function queue_successful_delete(): void {
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->xml_response( 200, $this->reply( '280' ) ),
			$this->xml_response( 200, $this->reply( '280' ) ),
			$this->xml_response( 200, $this->reply( '300' ) ),
			$this->xml_response(
				200,
				$this->reply(
					'300',
					'<resource_record><record_id>abc123</record_id><type>TXT</type><host>' . $this->fqdn() . '</host><value>' . $this->record_value() . '</value><ttl>3600</ttl></resource_record>'
				)
			), // dnsListRecords
			$this->xml_response( 200, $this->reply( '300' ) ), // dnsDeleteRecord
		);
	}

	protected function queue_authentication_failure(): void {
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->xml_response( 200, $this->reply( '300' ) ), // zone found on the first candidate
			$this->xml_response( 200, $this->reply( '150', '<detail>Invalid API key</detail>' ) ), // dnsAddRecord rejected
		);
	}

	protected function queue_zone_not_found(): void {
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->xml_response( 200, $this->reply( '280' ) ),
			$this->xml_response( 200, $this->reply( '280' ) ),
			$this->xml_response( 200, $this->reply( '280' ) ),
		);
	}

	protected function queue_malformed_response(): void {
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->xml_response( 200, 'not xml at all {{{' ),
			$this->xml_response( 200, 'not xml at all {{{' ),
			$this->xml_response( 200, 'not xml at all {{{' ),
		);
	}

	protected function queue_http_failure(): void {
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->xml_response( 200, $this->reply( '300' ) ),
			$this->xml_response( 500, 'Internal Server Error' ),
		);
	}

	protected function assert_authenticated_correctly( array $request ): void {
		$query = array();
		parse_str( (string) parse_url( $request['url'], PHP_URL_QUERY ), $query );
		$this->assertSame( 'fixture-namesilo-key', $query['key'] ?? null );
	}

	protected function assert_record_naming_correct( array $create_request ): void {
		$query = array();
		parse_str( (string) parse_url( $create_request['url'], PHP_URL_QUERY ), $query );
		$this->assertStringContainsString( '/dnsAddRecord', $create_request['url'] );
		$this->assertSame( 'example.com', $query['domain'] ?? null );
		$this->assertSame( 'TXT', $query['rrtype'] ?? null );
		$this->assertSame( '_acme-challenge.www', $query['rrhost'] ?? null, 'dnsAddRecord\'s rrhost is documented to take a relative hostname, no domain suffix' );
		$this->assertSame( $this->record_value(), $query['rrvalue'] ?? null );
	}

	// ── Investigation: the naming "asymmetry" matches NameSilo's real API ────

	public function test_delete_matches_a_resource_record_whose_host_is_the_fully_qualified_name(): void {
		$provider = $this->make_provider();
		$this->queue_successful_delete();

		// queue_successful_delete() already supplies a <host> equal to the
		// full fqdn, matching dnsListRecords' documented response format
		// (see class docblock). This proves the driver's exact-fqdn match
		// against that real response shape succeeds.
		$provider->delete_txt_record( $this->fqdn(), $this->record_value() );

		$requests = $this->captured_requests();
		$last     = end( $requests );
		$query    = array();
		parse_str( (string) parse_url( $last['url'], PHP_URL_QUERY ), $query );
		$this->assertStringContainsString( '/dnsDeleteRecord', $last['url'] );
		$this->assertSame( 'abc123', $query['rrid'] ?? null );
	}

	public function test_delete_does_not_match_a_resource_record_whose_host_is_only_the_relative_name(): void {
		$provider = $this->make_provider();
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->xml_response( 200, $this->reply( '280' ) ),
			$this->xml_response( 200, $this->reply( '280' ) ),
			$this->xml_response( 200, $this->reply( '300' ) ),
			$this->xml_response(
				200,
				$this->reply(
					// A hypothetical relative host, contrary to NameSilo's
					// actual documented/observed response format -- proves
					// the driver's full-fqdn match is a deliberate, exact
					// requirement, not an accidentally-loose one.
					'300',
					'<resource_record><record_id>abc123</record_id><type>TXT</type><host>_acme-challenge.www</host><value>' . $this->record_value() . '</value><ttl>3600</ttl></resource_record>'
				)
			),
		);

		$provider->delete_txt_record( $this->fqdn(), $this->record_value() );

		$requests = $this->captured_requests();
		$this->assertCount( 4, $requests, 'a resource_record whose <host> is only the relative name does not match the full-fqdn check, so no DELETE request is made -- this is not exercised by NameSilo\'s real API, which always returns the fully qualified host' );
	}

	// ── Provider-specific: a genuine HTTP-level error is NOT misreported ─────
	// (a narrower finding than overall immunity -- see class docblock)

	public function test_a_genuine_http_level_error_during_zone_discovery_surfaces_distinctly(): void {
		$provider = $this->make_provider();
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->xml_response( 401, 'Unauthorized' ),
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

	// ── Provider-specific: confirmed auth-misdiagnosis defect (realistic) ────

	public function test_authentication_failure_during_zone_discovery_is_misreported_as_zone_not_found(): void {
		$provider           = $this->make_provider();
		$invalid_key_reply = $this->reply( '150', '<detail>Invalid API key</detail>' );
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->xml_response( 200, $invalid_key_reply ),
			$this->xml_response( 200, $invalid_key_reply ),
			$this->xml_response( 200, $invalid_key_reply ),
		);

		try {
			$provider->create_txt_record( $this->fqdn(), $this->record_value() );
			$this->fail( 'expected an exception when every zone-discovery candidate reports an invalid API key' );
		} catch ( \RuntimeException $e ) {
			$this->assertStringContainsString( 'no domain found', $e->getMessage() );
		}

		$this->assertCount( 3, $this->captured_requests(), 'an authentication failure reported in-band (HTTP 200 with a non-300 code) during zone discovery must not proceed to a write request' );
	}
}
