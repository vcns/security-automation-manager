<?php
/**
 * Phase 6C, Batch 7 ("Signature and multi-step auth heavyweights"):
 * request-level contract coverage for
 * WP_SAM\Certificates\Providers\Provider_Namecheap.
 *
 * Shape: Dns_Provider::request_raw() (XML API, query-string credentials --
 * ApiUser/ApiKey/ClientIp on every call, no session or token pre-step at
 * all). A read-modify-write pattern: modify_hosts() calls zone() to find
 * the registrable domain, then re-fetches the full host list via its own
 * separate getHosts call (the same SLD/TLD zone() already just confirmed
 * -- a redundant, mildly wasteful but not incorrect extra round trip),
 * mutates it, and writes the whole set back with setHosts (which REPLACES
 * every host at the domain).
 *
 * Confirmed production defect -- a new instance of the established
 * auth-misdiagnosis family, but via a DIFFERENT mechanism than the
 * try/catch-swallow shape (deSEC, Akamai, DNSimple, et al.): zone()'s
 * per-candidate loop has no try/catch at all, and needs none, because
 * Namecheap's XML API always returns HTTP 200 regardless of the logical
 * outcome -- every failure, including an invalid API key or a
 * non-whitelisted IP, is represented identically to "this candidate isn't
 * a domain in this account": a body containing `Status="ERROR"` at
 * HTTP 200. zone()'s only check is `str_contains($body, 'Status="OK"')`,
 * which cannot distinguish the two cases, so an authentication/IP-whitelist
 * failure exhausts every candidate and surfaces as "no manageable domain
 * found for {fqdn}", not as a distinguishable auth error. A genuine
 * HTTP-level failure (5xx, or a transport WP_Error) is NOT subject to this
 * -- request_raw() throws directly and zone() has nothing to catch it
 * with, so it propagates immediately and distinctly. Proven by
 * test_a_genuine_http_failure_during_discovery_propagates_directly_unlike_an_in_band_auth_error().
 */

declare( strict_types=1 );

use WP_SAM\Certificates\Providers\Provider_Namecheap;

class ProviderContractNamecheapTest extends Dns_Provider_Contract_TestCase {

	private function raw_response( int $code, string $body ): array {
		return array(
			'response' => array( 'code' => $code ),
			'body'     => $body,
		);
	}

	private function get_hosts_not_ok(): array {
		return $this->raw_response( 200, '<?xml version="1.0"?><ApiResponse Status="ERROR"><Errors><Error Number="1011150">Domain not found</Error></Errors></ApiResponse>' );
	}

	private function get_hosts_auth_error(): array {
		return $this->raw_response( 200, '<?xml version="1.0"?><ApiResponse Status="ERROR"><Errors><Error Number="1011102">API Key is invalid or API access has not been enabled</Error></Errors></ApiResponse>' );
	}

	private function get_hosts_zone_confirmed(): array {
		return $this->raw_response( 200, '<?xml version="1.0"?><ApiResponse Status="OK"><CommandResponse Type="namecheap.domains.dns.getHosts"><DomainDNSGetHostsResult Domain="example.com"/></CommandResponse></ApiResponse>' );
	}

	private function get_hosts_with_existing(): array {
		return $this->raw_response(
			200,
			'<?xml version="1.0"?><ApiResponse Status="OK"><CommandResponse Type="namecheap.domains.dns.getHosts"><DomainDNSGetHostsResult Domain="example.com">'
			. '<host HostId="1" Name="www" Type="A" Address="1.2.3.4" TTL="1800"/>'
			. '</DomainDNSGetHostsResult></CommandResponse></ApiResponse>'
		);
	}

	private function get_hosts_with_existing_and_challenge(): array {
		return $this->raw_response(
			200,
			'<?xml version="1.0"?><ApiResponse Status="OK"><CommandResponse Type="namecheap.domains.dns.getHosts"><DomainDNSGetHostsResult Domain="example.com">'
			. '<host HostId="1" Name="www" Type="A" Address="1.2.3.4" TTL="1800"/>'
			. '<host HostId="2" Name="_acme-challenge.www" Type="TXT" Address="' . $this->record_value() . '" TTL="60"/>'
			. '</DomainDNSGetHostsResult></CommandResponse></ApiResponse>'
		);
	}

	private function set_hosts_success(): array {
		return $this->raw_response( 200, '<?xml version="1.0"?><ApiResponse Status="OK"><CommandResponse Type="namecheap.domains.dns.setHosts"><DomainDNSSetHostsResult Domain="example.com" IsSuccess="true"/></CommandResponse></ApiResponse>' );
	}

	private function set_hosts_failure(): array {
		return $this->raw_response( 200, '<?xml version="1.0"?><ApiResponse Status="ERROR"><Errors><Error Number="1011102">API Key is invalid or API access has not been enabled</Error></Errors></ApiResponse>' );
	}

	protected function make_provider(): Provider_Namecheap {
		return new Provider_Namecheap(
			array(
				'api_user'  => 'fixture-api-user',
				'api_key'   => 'fixture-api-key',
				'client_ip' => '203.0.113.10',
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
			$this->get_hosts_not_ok(), // candidate: _acme-challenge.www.example.com
			$this->get_hosts_not_ok(), // candidate: www.example.com
			$this->get_hosts_zone_confirmed(), // candidate: example.com -- confirmed
			$this->get_hosts_with_existing(), // modify_hosts()'s own read of the current host set
			$this->set_hosts_success(),
		);
	}

	protected function queue_successful_delete(): void {
		// Namecheap caches nothing across calls -- delete_txt_record() re-walks
		// zone discovery from scratch, identically to create_txt_record().
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->get_hosts_not_ok(),
			$this->get_hosts_not_ok(),
			$this->get_hosts_zone_confirmed(),
			$this->get_hosts_with_existing_and_challenge(),
			$this->set_hosts_success(),
		);
	}

	protected function queue_authentication_failure(): void {
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->get_hosts_not_ok(),
			$this->get_hosts_not_ok(),
			$this->get_hosts_zone_confirmed(),
			$this->get_hosts_with_existing(),
			$this->set_hosts_failure(),
		);
	}

	protected function queue_zone_not_found(): void {
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->get_hosts_not_ok(),
			$this->get_hosts_not_ok(),
			$this->get_hosts_not_ok(),
		);
	}

	protected function queue_malformed_response(): void {
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->raw_response( 200, 'not xml at all {{{' ),
			$this->raw_response( 200, 'not xml at all {{{' ),
			$this->raw_response( 200, 'not xml at all {{{' ),
		);
	}

	protected function queue_http_failure(): void {
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->raw_response( 500, 'Internal Server Error' ),
		);
	}

	protected function assert_authenticated_correctly( array $request ): void {
		$url = (string) ( $request['url'] ?? '' );
		$this->assertStringContainsString( 'ApiUser=fixture-api-user', $url );
		$this->assertStringContainsString( 'ApiKey=fixture-api-key', $url );
		$this->assertStringContainsString( 'ClientIp=203.0.113.10', $url );
	}

	protected function assert_record_naming_correct( array $create_request ): void {
		$this->assertSame( 'POST', $create_request['args']['method'] ?? null );
		parse_str( (string) ( $create_request['args']['body'] ?? '' ), $params );
		$this->assertSame( 'namecheap.domains.dns.setHosts', $params['Command'] ?? null );
		// index 1 is the pre-existing www/A host, untouched by create.
		$this->assertSame( 'www', $params['HostName1'] ?? null );
		$this->assertSame( 'A', $params['RecordType1'] ?? null );
		// index 2 is the newly appended challenge TXT record, using the
		// zone-relative name, not the full fqdn.
		$this->assertSame( '_acme-challenge.www', $params['HostName2'] ?? null );
		$this->assertSame( 'TXT', $params['RecordType2'] ?? null );
		$this->assertSame( $this->record_value(), $params['Address2'] ?? null );
		$this->assertSame( '60', $params['TTL2'] ?? null );
	}

	// ── Provider-specific: a real HTTP failure is NOT misdiagnosed (contrast) ──

	public function test_a_genuine_http_failure_during_discovery_propagates_directly_unlike_an_in_band_auth_error(): void {
		$provider = $this->make_provider();
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->raw_response( 500, 'Internal Server Error' ),
		);

		try {
			$provider->create_txt_record( $this->fqdn(), $this->record_value() );
			$this->fail( 'expected an exception when the very first getHosts call returns HTTP 500' );
		} catch ( \RuntimeException $e ) {
			$this->assertStringContainsString( 'HTTP 500', $e->getMessage() );
			$this->assertStringNotContainsString( 'no manageable domain found', $e->getMessage() );
		}

		$this->assertCount( 1, $this->captured_requests(), 'a genuine HTTP failure throws immediately -- it is never retried across candidates like an in-band Status="ERROR" is' );
	}

	// ── Provider-specific: discovery-stage in-band auth failure is misreported ──

	public function test_authentication_failure_during_zone_discovery_is_misreported_as_no_manageable_domain_found(): void {
		$provider = $this->make_provider();
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->get_hosts_auth_error(), // candidate 1 -- API key invalid, HTTP 200
			$this->get_hosts_auth_error(), // candidate 2
			$this->get_hosts_auth_error(), // candidate 3
		);

		try {
			$provider->create_txt_record( $this->fqdn(), $this->record_value() );
			$this->fail( 'expected "no manageable domain found" once every candidate is rejected via an in-band Status="ERROR"' );
		} catch ( \RuntimeException $e ) {
			$this->assertStringContainsString( 'no manageable domain found', $e->getMessage() );
		}

		$this->assertCount( 3, $this->captured_requests(), 'each candidate is retried once -- an in-band auth error looks identical to a genuine not-found' );
	}

	// ── Provider-specific: getHosts failing at write time never wipes the zone ──

	public function test_a_failed_get_hosts_during_the_write_step_refuses_to_call_set_hosts(): void {
		$provider = $this->make_provider();
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->get_hosts_not_ok(),
			$this->get_hosts_not_ok(),
			$this->get_hosts_zone_confirmed(),
			$this->get_hosts_auth_error(), // modify_hosts()'s own getHosts -- fails here specifically
		);

		try {
			$provider->create_txt_record( $this->fqdn(), $this->record_value() );
			$this->fail( 'expected an exception when the read-before-write getHosts call fails' );
		} catch ( \RuntimeException $e ) {
			$this->assertStringContainsString( 'refusing to write', $e->getMessage() );
		}

		$this->assertCount( 4, $this->captured_requests(), 'setHosts must never be called -- a partial read must never wipe the zone' );
	}

	// ── Provider-specific: delete preserves unrelated hosts ──────────────────

	public function test_delete_preserves_unrelated_hosts_and_only_removes_the_matching_txt(): void {
		$provider = $this->make_provider();
		$this->queue_successful_create();
		$provider->create_txt_record( $this->fqdn(), $this->record_value() );

		$this->queue_successful_delete();
		$provider->delete_txt_record( $this->fqdn(), $this->record_value() );

		$requests = $this->captured_requests();
		$last     = end( $requests );
		parse_str( (string) ( $last['args']['body'] ?? '' ), $params );

		$this->assertSame( 'namecheap.domains.dns.setHosts', $params['Command'] ?? null );
		$this->assertSame( 'www', $params['HostName1'] ?? null );
		$this->assertSame( 'A', $params['RecordType1'] ?? null );
		$this->assertArrayNotHasKey( 'HostName2', $params, 'only the one pre-existing host remains -- the matching TXT challenge record must be the sole entry removed' );
	}
}
