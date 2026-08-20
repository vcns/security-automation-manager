<?php
/**
 * Phase 6C, Batch 3 ("Enumerate-all-zones and unusual discovery"): request-
 * level contract coverage for WP_SAM\Certificates\Providers\Provider_Linode.
 *
 * Shape: shared Dns_Provider::request() (JSON), Bearer auth. Zone discovery
 * makes exactly ONE request (GET /domains?page_size=500) and loops
 * zone_candidates() against that single cached list client-side -- same
 * "enumerate once, filter locally" shape as IONOS (see
 * ProviderContractIonosTest's docblock). No try/catch, so a non-2xx on
 * that one call propagates immediately and distinctly (no auth-during-
 * discovery misdiagnosis). zone() reads the response body, so this driver
 * validates bodies on the create path (response_body_is_validated_on_success()
 * stays at its default true).
 *
 * Confirmed production defect, not fixed here: Linode's v4 API documents
 * page/page_size pagination (default page_size=100, maximum 500) with
 * page/pages/results fields in every list response, verified directly
 * against Linode's (Akamai TechDocs) published API reference
 * (https://techdocs.akamai.com/linode-api/reference/get-domain-records).
 * This driver sends page_size=500 (the documented maximum) on BOTH the
 * domains list (zone discovery) and the records list (delete lookup), but
 * never checks the "pages" field or requests page=2 on either. An account
 * with more than 500 domains, or a zone with more than 500 records, can
 * silently miss the correct entry -- the domains-list case can break
 * issuance entirely (matching IONOS's zone-discovery severity), the
 * records-list case only leaves a cleanup record undeleted (matching
 * Batch 2's DigitalOcean/Vultr/Vercel findings). Both proven below.
 */

declare( strict_types=1 );

use WP_SAM\Certificates\Providers\Provider_Linode;

class ProviderContractLinodeTest extends Dns_Provider_Contract_TestCase {

	private function wp_response( int $code, array $body = array() ): array {
		return array(
			'response' => array( 'code' => $code ),
			'body'     => (string) wp_json_encode( $body ),
		);
	}

	private function domains_list_matching(): array {
		return $this->wp_response( 200, array( 'data' => array( array( 'id' => 42, 'domain' => 'example.com' ) ) ) );
	}

	protected function make_provider(): Provider_Linode {
		return new Provider_Linode( array( 'api_token' => 'fixture-linode-token' ) );
	}

	protected function fqdn(): string {
		return '_acme-challenge.www.example.com';
	}

	protected function record_value(): string {
		return 'fixture-challenge-digest-value';
	}

	protected function queue_successful_create(): void {
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->domains_list_matching(),
			$this->wp_response( 201 ), // POST create
		);
	}

	protected function queue_successful_delete(): void {
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->domains_list_matching(),
			$this->wp_response(
				200,
				array(
					'data' => array(
						array( 'id' => 999, 'type' => 'TXT', 'name' => '_acme-challenge.www', 'target' => $this->record_value() ),
					),
				)
			),
			$this->wp_response( 200 ), // DELETE
		);
	}

	protected function queue_authentication_failure(): void {
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->domains_list_matching(),
			$this->wp_response( 401 ),
		);
	}

	protected function queue_zone_not_found(): void {
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->wp_response( 200, array( 'data' => array() ) ),
		);
	}

	protected function queue_malformed_response(): void {
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			array( 'response' => array( 'code' => 200 ), 'body' => 'not json at all {{{' ),
		);
	}

	protected function queue_http_failure(): void {
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->domains_list_matching(),
			$this->wp_response( 500 ),
		);
	}

	protected function assert_authenticated_correctly( array $request ): void {
		$this->assertSame( 'Bearer fixture-linode-token', $request['args']['headers']['Authorization'] ?? null );
	}

	protected function assert_record_naming_correct( array $create_request ): void {
		$this->assertStringContainsString( '/domains/42/records', $create_request['url'] );
		$body = $this->decoded_body( $create_request );
		$this->assertIsArray( $body );
		$this->assertSame( '_acme-challenge.www', $body['name'] ?? null );
		$this->assertSame( 'TXT', $body['type'] ?? null );
		$this->assertSame( $this->record_value(), $body['target'] ?? null );
	}

	// ── Provider-specific: record identifier extracted from the list ─────────

	public function test_delete_uses_the_server_assigned_record_id_from_the_list_response(): void {
		$provider = $this->make_provider();
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->domains_list_matching(),
			$this->wp_response(
				200,
				array(
					'data' => array(
						array( 'id' => 1, 'type' => 'TXT', 'name' => '_acme-challenge.www', 'target' => 'not-the-value' ),
						array( 'id' => 2, 'type' => 'TXT', 'name' => '_acme-challenge.www', 'target' => $this->record_value() ),
					),
				)
			),
			$this->wp_response( 200 ),
		);

		$provider->delete_txt_record( $this->fqdn(), $this->record_value() );

		$requests = $this->captured_requests();
		$last     = end( $requests );
		$this->assertSame( 'DELETE', $last['args']['method'] ?? null );
		$this->assertStringContainsString( '/domains/42/records/2', $last['url'] );
	}

	// ── Provider-specific: confirmed pagination defect -- records list ───────

	public function test_records_list_pagination_can_leave_a_matching_record_undeleted(): void {
		$provider = $this->make_provider();
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->domains_list_matching(),
			$this->wp_response(
				200,
				array(
					'data' => array(
						array( 'id' => 1, 'type' => 'TXT', 'name' => 'unrelated', 'target' => 'x' ),
					),
					'page'    => 1,
					'pages'   => 2,
					'results' => 501,
				)
			),
		);

		$provider->delete_txt_record( $this->fqdn(), $this->record_value() );

		$requests = $this->captured_requests();
		$this->assertCount( 2, $requests, 'the driver never inspects "pages" or requests page=2, so a record on a later page is silently left undeleted' );
	}

	// ── Provider-specific: confirmed pagination defect -- domains list ───────

	public function test_domains_list_pagination_can_silently_miss_the_correct_zone(): void {
		$provider = $this->make_provider();
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->wp_response(
				200,
				array(
					'data'    => array(
						array( 'id' => 1, 'domain' => 'unrelated-1.com' ),
						array( 'id' => 2, 'domain' => 'unrelated-2.com' ),
					),
					'page'    => 1,
					'pages'   => 2,
					'results' => 501,
				)
			),
		);

		try {
			$provider->create_txt_record( $this->fqdn(), $this->record_value() );
			$this->fail( 'expected an exception when the correct domain is absent from the single unpaginated response' );
		} catch ( \RuntimeException $e ) {
			$this->assertStringContainsString( 'no domain found', $e->getMessage() );
		}

		$this->assertCount( 1, $this->captured_requests(), 'the driver never inspects "pages" or requests page=2 for the domains list either' );
	}

	// ── Provider-specific: discovery-stage auth failure is NOT misreported ───

	public function test_authentication_failure_during_zone_discovery_surfaces_distinctly_not_as_zone_not_found(): void {
		$provider = $this->make_provider();
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->wp_response( 401 ),
		);

		try {
			$provider->create_txt_record( $this->fqdn(), $this->record_value() );
			$this->fail( 'expected an exception when the single domains-list request is rejected with 401' );
		} catch ( \RuntimeException $e ) {
			$this->assertStringNotContainsString( 'no domain found', $e->getMessage() );
			$this->assertStringContainsString( 'HTTP 401', $e->getMessage() );
		}

		$this->assertCount( 1, $this->captured_requests() );
	}
}
