<?php
/**
 * Phase 6C, Batch 2 ("Cloudflare clones, list-then-delete-by-ID"): request-
 * level contract coverage for WP_SAM\Certificates\Providers\Provider_Vercel.
 *
 * Shape: shared Dns_Provider::request() (JSON), Bearer auth, try/catch zone
 * discovery (same status-only-on-create finding and recurring
 * auth-during-discovery misdiagnosis as DigitalOcean/Vultr/Name.com/
 * easyDNS -- see ProviderContractDigitaloceanTest's docblock). Distinctive:
 * three different API versions are used across zone lookup (v5), create
 * (v2), and list/delete (v4 list, v2 delete); and every request optionally
 * carries a "teamId" query-string parameter when a team scope is
 * configured, appended via team_query() -- tested as part of
 * "authentication construction" below since an omitted or wrong team scope
 * is effectively an authorization-scope defect even though the Bearer
 * token itself is unaffected.
 *
 * Confirmed production defect, not fixed here: the List existing DNS
 * records endpoint documents a `limit` parameter (default 20) and
 * `since`/`until` timestamp cursors, returning a `pagination.next`/`prev`
 * object when more records exist than fit in one page
 * (https://vercel.com/docs/rest-api/reference/endpoints/dns/list-existing-dns-records,
 * verified directly against the current published docs). This driver
 * sends ?limit=100 but never uses since/until to fetch a further page. A
 * matching record beyond the first 100 remains undeleted, with no error
 * surfaced -- proven by test_pagination_only_fetches_a_single_page_of_records()
 * below.
 */

declare( strict_types=1 );

use WP_SAM\Certificates\Providers\Provider_Vercel;

class ProviderContractVercelTest extends Dns_Provider_Contract_TestCase {

	private function wp_response( int $code, array $body = array() ): array {
		return array(
			'response' => array( 'code' => $code ),
			'body'     => (string) wp_json_encode( $body ),
		);
	}

	protected function make_provider(): Provider_Vercel {
		return new Provider_Vercel( array( 'api_token' => 'fixture-vercel-token' ) );
	}

	protected function fqdn(): string {
		return '_acme-challenge.www.example.com';
	}

	protected function record_value(): string {
		return 'fixture-challenge-digest-value';
	}

	protected function queue_successful_create(): void {
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->wp_response( 404 ),
			$this->wp_response( 404 ),
			$this->wp_response( 200 ),
			$this->wp_response( 201 ), // POST create
		);
	}

	protected function queue_successful_delete(): void {
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->wp_response( 404 ),
			$this->wp_response( 404 ),
			$this->wp_response( 200 ),
			$this->wp_response(
				200,
				array(
					'records' => array(
						array(
							'id'    => 'rec-vercel-1',
							'type'  => 'TXT',
							'name'  => '_acme-challenge.www',
							'value' => $this->record_value(),
						),
					),
				)
			),
			$this->wp_response( 204 ), // DELETE
		);
	}

	protected function queue_authentication_failure(): void {
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->wp_response( 200 ),
			$this->wp_response( 401 ),
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
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			array( 'response' => array( 'code' => 200 ), 'body' => 'not json at all {{{' ),
			array( 'response' => array( 'code' => 200 ), 'body' => 'not json at all {{{' ),
		);
	}

	protected function response_body_is_validated_on_success(): bool {
		return false;
	}

	protected function queue_http_failure(): void {
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->wp_response( 200 ),
			$this->wp_response( 500 ),
		);
	}

	protected function assert_authenticated_correctly( array $request ): void {
		$this->assertSame( 'Bearer fixture-vercel-token', $request['args']['headers']['Authorization'] ?? null );
		$this->assertStringNotContainsString( 'teamId=', $request['url'], 'no team scope configured -- teamId must not be appended' );
	}

	protected function assert_record_naming_correct( array $create_request ): void {
		$this->assertStringContainsString( '/v2/domains/example.com/records', $create_request['url'] );
		$body = $this->decoded_body( $create_request );
		$this->assertIsArray( $body );
		$this->assertSame( '_acme-challenge.www', $body['name'] ?? null );
		$this->assertSame( 'TXT', $body['type'] ?? null );
		$this->assertSame( $this->record_value(), $body['value'] ?? null );
	}

	// ── Provider-specific: record identifier extracted from the list ─────────

	public function test_delete_uses_the_server_assigned_record_id_from_the_list_response(): void {
		$provider = $this->make_provider();
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->wp_response( 404 ),
			$this->wp_response( 404 ),
			$this->wp_response( 200 ),
			$this->wp_response(
				200,
				array(
					'records' => array(
						array( 'id' => 'rec-1', 'type' => 'TXT', 'name' => '_acme-challenge.www', 'value' => 'not-the-value' ),
						array( 'id' => 'rec-2', 'type' => 'TXT', 'name' => '_acme-challenge.www', 'value' => $this->record_value() ),
					),
				)
			),
			$this->wp_response( 204 ),
		);

		$provider->delete_txt_record( $this->fqdn(), $this->record_value() );

		$requests = $this->captured_requests();
		$last     = end( $requests );
		$this->assertSame( 'DELETE', $last['args']['method'] ?? null );
		$this->assertStringContainsString( '/v2/domains/example.com/records/rec-2', $last['url'] );
	}

	// ── Provider-specific: confirmed pagination defect (see class docblock) ──

	public function test_pagination_only_fetches_a_single_page_of_records(): void {
		$provider = $this->make_provider();
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->wp_response( 404 ),
			$this->wp_response( 404 ),
			$this->wp_response( 200 ),
			$this->wp_response(
				200,
				array(
					'records' => array(
						array( 'id' => 'rec-1', 'type' => 'TXT', 'name' => 'unrelated', 'value' => 'x' ),
					),
				)
			),
		);

		$provider->delete_txt_record( $this->fqdn(), $this->record_value() );

		$requests = $this->captured_requests();
		$this->assertCount( 4, $requests, 'a record absent from the single fetched page (?limit=100) must not cause a DELETE request, and must not throw' );
	}

	// ── Provider-specific: discovery-stage auth failure is misreported ───────

	public function test_authentication_failure_during_zone_discovery_is_misreported_as_zone_not_found(): void {
		$provider = $this->make_provider();
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->wp_response( 401 ),
			$this->wp_response( 401 ),
			$this->wp_response( 401 ),
		);

		try {
			$provider->create_txt_record( $this->fqdn(), $this->record_value() );
			$this->fail( 'expected an exception when every zone-discovery candidate is rejected with 401' );
		} catch ( \RuntimeException $e ) {
			$this->assertStringContainsString( 'no domain found', $e->getMessage() );
		}

		$this->assertCount( 3, $this->captured_requests(), 'an authentication failure during zone discovery must not proceed to a write request' );
	}

	// ── Provider-specific: optional team scope is appended everywhere ────────

	public function test_team_id_is_appended_to_every_request_when_configured(): void {
		$provider = new Provider_Vercel(
			array(
				'api_token' => 'fixture-vercel-token',
				'team_id'   => 'team_fixture123',
			)
		);
		$this->queue_successful_create();

		$provider->create_txt_record( $this->fqdn(), $this->record_value() );

		foreach ( $this->captured_requests() as $request ) {
			$this->assertStringContainsString( 'teamId=team_fixture123', $request['url'], 'every request must carry the configured team scope, including zone-discovery lookups' );
		}
	}
}
