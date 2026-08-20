<?php
/**
 * Phase 6C, Batch 4 ("JSON transport, non-standard auth or a pre-step"):
 * request-level contract coverage for
 * WP_SAM\Certificates\Providers\Provider_Dnsimple.
 *
 * Shape: shared Dns_Provider::request() (JSON), Bearer auth, try/catch
 * zone discovery -- but with an added memoised account-resolution
 * pre-step: private account() calls GET /whoami once, caches the account
 * ID on the instance ($account_id), and every zone()/record URL is built
 * from that ID. Because `$this->account()` is evaluated as part of
 * constructing the URL argument *inside* zone()'s try block, an account()
 * failure (a bad token at the whoami stage, or a malformed whoami
 * response) is swallowed by the exact same per-candidate
 * catch (\RuntimeException $e) { continue; } as a genuine zone-not-found
 * -- with the added twist that, since account_id never gets cached on
 * failure, whoami() is retried on *every* candidate iteration (3 attempts
 * for a 3-candidate fqdn, not 1).
 *
 * Confirmed production defect (extends the established Batch 1/2
 * auth-during-discovery family, with direct code evidence -- the nested
 * try/catch above -- not merely inferred from provider similarity), not
 * fixed here: an authentication failure at the whoami stage (a request
 * that genuinely throws, e.g. a 401) is misreported as "no zone found for
 * {fqdn}", identically to deSEC et al. Proven by
 * test_authentication_failure_during_zone_discovery_is_misreported_as_zone_not_found()
 * below (3 separate whoami attempts, one per candidate, all rejected --
 * account_id is only ever assigned *after* a non-throwing whoami request
 * returns, so a throwing request never gets cached and is retried on
 * every candidate).
 *
 * Distinct finding, not the same code path: account_id is assigned
 * *before* its own empty-value check runs (`$this->account_id = (string)(
 * ... ?? ''); if ('' === $this->account_id) { throw ... }`), so a
 * malformed-but-2xx whoami response throws exactly ONCE (candidate 1),
 * then permanently caches an empty account_id and never calls whoami()
 * again. From candidate 2 onward, account() just returns '' silently, and
 * zone()'s own per-candidate check never reads a response body at all --
 * it treats *any* non-throwing status as "zone found," matching Batch 1's
 * status-only pattern. response_body_is_validated_on_success() is
 * therefore false, not the nested-pre-step default of true.
 */

declare( strict_types=1 );

use WP_SAM\Certificates\Providers\Provider_Dnsimple;

class ProviderContractDnsimpleTest extends Dns_Provider_Contract_TestCase {

	private function wp_response( int $code, array $body = array() ): array {
		return array(
			'response' => array( 'code' => $code ),
			'body'     => (string) wp_json_encode( $body ),
		);
	}

	private function whoami_matching(): array {
		return $this->wp_response( 200, array( 'data' => array( 'account' => array( 'id' => 999 ) ) ) );
	}

	protected function make_provider(): Provider_Dnsimple {
		return new Provider_Dnsimple( array( 'api_token' => 'fixture-dnsimple-token' ) );
	}

	protected function fqdn(): string {
		return '_acme-challenge.www.example.com';
	}

	protected function record_value(): string {
		return 'fixture-challenge-digest-value';
	}

	protected function queue_successful_create(): void {
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->whoami_matching(), // account() on candidate 1
			$this->wp_response( 404 ), // _acme-challenge.www.example.com
			$this->wp_response( 404 ), // www.example.com
			$this->wp_response( 200 ), // example.com -- exists (account() now cached, no further whoami calls)
			$this->wp_response( 201 ), // POST create
		);
	}

	protected function queue_successful_delete(): void {
		// account_id is already cached from the preceding create_txt_record()
		// call on the same $provider instance -- no further whoami request.
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->wp_response( 404 ),
			$this->wp_response( 404 ),
			$this->wp_response( 200 ),
			$this->wp_response( 200, array( 'data' => array( array( 'id' => 777, 'content' => '"' . $this->record_value() . '"' ) ) ) ), // GET list
			$this->wp_response( 204 ), // DELETE
		);
	}

	protected function queue_authentication_failure(): void {
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->whoami_matching(),
			$this->wp_response( 200 ), // zone found on the first candidate
			$this->wp_response( 401 ), // the POST create itself is rejected
		);
	}

	protected function queue_zone_not_found(): void {
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->whoami_matching(), // account() succeeds once and is cached
			$this->wp_response( 404 ),
			$this->wp_response( 404 ),
			$this->wp_response( 404 ),
		);
	}

	protected function queue_malformed_response(): void {
		// See class docblock: a malformed 2xx whoami response throws once
		// (candidate 1), then permanently caches an empty account_id --
		// candidates 2 onward make a real zone-check request each, and
		// zone() never reads a response body, so a malformed-but-2xx
		// zone-check is treated as "found," matching Batch 1's status-only
		// providers. create_txt_record() is therefore expected to succeed.
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			array( 'response' => array( 'code' => 200 ), 'body' => 'not json at all {{{' ), // whoami -- malformed, throws once, caches ''
			array( 'response' => array( 'code' => 200 ), 'body' => 'not json at all {{{' ), // zone check, candidate 2 -- malformed but 2xx, treated as found
			array( 'response' => array( 'code' => 200 ), 'body' => 'not json at all {{{' ), // POST create -- response discarded regardless
		);
	}

	protected function response_body_is_validated_on_success(): bool {
		return false;
	}

	protected function queue_http_failure(): void {
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->whoami_matching(),
			$this->wp_response( 200 ),
			$this->wp_response( 500 ),
		);
	}

	protected function assert_authenticated_correctly( array $request ): void {
		$this->assertSame( 'Bearer fixture-dnsimple-token', $request['args']['headers']['Authorization'] ?? null );
	}

	protected function assert_record_naming_correct( array $create_request ): void {
		$this->assertStringContainsString( '/999/zones/example.com/records', $create_request['url'], 'the account ID resolved via whoami() must appear in the URL' );
		$body = $this->decoded_body( $create_request );
		$this->assertIsArray( $body );
		$this->assertSame( '_acme-challenge.www', $body['name'] ?? null );
		$this->assertSame( 'TXT', $body['type'] ?? null );
		$this->assertSame( $this->record_value(), $body['content'] ?? null );
	}

	// ── Provider-specific: whoami() is resolved once and cached ──────────────

	public function test_whoami_is_called_once_and_cached_across_create_and_delete(): void {
		$provider = $this->make_provider();
		$this->queue_successful_create();
		$provider->create_txt_record( $this->fqdn(), $this->record_value() );

		$this->queue_successful_delete();
		$provider->delete_txt_record( $this->fqdn(), $this->record_value() );

		$whoami_calls = array_filter(
			$this->captured_requests(),
			static fn( array $r ): bool => str_contains( (string) ( $r['url'] ?? '' ), '/whoami' )
		);
		$this->assertCount( 1, $whoami_calls, 'the account pre-step must resolve once and be cached for the rest of this provider instance\'s lifetime' );
	}

	// ── Provider-specific: record identifier extracted from the list ─────────

	public function test_delete_uses_the_server_assigned_record_id_from_the_list_response(): void {
		$provider = $this->make_provider();
		$this->queue_successful_create();
		$provider->create_txt_record( $this->fqdn(), $this->record_value() );

		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->wp_response( 404 ),
			$this->wp_response( 404 ),
			$this->wp_response( 200 ),
			$this->wp_response(
				200,
				array(
					'data' => array(
						array( 'id' => 1, 'content' => '"not-the-value"' ),
						array( 'id' => 2, 'content' => '"' . $this->record_value() . '"' ),
					),
				)
			),
			$this->wp_response( 204 ),
		);

		$provider->delete_txt_record( $this->fqdn(), $this->record_value() );

		$requests = $this->captured_requests();
		$last     = end( $requests );
		$this->assertSame( 'DELETE', $last['args']['method'] ?? null );
		$this->assertStringContainsString( '/999/zones/example.com/records/2', $last['url'] );
	}

	// ── Provider-specific: confirmed pagination defect on the records list ───

	public function test_records_list_pagination_can_leave_a_matching_record_undeleted(): void {
		$provider = $this->make_provider();
		$this->queue_successful_create();
		$provider->create_txt_record( $this->fqdn(), $this->record_value() );

		$before = count( $this->captured_requests() );
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->wp_response( 404 ),
			$this->wp_response( 404 ),
			$this->wp_response( 200 ),
			$this->wp_response(
				200,
				array(
					'data'       => array(
						array( 'id' => 1, 'content' => '"unrelated"' ),
					),
					'pagination' => array( 'current_page' => 1, 'per_page' => 30, 'total_entries' => 31, 'total_pages' => 2 ),
				)
			),
		);

		$provider->delete_txt_record( $this->fqdn(), $this->record_value() );

		$requests = $this->captured_requests();
		$this->assertCount( $before + 4, $requests, 'the driver never inspects "total_pages" or requests page=2, so a record on a later page is silently left undeleted' );
	}

	// ── Provider-specific: discovery-stage auth failure is misreported ───────

	public function test_authentication_failure_during_zone_discovery_is_misreported_as_zone_not_found(): void {
		$provider = $this->make_provider();
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->wp_response( 401 ), // whoami on candidate 1
			$this->wp_response( 401 ), // whoami retried on candidate 2 (never cached)
			$this->wp_response( 401 ), // whoami retried on candidate 3
		);

		try {
			$provider->create_txt_record( $this->fqdn(), $this->record_value() );
			$this->fail( 'expected an exception when whoami() is rejected on every candidate' );
		} catch ( \RuntimeException $e ) {
			$this->assertStringContainsString( 'no zone found', $e->getMessage() );
		}

		$this->assertCount( 3, $this->captured_requests(), 'whoami() is retried once per candidate since it never succeeds long enough to be cached' );
	}
}
