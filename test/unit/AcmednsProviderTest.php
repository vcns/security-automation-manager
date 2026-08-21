<?php
/**
 * Phase 6C, Batch 5: request-level coverage for
 * WP_SAM\Certificates\Providers\Provider_Acmedns.
 *
 * Deliberately NOT built on Dns_Provider_Contract_TestCase -- acme-dns is
 * architecturally incompatible with the shared ten-item contract, not
 * merely a variant of it:
 *   - There is no zone concept at all. zone_candidates() and
 *     relative_name() are never called; $fqdn is accepted as a parameter
 *     (to satisfy the Dns_Provider interface) but is never read anywhere
 *     in either method. The actual target is entirely determined by the
 *     "subdomain" credential captured once at acme-dns registration time.
 *   - delete_txt_record() is an intentional, total no-op (an empty method
 *     body) -- acme-dns keeps a rolling window of the last two TXT values
 *     server-side and has no delete endpoint at all; old values simply
 *     age out on the next update. Forcing this through the shared
 *     contract's test_successful_txt_record_deletion() (which asserts a
 *     delete call makes *more* requests than before it) would either fail
 *     honestly or require a misleading workaround.
 *   - There is consequently no "zone not found," "auth failure during
 *     discovery," or "relative name handling" dimension to test at all --
 *     these are not merely inapplicable variants, they don't exist as
 *     concepts for this provider (matching PowerDNS's and RFC 2136's
 *     precedent of an explicit, disclosed "no applicable mechanism"
 *     rather than a forced, artificial test).
 *
 * This file instead tests the driver's actual behaviour directly: request
 * construction and headers, malformed/failed create() responses not being
 * treated as success, transport/HTTP failures, and the delete-is-a-no-op
 * behaviour explicitly.
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;
use WP_SAM\Certificates\Providers\Provider_Acmedns;

class AcmednsProviderTest extends TestCase {

	protected function setUp(): void {
		wp_test_reset_globals();
	}

	private function raw_response( int $code, string $body ): array {
		return array(
			'response' => array( 'code' => $code ),
			'body'     => $body,
		);
	}

	private function captured_requests(): array {
		return $GLOBALS['_wp_remote_all_requests'] ?? array();
	}

	private function make_provider(): Provider_Acmedns {
		return new Provider_Acmedns(
			array(
				'server_url' => 'https://auth.acme-dns.io',
				'username'   => 'fixture-acmedns-user',
				'password'   => 'fixture-acmedns-pass',
				'subdomain'  => 'd420c923-bbd7-4056-ab64-c3ca54c9b3cf',
			)
		);
	}

	private function fqdn(): string {
		return '_acme-challenge.www.example.com';
	}

	private function record_value(): string {
		return 'fixture-challenge-digest-value';
	}

	public function test_successful_create_posts_to_update_with_the_subdomain_and_txt_value(): void {
		$provider = $this->make_provider();
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->raw_response( 200, (string) wp_json_encode( array( 'subdomain' => 'd420c923-bbd7-4056-ab64-c3ca54c9b3cf', 'txt' => $this->record_value() ) ) ),
		);

		$provider->create_txt_record( $this->fqdn(), $this->record_value() );

		$requests = $this->captured_requests();
		$this->assertCount( 1, $requests );
		$this->assertStringContainsString( '/update', $requests[0]['url'] );
		$this->assertSame( 'POST', $requests[0]['args']['method'] ?? null );

		$headers = $requests[0]['args']['headers'] ?? array();
		$this->assertSame( 'fixture-acmedns-user', $headers['X-Api-User'] ?? null );
		$this->assertSame( 'fixture-acmedns-pass', $headers['X-Api-Key'] ?? null );

		$body = json_decode( (string) ( $requests[0]['args']['body'] ?? '' ), true );
		$this->assertSame( 'd420c923-bbd7-4056-ab64-c3ca54c9b3cf', $body['subdomain'] ?? null );
		$this->assertSame( $this->record_value(), $body['txt'] ?? null );
	}

	public function test_fqdn_parameter_is_accepted_but_never_used(): void {
		$provider = $this->make_provider();
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->raw_response( 200, (string) wp_json_encode( array( 'subdomain' => 'd420c923-bbd7-4056-ab64-c3ca54c9b3cf', 'txt' => $this->record_value() ) ) ),
		);

		// A completely different, arbitrary fqdn -- the request must be
		// identical regardless, since the target is the "subdomain"
		// credential, not $fqdn.
		$provider->create_txt_record( 'totally-unrelated.example.org', $this->record_value() );

		$requests = $this->captured_requests();
		$body     = json_decode( (string) ( $requests[0]['args']['body'] ?? '' ), true );
		$this->assertStringNotContainsString( 'totally-unrelated', (string) $requests[0]['args']['body'] );
		$this->assertSame( 'd420c923-bbd7-4056-ab64-c3ca54c9b3cf', $body['subdomain'] ?? null );
	}

	public function test_a_txt_value_mismatch_in_the_response_is_not_treated_as_success(): void {
		$provider = $this->make_provider();
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			// acme-dns accepted the request but echoed back a different
			// txt value than what was submitted -- must not be silently
			// treated as success.
			$this->raw_response( 200, (string) wp_json_encode( array( 'subdomain' => 'd420c923-bbd7-4056-ab64-c3ca54c9b3cf', 'txt' => 'a-different-value' ) ) ),
		);

		$this->expectException( \RuntimeException::class );
		$provider->create_txt_record( $this->fqdn(), $this->record_value() );
	}

	public function test_a_malformed_response_is_not_treated_as_success(): void {
		$provider = $this->make_provider();
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->raw_response( 200, 'not json at all {{{' ),
		);

		$this->expectException( \RuntimeException::class );
		$provider->create_txt_record( $this->fqdn(), $this->record_value() );
	}

	public function test_provider_side_http_failure_throws(): void {
		$provider = $this->make_provider();
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->raw_response( 500, 'Internal Server Error' ),
		);

		$this->expectException( \RuntimeException::class );
		$provider->create_txt_record( $this->fqdn(), $this->record_value() );
	}

	public function test_authentication_failure_is_not_treated_as_success(): void {
		$provider = $this->make_provider();
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->raw_response( 401, (string) wp_json_encode( array( 'error' => 'Forbidden' ) ) ),
		);

		$this->expectException( \RuntimeException::class );
		$provider->create_txt_record( $this->fqdn(), $this->record_value() );
	}

	public function test_transport_level_wp_error_throws(): void {
		$provider                                = $this->make_provider();
		$GLOBALS['_wp_remote_request_response'] = new WP_Error( 'http_request_failed', 'Connection timed out' );

		$this->expectException( \RuntimeException::class );
		$provider->create_txt_record( $this->fqdn(), $this->record_value() );
	}

	// ── delete_txt_record() is an intentional, total no-op ───────────────────

	public function test_delete_makes_no_request_and_never_throws(): void {
		$provider = $this->make_provider();

		$provider->delete_txt_record( $this->fqdn(), $this->record_value() );

		$this->assertCount( 0, $this->captured_requests(), 'acme-dns has no delete endpoint -- old TXT values age out of its rolling two-value window on the next update, so delete_txt_record() must not attempt any request' );
	}

	public function test_delete_is_a_no_op_regardless_of_arguments(): void {
		$provider = $this->make_provider();

		$provider->delete_txt_record( 'anything.example.com', 'any-value-at-all' );

		$this->assertCount( 0, $this->captured_requests() );
	}
}
