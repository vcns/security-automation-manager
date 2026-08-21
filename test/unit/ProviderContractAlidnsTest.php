<?php
/**
 * Phase 6C, Batch 6 ("Raw transport, JSON/RPC envelopes"): request-level
 * contract coverage for WP_SAM\Certificates\Providers\Provider_Alidns.
 *
 * Shape: Dns_Provider::request_raw() (GET with a signed query string,
 * HMAC-SHA1 per Alibaba Cloud's RPC signing convention). Zone discovery
 * makes exactly ONE request to a specialised resolver operation
 * (GetMainDomainName), Dynu-getroot-style, with no zone_candidates()
 * walk and no try/catch. Alibaba Cloud's documentation confirms
 * authentication/signature failures use real HTTP status codes (403 or
 * 400) generally across their APIs (alibabacloud.com/help, "If
 * authentication fails, the HTTP response status code will be 403 or
 * 400"), so a genuine auth failure on that one call propagates
 * immediately and directly via request_raw()'s own HTTP-status throw --
 * confirmed immune to the auth-misdiagnosis defect for this specific
 * dimension. Proven by
 * test_authentication_failure_during_zone_discovery_surfaces_distinctly_not_as_zone_not_found()
 * below.
 *
 * SEPARATE, more significant confirmed production defect, not fixed
 * here: call() never validates the decoded response body for
 * success/failure on ANY operation -- it simply returns whatever JSON
 * decodes to (or an empty array if it doesn't decode), with no check for
 * Alibaba Cloud's own documented error-response shape ("in most cases an
 * error response contains an error code and an error message" --
 * Code/Message fields, alibabacloud.com/help/en/doc-detail/25491.html).
 * zone()'s own check (whether "DomainName" is present in the response)
 * incidentally catches this for the *zone-resolution* step only;
 * create_txt_record()'s AddDomainRecord call and delete_txt_record()'s
 * DeleteDomainRecord call discard their responses entirely without
 * checking for success at all. Concretely: if AddDomainRecord or
 * DeleteDomainRecord ever returns a 2xx HTTP response containing a
 * Code/Message business-error body (Alibaba Cloud's documentation notes
 * this "may vary by service", and no DNS-specific confirmation either way
 * could be established -- logged as [Unverified] whether this specific
 * scenario is realistic for AliDNS's create/delete operations
 * specifically), create_txt_record()/delete_txt_record() would report
 * success even though nothing was actually created or removed. Proven
 * precisely by test_create_does_not_detect_a_2xx_business_error_response()
 * below. response_body_is_validated_on_success() is false for this
 * reason (create's own response is never inspected).
 *
 * Confirmed pagination defect: DescribeDomainRecords documents
 * PageNumber (default 1) and PageSize (default 20, maximum 500)
 * (alibabacloud.com/help/en/dns/api-alidns-2015-01-09-describedomainrecords,
 * verified directly). delete_txt_record()'s call is already filtered by
 * RRKeyWord and TypeKeyWord, narrowing results, but sends neither
 * pagination parameter, so the mechanism is confirmed to exist and go
 * unused.
 */

declare( strict_types=1 );

use WP_SAM\Certificates\Providers\Provider_Alidns;

class ProviderContractAlidnsTest extends Dns_Provider_Contract_TestCase {

	private function raw_response( int $code, array $body = array() ): array {
		return array(
			'response' => array( 'code' => $code ),
			'body'     => (string) wp_json_encode( $body ),
		);
	}

	protected function make_provider(): Provider_Alidns {
		return new Provider_Alidns(
			array(
				'access_key_id'     => 'fixture-access-key-id',
				'access_key_secret' => 'fixture-access-key-secret',
			)
		);
	}

	protected function fqdn(): string {
		return '_acme-challenge.www.example.com';
	}

	protected function record_value(): string {
		return 'fixture-challenge-digest-value';
	}

	private function zone_resolution_response(): array {
		return $this->raw_response( 200, array( 'DomainName' => 'example.com' ) );
	}

	protected function queue_successful_create(): void {
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->zone_resolution_response(),
			$this->raw_response( 200, array( 'RecordId' => 'rec-1' ) ), // AddDomainRecord
		);
	}

	protected function queue_successful_delete(): void {
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->zone_resolution_response(),
			$this->raw_response( 200, array( 'DomainRecords' => array( 'Record' => array( array( 'RecordId' => 'rec-9001', 'RR' => '_acme-challenge.www', 'Value' => $this->record_value() ) ) ) ) ), // DescribeDomainRecords
			$this->raw_response( 200 ), // DeleteDomainRecord
		);
	}

	protected function queue_authentication_failure(): void {
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->zone_resolution_response(),
			$this->raw_response( 403, array( 'Code' => 'InvalidAccessKeyId.NotFound', 'Message' => 'invalid access key' ) ),
		);
	}

	protected function queue_zone_not_found(): void {
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->raw_response( 200, array() ), // GetMainDomainName -- no "DomainName" field
		);
	}

	protected function queue_malformed_response(): void {
		// zone() succeeds normally; the create step's own response is
		// malformed -- proves create_txt_record() never inspects it (see
		// class docblock).
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->zone_resolution_response(),
			array( 'response' => array( 'code' => 200 ), 'body' => 'not json at all {{{' ),
		);
	}

	protected function response_body_is_validated_on_success(): bool {
		return false;
	}

	protected function queue_http_failure(): void {
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->zone_resolution_response(),
			$this->raw_response( 500, array( 'Code' => 'InternalError' ) ),
		);
	}

	protected function assert_authenticated_correctly( array $request ): void {
		$query = array();
		parse_str( (string) parse_url( $request['url'], PHP_URL_QUERY ), $query );
		$this->assertSame( 'fixture-access-key-id', $query['AccessKeyId'] ?? null );
		$this->assertSame( 'HMAC-SHA1', $query['SignatureMethod'] ?? null );
		$this->assertArrayHasKey( 'Signature', $query );
		$this->assertArrayHasKey( 'SignatureNonce', $query );
	}

	protected function assert_record_naming_correct( array $create_request ): void {
		$query = array();
		parse_str( (string) parse_url( $create_request['url'], PHP_URL_QUERY ), $query );
		$this->assertSame( 'AddDomainRecord', $query['Action'] ?? null );
		$this->assertSame( 'example.com', $query['DomainName'] ?? null );
		$this->assertSame( '_acme-challenge.www', $query['RR'] ?? null );
		$this->assertSame( 'TXT', $query['Type'] ?? null );
		$this->assertSame( $this->record_value(), $query['Value'] ?? null );
	}

	// ── Provider-specific: record identifier extracted from the list ─────────

	public function test_delete_uses_the_server_assigned_record_id_from_the_list_response(): void {
		$provider = $this->make_provider();
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->zone_resolution_response(),
			$this->raw_response(
				200,
				array(
					'DomainRecords' => array(
						'Record' => array(
							array( 'RecordId' => 'rec-a', 'RR' => '_acme-challenge.www', 'Value' => 'not-the-value' ),
							array( 'RecordId' => 'rec-b', 'RR' => '_acme-challenge.www', 'Value' => $this->record_value() ),
						),
					),
				)
			),
			$this->raw_response( 200 ),
		);

		$provider->delete_txt_record( $this->fqdn(), $this->record_value() );

		$requests = $this->captured_requests();
		$last     = end( $requests );
		$query    = array();
		parse_str( (string) parse_url( $last['url'], PHP_URL_QUERY ), $query );
		$this->assertSame( 'DeleteDomainRecord', $query['Action'] ?? null );
		$this->assertSame( 'rec-b', $query['RecordId'] ?? null );
	}

	// ── Provider-specific: confirmed pagination defect on the records list ───

	public function test_records_list_pagination_can_leave_a_matching_record_undeleted(): void {
		$provider = $this->make_provider();
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->zone_resolution_response(),
			$this->raw_response( 200, array( 'DomainRecords' => array( 'Record' => array( array( 'RecordId' => 'rec-x', 'RR' => 'unrelated', 'Value' => 'x' ) ) ) ) ),
		);

		$provider->delete_txt_record( $this->fqdn(), $this->record_value() );

		$requests = $this->captured_requests();
		$this->assertCount( 2, $requests, 'the driver never sends PageNumber/PageSize, so a record beyond the default 20-record page is silently left undeleted' );
	}

	// ── Provider-specific: confirmed defect -- unvalidated write responses ───

	public function test_create_does_not_detect_a_2xx_business_error_response(): void {
		$provider = $this->make_provider();
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->zone_resolution_response(),
			// A genuine Alibaba Cloud business-error shape (Code/Message),
			// but at HTTP 200 -- call() never checks for this at all.
			$this->raw_response( 200, array( 'Code' => 'DomainRecordDuplicate', 'Message' => 'The specified DNS record already exists.' ) ),
		);

		// Must NOT throw -- this is the confirmed defect: a genuine
		// business-level failure, reported at 2xx, is silently treated as
		// success because create_txt_record() never inspects the response.
		$provider->create_txt_record( $this->fqdn(), $this->record_value() );

		$this->assertCount( 2, $this->captured_requests() );
	}

	public function test_delete_does_not_detect_a_2xx_business_error_response(): void {
		$provider = $this->make_provider();
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->zone_resolution_response(),
			$this->raw_response( 200, array( 'DomainRecords' => array( 'Record' => array( array( 'RecordId' => 'rec-9001', 'RR' => '_acme-challenge.www', 'Value' => $this->record_value() ) ) ) ) ),
			$this->raw_response( 200, array( 'Code' => 'DomainRecordNotBelongToUser', 'Message' => 'The domain record does not belong to this user.' ) ),
		);

		$provider->delete_txt_record( $this->fqdn(), $this->record_value() );

		$this->assertCount( 3, $this->captured_requests() );
	}

	// ── Provider-specific: discovery-stage auth failure is NOT misreported ───

	public function test_authentication_failure_during_zone_discovery_surfaces_distinctly_not_as_zone_not_found(): void {
		$provider = $this->make_provider();
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->raw_response( 403, array( 'Code' => 'InvalidAccessKeyId.NotFound', 'Message' => 'invalid access key' ) ),
		);

		try {
			$provider->create_txt_record( $this->fqdn(), $this->record_value() );
			$this->fail( 'expected an exception when the single zone-resolution request is rejected with 403' );
		} catch ( \RuntimeException $e ) {
			$this->assertStringNotContainsString( 'unable to resolve the zone', $e->getMessage() );
			$this->assertStringContainsString( 'HTTP 403', $e->getMessage() );
		}

		$this->assertCount( 1, $this->captured_requests() );
	}
}
