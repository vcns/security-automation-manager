<?php
/**
 * Representative fixture #2 for Dns_Provider_Contract_TestCase (Phase 6B):
 * a provider built on the shared Dns_Provider::request_raw() helper (raw
 * body, not JSON), using AWS Signature Version 4 as its authentication
 * header rather than a simple Bearer token, XML request/response bodies,
 * and a query-string-parameterised zone lookup rather than Cloudflare's
 * query-string-URL-parameter style. Deliberately as different from the
 * Cloudflare fixture as a real driver gets, short of RFC 2136's raw socket
 * (out of scope for this HTTP-transport framework -- see this file's sibling
 * Dns_Provider_Contract_TestCase.php docblock).
 */

declare( strict_types=1 );

use WP_SAM\Certificates\Providers\Provider_Route53;

class ProviderContractRoute53Test extends Dns_Provider_Contract_TestCase {

	private function xml_response( int $code, string $xml_body ): array {
		return array(
			'response' => array( 'code' => $code ),
			'body'     => $xml_body,
		);
	}

	private function zone_found_xml( string $candidate, string $zone_id ): string {
		return '<?xml version="1.0"?><ListHostedZonesByNameResponse><HostedZones><HostedZone>'
			. "<Id>/hostedzone/{$zone_id}</Id><Name>{$candidate}.</Name>"
			. '</HostedZone></HostedZones></ListHostedZonesByNameResponse>';
	}

	private function zone_not_found_xml(): string {
		return '<?xml version="1.0"?><ListHostedZonesByNameResponse><HostedZones/></ListHostedZonesByNameResponse>';
	}

	protected function make_provider(): Provider_Route53 {
		return new Provider_Route53(
			array(
				'access_key_id'     => 'AKIAFIXTUREACCESSKEY',
				'secret_access_key' => 'fixture-secret-access-key-value',
			)
		);
	}

	protected function fqdn(): string {
		// zone_candidates(): _acme-challenge.www.example.com, www.example.com,
		// example.com -- 3 candidates. Fixtures below assume the zone is
		// found on the 3rd (example.com), the realistic case.
		return '_acme-challenge.www.example.com';
	}

	protected function record_value(): string {
		return 'fixture-challenge-digest-value';
	}

	protected function queue_successful_create(): void {
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->xml_response( 200, $this->zone_not_found_xml() ), // _acme-challenge.www.example.com
			$this->xml_response( 200, $this->zone_not_found_xml() ), // www.example.com
			$this->xml_response( 200, $this->zone_found_xml( 'example.com', 'Z1234567890ABC' ) ), // example.com -- found
			$this->xml_response( 200, '<?xml version="1.0"?><ChangeResourceRecordSetsResponse><ChangeInfo><Status>PENDING</Status></ChangeInfo></ChangeResourceRecordSetsResponse>' ), // POST change (UPSERT)
		);
	}

	protected function queue_successful_delete(): void {
		// delete_txt_record() -> change(..., 'DELETE') re-resolves the zone
		// from scratch, exactly like create does -- Route 53 caches nothing
		// between calls.
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->xml_response( 200, $this->zone_not_found_xml() ),
			$this->xml_response( 200, $this->zone_not_found_xml() ),
			$this->xml_response( 200, $this->zone_found_xml( 'example.com', 'Z1234567890ABC' ) ),
			$this->xml_response( 200, '<?xml version="1.0"?><ChangeResourceRecordSetsResponse><ChangeInfo><Status>PENDING</Status></ChangeInfo></ChangeResourceRecordSetsResponse>' ), // POST change (DELETE)
		);
	}

	protected function queue_authentication_failure(): void {
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->xml_response( 403, '<?xml version="1.0"?><ErrorResponse><Error><Code>SignatureDoesNotMatch</Code><Message>The request signature we calculated does not match the signature you provided.</Message></Error></ErrorResponse>' ),
		);
	}

	protected function queue_zone_not_found(): void {
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->xml_response( 200, $this->zone_not_found_xml() ),
			$this->xml_response( 200, $this->zone_not_found_xml() ),
			$this->xml_response( 200, $this->zone_not_found_xml() ),
		);
	}

	protected function queue_malformed_response(): void {
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->xml_response( 200, 'this is not XML at all {{{' ),
			$this->xml_response( 200, 'this is not XML at all {{{' ),
			$this->xml_response( 200, 'this is not XML at all {{{' ),
		);
	}

	protected function queue_http_failure(): void {
		$GLOBALS['_wp_remote_request_response_queue'] = array(
			$this->xml_response( 500, '<?xml version="1.0"?><ErrorResponse><Error><Code>InternalError</Code></Error></ErrorResponse>' ),
		);
	}

	protected function assert_authenticated_correctly( array $request ): void {
		$auth = $request['args']['headers']['Authorization'] ?? '';
		$this->assertStringStartsWith( 'AWS4-HMAC-SHA256 Credential=AKIAFIXTUREACCESSKEY/', $auth );
		$this->assertStringContainsString( 'route53/aws4_request', $auth );
		$this->assertStringContainsString( 'Signature=', $auth );
		$this->assertArrayHasKey( 'X-Amz-Date', $request['args']['headers'] ?? array() );
	}

	protected function assert_record_naming_correct( array $create_request ): void {
		$body = (string) ( $create_request['args']['body'] ?? '' );
		$this->assertStringContainsString( '<Name>' . $this->fqdn() . '.</Name>', $body, 'Route 53\'s ChangeResourceRecordSets body must carry the full fqdn (trailing dot), not a zone-relative name' );
		$this->assertStringContainsString( '<Type>TXT</Type>', $body );
		$this->assertStringContainsString( $this->record_value(), $body );
	}
}
