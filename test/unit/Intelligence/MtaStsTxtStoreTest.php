<?php
/**
 * Unit tests for WP_SAM\Intelligence\Mta_Sts_Txt_Store.
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;
use WP_SAM\Intelligence\Mta_Sts_Txt_Store;

class MtaStsTxtStoreTest extends TestCase {

	/** @var array<int, string> */
	private array $fetched = array();

	protected function setUp(): void {
		wp_test_reset_globals();
		$this->fetched = array();
	}

	/** @param array|WP_Error $response */
	private function store( $response ): Mta_Sts_Txt_Store {
		return new Mta_Sts_Txt_Store(
			function ( string $url ) use ( $response ) {
				$this->fetched[] = $url;
				return $response;
			}
		);
	}

	private function policy_response( string $body, string $type = 'text/plain' ): array {
		return array(
			'response' => array( 'code' => 200 ),
			'headers'  => array( 'content-type' => $type ),
			'body'     => $body,
		);
	}

	private function advertise( string $record = 'v=STSv1; id=abc123' ): void {
		$GLOBALS['_wp_dns_records'][ DNS_TXT . ':_mta-sts.example.com' ] = array( array( 'txt' => $record ) );
	}

	public function test_a_served_policy_is_parsed_with_what_dns_says(): void {
		$this->advertise();

		$result = $this->store( $this->policy_response( "version: STSv1\nmode: enforce\nmx: mx1.example.com\nmax_age: 604800\n" ) )->refresh();

		$this->assertSame( 'refreshed', $result['status'] );
		$this->assertSame( array( 'https://mta-sts.example.com/.well-known/mta-sts.txt' ), $this->fetched );
		$store = new Mta_Sts_Txt_Store();
		$this->assertTrue( $store->is_present() );
		$this->assertSame( 'enforce', $store->fields()['mode'] );
		$this->assertSame( array( 'mx1.example.com' ), $store->fields()['mx'] );
		$this->assertSame( 'found', $store->fields()['dns_status'] );
		$this->assertSame( 'abc123', $store->fields()['dns_id'] );
	}

	public function test_no_dns_record_and_no_policy_host_is_absent_not_a_failure(): void {
		$result = $this->store( new WP_Error( 'http_request_failed', 'cURL error 6: Could not resolve host' ) )->refresh();

		$this->assertSame( 'absent', $result['status'] );
		$this->assertSame( 'absent', ( new Mta_Sts_Txt_Store() )->last_fetch_status() );
	}

	public function test_a_dns_record_with_an_unreachable_policy_is_a_failure(): void {
		$this->advertise();

		$result = $this->store( array( 'response' => array( 'code' => 404 ) ) )->refresh();

		$this->assertSame( 'failed', $result['status'] );
		$this->assertStringContainsString( 'HTTP 404', $result['message'] );
	}

	public function test_a_redirect_or_html_policy_is_not_one_mail_servers_accept(): void {
		$this->advertise();

		$redirect = $this->store(
			array(
				'response' => array( 'code' => 302 ),
				'headers'  => array( 'location' => 'https://example.org/' ),
			)
		)->refresh();
		$html     = $this->store( $this->policy_response( "version: STSv1\n", 'text/html' ) )->refresh();

		$this->assertSame( 'failed', $redirect['status'] );
		$this->assertStringNotContainsString( 'example.org', $redirect['message'] );
		$this->assertSame( 'failed', $html['status'] );
	}

	public function test_a_failure_keeps_the_last_good_reading(): void {
		$this->advertise();
		$this->store( $this->policy_response( "version: STSv1\nmode: testing\nmx: mx1.example.com\nmax_age: 86400\n" ) )->refresh();

		$this->store( new WP_Error( 'http_request_failed', 'timed out' ) )->refresh();

		$store = new Mta_Sts_Txt_Store();
		$this->assertSame( 'failed', $store->last_fetch_status() );
		$this->assertSame( 'testing', $store->fields()['mode'] );
	}
}
