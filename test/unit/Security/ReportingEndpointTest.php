<?php
/**
 * Unit tests for WP_SAM\Security\Reporting_Endpoint.
 *
 * Header emission itself is not tested here as it requires PHP header state
 * (same limitation documented in PolicyBuilderTest) -- only the pure
 * URL-resolution and validation logic is covered.
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;
use WP_SAM\Security\Reporting_Endpoint;

class ReportingEndpointTest extends TestCase {

	protected function setUp(): void {
		wp_test_reset_globals();
	}

	public function test_url_uses_home_url_before_init(): void {
		$GLOBALS['_wp_rest_url_should_throw'] = true;

		$this->assertSame( 'https://example.com/wp-json/sam/v1/report', Reporting_Endpoint::url() );
	}

	public function test_url_uses_rest_url_after_init(): void {
		$GLOBALS['_wp_did_actions']['init'] = 1;

		$this->assertSame( 'https://example.com/wp-json/sam/v1/report', Reporting_Endpoint::url() );
	}

	public function test_url_prefers_valid_configured_override(): void {
		update_option( 'wp_sam_report_endpoint_url', 'https://public.example.net/wp-json/custom-endpoint/v1/report' );

		$this->assertSame( 'https://public.example.net/wp-json/custom-endpoint/v1/report', Reporting_Endpoint::url() );
	}

	public function test_url_ignores_invalid_configured_override(): void {
		update_option( 'wp_sam_report_endpoint_url', 'javascript:alert(1)' );

		$this->assertSame( 'https://example.com/wp-json/sam/v1/report', Reporting_Endpoint::url() );
	}

	public function test_is_allowed_url_accepts_https(): void {
		$this->assertTrue( Reporting_Endpoint::is_allowed_url( 'https://example.com/report' ) );
	}

	public function test_is_allowed_url_accepts_http(): void {
		$this->assertTrue( Reporting_Endpoint::is_allowed_url( 'http://example.com/report' ) );
	}

	public function test_is_allowed_url_rejects_non_http_scheme(): void {
		$this->assertFalse( Reporting_Endpoint::is_allowed_url( 'javascript:alert(1)' ) );
	}

	public function test_is_allowed_url_rejects_header_injection_characters(): void {
		$this->assertFalse( Reporting_Endpoint::is_allowed_url( "https://example.com/\r\nX-Injected: 1" ) );
	}

	public function test_is_allowed_url_rejects_a_url_with_no_host(): void {
		$this->assertFalse( Reporting_Endpoint::is_allowed_url( 'https:///report' ) );
	}

	public function test_group_name_is_shared_and_stable(): void {
		// The report-to CSP directive, Reporting-Endpoints header, and any
		// future COOP/COEP-Report-Only header attribute must all reference
		// this exact identifier for browsers to correlate them.
		$this->assertSame( 'csp-endpoint', Reporting_Endpoint::GROUP_NAME );
	}
}
