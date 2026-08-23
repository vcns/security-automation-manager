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

	/**
	 * url() delegates unconditionally to rest_url() -- WordPress's own
	 * reference docs for rest_url()/get_rest_url() document no `init`
	 * requirement, and the reviewer explicitly required removing the
	 * hardcoded pre-init fallback this method used to have. These two tests
	 * prove indifference to did_action('init') by getting the identical
	 * result whether or not it's been recorded as fired.
	 */
	public function test_url_is_identical_before_init(): void {
		// did_action('init') deliberately left unset.
		$this->assertSame( 'https://example.com/wp-json/sam/v1/report', Reporting_Endpoint::url() );
	}

	public function test_url_is_identical_after_init(): void {
		$GLOBALS['_wp_did_actions']['init'] = 1;

		$this->assertSame( 'https://example.com/wp-json/sam/v1/report', Reporting_Endpoint::url() );
	}

	/**
	 * The remaining tests below prove url() has no independent opinion of
	 * its own about permalink structure, the REST URL prefix, or a
	 * multisite subsite path -- it reflects exactly whatever rest_url()
	 * produces. The test stub (test/bootstrap.php) models each of these as
	 * a configurable global, standing in for the real WordPress behaviour
	 * documented for get_rest_url() -- this suite has no real-WordPress
	 * integration harness (every WP function here is a hand-written stub),
	 * so these are stub-level simulations of that behaviour, not tests
	 * against WordPress core itself.
	 */
	public function test_url_reflects_pretty_permalinks(): void {
		// Default stub state already models the pretty-permalink form.
		$this->assertSame( 'https://example.com/wp-json/sam/v1/report', Reporting_Endpoint::url() );
	}

	public function test_url_reflects_plain_permalinks(): void {
		$GLOBALS['_wp_rest_url_plain_permalinks'] = true;

		$this->assertSame( 'https://example.com/?rest_route=/sam/v1/report', Reporting_Endpoint::url() );
	}

	public function test_url_reflects_a_modified_rest_url_prefix(): void {
		// Simulates the real `rest_url_prefix` filter changing WordPress's
		// default "wp-json" segment.
		$GLOBALS['_wp_rest_url_prefix'] = 'custom-api';

		$this->assertSame( 'https://example.com/custom-api/sam/v1/report', Reporting_Endpoint::url() );
	}

	public function test_url_reflects_a_multisite_subsite_path(): void {
		$GLOBALS['_wp_multisite_subsite_path'] = '/mysite';

		$this->assertSame( 'https://example.com/mysite/wp-json/sam/v1/report', Reporting_Endpoint::url() );
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
