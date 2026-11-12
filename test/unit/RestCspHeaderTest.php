<?php
/**
 * Unit tests for WP_SAM\CSP\Rest_Csp_Header.
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;
use WP_SAM\CSP\Rest_Csp_Header;

class RestCspHeaderTest extends TestCase {

	private Rest_Csp_Header $header;

	protected function setUp(): void {
		wp_test_reset_globals();
		$this->header = new Rest_Csp_Header();
	}

	public function test_register_hooks_rest_post_dispatch(): void {
		$this->header->register();

		$this->assertSame( array( $this->header, 'add_header' ), $GLOBALS['_wp_actions']['rest_post_dispatch'][0][0] );
	}

	public function test_a_json_response_gets_the_lock_down_policy(): void {
		$response = $this->header->add_header( new WP_REST_Response( array( 'ok' => true ) ) );

		$this->assertSame( "default-src 'none'; frame-ancestors 'none'", $response->get_headers()['Content-Security-Policy'] );
	}

	public function test_an_explicit_json_content_type_still_gets_it(): void {
		$response = $this->header->add_header( new WP_REST_Response( null, 200, array( 'Content-Type' => 'application/json; charset=UTF-8' ) ) );

		$this->assertArrayHasKey( 'Content-Security-Policy', $response->get_headers() );
	}

	public function test_a_non_json_response_is_left_alone(): void {
		$response = $this->header->add_header( new WP_REST_Response( '<p>hi</p>', 200, array( 'Content-Type' => 'text/html' ) ) );

		$this->assertArrayNotHasKey( 'Content-Security-Policy', $response->get_headers() );
	}

	public function test_an_endpoints_own_policy_is_kept(): void {
		$response = $this->header->add_header( new WP_REST_Response( null, 200, array( 'content-security-policy' => "default-src 'self'" ) ) );

		$this->assertSame( array( 'content-security-policy' => "default-src 'self'" ), $response->get_headers() );
	}

	public function test_the_filter_can_turn_it_off(): void {
		add_filter( 'wp_sam_rest_csp_header', static fn (): string => '' );

		$response = $this->header->add_header( new WP_REST_Response() );

		$this->assertArrayNotHasKey( 'Content-Security-Policy', $response->get_headers() );
	}

	public function test_anything_that_is_not_a_response_passes_through(): void {
		$this->assertSame( 'not-a-response', $this->header->add_header( 'not-a-response' ) );
	}
}
