<?php
/**
 * Unit tests for WP_SAM\Intelligence\Surface_Classifier.
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;
use WP_SAM\Intelligence\Surface_Classifier;
use WP_SAM\Security\Request_Surface;

class SurfaceClassifierTest extends TestCase {

	protected function setUp(): void {
		wp_test_reset_globals();
		unset( $_SERVER['REQUEST_URI'], $_SERVER['QUERY_STRING'], $GLOBALS['pagenow'] );
	}

	// ── detect() ─────────────────────────────────────────────────────────────

	public function test_detect_uses_admin_path_for_admin_404s(): void {
		$_SERVER['REQUEST_URI'] = '/wp-admin/wp-login.php';

		$this->assertSame( 'admin', Surface_Classifier::detect() );
	}

	public function test_detect_uses_login_path_for_login_page(): void {
		$_SERVER['REQUEST_URI'] = '/wp-login.php?redirect_to=https%3A%2F%2Fexample.com%2Fwp-admin%2F';

		$this->assertSame( 'login', Surface_Classifier::detect() );
	}

	public function test_detect_supports_subdirectory_admin_paths(): void {
		$_SERVER['REQUEST_URI'] = '/wordpress/wp-admin/edit.php';

		$this->assertSame( 'admin', Surface_Classifier::detect() );
	}

	public function test_detect_uses_login_pagenow_global(): void {
		$GLOBALS['pagenow'] = 'wp-login.php';

		$this->assertSame( 'login', Surface_Classifier::detect() );
	}

	// detect()'s REST_REQUEST branch is deliberately not covered here: REST_REQUEST
	// is a global PHP constant that, once defined, cannot be undefined for the rest
	// of the test process -- defining it here would silently force every other
	// test's detect()/detect_surface() calls (in this suite and Policy_Builder's)
	// onto the 'api' branch for the remainder of the run.

	public function test_detect_defaults_to_frontend(): void {
		$_SERVER['REQUEST_URI'] = '/hello-world/';

		$this->assertSame( 'frontend', Surface_Classifier::detect() );
	}

	// ── request_path() ───────────────────────────────────────────────────────

	public function test_request_path_strips_query_string_and_trailing_slash(): void {
		$_SERVER['REQUEST_URI'] = '/wp-admin/edit.php/?post_type=page';

		$this->assertSame( '/wp-admin/edit.php', Surface_Classifier::request_path() );
	}

	public function test_request_path_returns_empty_string_when_absent(): void {
		unset( $_SERVER['REQUEST_URI'] );

		$this->assertSame( '', Surface_Classifier::request_path() );
	}

	// ── query_string() ───────────────────────────────────────────────────────

	public function test_query_string_returns_the_raw_query_string(): void {
		$_SERVER['QUERY_STRING'] = 'id=1&s=hello';

		$this->assertSame( 'id=1&s=hello', Surface_Classifier::query_string() );
	}

	public function test_query_string_returns_empty_string_when_absent(): void {
		unset( $_SERVER['QUERY_STRING'] );

		$this->assertSame( '', Surface_Classifier::query_string() );
	}

	// ── is_conflict_probe_request() ─────────────────────────────────────────

	public function test_is_conflict_probe_request_recognises_the_shared_header_name(): void {
		$server_key = 'HTTP_' . strtoupper( str_replace( '-', '_', Request_Surface::CONFLICT_PROBE_HEADER ) );

		$_SERVER[ $server_key ] = '1';
		$this->assertTrue( Surface_Classifier::is_conflict_probe_request() );

		unset( $_SERVER[ $server_key ] );
		$this->assertFalse( Surface_Classifier::is_conflict_probe_request() );
	}
}
