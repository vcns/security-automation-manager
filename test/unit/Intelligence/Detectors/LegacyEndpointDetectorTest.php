<?php
/**
 * Unit tests for WP_SAM\Intelligence\Detectors\Legacy_Endpoint_Detector.
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;
use WP_SAM\Intelligence\Detectors\Legacy_Endpoint_Detector;

class LegacyEndpointDetectorTest extends TestCase {

	private Legacy_Endpoint_Detector $detector;

	protected function setUp(): void {
		wp_test_reset_globals();
		$this->detector = new Legacy_Endpoint_Detector();
	}

	private function context( string $path ): array {
		return array(
			'surface' => 'frontend',
			'path'    => $path,
		);
	}

	public function test_positive_match_xmlrpc(): void {
		$finding = $this->detector->evaluate( $this->context( '/xmlrpc.php' ) );

		$this->assertNotNull( $finding );
		$this->assertSame( 'LEGACY-001', $finding['detail']['rule_id'] );
		$this->assertSame( 'medium', $finding['severity'] );
	}

	public function test_positive_match_wp_trackback(): void {
		$finding = $this->detector->evaluate( $this->context( '/wp-trackback.php' ) );

		$this->assertNotNull( $finding );
		$this->assertSame( 'LEGACY-002', $finding['detail']['rule_id'] );
	}

	public function test_positive_match_wp_app(): void {
		$finding = $this->detector->evaluate( $this->context( '/wp-app.php' ) );

		$this->assertNotNull( $finding );
		$this->assertSame( 'LEGACY-003', $finding['detail']['rule_id'] );
		$this->assertSame( 'low', $finding['severity'] );
	}

	public function test_negative_match_ordinary_wordpress_paths(): void {
		$this->assertNull( $this->detector->evaluate( $this->context( '/wp-login.php' ) ) );
		$this->assertNull( $this->detector->evaluate( $this->context( '/wp-admin/admin-ajax.php' ) ) );
		$this->assertNull( $this->detector->evaluate( $this->context( '/' ) ) );
	}

	public function test_negative_match_requires_an_exact_filename_not_a_substring(): void {
		// A path merely containing "xmlrpc" as a substring of something
		// else (e.g. a plugin's own custom route) must not match -- only
		// the exact xmlrpc.php filename should.
		$this->assertNull( $this->detector->evaluate( $this->context( '/my-xmlrpc-helper/status' ) ) );
	}

	public function test_surface_applicability_is_every_surface(): void {
		$this->assertSame( array(), $this->detector->applicable_surfaces() );
	}

	public function test_control_action_framework_allows_enforce_but_defaults_to_observe(): void {
		$this->assertSame( array( 'observe', 'enforce' ), $this->detector->allowed_control_actions() );
		$this->assertSame( 'observe', $this->detector->default_control_action() );
	}
}
