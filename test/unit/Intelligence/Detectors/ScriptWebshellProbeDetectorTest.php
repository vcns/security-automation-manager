<?php
/**
 * Unit tests for WP_SAM\Intelligence\Detectors\Script_Webshell_Probe_Detector.
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;
use WP_SAM\Intelligence\Detectors\Script_Webshell_Probe_Detector;

class ScriptWebshellProbeDetectorTest extends TestCase {

	private Script_Webshell_Probe_Detector $detector;

	protected function setUp(): void {
		wp_test_reset_globals();
		$this->detector = new Script_Webshell_Probe_Detector();
	}

	private function context( string $path ): array {
		return array(
			'surface'      => 'frontend',
			'path'         => $path,
			'query_string' => '',
		);
	}

	public function test_positive_match_script_in_uploads_directory(): void {
		$finding = $this->detector->evaluate( $this->context( '/wp-content/uploads/2026/09/x.php' ) );

		$this->assertNotNull( $finding );
		$this->assertSame( 'WSHELL-003', $finding['detail']['rule_id'] );
		$this->assertSame( 'critical', $finding['severity'] );
	}

	public function test_negative_match_ordinary_uploaded_image(): void {
		$this->assertNull( $this->detector->evaluate( $this->context( '/wp-content/uploads/2026/09/photo.jpg' ) ) );
	}

	public function test_encoded_variant_of_known_webshell_filename(): void {
		$finding = $this->detector->evaluate( $this->context( '/wp-content%2Fc99.php' ) );

		$this->assertNotNull( $finding );
		$this->assertSame( 'WSHELL-001', $finding['detail']['rule_id'] );
	}

	public function test_benign_lookalike_normal_wordpress_php_requests_are_not_flagged(): void {
		// The roadmap's own explicit false-positive trap: a bare .php
		// extension must never be flagged outside the two constrained
		// contexts (known-bad filename, or inside uploads/).
		$this->assertNull( $this->detector->evaluate( $this->context( '/wp-login.php' ) ) );
		$this->assertNull( $this->detector->evaluate( $this->context( '/wp-admin/admin-ajax.php' ) ) );
		$this->assertNull( $this->detector->evaluate( $this->context( '/xmlrpc.php' ) ) );
	}

	public function test_surface_applicability_is_every_surface(): void {
		$this->assertSame( array(), $this->detector->applicable_surfaces() );
	}

	public function test_action_eligibility_finding_carries_no_control_field(): void {
		$finding = $this->detector->evaluate( $this->context( '/wp-content/uploads/x.php' ) );

		$this->assertArrayNotHasKey( 'action', $finding );
		$this->assertArrayNotHasKey( 'control', $finding );
	}

	public function test_confidence_outcome(): void {
		$finding = $this->detector->evaluate( $this->context( '/wp-content/uploads/x.php' ) );

		$this->assertSame( 0.9, $finding['confidence'] );
	}

	public function test_false_positive_regression_uploads_rule_is_root_anchored(): void {
		// WSHELL-003 is anchored to the uploads directory specifically -- a
		// plugin/theme file that happens to be named "uploads" mid-path must
		// not match.
		$this->assertNull( $this->detector->evaluate( $this->context( '/wp-content/plugins/foo/uploads/x.php' ) ) );
	}
}
