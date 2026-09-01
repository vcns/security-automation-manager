<?php
/**
 * Unit tests for WP_SAM\Intelligence\Detectors\Setup_Install_Probe_Detector.
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;
use WP_SAM\Intelligence\Detectors\Setup_Install_Probe_Detector;

class SetupInstallProbeDetectorTest extends TestCase {

	private Setup_Install_Probe_Detector $detector;

	protected function setUp(): void {
		wp_test_reset_globals();
		$this->detector = new Setup_Install_Probe_Detector();
	}

	private function context( string $path ): array {
		return array(
			'surface'      => 'frontend',
			'path'         => $path,
			'query_string' => '',
		);
	}

	public function test_positive_match_root_install_php(): void {
		$finding = $this->detector->evaluate( $this->context( '/install.php' ) );

		$this->assertNotNull( $finding );
		$this->assertSame( 'SETUP-003', $finding['detail']['rule_id'] );
	}

	public function test_negative_match_ordinary_wordpress_path(): void {
		$this->assertNull( $this->detector->evaluate( $this->context( '/wp-admin/edit.php' ) ) );
	}

	public function test_encoded_variant_of_phpinfo(): void {
		$finding = $this->detector->evaluate( $this->context( '/tools%2Fphpinfo.php' ) );

		$this->assertNotNull( $finding );
		$this->assertSame( 'SETUP-005', $finding['detail']['rule_id'] );
	}

	public function test_benign_lookalike_setup_config_is_low_confidence(): void {
		// wp-admin/setup-config.php is hit legitimately during every real
		// WordPress install -- must stay low severity/confidence, not be
		// treated the same as an unambiguous probe.
		$finding = $this->detector->evaluate( $this->context( '/wp-admin/setup-config.php' ) );

		$this->assertNotNull( $finding );
		$this->assertSame( 'low', $finding['severity'] );
		$this->assertSame( 0.5, $finding['confidence'] );
	}

	public function test_surface_applicability_is_every_surface(): void {
		$this->assertSame( array(), $this->detector->applicable_surfaces() );
	}

	public function test_action_eligibility_finding_carries_no_control_field(): void {
		$finding = $this->detector->evaluate( $this->context( '/install.php' ) );

		$this->assertArrayNotHasKey( 'action', $finding );
		$this->assertArrayNotHasKey( 'control', $finding );
	}

	public function test_confidence_outcome(): void {
		$finding = $this->detector->evaluate( $this->context( '/phpinfo.php' ) );

		$this->assertSame( 0.7, $finding['confidence'] );
	}

	public function test_false_positive_regression_root_anchored_install_does_not_match_subpath(): void {
		// SETUP-003 is root-anchored (^/install.php$) -- a plugin's own
		// nested "install.php" (e.g. an onboarding wizard step) must not
		// match the root-level rule.
		$this->assertNull( $this->detector->evaluate( $this->context( '/wp-content/plugins/foo/install.php' ) ) );
	}
}
