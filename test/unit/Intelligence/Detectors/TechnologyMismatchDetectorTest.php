<?php
/**
 * Unit tests for WP_SAM\Intelligence\Detectors\Technology_Mismatch_Detector.
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;
use WP_SAM\Intelligence\Detectors\Technology_Mismatch_Detector;

class TechnologyMismatchDetectorTest extends TestCase {

	private Technology_Mismatch_Detector $detector;

	protected function setUp(): void {
		wp_test_reset_globals();
		$this->detector = new Technology_Mismatch_Detector();
	}

	private function context( string $path ): array {
		return array(
			'surface'      => 'frontend',
			'path'         => $path,
			'query_string' => '',
		);
	}

	public function test_positive_match_drupal_settings_file(): void {
		$finding = $this->detector->evaluate( $this->context( '/sites/default/settings.php' ) );

		$this->assertNotNull( $finding );
		$this->assertSame( 'TM-003', $finding['detail']['rule_id'] );
	}

	public function test_negative_match_ordinary_wordpress_path(): void {
		$this->assertNull( $this->detector->evaluate( $this->context( '/wp-content/uploads/2026/photo.jpg' ) ) );
	}

	public function test_encoded_variant_of_magento_config_path(): void {
		$finding = $this->detector->evaluate( $this->context( '/app%2Fetc%2Flocal.xml' ) );

		$this->assertNotNull( $finding );
		$this->assertSame( 'TM-006', $finding['detail']['rule_id'] );
	}

	public function test_benign_lookalike_plugin_own_changelog_is_not_flagged(): void {
		// A WordPress plugin's own CHANGELOG.txt, not Drupal's root-level one.
		$this->assertNull( $this->detector->evaluate( $this->context( '/wp-content/plugins/some-plugin/CHANGELOG.txt' ) ) );
	}

	public function test_surface_applicability_is_every_surface(): void {
		$this->assertSame( array(), $this->detector->applicable_surfaces() );
	}

	public function test_action_eligibility_finding_carries_no_control_field(): void {
		$finding = $this->detector->evaluate( $this->context( '/sites/default/settings.php' ) );

		$this->assertArrayNotHasKey( 'action', $finding );
		$this->assertArrayNotHasKey( 'control', $finding );
	}

	public function test_confidence_outcome_for_high_confidence_rule(): void {
		$finding = $this->detector->evaluate( $this->context( '/app/etc/local.xml' ) );

		$this->assertSame( 0.85, $finding['confidence'] );
	}

	public function test_false_positive_regression_root_changelog_is_anchored(): void {
		// Root-level CHANGELOG.txt only -- the roadmap's own drafted rule
		// would have matched every plugin's own file too. Confirms the fix.
		$finding = $this->detector->evaluate( $this->context( '/CHANGELOG.txt' ) );
		$this->assertNotNull( $finding );
		$this->assertSame( 'TM-005', $finding['detail']['rule_id'] );

		$this->assertNull( $this->detector->evaluate( $this->context( '/wp-content/plugins/foo/CHANGELOG.txt' ) ) );
	}

	public function test_severity_never_exceeds_medium(): void {
		// Roadmap §11.1: technology mismatch alone must stay a reconnaissance
		// signal, never high/critical.
		foreach ( array( '/administrator/index.php', '/sites/default/settings.php', '/app/etc/local.xml', '/typo3conf/x' ) as $path ) {
			$finding = $this->detector->evaluate( $this->context( $path ) );
			$this->assertNotNull( $finding );
			$this->assertContains( $finding['severity'], array( 'low', 'medium' ) );
		}
	}
}
