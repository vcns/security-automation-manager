<?php
/**
 * Unit tests for WP_SAM\Intelligence\Detectors\Version_Control_Artefact_Detector.
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;
use WP_SAM\Intelligence\Detectors\Version_Control_Artefact_Detector;

class VersionControlArtefactDetectorTest extends TestCase {

	private Version_Control_Artefact_Detector $detector;

	protected function setUp(): void {
		wp_test_reset_globals();
		$this->detector = new Version_Control_Artefact_Detector();
	}

	private function context( string $path ): array {
		return array(
			'surface'      => 'frontend',
			'path'         => $path,
			'query_string' => '',
		);
	}

	public function test_positive_match_git_config(): void {
		$finding = $this->detector->evaluate( $this->context( '/.git/config' ) );

		$this->assertNotNull( $finding );
		$this->assertSame( 'VCS-001', $finding['detail']['rule_id'] );
		$this->assertSame( 'high', $finding['severity'] );
	}

	public function test_negative_match_ordinary_wordpress_path(): void {
		$this->assertNull( $this->detector->evaluate( $this->context( '/wp-content/themes/foo/style.css' ) ) );
	}

	public function test_encoded_variant_of_git_head(): void {
		$finding = $this->detector->evaluate( $this->context( '/%2Egit%2FHEAD' ) );

		$this->assertNotNull( $finding );
		$this->assertSame( 'VCS-001', $finding['detail']['rule_id'] );
	}

	public function test_benign_lookalike_gitignore_file_is_not_flagged(): void {
		// .gitignore is a plain text file with no repository contents to
		// leak -- distinct from the .git/ metadata directory.
		$this->assertNull( $this->detector->evaluate( $this->context( '/.gitignore' ) ) );
	}

	public function test_surface_applicability_is_every_surface(): void {
		$this->assertSame( array(), $this->detector->applicable_surfaces() );
	}

	public function test_action_eligibility_finding_carries_no_control_field(): void {
		$finding = $this->detector->evaluate( $this->context( '/.git/config' ) );

		$this->assertArrayNotHasKey( 'action', $finding );
		$this->assertArrayNotHasKey( 'control', $finding );
	}

	public function test_confidence_outcome(): void {
		$finding = $this->detector->evaluate( $this->context( '/composer.lock' ) );

		$this->assertSame( 'low', $finding['severity'] );
		$this->assertSame( 0.6, $finding['confidence'] );
	}

	public function test_false_positive_regression_highest_severity_wins_for_git_config(): void {
		// Both VCS-001 (.git/config, high) and VCS-002 (.git/, medium) match
		// this exact URL -- the engine must report the more specific/severe
		// one regardless of declaration order.
		$finding = $this->detector->evaluate( $this->context( '/.git/config' ) );

		$this->assertSame( 'VCS-001', $finding['detail']['rule_id'] );
		$this->assertSame( 2, $finding['detail']['matched_rule_count'] );
	}
}
