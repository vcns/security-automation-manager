<?php
/**
 * Unit tests for WP_SAM\Intelligence\Detectors\Sensitive_Directory_Probing_Detector.
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;
use WP_SAM\Intelligence\Detectors\Sensitive_Directory_Probing_Detector;

class SensitiveDirectoryProbingDetectorTest extends TestCase {

	private Sensitive_Directory_Probing_Detector $detector;

	protected function setUp(): void {
		wp_test_reset_globals();
		$this->detector = new Sensitive_Directory_Probing_Detector();
	}

	private function context( string $path ): array {
		return array(
			'surface'      => 'frontend',
			'path'         => $path,
			'query_string' => '',
		);
	}

	public function test_positive_match_etc_passwd(): void {
		$finding = $this->detector->evaluate( $this->context( '/etc/passwd' ) );

		$this->assertNotNull( $finding );
		$this->assertSame( 'SDIR-001', $finding['detail']['rule_id'] );
		$this->assertSame( 'high', $finding['severity'] );
	}

	public function test_negative_match_ordinary_wordpress_path(): void {
		$this->assertNull( $this->detector->evaluate( $this->context( '/wp-content/themes/twentytwentyfive/style.css' ) ) );
	}

	public function test_encoded_variant_of_traversal_towards_etc_passwd(): void {
		$finding = $this->detector->evaluate( $this->context( '/download%2F..%2F..%2F..%2Fetc%2Fpasswd' ) );

		$this->assertNotNull( $finding );
		$this->assertSame( 'SDIR-001', $finding['detail']['rule_id'] );
	}

	public function test_benign_lookalike_uploads_folder_named_proc(): void {
		// A hypothetical uploads subfolder happening to be named "proc" is
		// not the root-anchored /proc/ this detector cares about.
		$this->assertNull( $this->detector->evaluate( $this->context( '/wp-content/uploads/proc/notes.txt' ) ) );
	}

	public function test_surface_applicability_is_every_surface(): void {
		$this->assertSame( array(), $this->detector->applicable_surfaces() );
	}

	public function test_action_eligibility_finding_carries_no_control_field(): void {
		$finding = $this->detector->evaluate( $this->context( '/etc/passwd' ) );

		$this->assertArrayNotHasKey( 'action', $finding );
		$this->assertArrayNotHasKey( 'control', $finding );
	}

	public function test_confidence_outcome(): void {
		$finding = $this->detector->evaluate( $this->context( '/etc/passwd' ) );

		$this->assertSame( 0.9, $finding['confidence'] );
	}

	public function test_false_positive_regression_root_anchored_rule_does_not_match_mid_path(): void {
		// SDIR-005 is start-anchored (^/etc/) -- a path with "etc" appearing
		// mid-string via a legitimate deep route must not match it.
		$this->assertNull( $this->detector->evaluate( $this->context( '/blog/2026/etc/some-post' ) ) );
	}
}
