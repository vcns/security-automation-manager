<?php
/**
 * Unit tests for WP_SAM\Intelligence\Detectors\Robots_Txt_Detector.
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;
use WP_SAM\Intelligence\Detectors\Robots_Txt_Detector;

class RobotsTxtDetectorTest extends TestCase {

	private Robots_Txt_Detector $detector;

	protected function setUp(): void {
		wp_test_reset_globals();
		$this->detector = new Robots_Txt_Detector();
	}

	private function context( string $path ): array {
		return array(
			'surface' => 'frontend',
			'path'    => $path,
		);
	}

	public function test_positive_match_robots_txt(): void {
		$finding = $this->detector->evaluate( $this->context( '/robots.txt' ) );

		$this->assertNotNull( $finding );
		$this->assertSame( 'ROBOTS-001', $finding['detail']['rule_id'] );
		$this->assertSame( 'low', $finding['severity'] );
	}

	public function test_negative_match_a_path_merely_containing_robots(): void {
		$this->assertNull( $this->detector->evaluate( $this->context( '/wp-content/uploads/robots-illustration.png' ) ) );
	}

	public function test_negative_match_root_path(): void {
		$this->assertNull( $this->detector->evaluate( $this->context( '/' ) ) );
	}

	public function test_surface_applicability_is_every_surface(): void {
		$this->assertSame( array(), $this->detector->applicable_surfaces() );
	}

	public function test_control_action_defaults_to_observe_only(): void {
		$this->assertSame( array( 'observe' ), $this->detector->allowed_control_actions() );
		$this->assertSame( 'observe', $this->detector->default_control_action() );
	}
}
