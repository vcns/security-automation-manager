<?php
/**
 * Unit tests for WP_SAM\Intelligence\Detectors\Robots_Compliance_Detector.
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;
use WP_SAM\Intelligence\Detectors\Robots_Compliance_Detector;
use WP_SAM\Intelligence\Robots_Rules_Store;

class RobotsComplianceDetectorTest extends TestCase {

	protected function setUp(): void {
		wp_test_reset_globals();
	}

	private function detector(): Robots_Compliance_Detector {
		return new Robots_Compliance_Detector( new Robots_Rules_Store() );
	}

	/** @return array<string, mixed> */
	private function context( string $state, string $path ): array {
		return array(
			'surface'                       => 'frontend',
			'path'                          => $path,
			'identity_verification_state'   => $state,
		);
	}

	public function test_known_crawler_requesting_a_disallowed_path_produces_a_finding(): void {
		update_option( 'wp_sam_robots_disallow_rules', array( '/wp-admin/' ) );

		$finding = $this->detector()->evaluate( $this->context( 'known_crawler', '/wp-admin/plugins.php' ) );

		$this->assertNotNull( $finding );
		$this->assertSame( 'disallowed_path_requested', $finding['detail']['robots_signal'] );
		$this->assertSame( 'medium', $finding['severity'] );
	}

	public function test_known_commercial_scanner_and_known_research_scanner_are_also_checked(): void {
		update_option( 'wp_sam_robots_disallow_rules', array( '/private/' ) );

		$this->assertNotNull( $this->detector()->evaluate( $this->context( 'known_commercial_scanner', '/private/data' ) ) );
		$this->assertNotNull( $this->detector()->evaluate( $this->context( 'known_research_scanner', '/private/data' ) ) );
	}

	public function test_unknown_identity_requesting_a_disallowed_path_produces_no_finding(): void {
		// robots.txt is a voluntary convention for automated crawlers --
		// an ordinary, unrecognised visitor is never flagged here.
		update_option( 'wp_sam_robots_disallow_rules', array( '/wp-admin/' ) );

		$this->assertNull( $this->detector()->evaluate( $this->context( 'unknown', '/wp-admin/plugins.php' ) ) );
	}

	public function test_known_crawler_requesting_an_allowed_path_produces_no_finding(): void {
		update_option( 'wp_sam_robots_disallow_rules', array( '/wp-admin/' ) );

		$this->assertNull( $this->detector()->evaluate( $this->context( 'known_crawler', '/blog/hello-world' ) ) );
	}

	public function test_no_cached_rules_produces_no_finding(): void {
		$this->assertNull( $this->detector()->evaluate( $this->context( 'known_crawler', '/wp-admin/plugins.php' ) ) );
	}

	public function test_admin_decision_states_are_not_treated_as_crawler_states(): void {
		update_option( 'wp_sam_robots_disallow_rules', array( '/wp-admin/' ) );

		$this->assertNull( $this->detector()->evaluate( $this->context( 'customer_authorised', '/wp-admin/plugins.php' ) ) );
	}

	public function test_surface_applicability_is_every_surface(): void {
		$this->assertSame( array(), $this->detector()->applicable_surfaces() );
	}

	public function test_control_action_framework_allows_enforce_but_defaults_to_observe(): void {
		$detector = $this->detector();
		$this->assertSame( array( 'observe', 'enforce' ), $detector->allowed_control_actions() );
		$this->assertSame( 'observe', $detector->default_control_action() );
	}
}
