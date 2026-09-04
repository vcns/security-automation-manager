<?php
/**
 * Unit tests for WP_SAM\Intelligence\Detectors\Tor_Exit_Detector.
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;
use WP_SAM\Intelligence\Detectors\Tor_Exit_Detector;
use WP_SAM\Intelligence\Tor_Exit_List_Store;

class TorExitDetectorTest extends TestCase {

	private Tor_Exit_Detector $detector;

	protected function setUp(): void {
		wp_test_reset_globals();
		$this->detector = new Tor_Exit_Detector( new Tor_Exit_List_Store() );
	}

	public function test_id_and_family(): void {
		$this->assertSame( 'tor-exit-node', $this->detector->id() );
		$this->assertSame( 'network-intelligence', $this->detector->family() );
	}

	public function test_applicable_to_every_surface(): void {
		$this->assertSame( array(), $this->detector->applicable_surfaces() );
	}

	public function test_allows_both_observe_and_enforce(): void {
		$this->assertSame( array( 'observe', 'enforce' ), $this->detector->allowed_control_actions() );
	}

	public function test_default_control_action_is_observe(): void {
		$this->assertSame( 'observe', $this->detector->default_control_action() );
	}

	public function test_evaluate_returns_null_for_an_empty_ip(): void {
		$this->assertNull( $this->detector->evaluate( array( 'ip' => '' ) ) );
	}

	public function test_evaluate_returns_null_when_the_ip_is_not_a_known_exit_node(): void {
		$GLOBALS['_wpdb_get_var'] = null;

		$this->assertNull( $this->detector->evaluate( array( 'ip' => '203.0.113.42' ) ) );
	}

	public function test_evaluate_flags_a_known_exit_node(): void {
		$GLOBALS['_wpdb_get_var'] = 1;

		$finding = $this->detector->evaluate( array( 'ip' => '203.0.113.42' ) );

		$this->assertNotNull( $finding );
		$this->assertSame( 'low', $finding['severity'] );
	}
}
