<?php
/**
 * Unit tests for WP_SAM\Security\Cache_Control_Conflict_Detector.
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;
use WP_SAM\Security\Cache_Control_Conflict_Detector;

class CacheControlConflictDetectorTest extends TestCase {

	protected function setUp(): void {
		wp_test_reset_globals();
	}

	public function test_detect_is_not_blocked_by_default(): void {
		$result = Cache_Control_Conflict_Detector::detect();

		$this->assertFalse( $result['blocked'] );
		$this->assertNull( $result['reason'] );
		$this->assertNull( $result['detail'] );
	}

	public function test_detect_is_blocked_when_cdn_is_acknowledged(): void {
		update_option( Cache_Control_Conflict_Detector::CDN_ACKNOWLEDGED_OPTION, true );

		$result = Cache_Control_Conflict_Detector::detect();

		$this->assertTrue( $result['blocked'] );
		$this->assertSame( 'cdn_acknowledged', $result['reason'] );
		$this->assertNotNull( $result['detail'] );
	}

	public function test_detect_is_not_blocked_when_cdn_acknowledgement_is_explicitly_false(): void {
		update_option( Cache_Control_Conflict_Detector::CDN_ACKNOWLEDGED_OPTION, false );

		$this->assertFalse( Cache_Control_Conflict_Detector::detect()['blocked'] );
	}

	public function test_detect_is_blocked_when_a_known_caching_plugin_constant_is_defined(): void {
		if ( ! defined( 'WP_ROCKET_VERSION' ) ) {
			define( 'WP_ROCKET_VERSION', '3.0' );
		}

		$result = Cache_Control_Conflict_Detector::detect();

		$this->assertTrue( $result['blocked'] );
		$this->assertSame( 'known_plugin', $result['reason'] );
		$this->assertStringContainsString( 'WP Rocket', $result['detail'] );
	}

	public function test_known_plugins_returns_a_non_empty_list_of_label_and_callable_pairs(): void {
		$plugins = Cache_Control_Conflict_Detector::known_plugins();

		$this->assertNotEmpty( $plugins );
		foreach ( $plugins as $plugin ) {
			$this->assertArrayHasKey( 'label', $plugin );
			$this->assertArrayHasKey( 'check', $plugin );
			$this->assertIsString( $plugin['label'] );
			$this->assertIsCallable( $plugin['check'] );
			// Every check must be safely callable without throwing, whether
			// or not that plugin is actually present in this environment.
			$this->assertIsBool( ( $plugin['check'] )() );
		}
	}

	public function test_known_plugin_labels_are_unique(): void {
		$labels = array_column( Cache_Control_Conflict_Detector::known_plugins(), 'label' );

		$this->assertSame( array_unique( $labels ), array_values( $labels ) );
	}
}
