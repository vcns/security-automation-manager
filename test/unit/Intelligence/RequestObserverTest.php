<?php
/**
 * Unit tests for WP_SAM\Intelligence\Request_Observer.
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;
use WP_SAM\Intelligence\Detector_Engine;
use WP_SAM\Intelligence\Detector_Registry;
use WP_SAM\Intelligence\Event_Store;
use WP_SAM\Intelligence\Request_Observer;
use WP_SAM\Security\Request_Surface;

class RequestObserverTest extends TestCase {

	private Request_Observer $observer;

	protected function setUp(): void {
		wp_test_reset_globals();
		Detector_Registry::reset();
		unset( $_SERVER['REQUEST_URI'], $GLOBALS['pagenow'] );
		$_SERVER['REMOTE_ADDR'] = '203.0.113.42';

		$this->observer = new Request_Observer( new Detector_Engine(), new Event_Store() );
	}

	public function test_register_hooks_send_headers_login_init_and_wp_redirect(): void {
		$this->observer->register();

		$this->assertArrayHasKey( 'send_headers', $GLOBALS['_wp_actions'] );
		$this->assertArrayHasKey( 'login_init', $GLOBALS['_wp_actions'] );
		$this->assertArrayHasKey( 'wp_redirect', $GLOBALS['_wp_actions'] );
		$this->assertSame( 1, $GLOBALS['_wp_actions']['wp_redirect'][0][1] );
	}

	public function test_observe_writes_nothing_on_an_empty_registry(): void {
		$this->observer->observe();

		$this->assertSame( array(), $GLOBALS['_wpdb_queries'] );
	}

	public function test_observe_records_a_fixture_detectors_match(): void {
		Detector_Registry::register( new Observer_Fixture_Detector() );

		$this->observer->observe();

		$this->assertCount( 1, $GLOBALS['_wpdb_queries'] );
		$this->assertStringContainsString( 'sam_request_events', $GLOBALS['_wpdb_queries'][0] );
		$this->assertStringContainsString( "'observer-fixture'", $GLOBALS['_wpdb_queries'][0] );
	}

	public function test_observe_only_records_once_per_request_across_multiple_hook_firings(): void {
		Detector_Registry::register( new Observer_Fixture_Detector() );

		// Simulates send_headers and login_init both firing observe() for the
		// same request (they never both fire in real WordPress, but the guard
		// must hold regardless of which hook fires first).
		$this->observer->observe();
		$this->observer->observe();

		$this->assertCount( 1, $GLOBALS['_wpdb_queries'] );
	}

	public function test_observe_before_redirect_observes_and_returns_the_location_unchanged(): void {
		Detector_Registry::register( new Observer_Fixture_Detector() );

		$result = $this->observer->observe_before_redirect( 'https://example.com/wp-admin/', 302 );

		$this->assertSame( 'https://example.com/wp-admin/', $result );
		$this->assertCount( 1, $GLOBALS['_wpdb_queries'] );
	}

	public function test_observe_skips_the_plugins_own_conflict_probe_request(): void {
		Detector_Registry::register( new Observer_Fixture_Detector() );

		$server_key             = 'HTTP_' . strtoupper( str_replace( '-', '_', Request_Surface::CONFLICT_PROBE_HEADER ) );
		$_SERVER[ $server_key ] = '1';

		$this->observer->observe();

		$this->assertSame( array(), $GLOBALS['_wpdb_queries'] );

		unset( $_SERVER[ $server_key ] );
	}
}

final class Observer_Fixture_Detector extends \WP_SAM\Intelligence\Detector {
	public function id(): string {
		return 'observer-fixture';
	}
	public function family(): string {
		return 'fixture-family';
	}
	public function applicable_surfaces(): array {
		return array();
	}
	public function evaluate( array $context ): ?array {
		return array( 'severity' => 'low' );
	}
}
