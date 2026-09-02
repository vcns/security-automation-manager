<?php
/**
 * Unit tests for WP_SAM\Intelligence\Request_Observer.
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;
use WP_SAM\Intelligence\Detector_Engine;
use WP_SAM\Intelligence\Detector_Registry;
use WP_SAM\Intelligence\Event_Store;
use WP_SAM\Intelligence\Identity_Resolver;
use WP_SAM\Intelligence\Request_Observer;
use WP_SAM\Intelligence\Scanner_Identity_Store;
use WP_SAM\Intelligence\Scanner_Vendor_Store;
use WP_SAM\Security\Request_Surface;

class RequestObserverTest extends TestCase {

	private Request_Observer $observer;

	protected function setUp(): void {
		wp_test_reset_globals();
		Detector_Registry::reset();
		unset( $_SERVER['REQUEST_URI'], $_SERVER['QUERY_STRING'], $_SERVER['HTTP_USER_AGENT'], $GLOBALS['pagenow'] );
		$_SERVER['REMOTE_ADDR'] = '203.0.113.42';

		$this->observer = new Request_Observer(
			new Detector_Engine(),
			new Event_Store(),
			new Identity_Resolver( new Scanner_Vendor_Store() ),
			new Scanner_Identity_Store()
		);
	}

	/**
	 * Every observe() call also resolves and records the request's identity
	 * (Phase 3D) -- filters that query out so pre-existing Event_Store
	 * assertions stay meaningful regardless of that unrelated write.
	 *
	 * @return array<int, string>
	 */
	private function event_queries(): array {
		return array_values( array_filter( $GLOBALS['_wpdb_queries'], static fn( $q ) => str_contains( $q, 'sam_request_events' ) ) );
	}

	/** @return array<int, string> */
	private function identity_queries(): array {
		return array_values( array_filter( $GLOBALS['_wpdb_queries'], static fn( $q ) => str_contains( $q, 'sam_scanner_identities' ) ) );
	}

	public function test_register_hooks_send_headers_login_init_and_wp_redirect(): void {
		$this->observer->register();

		$this->assertArrayHasKey( 'send_headers', $GLOBALS['_wp_actions'] );
		$this->assertArrayHasKey( 'login_init', $GLOBALS['_wp_actions'] );
		$this->assertArrayHasKey( 'wp_redirect', $GLOBALS['_wp_actions'] );
		$this->assertSame( 1, $GLOBALS['_wp_actions']['wp_redirect'][0][1] );
	}

	public function test_observe_writes_nothing_to_event_store_on_an_empty_registry(): void {
		$this->observer->observe();

		$this->assertSame( array(), $this->event_queries() );
	}

	public function test_observe_records_a_fixture_detectors_match(): void {
		Detector_Registry::register( new Observer_Fixture_Detector() );

		$this->observer->observe();

		$event_queries = $this->event_queries();
		$this->assertCount( 1, $event_queries );
		$this->assertStringContainsString( "'observer-fixture'", $event_queries[0] );
	}

	public function test_observe_only_records_once_per_request_across_multiple_hook_firings(): void {
		Detector_Registry::register( new Observer_Fixture_Detector() );

		// Simulates send_headers and login_init both firing observe() for the
		// same request (they never both fire in real WordPress, but the guard
		// must hold regardless of which hook fires first).
		$this->observer->observe();
		$this->observer->observe();

		$this->assertCount( 1, $this->event_queries() );
		$this->assertCount( 1, $this->identity_queries() );
	}

	public function test_observe_before_redirect_observes_and_returns_the_location_unchanged(): void {
		Detector_Registry::register( new Observer_Fixture_Detector() );

		$result = $this->observer->observe_before_redirect( 'https://example.com/wp-admin/', 302 );

		$this->assertSame( 'https://example.com/wp-admin/', $result );
		$this->assertCount( 1, $this->event_queries() );
	}

	public function test_observe_records_the_query_string_in_detail(): void {
		Detector_Registry::register( new Observer_Fixture_Detector() );
		$_SERVER['QUERY_STRING'] = 'id=1%27';

		$this->observer->observe();

		$event_queries = $this->event_queries();
		$this->assertCount( 1, $event_queries );
		$this->assertStringContainsString( 'id=1%27', $event_queries[0] );

		unset( $_SERVER['QUERY_STRING'] );
	}

	public function test_observe_skips_the_plugins_own_conflict_probe_request(): void {
		Detector_Registry::register( new Observer_Fixture_Detector() );

		$server_key             = 'HTTP_' . strtoupper( str_replace( '-', '_', Request_Surface::CONFLICT_PROBE_HEADER ) );
		$_SERVER[ $server_key ] = '1';

		$this->observer->observe();

		$this->assertSame( array(), $GLOBALS['_wpdb_queries'] );

		unset( $_SERVER[ $server_key ] );
	}

	// ── Identity resolution (Phase 3D) ──────────────────────────────────────

	public function test_observe_records_an_identity_for_every_request_with_an_ip(): void {
		$this->observer->observe();

		$identity_queries = $this->identity_queries();
		$this->assertCount( 1, $identity_queries );
		$this->assertStringContainsString( '203.0.113.42', $identity_queries[0] );
	}

	public function test_observe_skips_identity_recording_when_ip_cannot_be_resolved(): void {
		unset( $_SERVER['REMOTE_ADDR'] );

		$this->observer->observe();

		$this->assertSame( array(), $this->identity_queries() );
	}

	public function test_observe_records_recognised_crawler_identity(): void {
		$GLOBALS['_wpdb_get_results'] = array(
			array(
				'vendor_key'           => 'googlebot',
				'vendor_name'          => 'Googlebot',
				'category'             => 'known_crawler',
				'ua_pattern'           => 'Googlebot',
				'rdns_suffixes'        => '["googlebot.com"]',
				'cidr_ranges'          => '[]',
				'source_url'           => 'https://developers.google.com/search/docs/crawling-indexing/verifying-googlebot',
				'verification_method'  => 'fcrdns',
				'notes'                => '',
				'is_builtin'           => 1,
			),
		);
		$_SERVER['HTTP_USER_AGENT'] = 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)';

		$this->observer->observe();

		$identity_queries = $this->identity_queries();
		$this->assertCount( 1, $identity_queries );
		$this->assertStringContainsString( "'known_crawler'", $identity_queries[0] );
		$this->assertStringContainsString( "'googlebot'", $identity_queries[0] );
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
