<?php
/**
 * Unit tests for WP_SAM\Intelligence\Request_Observer.
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;
use WP_SAM\Intelligence\Asn_Lookup_Store;
use WP_SAM\Intelligence\Detector_Engine;
use WP_SAM\Intelligence\Detector_Registry;
use WP_SAM\Intelligence\Event_Store;
use WP_SAM\Intelligence\Geo_Ip_Store;
use WP_SAM\Intelligence\Identity_Resolver;
use WP_SAM\Intelligence\Network_Intelligence_Resolver;
use WP_SAM\Intelligence\Request_Observer;
use WP_SAM\Intelligence\Scanner_Identity_Store;
use WP_SAM\Intelligence\Scanner_Vendor_Store;
use WP_SAM\Intelligence\Tor_Exit_List_Store;
use WP_SAM\Intelligence\Traffic_Block_Store;
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
			new Scanner_Identity_Store(),
			new Network_Intelligence_Resolver(
				new Tor_Exit_List_Store(),
				new Asn_Lookup_Store( static fn( string $h ): array => array() ),
				new Geo_Ip_Store()
			),
			new Traffic_Block_Store()
		);
	}

	/**
	 * Traffic_Block_Store::record_violation() writes via $wpdb->insert()/
	 * update(), not query() -- those land in _wpdb_inserted_rows/
	 * _wpdb_updated_rows, not _wpdb_queries (see Event_Store's own
	 * record(), which uses a raw query() and so IS visible in
	 * _wpdb_queries -- the two stores use different wpdb write paths).
	 *
	 * @return array<int, array<string, mixed>>
	 */
	private function block_writes(): array {
		$inserts = array_filter( $GLOBALS['_wpdb_inserted_rows'], static fn( $row ) => str_contains( $row['table'], 'sam_traffic_blocks' ) );
		$updates = array_filter( $GLOBALS['_wpdb_updated_rows'], static fn( $row ) => str_contains( $row['table'], 'sam_traffic_blocks' ) );
		return array_values( array_merge( $inserts, $updates ) );
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

	public function test_register_hooks_send_headers_login_init_wp_redirect_and_init(): void {
		$this->observer->register();

		$this->assertArrayHasKey( 'send_headers', $GLOBALS['_wp_actions'] );
		$this->assertArrayHasKey( 'login_init', $GLOBALS['_wp_actions'] );
		$this->assertArrayHasKey( 'wp_redirect', $GLOBALS['_wp_actions'] );
		$this->assertSame( 1, $GLOBALS['_wp_actions']['wp_redirect'][0][1] );

		// init: covers direct WP entry points (xmlrpc.php, wp-cron.php) that
		// never fire send_headers -- priority 20, after Detector_Registry::
		// register_defaults() (priority 10) has already run.
		$this->assertArrayHasKey( 'init', $GLOBALS['_wp_actions'] );
		$this->assertSame( 20, $GLOBALS['_wp_actions']['init'][0][1] );
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

	// ── Network intelligence enrichment (Phase 4A) ──────────────────────────

	public function test_observe_enriches_a_finding_with_tor_exit_status_when_matched(): void {
		Detector_Registry::register( new Observer_Fixture_Detector() );
		$GLOBALS['_wpdb_get_var'] = '1';

		$this->observer->observe();

		$event_queries = $this->event_queries();
		$this->assertCount( 1, $event_queries );
		// The wpdb stub's prepare() addslashes() every %s substitution, so
		// the JSON detail's own quotes are backslash-escaped once more when
		// embedded as a SQL string literal -- compute the expected form the
		// same way rather than hardcoding the escaping.
		$this->assertStringContainsString( addslashes( '"is_tor_exit":true' ), $event_queries[0] );
	}

	public function test_observe_enriches_a_finding_with_non_tor_status_by_default(): void {
		Detector_Registry::register( new Observer_Fixture_Detector() );
		$GLOBALS['_wpdb_get_var'] = null;

		$this->observer->observe();

		$event_queries = $this->event_queries();
		$this->assertCount( 1, $event_queries );
		$this->assertStringContainsString( addslashes( '"is_tor_exit":false' ), $event_queries[0] );
	}

	public function test_observe_never_queries_the_tor_list_when_nothing_matched(): void {
		// No detector registered -- findings is always empty, so the Tor
		// lookup must never run at all (performance requirement: don't pay
		// for network-intelligence resolution on ordinary benign requests).
		$this->observer->observe();

		$tor_queries = array_values( array_filter( $GLOBALS['_wpdb_queries'], static fn( $q ) => str_contains( $q, 'sam_tor_exit_nodes' ) ) );
		$this->assertSame( array(), $tor_queries );
	}

	// ── Detector-family-aware control actions (Phase 4B) ────────────────────

	public function test_observe_records_a_traffic_block_violation_when_a_findings_control_action_is_enforce(): void {
		Detector_Registry::register( new Observer_Enforce_Fixture_Detector() );

		$this->observer->observe();

		$writes = $this->block_writes();
		$this->assertCount( 1, $writes );
		$this->assertSame( '203.0.113.42', $writes[0]['data']['ip'] );
		$this->assertSame( 'detector:fixture-enforce-family', $writes[0]['data']['reason'] );
	}

	public function test_observe_never_records_a_traffic_block_violation_for_an_observe_only_finding(): void {
		Detector_Registry::register( new Observer_Fixture_Detector() );

		$this->observer->observe();

		$this->assertSame( array(), $this->block_writes() );
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

final class Observer_Enforce_Fixture_Detector extends \WP_SAM\Intelligence\Detector {
	public function id(): string {
		return 'observer-enforce-fixture';
	}
	public function family(): string {
		return 'fixture-enforce-family';
	}
	public function applicable_surfaces(): array {
		return array();
	}
	public function evaluate( array $context ): ?array {
		return array( 'severity' => 'high' );
	}
	public function allowed_control_actions(): array {
		return array( 'observe', 'enforce' );
	}
	public function default_control_action(): string {
		return 'enforce';
	}
}
