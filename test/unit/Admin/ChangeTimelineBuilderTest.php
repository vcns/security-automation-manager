<?php
/**
 * Unit tests for WP_SAM\Admin\Change_Timeline_Builder.
 *
 * The wpdb stub's get_results() replays a per-call queue
 * (_wpdb_get_results_queue), so each test primes one entry per source query
 * fetch() is expected to run, in call order: Change_Log_Store::all(),
 * Drift_Store::all(), Campaign_Store::all().
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;
use WP_SAM\Admin\Change_Timeline_Builder;
use WP_SAM\Intelligence\Campaign_Store;
use WP_SAM\Intelligence\Change_Log_Store;
use WP_SAM\Intelligence\Drift_Store;

class ChangeTimelineBuilderTest extends TestCase {

	protected function setUp(): void {
		wp_test_reset_globals();
	}

	public function test_fetch_merges_and_sorts_all_three_sources_most_recent_first(): void {
		$GLOBALS['_wpdb_get_results_queue'] = array(
			array(
				array(
					'change_type' => 'plugin_updated',
					'item_name'   => 'akismet/akismet.php',
					'old_version' => '5.2',
					'new_version' => '5.3',
					'occurred_at' => '2026-01-01 10:00:00',
				),
			),
			array(
				array(
					'category'          => 'pillar',
					'surface'           => 'frontend',
					'item_key'          => 'x-frame-options',
					'risk_level'        => 'medium',
					'correlated_change' => '',
					'first_seen_at'     => '2026-01-01 12:00:00',
				),
			),
			array(
				array(
					'detector_id'        => 'sqli-probe',
					'surface'            => 'frontend',
					'participant_count'  => 15,
					'first_detected_at'  => '2026-01-01 08:00:00',
				),
			),
		);

		$events = Change_Timeline_Builder::fetch( new Change_Log_Store(), new Drift_Store(), new Campaign_Store() );

		$this->assertCount( 3, $events );
		$this->assertSame( '2026-01-01 12:00:00', $events[0]['when'] );
		$this->assertSame( '2026-01-01 10:00:00', $events[1]['when'] );
		$this->assertSame( '2026-01-01 08:00:00', $events[2]['when'] );
	}

	public function test_fetch_labels_a_known_change_type(): void {
		$GLOBALS['_wpdb_get_results_queue'] = array(
			array(
				array(
					'change_type' => 'admin_account_created',
					'item_name'   => 'jane',
					'old_version' => '',
					'new_version' => 'administrator',
					'occurred_at' => '2026-01-01 10:00:00',
				),
			),
			array(),
			array(),
		);

		$events = Change_Timeline_Builder::fetch( new Change_Log_Store(), new Drift_Store(), new Campaign_Store() );

		$this->assertSame( 'New administrator account', $events[0]['event'] );
	}

	public function test_fetch_words_drift_correlation_never_as_causation(): void {
		$GLOBALS['_wpdb_get_results_queue'] = array(
			array(),
			array(
				array(
					'category'          => 'pillar',
					'surface'           => 'frontend',
					'item_key'          => 'x-frame-options',
					'risk_level'        => 'medium',
					'correlated_change' => 'Correlates with a plugin update recorded 3 minutes earlier.',
					'first_seen_at'     => '2026-01-01 12:00:00',
				),
			),
			array(),
		);

		$events = Change_Timeline_Builder::fetch( new Change_Log_Store(), new Drift_Store(), new Campaign_Store() );

		$this->assertStringContainsString( 'Correlates with', $events[0]['detail'] );
		$this->assertStringNotContainsString( 'caused by', $events[0]['detail'] );
	}

	public function test_fetch_campaign_detail_reports_distinct_ip_count(): void {
		$GLOBALS['_wpdb_get_results_queue'] = array(
			array(),
			array(),
			array(
				array(
					'detector_id'       => 'sqli-probe',
					'surface'           => 'frontend',
					'participant_count' => 15,
					'first_detected_at' => '2026-01-01 08:00:00',
				),
			),
		);

		$events = Change_Timeline_Builder::fetch( new Change_Log_Store(), new Drift_Store(), new Campaign_Store() );

		$this->assertStringContainsString( '15 distinct source IPs', $events[0]['detail'] );
		$this->assertSame( 'high', $events[0]['risk_level'] );
	}

	public function test_fetch_returns_empty_array_when_nothing_recorded(): void {
		$GLOBALS['_wpdb_get_results_queue'] = array( array(), array(), array() );

		$events = Change_Timeline_Builder::fetch( new Change_Log_Store(), new Drift_Store(), new Campaign_Store() );

		$this->assertSame( array(), $events );
	}
}
