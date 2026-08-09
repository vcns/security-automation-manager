<?php
/**
 * Unit tests for WP_SAM\Admin\Policy_Events_Builder.
 *
 * The wpdb stub's get_results() replays a per-call queue (_wpdb_get_results_queue),
 * so each test primes one entry per source query the fetch() call is expected to
 * actually run -- an un-primed/extra call would return the shared empty default.
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;
use WP_SAM\Admin\Policy_Events_Builder;

class PolicyEventsBuilderTest extends TestCase {

	protected function setUp(): void {
		wp_test_reset_globals();
	}

	private function decision_row( array $overrides = array() ): array {
		return array_merge(
			array(
				'created_at'         => '2026-01-01 10:00:00',
				'action'             => 'approved',
				'actor_type'         => 'administrator',
				'surface'            => 'frontend',
				'directive'          => 'script-src',
				'source_host'        => 'cdn.example.com',
				'risk_level'         => 'low',
				'risk_reason'        => 'Known CDN',
				'policy_version_id'  => 5,
				'suppression_active' => 0,
				'reason'             => 'Looks safe',
			),
			$overrides
		);
	}

	private function version_row( array $overrides = array() ): array {
		return array_merge(
			array(
				'id'               => 1,
				'surface'          => 'frontend',
				'version_number'   => 3,
				'mode'             => 'enforce',
				'trigger_type'     => 'decision',
				'trigger_id'       => 42,
				'software_version' => '1.0.16',
				'created_at'       => '2026-01-02 10:00:00',
			),
			$overrides
		);
	}

	private function audit_row( array $overrides = array() ): array {
		return array_merge(
			array(
				'id'         => 1,
				'component'  => 'policy_change',
				'event'      => 'source_proposed',
				'detail'     => 'Proposed cdn.example.com for script-src',
				'severity'   => 'info',
				'user_id'    => null,
				'created_at' => '2026-01-03 10:00:00',
			),
			$overrides
		);
	}

	// ── Basic normalization across all three sources ──────────────────────────────

	public function test_fetch_merges_all_three_sources_when_no_filters_active(): void {
		$GLOBALS['_wpdb_get_results_queue'] = array(
			array( $this->decision_row() ),
			array( $this->version_row() ),
			array( $this->audit_row() ),
		);

		$result = Policy_Events_Builder::fetch( $GLOBALS['wpdb'], array() );

		$this->assertCount( 3, $result['events'] );
		$this->assertFalse( $result['truncated'] );

		$types = array_column( $result['events'], 'type' );
		$this->assertContains( 'Decision', $types );
		$this->assertContains( 'Policy version', $types );
		$this->assertContains( 'Discovery', $types );
	}

	public function test_fetch_normalises_decision_row_fields(): void {
		$GLOBALS['_wpdb_get_results_queue'] = array(
			array( $this->decision_row() ),
			array(),
			array(),
		);

		$result = Policy_Events_Builder::fetch( $GLOBALS['wpdb'], array() );
		$event  = $result['events'][0];

		$this->assertSame( 'Approved', $event['event'] );
		$this->assertSame( 'Decision', $event['type'] );
		$this->assertSame( 'cdn.example.com', $event['source'] );
		$this->assertSame( '5', $event['policy_version'] );
		$this->assertSame( '', $event['suppression'] );
	}

	// ── Skip matrix: type filter skips whole source queries ────────────────────────

	public function test_type_filter_of_decision_only_skips_the_other_two_queries(): void {
		$GLOBALS['_wpdb_get_results_queue'] = array(
			array( $this->decision_row() ),
		);

		$result = Policy_Events_Builder::fetch(
			$GLOBALS['wpdb'],
			array( 'type' => array( 'Decision' ) )
		);

		// Only one queued result set was consumed; if versions/discovery had run
		// too they would have drained the queue and fallen back to the shared
		// empty default, so this also proves those queries were never issued.
		$this->assertCount( 1, $result['events'] );
		$this->assertSame( 'Decision', $result['events'][0]['type'] );
	}

	public function test_surface_filter_skips_discovery_source_because_it_has_no_surface_column(): void {
		$GLOBALS['_wpdb_get_results_queue'] = array(
			array( $this->decision_row() ),
			array( $this->version_row() ),
		);

		$result = Policy_Events_Builder::fetch(
			$GLOBALS['wpdb'],
			array( 'surface' => array( 'frontend' ) )
		);

		$this->assertCount( 2, $result['events'] );
		foreach ( $result['events'] as $event ) {
			$this->assertNotSame( 'Discovery', $event['type'] );
		}
	}

	public function test_directive_filter_skips_versions_and_discovery(): void {
		$GLOBALS['_wpdb_get_results_queue'] = array(
			array( $this->decision_row() ),
		);

		$result = Policy_Events_Builder::fetch(
			$GLOBALS['wpdb'],
			array( 'directive' => array( 'script-src' ) )
		);

		$this->assertCount( 1, $result['events'] );
		$this->assertSame( 'Decision', $result['events'][0]['type'] );
	}

	public function test_event_filter_with_only_snapshot_selected_skips_decisions_and_discovery(): void {
		$GLOBALS['_wpdb_get_results_queue'] = array(
			array( $this->version_row() ),
		);

		$result = Policy_Events_Builder::fetch(
			$GLOBALS['wpdb'],
			array( 'event' => array( 'Snapshot' ) )
		);

		$this->assertCount( 1, $result['events'] );
		$this->assertSame( 'Policy version', $result['events'][0]['type'] );
	}

	public function test_event_filter_with_no_matching_label_skips_every_source(): void {
		$GLOBALS['_wpdb_get_results_queue'] = array();

		$result = Policy_Events_Builder::fetch(
			$GLOBALS['wpdb'],
			array( 'event' => array( 'Not A Real Event Label' ) )
		);

		$this->assertSame( array(), $result['events'] );
	}

	// ── PHP post-fetch filters (actor on versions/discovery, detail on versions) ──

	public function test_actor_filter_is_applied_post_fetch_for_version_rows(): void {
		$GLOBALS['_wpdb_get_results_queue'] = array(
			array( $this->decision_row() ),
			array(
				$this->version_row( array( 'trigger_type' => 'decision' ) ), // maps to actor label "system".
				$this->version_row( array( 'trigger_type' => 'cron' ) ),
			),
			array( $this->audit_row() ),
		);

		$result = Policy_Events_Builder::fetch(
			$GLOBALS['wpdb'],
			array( 'actor' => array( 'system' ) )
		);

		$version_events = array_values( array_filter( $result['events'], static fn( array $e ): bool => 'Policy version' === $e['type'] ) );
		$this->assertCount( 1, $version_events );
		$this->assertSame( 'system', $version_events[0]['actor'] );
	}

	public function test_actor_filter_is_applied_post_fetch_for_discovery_rows(): void {
		$GLOBALS['_wpdb_get_results_queue'] = array(
			array( $this->decision_row() ),
			array( $this->version_row() ),
			array(
				$this->audit_row( array( 'user_id' => null ) ), // actor "system"
				$this->audit_row( array( 'user_id' => 9 ) ),    // actor "administrator"
			),
		);

		$result = Policy_Events_Builder::fetch(
			$GLOBALS['wpdb'],
			array( 'actor' => array( 'administrator' ) )
		);

		$discovery_events = array_values( array_filter( $result['events'], static fn( array $e ): bool => 'Discovery' === $e['type'] ) );
		$this->assertCount( 1, $discovery_events );
	}

	public function test_detail_filter_is_applied_post_fetch_for_composed_version_detail(): void {
		$GLOBALS['_wpdb_get_results_queue'] = array(
			array( $this->decision_row() ),
			array( $this->version_row( array( 'mode' => 'enforce' ) ) ),
			array( $this->audit_row() ),
		);

		$result = Policy_Events_Builder::fetch(
			$GLOBALS['wpdb'],
			array( 'detail' => 'enforce policy snapshot' )
		);

		$version_events = array_values( array_filter( $result['events'], static fn( array $e ): bool => 'Policy version' === $e['type'] ) );
		$this->assertCount( 1, $version_events );
	}

	// ── Truncation flag ──────────────────────────────────────────────────────────

	public function test_truncated_flag_set_when_a_source_hits_the_cap(): void {
		$capped_rows = array_fill( 0, Policy_Events_Builder::SOURCE_CAP, $this->decision_row() );

		$GLOBALS['_wpdb_get_results_queue'] = array(
			$capped_rows,
			array(),
			array(),
		);

		$result = Policy_Events_Builder::fetch( $GLOBALS['wpdb'], array() );

		$this->assertTrue( $result['truncated'] );
	}

	public function test_truncated_flag_false_when_no_source_hits_the_cap(): void {
		$GLOBALS['_wpdb_get_results_queue'] = array(
			array( $this->decision_row() ),
			array(),
			array(),
		);

		$result = Policy_Events_Builder::fetch( $GLOBALS['wpdb'], array() );

		$this->assertFalse( $result['truncated'] );
	}

	// ── sort() ───────────────────────────────────────────────────────────────────

	public function test_sort_orders_by_requested_field_and_direction(): void {
		$events = array(
			array( 'created_at' => '2026-01-01 00:00:00', 'surface' => 'zeta' ),
			array( 'created_at' => '2026-01-02 00:00:00', 'surface' => 'alpha' ),
		);

		$asc = Policy_Events_Builder::sort( $events, 'surface', 'asc' );
		$this->assertSame( 'alpha', $asc[0]['surface'] );

		$desc = Policy_Events_Builder::sort( $events, 'when', 'desc' );
		$this->assertSame( '2026-01-02 00:00:00', $desc[0]['created_at'] );
	}

	public function test_sort_falls_back_to_created_at_for_unknown_field(): void {
		$events = array(
			array( 'created_at' => '2026-01-01 00:00:00' ),
			array( 'created_at' => '2026-01-02 00:00:00' ),
		);

		$sorted = Policy_Events_Builder::sort( $events, 'not_a_real_field', 'desc' );

		$this->assertSame( '2026-01-02 00:00:00', $sorted[0]['created_at'] );
	}
}
