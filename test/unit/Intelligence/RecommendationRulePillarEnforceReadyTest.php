<?php
/**
 * Unit tests for WP_SAM\Intelligence\Recommendation_Rule_Pillar_Enforce_Ready.
 *
 * Pillar_Registry::pillars() sorts alphabetically by label -- of the 14
 * registered pillars, only two (Cross-Origin-Embedder-Policy, Cross-Origin-
 * Opener-Policy) have a 'report-only' entry in mode_status_map, and COEP
 * sorts before COOP ("E" < "O"). Every other pillar is skipped before any
 * wpdb call, so the queues below only ever need two get_results entries
 * (COEP's own profile rows, then COOP's), in that order.
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;
use WP_SAM\Intelligence\Recommendation_Rule_Pillar_Enforce_Ready;

class RecommendationRulePillarEnforceReadyTest extends TestCase {

	private Recommendation_Rule_Pillar_Enforce_Ready $rule;

	protected function setUp(): void {
		wp_test_reset_globals();
		$this->rule = new Recommendation_Rule_Pillar_Enforce_Ready();
	}

	/** @param array<string, mixed> $overrides */
	private function profile_row( array $overrides = array() ): array {
		return array_merge(
			array(
				'surface'    => 'frontend',
				'payload'    => wp_json_encode( array( 'mode' => 'report-only', 'value' => 'same-origin' ) ),
				'updated_at' => '2026-01-01 00:00:00',
			),
			$overrides
		);
	}

	public function test_no_enabled_rows_on_either_pillar_produces_no_recommendations(): void {
		$GLOBALS['_wpdb_get_results_queue'] = array( array(), array() );

		$this->assertSame( array(), $this->rule->evaluate() );
	}

	public function test_an_enforcing_row_is_never_a_candidate(): void {
		$GLOBALS['_wpdb_get_results_queue'] = array(
			array( $this->profile_row( array( 'payload' => wp_json_encode( array( 'mode' => 'enforce', 'value' => 'same-origin' ) ) ) ) ),
			array(),
		);

		$this->assertSame( array(), $this->rule->evaluate() );
	}

	public function test_an_exempted_surface_does_not_fire(): void {
		$GLOBALS['_wpdb_get_results_queue'] = array(
			array( $this->profile_row() ), // COEP row.
			array(),
		);
		$GLOBALS['_wpdb_get_var_queue'] = array( 1 ); // has_active_for() -- an active exception exists.

		$this->assertSame( array(), $this->rule->evaluate() );
	}

	public function test_a_surface_with_recent_violations_does_not_fire(): void {
		$GLOBALS['_wpdb_get_results_queue'] = array(
			array( $this->profile_row() ),
			array(),
		);
		$GLOBALS['_wpdb_get_var_queue'] = array( 0, 2 ); // no exception, but 2 recent violations.

		$this->assertSame( array(), $this->rule->evaluate() );
	}

	public function test_a_quiet_unexempted_report_only_coep_row_fires(): void {
		$GLOBALS['_wpdb_get_results_queue'] = array(
			array( $this->profile_row( array( 'surface' => 'frontend', 'updated_at' => '2026-04-01 00:00:00' ) ) ),
			array(),
		);
		$GLOBALS['_wpdb_get_var_queue'] = array( 0, 0 ); // no exception, zero violations.

		$results = $this->rule->evaluate();

		$this->assertCount( 1, $results );
		$this->assertSame( 'pillar_enforce_ready_cross-origin-embedder-policy_frontend', $results[0]['key'] );
		$this->assertSame( 'Cross-Origin-Embedder-Policy', $results[0]['pillar'] );
		$this->assertSame( 'frontend', $results[0]['surface'] );
		$this->assertSame( 'low', $results[0]['risk'] );
		$this->assertTrue( $results[0]['dismissible'] );
		$this->assertSame( '2026-04-01 00:00:00', $results[0]['evidence_changed_at'] );
	}

	public function test_a_quiet_unexempted_report_only_coop_row_fires(): void {
		$GLOBALS['_wpdb_get_results_queue'] = array(
			array(), // COEP -- nothing enabled.
			array( $this->profile_row( array( 'surface' => 'admin' ) ) ), // COOP.
		);
		$GLOBALS['_wpdb_get_var_queue'] = array( 0, 0 );

		$results = $this->rule->evaluate();

		$this->assertCount( 1, $results );
		$this->assertSame( 'pillar_enforce_ready_cross-origin-opener-policy_admin', $results[0]['key'] );
		$this->assertSame( 'Cross-Origin-Opener-Policy', $results[0]['pillar'] );
	}

	public function test_cta_url_points_at_the_shared_cross_origin_page(): void {
		$GLOBALS['_wpdb_get_results_queue'] = array(
			array( $this->profile_row() ),
			array(),
		);
		$GLOBALS['_wpdb_get_var_queue'] = array( 0, 0 );

		$results = $this->rule->evaluate();

		$this->assertStringContainsString( 'page=security-automation-manager-cross-origin', $results[0]['cta_url'] );
		$this->assertStringContainsString( 'tab=coep', $results[0]['cta_url'] );
	}
}
