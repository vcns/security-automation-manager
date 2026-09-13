<?php
/**
 * Unit tests for WP_SAM\Intelligence\Recommendation_Rule_Csp_Enforce_Ready.
 *
 * Call order per candidate (report-only) surface: Exception_Store::
 * has_active_for() (a get_var count), then -- only if that's 0 --
 * Violation_Reporter::count_since() (also a get_var count). Both are queued
 * via _wpdb_get_var_queue in that exact order; a surface that short-circuits
 * (wrong mode, or already exempted) consumes fewer queue entries.
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;
use WP_SAM\Intelligence\Recommendation_Rule_Csp_Enforce_Ready;

class RecommendationRuleCspEnforceReadyTest extends TestCase {

	private Recommendation_Rule_Csp_Enforce_Ready $rule;

	protected function setUp(): void {
		wp_test_reset_globals();
		$this->rule = new Recommendation_Rule_Csp_Enforce_Ready();
	}

	/** @param array<string, mixed> $overrides */
	private function profile_row( array $overrides = array() ): array {
		return array_merge(
			array(
				'surface'    => 'frontend',
				'mode'       => 'report-only',
				'updated_at' => '2026-01-01 00:00:00',
			),
			$overrides
		);
	}

	public function test_no_profiles_produces_no_recommendations(): void {
		$GLOBALS['_wpdb_get_results'] = array();

		$this->assertSame( array(), $this->rule->evaluate() );
	}

	public function test_a_disabled_or_enforcing_surface_is_never_a_candidate(): void {
		$GLOBALS['_wpdb_get_results'] = array(
			$this->profile_row( array( 'surface' => 'admin', 'mode' => 'disabled' ) ),
			$this->profile_row( array( 'surface' => 'login', 'mode' => 'enforce' ) ),
		);

		$this->assertSame( array(), $this->rule->evaluate() );
	}

	public function test_an_exempted_surface_does_not_fire(): void {
		$GLOBALS['_wpdb_get_results']   = array( $this->profile_row() );
		$GLOBALS['_wpdb_get_var_queue'] = array( 1 ); // has_active_for() -- an active exception exists.

		$this->assertSame( array(), $this->rule->evaluate() );
	}

	public function test_a_surface_with_recent_violations_does_not_fire(): void {
		$GLOBALS['_wpdb_get_results']   = array( $this->profile_row() );
		$GLOBALS['_wpdb_get_var_queue'] = array( 0, 3 ); // no exception, but 3 recent violations.

		$this->assertSame( array(), $this->rule->evaluate() );
	}

	public function test_a_quiet_unexempted_report_only_surface_fires(): void {
		$GLOBALS['_wpdb_get_results']   = array( $this->profile_row( array( 'surface' => 'frontend', 'updated_at' => '2026-03-05 00:00:00' ) ) );
		$GLOBALS['_wpdb_get_var_queue'] = array( 0, 0 ); // no exception, zero violations.

		$results = $this->rule->evaluate();

		$this->assertCount( 1, $results );
		$this->assertSame( 'csp_enforce_ready_frontend', $results[0]['key'] );
		$this->assertSame( 'frontend', $results[0]['surface'] );
		$this->assertSame( 'low', $results[0]['risk'] );
		$this->assertSame( 'medium', $results[0]['confidence'] );
		$this->assertTrue( $results[0]['dismissible'] );
		$this->assertSame( '2026-03-05 00:00:00', $results[0]['evidence_changed_at'] );
	}

	public function test_multiple_qualifying_surfaces_each_produce_their_own_recommendation(): void {
		$GLOBALS['_wpdb_get_results']   = array(
			$this->profile_row( array( 'surface' => 'frontend' ) ),
			$this->profile_row( array( 'surface' => 'api' ) ),
		);
		$GLOBALS['_wpdb_get_var_queue'] = array( 0, 0, 0, 0 ); // Two surfaces, two calls each.

		$results = $this->rule->evaluate();

		$this->assertSame( array( 'csp_enforce_ready_frontend', 'csp_enforce_ready_api' ), array_column( $results, 'key' ) );
	}
}
