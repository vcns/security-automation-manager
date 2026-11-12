<?php
/**
 * Unit tests for WP_SAM\Intelligence\Recommendation_Rule_Csp_Enforce_Ready.
 *
 * Call order per candidate (report-only) surface: Exception_Store::
 * has_active_for() (a get_var count), then -- only if that's 0 --
 * Violation_Reporter::count_since() (also a get_var count). Both are queued
 * via _wpdb_get_var_queue in that exact order; a surface that short-circuits
 * (wrong mode, or already exempted) consumes fewer queue entries.
 *
 * A candidate also needs a Csp_Delivery_Log record showing the policy was
 * actually sent for the whole quiet window -- see deliver().
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

	/**
	 * Records delivery of $surface's policy in Csp_Delivery_Log's option,
	 * relative to now.
	 */
	private function deliver( string $surface, int $first_sent_days_ago = 40, int $last_sent_hours_ago = 1, ?int $trimmed_days_ago = null ): void {
		$entry = array(
			'first_sent' => time() - ( $first_sent_days_ago * DAY_IN_SECONDS ),
			'last_sent'  => time() - ( $last_sent_hours_ago * HOUR_IN_SECONDS ),
		);
		if ( null !== $trimmed_days_ago ) {
			$entry['last_trimmed'] = time() - ( $trimmed_days_ago * DAY_IN_SECONDS );
		}
		$GLOBALS['_wp_options'][ 'wp_sam_csp_delivery_' . $surface ] = $entry;
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
		$this->deliver( 'frontend', 40 );

		$results = $this->rule->evaluate();

		$this->assertCount( 1, $results );
		$this->assertSame( 'csp_enforce_ready_frontend', $results[0]['key'] );
		$this->assertSame( gmdate( 'Y-m-d', time() - ( 40 * DAY_IN_SECONDS ) ), $results[0]['evidence']['policy_sent_since'] );
		$this->assertSame( 'frontend', $results[0]['surface'] );
		$this->assertSame( 'low', $results[0]['risk'] );
		$this->assertSame( 'medium', $results[0]['confidence'] );
		$this->assertTrue( $results[0]['dismissible'] );
		$this->assertSame( '2026-03-05 00:00:00', $results[0]['evidence_changed_at'] );
	}

	public function test_multiple_qualifying_surfaces_each_produce_their_own_recommendation(): void {
		$GLOBALS['_wpdb_get_results']   = array(
			$this->profile_row( array( 'surface' => 'frontend' ) ),
			$this->profile_row( array( 'surface' => 'login' ) ),
		);
		$GLOBALS['_wpdb_get_var_queue'] = array( 0, 0, 0, 0 ); // Two surfaces, two calls each.
		$this->deliver( 'frontend' );
		$this->deliver( 'login' );

		$results = $this->rule->evaluate();

		$this->assertSame( array( 'csp_enforce_ready_frontend', 'csp_enforce_ready_login' ), array_column( $results, 'key' ) );
	}

	public function test_a_quiet_surface_whose_policy_was_never_sent_does_not_fire(): void {
		// The admin case: report-only, no exception, no violations -- but no
		// policy was ever delivered, so the silence proves nothing.
		$GLOBALS['_wpdb_get_results']   = array( $this->profile_row( array( 'surface' => 'admin' ) ) );
		$GLOBALS['_wpdb_get_var_queue'] = array( 0, 0 );

		$this->assertSame( array(), $this->rule->evaluate() );
	}

	public function test_a_policy_sent_for_less_than_the_quiet_window_does_not_fire(): void {
		$GLOBALS['_wpdb_get_results']   = array( $this->profile_row() );
		$GLOBALS['_wpdb_get_var_queue'] = array( 0, 0 );
		$this->deliver( 'frontend', 10 );

		$this->assertSame( array(), $this->rule->evaluate() );
	}

	public function test_a_policy_not_sent_recently_does_not_fire(): void {
		$GLOBALS['_wpdb_get_results']   = array( $this->profile_row() );
		$GLOBALS['_wpdb_get_var_queue'] = array( 0, 0 );
		$this->deliver( 'frontend', 60, 10 * 24 );

		$this->assertSame( array(), $this->rule->evaluate() );
	}

	public function test_a_surface_whose_hashes_were_trimmed_in_the_window_does_not_fire(): void {
		$GLOBALS['_wpdb_get_results']   = array( $this->profile_row() );
		$GLOBALS['_wpdb_get_var_queue'] = array( 0, 0 );
		$this->deliver( 'frontend', 60, 1, 5 );

		$this->assertSame( array(), $this->rule->evaluate() );
	}

	public function test_trimming_before_the_window_does_not_block_the_recommendation(): void {
		$GLOBALS['_wpdb_get_results']   = array( $this->profile_row() );
		$GLOBALS['_wpdb_get_var_queue'] = array( 0, 0 );
		$this->deliver( 'frontend', 60, 1, 45 );

		$this->assertCount( 1, $this->rule->evaluate() );
	}

	public function test_a_surface_whose_reports_were_throttled_in_the_window_does_not_fire(): void {
		$GLOBALS['_wpdb_get_results']   = array( $this->profile_row( array( 'surface' => 'admin' ) ) );
		$GLOBALS['_wpdb_get_var_queue'] = array( 0, 0 );
		$this->deliver( 'admin', 60, 1 );
		$GLOBALS['_wp_options']['wp_sam_csp_delivery_admin']['last_throttled'] = time() - ( 3 * DAY_IN_SECONDS );

		$this->assertSame( array(), $this->rule->evaluate() );
	}
}
