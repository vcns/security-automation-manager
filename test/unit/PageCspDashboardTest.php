<?php
/**
 * Regression coverage for Phase 4D (issue #167): proves the Sources, Policy
 * Changes, and Violations tabs actually wire Table_Query's pagination
 * correctly when the real view file renders -- an out-of-range page number
 * caps at the true last page instead of showing a nonsensical "Page N of M",
 * a filter survives a page change, and an empty result set renders without a
 * fatal. Table_Query itself is already covered in isolation by
 * Admin/TableQueryTest.php; this exercises the actual require() chain.
 *
 * page-csp-dashboard.php issues exactly one unconditional $wpdb->get_results()
 * call before any tab-specific branch runs (the conflict-notices banner,
 * shown on every tab) -- every fixture queue below reserves one leading
 * empty-array slot for that before its tab's own query/queries. Profiles,
 * violations, and scan-log queries are gated to the tabs that actually need
 * them (issue #166); see the "Query scoping" section below for coverage of
 * that gating itself.
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;

class PageCspDashboardTest extends TestCase {

	protected function setUp(): void {
		wp_test_reset_globals();
	}

	// ── Sources tab ──────────────────────────────────────────────────────────────

	public function test_sources_pagination_caps_out_of_range_page(): void {
		$_GET['tab']   = 'sources';
		$_GET['paged'] = '9999';
		$GLOBALS['_wpdb_get_var']           = 45;
		$GLOBALS['_wpdb_get_results_queue'] = array_merge( $this->leading_top_level_queries(), array( $this->source_rows( 20 ) ) );

		ob_start();
		require WP_SAM_DIR . 'includes/admin/views/page-csp-dashboard.php';
		$output = (string) ob_get_clean();

		unset( $_GET['tab'], $_GET['paged'] );

		$this->assertStringNotContainsString( 'Page 9999', $output );
		$this->assertStringContainsString( 'Page 3 of 3', $output );
	}

	public function test_sources_filter_survives_page_change(): void {
		$_GET['tab']       = 'sources';
		$_GET['src_host']  = 'cdn1';
		$_GET['paged']     = '1';
		$GLOBALS['_wpdb_get_var']           = 45;
		$GLOBALS['_wpdb_get_results_queue'] = array_merge( $this->leading_top_level_queries(), array( $this->source_rows( 2 ) ) );

		ob_start();
		require WP_SAM_DIR . 'includes/admin/views/page-csp-dashboard.php';
		$output = (string) ob_get_clean();

		unset( $_GET['tab'], $_GET['src_host'], $_GET['paged'] );

		$this->assertStringContainsString( 'src_host=cdn1', $output );
		$this->assertStringContainsString( 'paged=2', $output );
	}

	public function test_sources_empty_result_set_renders_without_fatal(): void {
		$_GET['tab']              = 'sources';
		$GLOBALS['_wpdb_get_var'] = 0;

		ob_start();
		require WP_SAM_DIR . 'includes/admin/views/page-csp-dashboard.php';
		$output = (string) ob_get_clean();

		unset( $_GET['tab'] );

		$this->assertStringContainsString( 'No sources discovered yet.', $output );
		$this->assertStringNotContainsString( 'tablenav-pages', $output );
	}

	/**
	 * Regression coverage ahead of the admin-table layout migration:
	 * assets/js/admin.js reads `.wp-sam-state-badge` (to swap its `state-*`
	 * modifier class after an approve/deny/revert/undo AJAX call) and
	 * `.wp-sam-source-actions` (to replace that cell's inner HTML with
	 * fresh buttons) directly off this row -- neither class has any other
	 * test coverage anywhere in the suite, so nothing else would catch an
	 * accidental rename of either while the table's markup/CSS is migrated
	 * onto the new semantic column-role system.
	 */
	public function test_sources_row_carries_the_js_dependent_state_and_actions_classes(): void {
		$_GET['tab']                        = 'sources';
		$GLOBALS['_wpdb_get_var']            = 1;
		$GLOBALS['_wpdb_get_results_queue']  = array_merge( $this->leading_top_level_queries(), array( $this->source_rows( 1 ) ) );

		ob_start();
		require WP_SAM_DIR . 'includes/admin/views/page-csp-dashboard.php';
		$output = (string) ob_get_clean();

		unset( $_GET['tab'] );

		$this->assertStringContainsString( 'wp-sam-state-badge state-pending', $output );
		$this->assertStringContainsString( 'wp-sam-source-actions', $output );
	}

	// ── Policy Changes tab ───────────────────────────────────────────────────────
	//
	// Policy_Events_Builder has no COUNT query of its own -- the merged
	// events array it returns *is* the total, so getting three real pages
	// means actually queuing 45 decision rows (the other two sources, policy
	// versions and discovery, stay empty), not just faking a $wpdb->get_var()
	// total the way the other tabs on this page can.

	public function test_policy_changes_pagination_caps_out_of_range_page(): void {
		$_GET['tab']      = 'policy-changes';
		$_GET['pc_paged'] = '9999';
		$GLOBALS['_wpdb_get_results_queue'] = array_merge( $this->leading_top_level_queries(), array( $this->decision_rows( 45 ), array(), array() ) );

		ob_start();
		require WP_SAM_DIR . 'includes/admin/views/page-csp-dashboard.php';
		$output = (string) ob_get_clean();

		unset( $_GET['tab'], $_GET['pc_paged'] );

		$this->assertStringNotContainsString( 'Page 9999', $output );
		$this->assertStringContainsString( 'Page 3 of 3', $output );
	}

	public function test_policy_changes_filter_survives_page_change(): void {
		// pc_detail is one of the few Policy Changes filters that doesn't
		// disable the policy-version/discovery source queries outright (see
		// Policy_Events_Builder::fetch()'s run_versions/run_discovery
		// skip matrix) -- keeps this test's queue shape identical to the
		// no-filter case above instead of needing a second, shorter queue.
		$_GET['tab']       = 'policy-changes';
		$_GET['pc_detail'] = 'revoked';
		$_GET['pc_paged']  = '1';
		$GLOBALS['_wpdb_get_results_queue'] = array_merge( $this->leading_top_level_queries(), array( $this->decision_rows( 45 ), array(), array() ) );

		ob_start();
		require WP_SAM_DIR . 'includes/admin/views/page-csp-dashboard.php';
		$output = (string) ob_get_clean();

		unset( $_GET['tab'], $_GET['pc_detail'], $_GET['pc_paged'] );

		$this->assertStringContainsString( 'pc_detail=revoked', $output );
		$this->assertStringContainsString( 'pc_paged=2', $output );
	}

	public function test_policy_changes_empty_result_set_renders_without_fatal(): void {
		$_GET['tab'] = 'policy-changes';

		ob_start();
		require WP_SAM_DIR . 'includes/admin/views/page-csp-dashboard.php';
		$output = (string) ob_get_clean();

		unset( $_GET['tab'] );

		$this->assertStringContainsString( 'No policy activity has been recorded yet.', $output );
		$this->assertStringNotContainsString( 'tablenav-pages', $output );
	}

	// ── Violations tab ───────────────────────────────────────────────────────────

	public function test_violations_pagination_caps_out_of_range_page(): void {
		$_GET['tab']     = 'violations';
		$_GET['v_paged'] = '9999';
		$GLOBALS['_wpdb_get_var']           = 45;
		$GLOBALS['_wpdb_get_results_queue'] = array_merge( $this->leading_top_level_queries(), array( $this->violation_rows( 20 ) ) );

		ob_start();
		require WP_SAM_DIR . 'includes/admin/views/page-csp-dashboard.php';
		$output = (string) ob_get_clean();

		unset( $_GET['tab'], $_GET['v_paged'] );

		$this->assertStringNotContainsString( 'Page 9999', $output );
		$this->assertStringContainsString( 'Page 3 of 3', $output );
	}

	public function test_violations_filter_survives_page_change(): void {
		$_GET['tab']       = 'violations';
		$_GET['v_surface'] = 'admin';
		$_GET['v_paged']   = '1';
		$GLOBALS['_wpdb_get_var']           = 45;
		$GLOBALS['_wpdb_get_results_queue'] = array_merge( $this->leading_top_level_queries(), array( $this->violation_rows( 2 ) ) );

		ob_start();
		require WP_SAM_DIR . 'includes/admin/views/page-csp-dashboard.php';
		$output = (string) ob_get_clean();

		unset( $_GET['tab'], $_GET['v_surface'], $_GET['v_paged'] );

		$this->assertStringContainsString( 'v_surface=admin', $output );
		$this->assertStringContainsString( 'v_paged=2', $output );
	}

	public function test_violations_empty_result_set_renders_without_fatal(): void {
		$_GET['tab']              = 'violations';
		$GLOBALS['_wpdb_get_var'] = 0;

		ob_start();
		require WP_SAM_DIR . 'includes/admin/views/page-csp-dashboard.php';
		$output = (string) ob_get_clean();

		unset( $_GET['tab'] );

		$this->assertStringContainsString( 'No browser violation reports have been recorded yet.', $output );
		$this->assertStringNotContainsString( 'tablenav-pages', $output );
	}

	// ── Query scoping (issue #166) ──────────────────────────────────────────────
	//
	// page-csp-dashboard.php used to issue four $wpdb->get_results() calls
	// (profiles, last-50 violations, conflict notices, scan log) before any
	// tab branch ran, regardless of which tab was actually being viewed.
	// Profiles, violations, and scan-log queries are now gated to the tabs
	// that need them; conflict notices alone stays unconditional (it feeds a
	// banner shown on every tab). These tests inspect
	// $GLOBALS['_wpdb_get_results_log'] -- every query string the stub has
	// seen this test -- rather than relying only on queue-shape side effects.

	public function test_start_here_tab_issues_only_the_conflict_notices_query(): void {
		$_GET['tab'] = 'start-here';

		ob_start();
		require WP_SAM_DIR . 'includes/admin/views/page-csp-dashboard.php';
		ob_end_clean();

		unset( $_GET['tab'] );

		$this->assertCount( 1, $GLOBALS['_wpdb_get_results_log'] );
		$this->assertStringContainsString( 'sam_audit_log', $GLOBALS['_wpdb_get_results_log'][0] );
	}

	public function test_sources_tab_does_not_query_profiles_violations_or_scan_logs(): void {
		$_GET['tab']              = 'sources';
		$GLOBALS['_wpdb_get_var'] = 0;

		ob_start();
		require WP_SAM_DIR . 'includes/admin/views/page-csp-dashboard.php';
		ob_end_clean();

		unset( $_GET['tab'] );

		$queried = implode( "\n", $GLOBALS['_wpdb_get_results_log'] );
		$this->assertStringNotContainsString( 'csp_policy_profiles', $queried );
		$this->assertStringNotContainsString( 'csp_violation_reports', $queried );
		$this->assertStringNotContainsString( 'sam_scan_logs', $queried );
	}

	public function test_profiles_tab_queries_the_profiles_table(): void {
		$_GET['tab'] = 'profiles';
		$GLOBALS['_wpdb_get_results_queue'] = array_merge( $this->leading_top_level_queries(), array( array() ) );

		ob_start();
		require WP_SAM_DIR . 'includes/admin/views/page-csp-dashboard.php';
		ob_end_clean();

		unset( $_GET['tab'] );

		$queried = implode( "\n", $GLOBALS['_wpdb_get_results_log'] );
		$this->assertStringContainsString( 'csp_policy_profiles', $queried );
	}

	public function test_policy_audit_tab_queries_the_profiles_table(): void {
		// policy-audit has no re-query of its own -- it relies entirely on
		// the gated top-level $profiles load, unlike every other tab here.
		$_GET['tab'] = 'policy-audit';
		$GLOBALS['_wpdb_get_results_queue'] = array_merge( $this->leading_top_level_queries(), array( array() ) );

		ob_start();
		require WP_SAM_DIR . 'includes/admin/views/page-csp-dashboard.php';
		ob_end_clean();

		unset( $_GET['tab'] );

		$queried = implode( "\n", $GLOBALS['_wpdb_get_results_log'] );
		$this->assertStringContainsString( 'csp_policy_profiles', $queried );
	}

	// ── Fixtures ─────────────────────────────────────────────────────────────────

	/** @return array<int, array<int, mixed>> placeholder rows for the page's one unconditional top-of-file query (conflict notices). */
	private function leading_top_level_queries(): array {
		return array( array() );
	}

	/** @return array<int, array<string, mixed>> */
	private function source_rows( int $count ): array {
		$rows = array();
		for ( $i = 1; $i <= $count; $i++ ) {
			$rows[] = array(
				'id'             => $i,
				'surface'        => 'frontend',
				'directive'      => 'script-src',
				'source_host'    => "cdn{$i}.example.test",
				'risk_level'     => 'low',
				'risk_reason'    => '',
				'approval_state' => 'pending',
				'evidence_count' => 1,
				'last_seen_at'   => '2026-01-01 00:00:00',
				'last_decision'  => '',
			);
		}
		return $rows;
	}

	/** @return array<int, array<string, mixed>> raw sam_policy_change_decisions rows, as Policy_Events_Builder::fetch_decisions() expects. */
	private function decision_rows( int $count ): array {
		$rows = array();
		for ( $i = 1; $i <= $count; $i++ ) {
			$rows[] = array(
				'created_at'          => '2026-01-01 00:00:00',
				'action'              => 'approved',
				'actor_type'          => 'administrator',
				'surface'             => 'frontend',
				'directive'           => 'script-src',
				'source_host'         => "cdn{$i}.example.test",
				'risk_level'          => 'low',
				'risk_reason'         => '',
				'policy_version_id'   => '',
				'suppression_active'  => 0,
				'reason'              => 'reviewed',
			);
		}
		return $rows;
	}

	/** @return array<int, array<string, mixed>> */
	private function violation_rows( int $count ): array {
		$rows = array();
		for ( $i = 1; $i <= $count; $i++ ) {
			$rows[] = array(
				'profile_surface'    => 'frontend',
				'blocked_host'       => "cdn{$i}.example.test",
				'blocked_uri'        => "https://cdn{$i}.example.test/x.js",
				'violated_directive' => 'script-src',
				'occurrence_count'   => 1,
				'reported_at'        => '2026-01-01 00:00:00',
				'disposition'        => 'report-only',
				'first_reported_at'  => '2026-01-01 00:00:00',
				'document_uri'       => '',
				'source_file'        => '',
				'line_number'        => '',
				'column_number'      => '',
				'referrer'           => '',
				'user_agent'         => '',
				'sample'             => '',
			);
		}
		return $rows;
	}
}
