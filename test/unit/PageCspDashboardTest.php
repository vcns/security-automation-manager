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
 * page-csp-dashboard.php unconditionally issues four $wpdb->get_results()
 * calls before any tab-specific branch runs (profiles, last-50 violations,
 * conflict notices, scan log) -- every fixture queue below reserves four
 * leading empty-array slots for those before its tab's own query/queries.
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

	// ── Fixtures ─────────────────────────────────────────────────────────────────

	/** @return array<int, array<int, mixed>> placeholder rows for the page's four unconditional top-of-file queries. */
	private function leading_top_level_queries(): array {
		return array( array(), array(), array(), array() );
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
