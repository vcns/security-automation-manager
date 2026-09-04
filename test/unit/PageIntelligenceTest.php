<?php
/**
 * Regression coverage for Phase 4D (issue #167): proves the Events and
 * Identities tabs actually wire Table_Query's pagination correctly when the
 * real view file renders -- an out-of-range page number caps at the true
 * last page instead of showing a nonsensical "Page N of M", a filter
 * survives a page change, and an empty result set renders without a fatal.
 * Table_Query itself is already covered in isolation by
 * Admin/TableQueryTest.php; this exercises the actual require() chain.
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;

class PageIntelligenceTest extends TestCase {

	protected function setUp(): void {
		wp_test_reset_globals();
	}

	// ── Events tab ───────────────────────────────────────────────────────────────

	public function test_events_pagination_caps_out_of_range_page(): void {
		$_GET['tab']     = 'events';
		$_GET['i_paged'] = '9999';
		$GLOBALS['_wpdb_get_var']           = 45;
		$GLOBALS['_wpdb_get_results_queue'] = array( $this->event_rows( 20 ) );

		ob_start();
		require WP_SAM_DIR . 'includes/admin/views/page-intelligence.php';
		$output = (string) ob_get_clean();

		unset( $_GET['tab'], $_GET['i_paged'] );

		$this->assertStringNotContainsString( 'Page 9999', $output );
		$this->assertStringContainsString( 'Page 3 of 3', $output );
	}

	public function test_events_filter_survives_page_change(): void {
		$_GET['tab']        = 'events';
		$_GET['i_severity'] = 'high';
		$_GET['i_paged']    = '1';
		$GLOBALS['_wpdb_get_var']           = 45;
		$GLOBALS['_wpdb_get_results_queue'] = array( $this->event_rows( 2 ) );

		ob_start();
		require WP_SAM_DIR . 'includes/admin/views/page-intelligence.php';
		$output = (string) ob_get_clean();

		unset( $_GET['tab'], $_GET['i_severity'], $_GET['i_paged'] );

		$this->assertStringContainsString( 'i_severity=high', $output );
		$this->assertStringContainsString( 'i_paged=2', $output );
	}

	public function test_events_empty_result_set_renders_without_fatal(): void {
		$_GET['tab']              = 'events';
		$GLOBALS['_wpdb_get_var'] = 0;

		ob_start();
		require WP_SAM_DIR . 'includes/admin/views/page-intelligence.php';
		$output = (string) ob_get_clean();

		unset( $_GET['tab'] );

		$this->assertStringContainsString( 'No events recorded', $output );
		$this->assertStringNotContainsString( 'tablenav-pages', $output );
	}

	// ── Identities tab ──────────────────────────────────────────────────────────

	public function test_identities_pagination_caps_out_of_range_page(): void {
		$_GET['tab']      = 'identities';
		$_GET['id_paged'] = '9999';
		$GLOBALS['_wpdb_get_var']           = 45;
		$GLOBALS['_wpdb_get_results_queue'] = array( $this->identity_rows( 20 ) );

		ob_start();
		require WP_SAM_DIR . 'includes/admin/views/page-intelligence.php';
		$output = (string) ob_get_clean();

		unset( $_GET['tab'], $_GET['id_paged'] );

		$this->assertStringNotContainsString( 'Page 9999', $output );
		$this->assertStringContainsString( 'Page 3 of 3', $output );
	}

	public function test_identities_filter_survives_page_change(): void {
		$_GET['tab']        = 'identities';
		$_GET['id_surface'] = 'admin';
		$_GET['id_paged']   = '1';
		$GLOBALS['_wpdb_get_var']           = 45;
		$GLOBALS['_wpdb_get_results_queue'] = array( $this->identity_rows( 2 ) );

		ob_start();
		require WP_SAM_DIR . 'includes/admin/views/page-intelligence.php';
		$output = (string) ob_get_clean();

		unset( $_GET['tab'], $_GET['id_surface'], $_GET['id_paged'] );

		$this->assertStringContainsString( 'id_surface=admin', $output );
		$this->assertStringContainsString( 'id_paged=2', $output );
	}

	public function test_identities_empty_result_set_renders_without_fatal(): void {
		$_GET['tab']              = 'identities';
		$GLOBALS['_wpdb_get_var'] = 0;

		ob_start();
		require WP_SAM_DIR . 'includes/admin/views/page-intelligence.php';
		$output = (string) ob_get_clean();

		unset( $_GET['tab'] );

		$this->assertStringContainsString( 'No identities recorded yet.', $output );
		$this->assertStringNotContainsString( 'tablenav-pages', $output );
	}

	// ── Vendors tab ──────────────────────────────────────────────────────────────

	public function test_vendors_tab_shows_an_edit_link_for_a_builtin_vendor_but_no_delete(): void {
		$_GET['tab']                   = 'vendors';
		$GLOBALS['_wpdb_get_results'] = array( $this->vendor_row( array( 'vendor_key' => 'googlebot', 'vendor_name' => 'Googlebot', 'is_builtin' => 1 ) ) );

		ob_start();
		require WP_SAM_DIR . 'includes/admin/views/page-intelligence.php';
		$output = (string) ob_get_clean();

		unset( $_GET['tab'] );

		$this->assertStringContainsString( 'Googlebot', $output );
		$this->assertStringContainsString( 'edit=googlebot', $output );
		$this->assertStringNotContainsString( 'wp_sam_scanner_vendor_delete', $output );
	}

	public function test_vendors_tab_shows_edit_and_delete_for_a_custom_vendor(): void {
		$_GET['tab']                   = 'vendors';
		$GLOBALS['_wpdb_get_results'] = array( $this->vendor_row( array( 'vendor_key' => 'qualys', 'vendor_name' => 'Qualys', 'is_builtin' => 0 ) ) );

		ob_start();
		require WP_SAM_DIR . 'includes/admin/views/page-intelligence.php';
		$output = (string) ob_get_clean();

		unset( $_GET['tab'] );

		$this->assertStringContainsString( 'edit=qualys', $output );
		$this->assertStringContainsString( 'wp_sam_scanner_vendor_delete', $output );
	}

	public function test_vendors_tab_prefills_the_form_when_editing(): void {
		$_GET['tab']  = 'vendors';
		$_GET['edit'] = 'googlebot';
		$GLOBALS['_wpdb_get_results'] = array();
		$GLOBALS['_wpdb_get_row']     = $this->vendor_row(
			array(
				'vendor_key'  => 'googlebot',
				'vendor_name' => 'Googlebot',
				'is_builtin'  => 1,
				'notes'       => 'Seeded on activation.',
			)
		);

		ob_start();
		require WP_SAM_DIR . 'includes/admin/views/page-intelligence.php';
		$output = (string) ob_get_clean();

		unset( $_GET['tab'], $_GET['edit'] );

		$this->assertStringContainsString( 'Edit vendor: Googlebot', $output );
		$this->assertStringContainsString( 'value="Googlebot"', $output );
		$this->assertStringContainsString( 'Seeded on activation.', $output );
		$this->assertStringContainsString( 'Delete and re-add under a new key instead.', $output );
	}

	// ── Fixtures ─────────────────────────────────────────────────────────────────

	/** @param array<string, mixed> $overrides */
	private function vendor_row( array $overrides = array() ): array {
		return array_merge(
			array(
				'vendor_key'           => 'googlebot',
				'vendor_name'          => 'Googlebot',
				'category'             => 'known_crawler',
				'ua_pattern'           => 'Googlebot',
				'rdns_suffixes'        => '["googlebot.com"]',
				'cidr_ranges'          => '[]',
				'source_url'           => 'https://example.test/verify',
				'verification_method'  => 'fcrdns',
				'notes'                => '',
				'is_builtin'           => 1,
			),
			$overrides
		);
	}

	/** @return array<int, array<string, mixed>> */
	private function event_rows( int $count ): array {
		$rows = array();
		for ( $i = 1; $i <= $count; $i++ ) {
			$rows[] = array(
				'surface'          => 'frontend',
				'detector_id'      => 'sqli_probe',
				'detector_family'  => 'injection',
				'severity'         => 'high',
				'occurrence_count' => 1,
				'first_seen_at'    => '2026-01-01 00:00:00',
				'last_seen_at'     => '2026-01-02 00:00:00',
				'detail'           => '',
			);
		}
		return $rows;
	}

	/** @return array<int, array<string, mixed>> */
	private function identity_rows( int $count ): array {
		$rows = array();
		for ( $i = 1; $i <= $count; $i++ ) {
			$rows[] = array(
				'id'                  => $i,
				'vendor_key'          => '',
				'verification_state'  => 'unknown',
				'ip'                  => "203.0.113.{$i}",
				'surface'             => 'frontend',
				'claimed_identity'    => '',
				'occurrence_count'    => 1,
				'last_seen_at'        => '2026-01-01 00:00:00',
				'recent_paths'        => '',
			);
		}
		return $rows;
	}
}
