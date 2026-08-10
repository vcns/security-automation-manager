<?php
/**
 * Unit tests for WP_SAM\Admin\Table_Query.
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;
use WP_SAM\Admin\Table_Query;

class TableQueryTest extends TestCase {

	protected function setUp(): void {
		wp_test_reset_globals();
	}

	private function whitelist(): array {
		return array(
			'last_seen' => array(
				'expr'        => 'reported_at',
				'default_dir' => 'desc',
			),
			'host'      => array(
				'expr'        => 'source_host',
				'default_dir' => 'asc',
			),
		);
	}

	// ── resolve_sort() ──────────────────────────────────────────────────────────

	public function test_resolve_sort_falls_back_to_default_for_unknown_key(): void {
		$resolved = Table_Query::resolve_sort( $this->whitelist(), 'last_seen', 'not_a_real_column', 'asc' );

		$this->assertSame( 'last_seen', $resolved['key'] );
		$this->assertSame( 'reported_at', $resolved['expr'] );
	}

	public function test_resolve_sort_falls_back_to_default_when_sort_is_null(): void {
		$resolved = Table_Query::resolve_sort( $this->whitelist(), 'last_seen', null, null );

		$this->assertSame( 'last_seen', $resolved['key'] );
		$this->assertSame( 'DESC', $resolved['dir'] );
	}

	public function test_resolve_sort_uses_requested_column_default_direction_when_dir_omitted(): void {
		$resolved = Table_Query::resolve_sort( $this->whitelist(), 'last_seen', 'host', null );

		$this->assertSame( 'host', $resolved['key'] );
		$this->assertSame( 'ASC', $resolved['dir'] );
	}

	public function test_resolve_sort_rejects_invalid_direction(): void {
		$resolved = Table_Query::resolve_sort( $this->whitelist(), 'last_seen', 'host', 'sideways' );

		$this->assertSame( 'ASC', $resolved['dir'] );
	}

	public function test_resolve_sort_never_leaks_raw_get_value_into_expr(): void {
		// The SQL expression must always be the whitelist literal, never derived
		// from the (attacker-controlled) $raw_sort string -- this is the entire
		// injection defense for ORDER BY.
		$resolved = Table_Query::resolve_sort( $this->whitelist(), 'last_seen', "host'; DROP TABLE wp_users; --", 'asc' );

		$this->assertSame( 'last_seen', $resolved['key'] );
		$this->assertSame( 'reported_at', $resolved['expr'] );
	}

	public function test_order_by_sql_returns_expected_clause_string(): void {
		$resolved = Table_Query::resolve_sort( $this->whitelist(), 'last_seen', 'host', 'asc' );

		$this->assertSame( 'ORDER BY source_host ASC', Table_Query::order_by_sql( $resolved ) );
	}

	// ── multi_select_where() ────────────────────────────────────────────────────

	public function test_multi_select_where_returns_null_for_empty_array(): void {
		$this->assertNull( Table_Query::multi_select_where( 'surface', array() ) );
	}

	public function test_multi_select_where_returns_in_clause_fragment(): void {
		$fragment = Table_Query::multi_select_where( 'surface', array( 'frontend', 'admin' ) );

		$this->assertSame( 'surface IN (%s,%s)', $fragment['sql'] );
		$this->assertSame( array( 'frontend', 'admin' ), $fragment['args'] );
	}

	public function test_multi_select_where_caps_at_fifty_values(): void {
		$values   = array_map( static fn( int $i ): string => "v{$i}", range( 1, 80 ) );
		$fragment = Table_Query::multi_select_where( 'directive', $values );

		$this->assertCount( 50, $fragment['args'] );
	}

	public function test_multi_select_where_deduplicates(): void {
		$fragment = Table_Query::multi_select_where( 'surface', array( 'frontend', 'frontend', 'admin' ) );

		$this->assertCount( 2, $fragment['args'] );
	}

	// ── equals_where() ──────────────────────────────────────────────────────────

	public function test_equals_where_returns_null_for_blank_value(): void {
		$this->assertNull( Table_Query::equals_where( 'surface', '  ' ) );
	}

	public function test_equals_where_builds_fragment(): void {
		$fragment = Table_Query::equals_where( 'surface', 'frontend' );

		$this->assertSame( 'surface = %s', $fragment['sql'] );
		$this->assertSame( array( 'frontend' ), $fragment['args'] );
	}

	// ── like_where() ─────────────────────────────────────────────────────────────

	public function test_like_where_returns_null_for_blank_term(): void {
		$this->assertNull( Table_Query::like_where( $GLOBALS['wpdb'], 'source_host', '   ' ) );
	}

	public function test_like_where_escapes_wildcards_via_esc_like(): void {
		$fragment = Table_Query::like_where( $GLOBALS['wpdb'], 'blocked_uri', '100%_off' );

		$this->assertSame( 'blocked_uri LIKE %s', $fragment['sql'] );
		$this->assertSame( '%100\%\_off%', $fragment['args'][0] );
	}

	// ── numeric_gte_where() ──────────────────────────────────────────────────────

	public function test_numeric_gte_where_returns_null_when_absent(): void {
		$this->assertNull( Table_Query::numeric_gte_where( 'occurrence_count', null ) );
	}

	public function test_numeric_gte_where_builds_fragment(): void {
		$fragment = Table_Query::numeric_gte_where( 'occurrence_count', 5 );

		$this->assertSame( 'occurrence_count >= %d', $fragment['sql'] );
		$this->assertSame( array( 5 ), $fragment['args'] );
	}

	// ── date_range_where() ───────────────────────────────────────────────────────

	public function test_date_range_where_returns_null_when_both_blank(): void {
		$this->assertNull( Table_Query::date_range_where( 'reported_at', '', '' ) );
	}

	public function test_date_range_where_rejects_malformed_dates(): void {
		$this->assertNull( Table_Query::date_range_where( 'reported_at', 'not-a-date', '' ) );
	}

	public function test_date_range_where_returns_both_bound_fragments(): void {
		$fragment = Table_Query::date_range_where( 'reported_at', '2026-01-01', '2026-01-31' );

		$this->assertSame( 'reported_at >= %s AND reported_at <= %s', $fragment['sql'] );
		$this->assertSame( array( '2026-01-01 00:00:00', '2026-01-31 23:59:59' ), $fragment['args'] );
	}

	public function test_date_range_where_builds_single_bound(): void {
		$fragment = Table_Query::date_range_where( 'reported_at', '2026-01-01', '' );

		$this->assertSame( 'reported_at >= %s', $fragment['sql'] );
		$this->assertSame( array( '2026-01-01 00:00:00' ), $fragment['args'] );
	}

	public function test_date_range_where_accepts_datetime_local_format(): void {
		$fragment = Table_Query::date_range_where( 'reported_at', '2026-01-01T09:30', '2026-01-31T17:45' );

		$this->assertSame( array( '2026-01-01 09:30:00', '2026-01-31 17:45:00' ), $fragment['args'] );
	}

	public function test_date_range_where_accepts_mixed_date_and_datetime_bounds(): void {
		$fragment = Table_Query::date_range_where( 'reported_at', '2026-01-01', '2026-01-31T17:45' );

		$this->assertSame( array( '2026-01-01 00:00:00', '2026-01-31 17:45:00' ), $fragment['args'] );
	}

	public function test_date_range_where_rejects_malformed_datetime(): void {
		$this->assertNull( Table_Query::date_range_where( 'reported_at', '2026-01-01T9:3', '' ) );
	}

	// ── multi_param() / text_param() / int_param() ──────────────────────────────

	public function test_multi_param_reads_array_and_drops_blanks(): void {
		$_GET['v_surface'] = array( 'frontend', '', 'admin' );

		$this->assertSame( array( 'frontend', 'admin' ), Table_Query::multi_param( 'v_surface' ) );

		unset( $_GET['v_surface'] );
	}

	public function test_multi_param_returns_empty_array_when_absent(): void {
		$this->assertSame( array(), Table_Query::multi_param( 'nope' ) );
	}

	public function test_int_param_returns_null_when_blank(): void {
		$_GET['v_occ_min'] = '';
		$this->assertNull( Table_Query::int_param( 'v_occ_min' ) );
		unset( $_GET['v_occ_min'] );
	}

	public function test_int_param_casts_value(): void {
		$_GET['v_occ_min'] = '7';
		$this->assertSame( 7, Table_Query::int_param( 'v_occ_min' ) );
		unset( $_GET['v_occ_min'] );
	}

	// ── sort_header() ────────────────────────────────────────────────────────────

	public function test_sort_header_flips_direction_on_active_column(): void {
		$resolved = Table_Query::resolve_sort( $this->whitelist(), 'last_seen', 'last_seen', 'desc' );

		$html = Table_Query::sort_header( 'Last Seen', 'last_seen', $this->whitelist(), $resolved, array( 'tab' => 'violations' ), 'https://example.com/wp-admin/admin.php', 'v_paged' );

		$this->assertStringContainsString( 'dir=asc', $html );
		$this->assertStringContainsString( 'dashicons-arrow-down-alt2', $html );
	}

	public function test_sort_header_uses_column_default_direction_when_switching_columns(): void {
		$resolved = Table_Query::resolve_sort( $this->whitelist(), 'last_seen', 'last_seen', 'desc' );

		$html = Table_Query::sort_header( 'Host', 'host', $this->whitelist(), $resolved, array( 'tab' => 'violations' ), 'https://example.com/wp-admin/admin.php', 'v_paged' );

		$this->assertStringContainsString( 'dir=asc', $html );
		$this->assertStringNotContainsString( 'dashicons-arrow', $html );
	}

	public function test_sort_header_resets_page_to_one(): void {
		$resolved = Table_Query::resolve_sort( $this->whitelist(), 'last_seen', 'last_seen', 'desc' );

		$html = Table_Query::sort_header( 'Host', 'host', $this->whitelist(), $resolved, array( 'tab' => 'violations', 'v_paged' => 4 ), 'https://example.com/wp-admin/admin.php', 'v_paged' );

		$this->assertStringContainsString( 'v_paged=1', $html );
	}

	// ── pagination() ─────────────────────────────────────────────────────────────

	public function test_pagination_renders_nothing_for_single_page(): void {
		$this->assertSame( '', Table_Query::pagination( 1, 1, array(), 'https://example.com/wp-admin/admin.php' ) );
	}

	public function test_pagination_omits_previous_on_first_page(): void {
		$html = Table_Query::pagination( 1, 3, array( 'tab' => 'violations' ), 'https://example.com/wp-admin/admin.php', 'v_paged' );

		$this->assertStringNotContainsString( 'Previous', $html );
		$this->assertStringContainsString( 'Next', $html );
		$this->assertStringContainsString( 'v_paged=2', $html );
	}

	public function test_pagination_omits_next_on_last_page(): void {
		$html = Table_Query::pagination( 3, 3, array( 'tab' => 'violations' ), 'https://example.com/wp-admin/admin.php', 'v_paged' );

		$this->assertStringContainsString( 'Previous', $html );
		$this->assertStringNotContainsString( 'Next', $html );
		$this->assertStringContainsString( 'v_paged=2', $html );
	}
}
