<?php
/**
 * Unit tests for WP_SAM\CSP\Wpdb_Policy_Data_Loader -- Policy_Builder's
 * default Policy_Data_Loader collaborator (GitHub issue #170). This is
 * where direct DB-query-shape coverage for policy input now lives, moved
 * out of PolicyBuilderTest.php now that Policy_Builder no longer performs
 * these queries itself.
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;
use WP_SAM\CSP\Wpdb_Policy_Data_Loader;

class WpdbPolicyDataLoaderTest extends TestCase {

	private Wpdb_Policy_Data_Loader $loader;

	protected function setUp(): void {
		wp_test_reset_globals();
		$this->loader = new Wpdb_Policy_Data_Loader();
	}

	public function test_load_profile_returns_the_stored_row(): void {
		$GLOBALS['_wpdb_get_row'] = array( 'surface' => 'frontend', 'mode' => 'enforce' );

		$this->assertSame( $GLOBALS['_wpdb_get_row'], $this->loader->load_profile( 'frontend' ) );
	}

	public function test_load_profile_returns_null_when_no_row_found(): void {
		$GLOBALS['_wpdb_get_row'] = null;

		$this->assertNull( $this->loader->load_profile( 'frontend' ) );
	}

	public function test_load_approved_hashes_returns_the_stored_rows(): void {
		$rows                            = array( array( 'directive' => 'script-src', 'hash_algo' => 'sha256', 'hash_value' => 'abc==' ) );
		$GLOBALS['_wpdb_get_results']     = $rows;

		$this->assertSame( $rows, $this->loader->load_approved_hashes( 'frontend' ) );
	}

	public function test_load_approved_hashes_returns_empty_array_when_none_found(): void {
		$GLOBALS['_wpdb_get_results'] = array();

		$this->assertSame( array(), $this->loader->load_approved_hashes( 'frontend' ) );
	}

	/**
	 * Regression test for a production bug (2026-08-19): ORDER BY
	 * last_seen_at DESC alone leaves ties (very common -- last_seen_at is
	 * a datetime column, one-second resolution, and many hashes get
	 * bumped by the same page render) in SQL-unspecified order, so the
	 * same ~1,027-row backlog produced a "Dropped 34" cutoff on one
	 * request and "Dropped 985" moments later on another. The query must
	 * always include a deterministic tiebreaker.
	 */
	public function test_load_approved_hashes_orders_deterministically_on_tied_timestamps(): void {
		$this->loader->load_approved_hashes( 'frontend' );

		$query = $GLOBALS['_wpdb_last_get_results_query'] ?? '';
		$this->assertStringContainsString( 'ORDER BY last_seen_at DESC, id DESC', $query );
	}

	public function test_load_approved_hashes_filters_to_active_status(): void {
		$this->loader->load_approved_hashes( 'frontend' );

		$query = $GLOBALS['_wpdb_last_get_results_query'] ?? '';
		$this->assertStringContainsString( "status = 'active'", $query );
	}

	public function test_load_approved_sources_returns_the_stored_rows(): void {
		$rows                        = array( array( 'directive' => 'script-src', 'source_host' => 'cdn.example.com', 'source_scheme' => 'https' ) );
		$GLOBALS['_wpdb_get_results'] = $rows;

		$this->assertSame( $rows, $this->loader->load_approved_sources( 'frontend' ) );
	}

	public function test_load_approved_sources_returns_empty_array_when_none_found(): void {
		$GLOBALS['_wpdb_get_results'] = array();

		$this->assertSame( array(), $this->loader->load_approved_sources( 'frontend' ) );
	}

	public function test_load_approved_sources_filters_to_approved_state(): void {
		$this->loader->load_approved_sources( 'frontend' );

		$query = $GLOBALS['_wpdb_last_get_results_query'] ?? '';
		$this->assertStringContainsString( "approval_state = 'approved'", $query );
	}
}
