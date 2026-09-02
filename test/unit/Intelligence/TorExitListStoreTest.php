<?php
/**
 * Unit tests for WP_SAM\Intelligence\Tor_Exit_List_Store.
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;
use WP_SAM\Intelligence\Tor_Exit_List_Store;

class TorExitListStoreTest extends TestCase {

	private Tor_Exit_List_Store $store;

	protected function setUp(): void {
		wp_test_reset_globals();
		$this->store = new Tor_Exit_List_Store();
	}

	private function plausible_ip_list( int $count ): string {
		$lines = array();
		for ( $i = 0; $i < $count; $i++ ) {
			$lines[] = sprintf( '203.0.%d.%d', intdiv( $i, 256 ), $i % 256 );
		}
		return implode( "\n", $lines );
	}

	public function test_is_exit_node_returns_false_for_empty_ip(): void {
		$this->assertFalse( $this->store->is_exit_node( '' ) );
	}

	public function test_is_exit_node_returns_true_when_found(): void {
		$GLOBALS['_wpdb_get_var'] = '1';

		$this->assertTrue( $this->store->is_exit_node( '203.0.113.42' ) );
	}

	public function test_is_exit_node_returns_false_when_not_found(): void {
		$GLOBALS['_wpdb_get_var'] = null;

		$this->assertFalse( $this->store->is_exit_node( '203.0.113.42' ) );
	}

	public function test_count_reads_from_the_table(): void {
		$GLOBALS['_wpdb_get_var'] = 1500;

		$this->assertSame( 1500, $this->store->count() );
	}

	public function test_last_refreshed_at_returns_null_when_never_run(): void {
		$this->assertNull( $this->store->last_refreshed_at() );
	}

	public function test_last_refreshed_at_reads_the_option(): void {
		$GLOBALS['_wp_options']['wp_sam_tor_list_refreshed_at'] = '2026-09-02 12:00:00';

		$this->assertSame( '2026-09-02 12:00:00', $this->store->last_refreshed_at() );
	}

	public function test_refresh_rejects_a_wp_error_response(): void {
		$GLOBALS['_wp_remote_get_response'] = new WP_Error( 'http_request_failed', 'Could not resolve host' );

		$result = $this->store->refresh();

		$this->assertSame( 'failed', $result['status'] );
		$this->assertStringContainsString( 'Could not resolve host', $result['message'] );
		$this->assertSame( 'failed', get_option( 'wp_sam_tor_list_last_fetch_status' ) );
	}

	public function test_refresh_rejects_a_non_200_response(): void {
		$GLOBALS['_wp_remote_get_response'] = array(
			'response' => array( 'code' => 503 ),
			'body'     => '',
		);

		$result = $this->store->refresh();

		$this->assertSame( 'failed', $result['status'] );
		$this->assertStringContainsString( '503', $result['message'] );
	}

	public function test_refresh_rejects_a_suspiciously_small_list(): void {
		$GLOBALS['_wp_remote_get_response'] = array(
			'response' => array( 'code' => 200 ),
			'body'     => $this->plausible_ip_list( 5 ),
		);

		$result = $this->store->refresh();

		$this->assertSame( 'failed', $result['status'] );
		$this->assertStringContainsString( 'truncated', $result['message'] );
	}

	public function test_refresh_never_truncates_the_table_on_failure(): void {
		$GLOBALS['_wp_remote_get_response'] = new WP_Error( 'http_request_failed', 'timeout' );

		$this->store->refresh();

		// get_var() (used by count() in the failure path) never touches
		// _wpdb_queries -- only mutating calls (query/insert/update) do, so
		// an empty list here is a direct proof no TRUNCATE/INSERT ran.
		$this->assertSame( array(), $GLOBALS['_wpdb_queries'] ?? array() );
	}

	public function test_refresh_replaces_the_table_on_a_plausible_response(): void {
		$GLOBALS['_wp_remote_get_response'] = array(
			'response' => array( 'code' => 200 ),
			'body'     => $this->plausible_ip_list( 150 ),
		);

		$result = $this->store->refresh();

		$this->assertSame( 'refreshed', $result['status'] );
		$this->assertSame( 150, $result['count'] );
		$this->assertTrue(
			(bool) array_filter(
				$GLOBALS['_wpdb_queries'] ?? array(),
				static fn( string $q ): bool => str_contains( $q, 'TRUNCATE' )
			)
		);
		$this->assertSame( 'success', get_option( 'wp_sam_tor_list_last_fetch_status' ) );
		$this->assertNotEmpty( get_option( 'wp_sam_tor_list_refreshed_at' ) );
	}

	public function test_refresh_ignores_comment_lines_and_blank_lines(): void {
		$body = "# comment\n\n" . $this->plausible_ip_list( 120 ) . "\n\n# trailing comment\n";
		$GLOBALS['_wp_remote_get_response'] = array(
			'response' => array( 'code' => 200 ),
			'body'     => $body,
		);

		$result = $this->store->refresh();

		$this->assertSame( 'refreshed', $result['status'] );
		$this->assertSame( 120, $result['count'] );
	}

	public function test_refresh_ignores_malformed_lines(): void {
		$body = $this->plausible_ip_list( 120 ) . "\nnot-an-ip\n999.999.999.999\n";
		$GLOBALS['_wp_remote_get_response'] = array(
			'response' => array( 'code' => 200 ),
			'body'     => $body,
		);

		$result = $this->store->refresh();

		$this->assertSame( 120, $result['count'] );
	}

	public function test_refresh_uses_the_configured_user_agent_convention(): void {
		$GLOBALS['_wp_remote_get_response'] = array(
			'response' => array( 'code' => 200 ),
			'body'     => $this->plausible_ip_list( 120 ),
		);

		$this->store->refresh();

		$request = $GLOBALS['_wp_remote_get_requests'][0];
		$this->assertStringContainsString( 'torbulkexitlist', $request['url'] );
		$this->assertStringContainsString( 'VCNS-Security-Automation-Manager', $request['args']['user-agent'] );
	}
}
