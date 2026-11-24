<?php
/**
 * Unit tests for WP_SAM\Intelligence\Network_Rule_Hit_Store: the per-day,
 * per-rule, per-address count of requests an ASN/country rule blocked.
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;
use WP_SAM\Intelligence\Network_Rule_Hit_Store;

class NetworkRuleHitStoreTest extends TestCase {

	private Network_Rule_Hit_Store $store;

	protected function setUp(): void {
		wp_test_reset_globals();
		$this->store = new Network_Rule_Hit_Store();
	}

	private function last_query(): string {
		$queries = $GLOBALS['_wpdb_queries'] ?? array();
		return (string) end( $queries );
	}

	public function test_record_upserts_one_row_per_day_rule_and_address(): void {
		$this->store->record( array( 'rule_type' => 'country', 'value' => 'CN' ), '198.51.100.9', 'frontend', '/contact' );

		$sql = $this->last_query();
		$this->assertStringStartsWith( 'INSERT INTO wp_sam_network_rule_hits', $sql );
		$this->assertStringContainsString( "VALUES ('" . gmdate( 'Y-m-d' ) . "', 'country', 'CN', '198.51.100.9', 'frontend', '/contact', 1,", $sql );
		$this->assertStringContainsString( "ON DUPLICATE KEY UPDATE hit_count = hit_count + 1, surface = 'frontend', last_path = '/contact'", $sql );
	}

	public function test_record_stores_the_home_page_as_a_slash_and_caps_long_paths(): void {
		$this->store->record( array( 'rule_type' => 'country', 'value' => 'CN' ), '198.51.100.9', 'frontend', '' );
		$this->assertStringContainsString( "'frontend', '/', 1,", $this->last_query() );

		$this->store->record( array( 'rule_type' => 'country', 'value' => 'CN' ), '198.51.100.9', 'frontend', '/' . str_repeat( 'a', 400 ) );
		$this->assertStringContainsString( "'/" . str_repeat( 'a', 254 ) . "', 1,", $this->last_query() );
		$this->assertStringNotContainsString( str_repeat( 'a', 255 ), $this->last_query() );
	}

	public function test_record_ignores_an_incomplete_rule_or_a_missing_address(): void {
		$this->store->record( array( 'rule_type' => 'country' ), '198.51.100.9', 'frontend', '/' );
		$this->store->record( array( 'rule_type' => 'country', 'value' => 'CN' ), '', 'frontend', '/' );

		$this->assertSame( array(), $GLOBALS['_wpdb_queries'] ?? array() );
	}

	public function test_summary_groups_by_rule_value_over_the_last_seven_days(): void {
		$GLOBALS['_wpdb_get_results'] = array(
			array( 'rule_value' => 'CN', 'requests' => '120', 'addresses' => '14', 'last_seen_at' => '2026-11-24 09:00:00' ),
			array( 'rule_value' => 'RU', 'requests' => '7', 'addresses' => '2', 'last_seen_at' => '2026-11-23 18:30:00' ),
		);

		$summary = $this->store->summary( 'country' );

		$sql = (string) $GLOBALS['_wpdb_last_get_results_query'];
		$this->assertStringContainsString( "WHERE rule_type = 'country' AND hit_date >= '" . gmdate( 'Y-m-d', time() - 6 * DAY_IN_SECONDS ) . "'", $sql );
		$this->assertStringContainsString( 'GROUP BY rule_value ORDER BY requests DESC', $sql );
		$this->assertSame(
			array( 'rule_value' => 'CN', 'requests' => 120, 'addresses' => 14, 'last_seen_at' => '2026-11-24 09:00:00' ),
			$summary[0]
		);
		$this->assertCount( 2, $summary );
	}

	public function test_recent_lists_latest_blocked_addresses_first(): void {
		$GLOBALS['_wpdb_get_results'] = array(
			array( 'rule_value' => 'CN', 'ip' => '198.51.100.9', 'surface' => 'login', 'last_path' => '/wp-login.php', 'hit_count' => '3', 'last_seen_at' => '2026-11-24 09:00:00' ),
		);

		$recent = $this->store->recent( 'country', 20 );

		$this->assertStringContainsString( "WHERE rule_type = 'country' ORDER BY last_seen_at DESC LIMIT 20", (string) $GLOBALS['_wpdb_last_get_results_query'] );
		$this->assertSame( 3, $recent[0]['hit_count'] );
		$this->assertSame( '/wp-login.php', $recent[0]['last_path'] );
	}

	public function test_totals_are_keyed_by_rule_type_and_value(): void {
		$GLOBALS['_wpdb_get_results'] = array(
			array( 'rule_type' => 'country', 'rule_value' => 'CN', 'requests' => '120' ),
			array( 'rule_type' => 'asn', 'rule_value' => '15169', 'requests' => '4' ),
		);

		$this->assertSame( array( 'country:CN' => 120, 'asn:15169' => 4 ), $this->store->totals() );
	}

	public function test_purge_deletes_rows_older_than_the_retention_window(): void {
		$this->store->purge_older_than( 90 );

		$this->assertSame(
			'DELETE FROM wp_sam_network_rule_hits WHERE last_seen_at < DATE_SUB(UTC_TIMESTAMP(), INTERVAL 90 DAY)',
			$this->last_query()
		);
	}

	public function test_purge_keeps_everything_when_retention_is_zero(): void {
		$this->assertSame( 0, $this->store->purge_older_than( 0 ) );
		$this->assertSame( array(), $GLOBALS['_wpdb_queries'] ?? array() );
	}
}
