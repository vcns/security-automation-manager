<?php
/**
 * Unit tests for WP_SAM\Intelligence\Ip_Rule_Store.
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;
use WP_SAM\Intelligence\Ip_Rule_Store;

class IpRuleStoreTest extends TestCase {

	private Ip_Rule_Store $store;

	protected function setUp(): void {
		wp_test_reset_globals();
		$this->store = new Ip_Rule_Store();
	}

	private function rule( array $overrides = array() ): array {
		return array_merge(
			array(
				'id'         => 1,
				'list_type'  => 'block',
				'cidr'       => '203.0.113.0/24',
				'surface'    => '',
				'reason'     => 'test',
				'created_by' => 1,
				'created_at' => '2026-09-02 00:00:00',
				'expires_at' => null,
			),
			$overrides
		);
	}

	public function test_add_rejects_an_invalid_list_type(): void {
		$this->assertFalse( $this->store->add( 'quarantine', '203.0.113.1', '', 'x', 1 ) );
	}

	public function test_add_rejects_an_empty_cidr(): void {
		$this->assertFalse( $this->store->add( 'block', '', '', 'x', 1 ) );
	}

	public function test_add_inserts_a_rule_with_an_expiry(): void {
		$ok = $this->store->add( 'block', '203.0.113.1', 'login', 'brute force', 5, 3600 );

		$this->assertTrue( $ok );
		$this->assertCount( 1, $GLOBALS['_wpdb_inserted_rows'] );
		$inserted = $GLOBALS['_wpdb_inserted_rows'][0]['data'];
		$this->assertSame( 'block', $inserted['list_type'] );
		$this->assertSame( 5, $inserted['created_by'] );
		$this->assertNotNull( $inserted['expires_at'] );
	}

	public function test_add_without_expiry_leaves_it_null(): void {
		$this->store->add( 'allow', '203.0.113.1', '', 'x', 1 );

		$this->assertNull( $GLOBALS['_wpdb_inserted_rows'][0]['data']['expires_at'] );
	}

	public function test_delete_removes_by_id(): void {
		$ok = $this->store->delete( 42 );

		$this->assertTrue( $ok );
		$this->assertCount( 1, $GLOBALS['_wpdb_queries'] );
		$this->assertStringContainsString( 'DELETE FROM', $GLOBALS['_wpdb_queries'][0] );
		$this->assertStringContainsString( '42', $GLOBALS['_wpdb_queries'][0] );
	}

	public function test_match_returns_null_when_no_rule_matches(): void {
		$GLOBALS['_wpdb_get_results'] = array( $this->rule( array( 'cidr' => '198.51.100.0/24' ) ) );

		$this->assertNull( $this->store->match( '203.0.113.42', 'frontend' ) );
	}

	public function test_match_finds_a_block_rule_covering_the_ip(): void {
		$GLOBALS['_wpdb_get_results'] = array( $this->rule() );

		$match = $this->store->match( '203.0.113.42', 'frontend' );

		$this->assertNotNull( $match );
		$this->assertSame( 'block', $match['list_type'] );
	}

	public function test_match_accepts_a_bare_ip_as_an_exact_match_shorthand(): void {
		$GLOBALS['_wpdb_get_results'] = array( $this->rule( array( 'cidr' => '203.0.113.42' ) ) );

		$this->assertNotNull( $this->store->match( '203.0.113.42', 'frontend' ) );
		$this->assertNull( $this->store->match( '203.0.113.43', 'frontend' ) );
	}

	public function test_match_respects_surface_scoping(): void {
		$GLOBALS['_wpdb_get_results'] = array( $this->rule( array( 'surface' => 'login' ) ) );

		$this->assertNull( $this->store->match( '203.0.113.42', 'frontend' ) );
		$this->assertNotNull( $this->store->match( '203.0.113.42', 'login' ) );
	}

	public function test_match_ignores_an_expired_rule(): void {
		$GLOBALS['_wpdb_get_results'] = array( $this->rule( array( 'expires_at' => '2000-01-01 00:00:00' ) ) );

		$this->assertNull( $this->store->match( '203.0.113.42', 'frontend' ) );
	}

	public function test_match_honours_a_future_expiry(): void {
		$GLOBALS['_wpdb_get_results'] = array( $this->rule( array( 'expires_at' => '2999-01-01 00:00:00' ) ) );

		$this->assertNotNull( $this->store->match( '203.0.113.42', 'frontend' ) );
	}

	public function test_match_prefers_a_block_rule_over_an_overlapping_allow_rule(): void {
		$GLOBALS['_wpdb_get_results'] = array(
			$this->rule( array( 'id' => 1, 'list_type' => 'allow', 'cidr' => '203.0.113.0/24' ) ),
			$this->rule( array( 'id' => 2, 'list_type' => 'block', 'cidr' => '203.0.113.42' ) ),
		);

		$match = $this->store->match( '203.0.113.42', 'frontend' );

		$this->assertSame( 'block', $match['list_type'] );
	}
}
