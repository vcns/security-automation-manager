<?php
/**
 * Unit tests for WP_SAM\Intelligence\Network_Rule_Store.
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;
use WP_SAM\Intelligence\Network_Rule_Store;

class NetworkRuleStoreTest extends TestCase {

	private Network_Rule_Store $store;

	protected function setUp(): void {
		wp_test_reset_globals();
		$this->store = new Network_Rule_Store();
	}

	private function rule( array $overrides = array() ): array {
		return array_merge(
			array(
				'id'         => 1,
				'rule_type'  => 'asn',
				'value'      => '15169',
				'surface'    => '',
				'reason'     => 'test',
				'created_by' => 1,
				'created_at' => '2026-09-02 00:00:00',
			),
			$overrides
		);
	}

	// ── add() ────────────────────────────────────────────────────────────────

	public function test_add_rejects_an_invalid_rule_type(): void {
		$this->assertFalse( $this->store->add( 'city', '15169', '', 'x', 1 ) );
	}

	public function test_add_rejects_an_empty_reason(): void {
		$this->assertFalse( $this->store->add( 'asn', '15169', '', '', 1 ) );
	}

	public function test_add_rejects_a_non_numeric_asn(): void {
		$this->assertFalse( $this->store->add( 'asn', 'not-a-number', '', 'x', 1 ) );
		$this->assertSame( array(), $GLOBALS['_wpdb_inserted_rows'] );
	}

	public function test_add_strips_a_leading_as_prefix_from_an_asn(): void {
		$ok = $this->store->add( 'asn', 'AS15169', '', 'x', 1 );

		$this->assertTrue( $ok );
		$this->assertSame( '15169', $GLOBALS['_wpdb_inserted_rows'][0]['data']['value'] );
	}

	public function test_add_rejects_a_country_code_that_is_not_two_letters(): void {
		$this->assertFalse( $this->store->add( 'country', 'USA', '', 'x', 1 ) );
		$this->assertSame( array(), $GLOBALS['_wpdb_inserted_rows'] );
	}

	public function test_add_uppercases_a_country_code(): void {
		$ok = $this->store->add( 'country', 'cn', '', 'x', 1 );

		$this->assertTrue( $ok );
		$this->assertSame( 'CN', $GLOBALS['_wpdb_inserted_rows'][0]['data']['value'] );
	}

	public function test_add_inserts_a_scoped_rule(): void {
		$ok = $this->store->add( 'asn', '15169', 'login', 'known scraper network', 5 );

		$this->assertTrue( $ok );
		$inserted = $GLOBALS['_wpdb_inserted_rows'][0]['data'];
		$this->assertSame( 'login', $inserted['surface'] );
		$this->assertSame( 5, $inserted['created_by'] );
	}

	// ── delete() ─────────────────────────────────────────────────────────────

	public function test_delete_removes_by_id(): void {
		$ok = $this->store->delete( 42 );

		$this->assertTrue( $ok );
		$this->assertStringContainsString( 'DELETE FROM', $GLOBALS['_wpdb_queries'][0] );
		$this->assertStringContainsString( '42', $GLOBALS['_wpdb_queries'][0] );
	}

	// ── has_any() ────────────────────────────────────────────────────────────

	public function test_has_any_is_false_with_no_rules(): void {
		$this->assertFalse( $this->store->has_any() );
	}

	public function test_has_any_is_true_once_a_rule_exists(): void {
		$GLOBALS['_wpdb_get_var'] = 1;

		$this->assertTrue( $this->store->has_any() );
	}

	// ── match() ──────────────────────────────────────────────────────────────

	public function test_match_returns_null_when_nothing_matches(): void {
		$GLOBALS['_wpdb_get_results'] = array( $this->rule() );

		$this->assertNull( $this->store->match( 64512, null, 'frontend' ) );
	}

	public function test_match_finds_an_asn_rule(): void {
		$GLOBALS['_wpdb_get_results'] = array( $this->rule( array( 'value' => '15169' ) ) );

		$match = $this->store->match( 15169, null, 'frontend' );

		$this->assertNotNull( $match );
		$this->assertSame( 'asn', $match['rule_type'] );
	}

	public function test_match_finds_a_country_rule_case_insensitively(): void {
		$GLOBALS['_wpdb_get_results'] = array( $this->rule( array( 'rule_type' => 'country', 'value' => 'CN' ) ) );

		$this->assertNotNull( $this->store->match( null, 'cn', 'frontend' ) );
	}

	public function test_match_ignores_a_null_asn_against_an_asn_rule(): void {
		$GLOBALS['_wpdb_get_results'] = array( $this->rule( array( 'value' => '15169' ) ) );

		$this->assertNull( $this->store->match( null, null, 'frontend' ) );
	}

	public function test_match_respects_surface_scoping(): void {
		$GLOBALS['_wpdb_get_results'] = array( $this->rule( array( 'surface' => 'login' ) ) );

		$this->assertNull( $this->store->match( 15169, null, 'frontend' ) );
		$this->assertNotNull( $this->store->match( 15169, null, 'login' ) );
	}

	public function test_match_never_matches_an_asn_rule_against_a_country_value(): void {
		// An 'asn' rule must only ever be checked against $asn, never $country,
		// even if the two happen to share a string representation.
		$GLOBALS['_wpdb_get_results'] = array( $this->rule( array( 'rule_type' => 'asn', 'value' => '15169' ) ) );

		$this->assertNull( $this->store->match( null, '15169', 'frontend' ) );
	}
}
