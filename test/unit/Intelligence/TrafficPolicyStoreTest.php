<?php
/**
 * Unit tests for WP_SAM\Intelligence\Traffic_Policy_Store.
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;
use WP_SAM\Intelligence\Traffic_Policy_Store;

class TrafficPolicyStoreTest extends TestCase {

	private Traffic_Policy_Store $store;

	protected function setUp(): void {
		wp_test_reset_globals();
		$this->store = new Traffic_Policy_Store();
	}

	public function test_get_returns_null_when_no_row_exists(): void {
		$GLOBALS['_wpdb_get_row'] = null;

		$this->assertNull( $this->store->get( 'frontend' ) );
	}

	public function test_is_enforcing_false_when_no_policy_row_exists(): void {
		$GLOBALS['_wpdb_get_row'] = null;

		$this->assertFalse( $this->store->is_enforcing( 'frontend' ) );
	}

	public function test_is_enforcing_false_in_observe_mode(): void {
		$GLOBALS['_wpdb_get_row'] = array( 'surface' => 'frontend', 'mode' => 'observe' );

		$this->assertFalse( $this->store->is_enforcing( 'frontend' ) );
	}

	public function test_is_enforcing_true_in_enforce_mode(): void {
		$GLOBALS['_wpdb_get_row'] = array( 'surface' => 'frontend', 'mode' => 'enforce' );

		$this->assertTrue( $this->store->is_enforcing( 'frontend' ) );
	}

	public function test_update_rejects_an_unknown_surface(): void {
		$this->assertFalse( $this->store->update( 'not-a-surface', 'enforce', 100, 60, 10, 900 ) );
	}

	public function test_update_rejects_an_unknown_mode(): void {
		$this->assertFalse( $this->store->update( 'frontend', 'block-everything', 100, 60, 10, 900 ) );
	}

	public function test_update_writes_sanitised_values(): void {
		$ok = $this->store->update( 'login', 'enforce', 20, 60, 10, 900 );

		$this->assertTrue( $ok );
		$row = $GLOBALS['_wpdb_updated_rows'][0];
		$this->assertSame( array( 'surface' => 'login' ), $row['where'] );
		$this->assertSame( 'enforce', $row['data']['mode'] );
		$this->assertSame( 20, $row['data']['rate_limit_max_requests'] );
	}

	public function test_update_floors_thresholds_at_one(): void {
		$this->store->update( 'frontend', 'observe', 0, -5, 0, 0 );

		$row = $GLOBALS['_wpdb_updated_rows'][0]['data'];
		$this->assertSame( 1, $row['rate_limit_max_requests'] );
		$this->assertSame( 1, $row['rate_limit_window_seconds'] );
		$this->assertSame( 1, $row['login_max_failed_attempts'] );
		$this->assertSame( 1, $row['login_lockout_seconds'] );
	}
}
