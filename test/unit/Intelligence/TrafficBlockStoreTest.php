<?php
/**
 * Unit tests for WP_SAM\Intelligence\Traffic_Block_Store.
 *
 * record_violation() calls get() twice internally (once to read existing
 * state, once at the end to return the fresh row) -- _wpdb_get_row_queue
 * feeds each call its own canned value.
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;
use WP_SAM\Intelligence\Traffic_Block_Store;

class TrafficBlockStoreTest extends TestCase {

	private Traffic_Block_Store $store;

	protected function setUp(): void {
		wp_test_reset_globals();
		$this->store = new Traffic_Block_Store();
	}

	private function row( array $overrides = array() ): array {
		return array_merge(
			array(
				'id'               => 1,
				'ip'               => '203.0.113.42',
				'surface'          => 'frontend',
				'stage'            => 'warn',
				'reason'           => 'rate_limit',
				'occurrence_count' => 1,
				'blocked_until'    => null,
				'is_persistent'    => 0,
				'fingerprint'      => 'x',
				'first_seen_at'    => '2026-09-02 00:00:00',
				'last_seen_at'     => '2026-09-02 00:00:00',
			),
			$overrides
		);
	}

	public function test_is_blocked_false_when_no_row_exists(): void {
		$GLOBALS['_wpdb_get_row'] = null;

		$this->assertFalse( $this->store->is_blocked( '203.0.113.42', 'frontend' ) );
	}

	public function test_is_blocked_true_when_persistent(): void {
		$GLOBALS['_wpdb_get_row'] = $this->row( array( 'is_persistent' => 1 ) );

		$this->assertTrue( $this->store->is_blocked( '203.0.113.42', 'frontend' ) );
	}

	public function test_is_blocked_true_when_blocked_until_is_in_the_future(): void {
		$GLOBALS['_wpdb_get_row'] = $this->row( array( 'blocked_until' => '2999-01-01 00:00:00' ) );

		$this->assertTrue( $this->store->is_blocked( '203.0.113.42', 'frontend' ) );
	}

	public function test_is_blocked_false_when_blocked_until_has_passed(): void {
		$GLOBALS['_wpdb_get_row'] = $this->row( array( 'blocked_until' => '2000-01-01 00:00:00' ) );

		$this->assertFalse( $this->store->is_blocked( '203.0.113.42', 'frontend' ) );
	}

	public function test_is_blocked_false_for_a_non_blocking_stage_like_warn(): void {
		$GLOBALS['_wpdb_get_row'] = $this->row( array( 'stage' => 'warn', 'blocked_until' => null ) );

		$this->assertFalse( $this->store->is_blocked( '203.0.113.42', 'frontend' ) );
	}

	public function test_record_violation_creates_a_new_row_at_warn_stage(): void {
		$GLOBALS['_wpdb_get_row_queue'] = array( null, $this->row( array( 'stage' => 'warn' ) ) );

		$result = $this->store->record_violation( '203.0.113.42', 'frontend', 'rate_limit' );

		$this->assertCount( 1, $GLOBALS['_wpdb_inserted_rows'] );
		$this->assertSame( 'warn', $GLOBALS['_wpdb_inserted_rows'][0]['data']['stage'] );
		$this->assertNull( $GLOBALS['_wpdb_inserted_rows'][0]['data']['blocked_until'] );
		$this->assertSame( 'warn', $result['stage'] );
	}

	public function test_record_violation_escalates_warn_to_throttle(): void {
		$GLOBALS['_wpdb_get_row_queue'] = array(
			$this->row( array( 'stage' => 'warn' ) ),
			$this->row( array( 'stage' => 'throttle' ) ),
		);

		$this->store->record_violation( '203.0.113.42', 'frontend', 'rate_limit' );

		$this->assertCount( 1, $GLOBALS['_wpdb_updated_rows'] );
		$this->assertSame( 'throttle', $GLOBALS['_wpdb_updated_rows'][0]['data']['stage'] );
		$this->assertNull( $GLOBALS['_wpdb_updated_rows'][0]['data']['blocked_until'] );
	}

	public function test_record_violation_escalates_throttle_to_temporary_block_with_an_expiry(): void {
		$GLOBALS['_wpdb_get_row_queue'] = array(
			$this->row( array( 'stage' => 'throttle' ) ),
			$this->row( array( 'stage' => 'temporary_block' ) ),
		);

		$this->store->record_violation( '203.0.113.42', 'frontend', 'rate_limit' );

		$updated = $GLOBALS['_wpdb_updated_rows'][0]['data'];
		$this->assertSame( 'temporary_block', $updated['stage'] );
		$this->assertNotNull( $updated['blocked_until'] );
	}

	public function test_record_violation_never_escalates_past_extended_block_automatically(): void {
		$GLOBALS['_wpdb_get_row_queue'] = array(
			$this->row( array( 'stage' => 'extended_block' ) ),
			$this->row( array( 'stage' => 'extended_block' ) ),
		);

		$this->store->record_violation( '203.0.113.42', 'frontend', 'rate_limit' );

		$this->assertSame( 'extended_block', $GLOBALS['_wpdb_updated_rows'][0]['data']['stage'] );
	}

	public function test_record_violation_on_a_persistent_row_only_updates_bookkeeping(): void {
		$existing = $this->row( array( 'is_persistent' => 1, 'stage' => 'persistent_block', 'occurrence_count' => 5 ) );
		$GLOBALS['_wpdb_get_row_queue'] = array( $existing, $existing );

		$this->store->record_violation( '203.0.113.42', 'frontend', 'rate_limit' );

		$updated = $GLOBALS['_wpdb_updated_rows'][0]['data'];
		$this->assertArrayNotHasKey( 'stage', $updated );
		$this->assertSame( 6, $updated['occurrence_count'] );
	}

	public function test_set_persistent_marks_the_row_permanently_blocked(): void {
		$ok = $this->store->set_persistent( 7, 5 );

		$this->assertTrue( $ok );
		$row = $GLOBALS['_wpdb_updated_rows'][0];
		$this->assertSame( 'persistent_block', $row['data']['stage'] );
		$this->assertSame( 1, $row['data']['is_persistent'] );
		$this->assertNull( $row['data']['blocked_until'] );
		$this->assertSame( array( 'id' => 7 ), $row['where'] );
	}

	public function test_release_resets_the_row_to_observe(): void {
		$ok = $this->store->release( 7 );

		$this->assertTrue( $ok );
		$row = $GLOBALS['_wpdb_updated_rows'][0];
		$this->assertSame( 'observe', $row['data']['stage'] );
		$this->assertSame( 0, $row['data']['is_persistent'] );
		$this->assertNull( $row['data']['blocked_until'] );
	}
}
