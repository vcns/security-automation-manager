<?php
/**
 * Unit tests for WP_SAM\Rollback_Guard's pure decision logic: schema-state
 * classification, downgrade-flag idempotency, and restore refusal reasons.
 *
 * What this file deliberately does NOT test: actual snapshot capture/restore
 * against real table rows. test/bootstrap.php's wpdb stub is a pre-programmed
 * response queue, not an in-memory database -- it can't hold state across
 * "DELETE FROM x" then "INSERT INTO x" the way a real MySQL connection does.
 * That round-trip is verified against a real WordPress + MySQL instance in
 * .github/workflows/release-verification.yml instead, the same division of
 * labour already established for schema migration testing in this suite.
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;
use WP_SAM\Rollback_Guard;

class RollbackGuardTest extends TestCase {

	protected function setUp(): void {
		wp_test_reset_globals();
	}

	public function test_schema_state_up_to_date_when_installed_matches_code(): void {
		update_option( 'wp_sam_db_version', (int) WP_SAM_DB_VERSION );

		$this->assertSame( 'up_to_date', Rollback_Guard::schema_state() );
	}

	public function test_schema_state_upgrade_needed_when_installed_behind_code(): void {
		update_option( 'wp_sam_db_version', (int) WP_SAM_DB_VERSION - 1 );

		$this->assertSame( 'upgrade_needed', Rollback_Guard::schema_state() );
	}

	public function test_schema_state_downgrade_detected_when_installed_ahead_of_code(): void {
		update_option( 'wp_sam_db_version', (int) WP_SAM_DB_VERSION + 1 );

		$this->assertSame( 'downgrade_detected', Rollback_Guard::schema_state() );
	}

	public function test_schema_state_upgrade_needed_on_a_fresh_install_with_no_option(): void {
		// get_option() default is 0 when the option has never been set --
		// a fresh install, not a downgrade.
		$this->assertSame( 'upgrade_needed', Rollback_Guard::schema_state() );
	}

	public function test_record_downgrade_detected_sets_the_flag_option(): void {
		Rollback_Guard::record_downgrade_detected( 99, 22 );

		$flag = get_option( Rollback_Guard::DOWNGRADE_OPTION );
		$this->assertIsArray( $flag );
		$this->assertSame( 99, $flag['installed'] );
		$this->assertSame( 22, $flag['code'] );
	}

	public function test_record_downgrade_detected_logs_once_for_the_same_pair(): void {
		Rollback_Guard::record_downgrade_detected( 99, 22 );
		$after_first = count( $GLOBALS['_wpdb_inserted_rows'] ?? array() );

		Rollback_Guard::record_downgrade_detected( 99, 22 );
		$after_second = count( $GLOBALS['_wpdb_inserted_rows'] ?? array() );

		// Second call is a no-op (same pair already recorded) -- no new
		// audit_log row should have been inserted.
		$this->assertSame( $after_first, $after_second );
	}

	public function test_record_downgrade_detected_logs_again_when_the_pair_changes(): void {
		// Audit_Log::write_to_db() checks the audit table exists before
		// inserting; without this, both calls below would silently no-op
		// and the assertion would be comparing 0 against 0.
		$GLOBALS['_wpdb_get_var'] = $GLOBALS['wpdb']->prefix . 'sam_audit_log';

		Rollback_Guard::record_downgrade_detected( 99, 22 );
		$after_first = count( $GLOBALS['_wpdb_inserted_rows'] ?? array() );

		Rollback_Guard::record_downgrade_detected( 100, 22 );
		$after_second = count( $GLOBALS['_wpdb_inserted_rows'] ?? array() );

		$this->assertGreaterThan( $after_first, $after_second );
	}

	public function test_clear_downgrade_flag_if_resolved_is_a_no_op_when_nothing_is_flagged(): void {
		Rollback_Guard::clear_downgrade_flag_if_resolved();

		$this->assertFalse( get_option( Rollback_Guard::DOWNGRADE_OPTION, false ) );
	}

	public function test_clear_downgrade_flag_if_resolved_deletes_an_existing_flag(): void {
		update_option( Rollback_Guard::DOWNGRADE_OPTION, array( 'installed' => 99, 'code' => 22 ) );

		Rollback_Guard::clear_downgrade_flag_if_resolved();

		$this->assertFalse( get_option( Rollback_Guard::DOWNGRADE_OPTION, false ) );
	}

	public function test_list_snapshots_returns_empty_array_when_the_snapshot_table_does_not_exist(): void {
		$GLOBALS['_wpdb_get_var'] = null; // table_exists() SHOW TABLES LIKE finds nothing.

		$this->assertSame( array(), Rollback_Guard::list_snapshots() );
	}

	public function test_list_snapshots_marks_restorable_only_when_to_version_matches_running_code(): void {
		$table                    = $GLOBALS['wpdb']->prefix . 'sam_migration_snapshots';
		$GLOBALS['_wpdb_get_var'] = $table; // table_exists() finds it.
		$GLOBALS['_wpdb_get_results'] = array(
			array( 'id' => '2', 'from_version' => '22', 'to_version' => (string) WP_SAM_DB_VERSION, 'created_at' => '2026-01-02 00:00:00' ),
			array( 'id' => '1', 'from_version' => '21', 'to_version' => '22', 'created_at' => '2026-01-01 00:00:00' ),
		);

		$snapshots = Rollback_Guard::list_snapshots();

		$this->assertCount( 2, $snapshots );
		$this->assertTrue( $snapshots[0]['restorable'], 'Snapshot whose to_version matches WP_SAM_DB_VERSION must be restorable.' );
		$this->assertFalse( $snapshots[1]['restorable'], 'Snapshot for an older schema than the running code must not be restorable.' );
	}

	public function test_restore_snapshot_refuses_when_snapshot_table_does_not_exist(): void {
		$GLOBALS['_wpdb_get_var'] = null;

		$result = Rollback_Guard::restore_snapshot( 1 );

		$this->assertFalse( $result['ok'] );
		$this->assertStringContainsString( 'No snapshot history', $result['reason'] );
	}

	public function test_restore_snapshot_refuses_when_the_id_does_not_exist(): void {
		$table                     = $GLOBALS['wpdb']->prefix . 'sam_migration_snapshots';
		$GLOBALS['_wpdb_get_var']  = $table;
		$GLOBALS['_wpdb_get_row']  = null;

		$result = Rollback_Guard::restore_snapshot( 999 );

		$this->assertFalse( $result['ok'] );
		$this->assertStringContainsString( 'no longer exists', $result['reason'] );
	}

	public function test_restore_snapshot_refuses_on_schema_version_mismatch(): void {
		$table                    = $GLOBALS['wpdb']->prefix . 'sam_migration_snapshots';
		$GLOBALS['_wpdb_get_var'] = $table;
		$GLOBALS['_wpdb_get_row'] = array(
			'to_version'    => (int) WP_SAM_DB_VERSION - 1, // A schema behind the running code.
			'snapshot_data' => wp_json_encode( array() ),
		);

		$result = Rollback_Guard::restore_snapshot( 1 );

		$this->assertFalse( $result['ok'] );
		$this->assertStringContainsString( 'not supported automatically', $result['reason'] );
	}

	public function test_restore_snapshot_refuses_on_corrupted_snapshot_data(): void {
		$table                    = $GLOBALS['wpdb']->prefix . 'sam_migration_snapshots';
		$GLOBALS['_wpdb_get_var'] = $table;
		$GLOBALS['_wpdb_get_row'] = array(
			'to_version'    => (int) WP_SAM_DB_VERSION,
			'snapshot_data' => 'not valid json {{{',
		);

		$result = Rollback_Guard::restore_snapshot( 1 );

		$this->assertFalse( $result['ok'] );
		$this->assertStringContainsString( 'corrupted', $result['reason'] );
	}

	public function test_restore_snapshot_succeeds_and_restores_every_snapshotted_table(): void {
		$snapshot_table = $GLOBALS['wpdb']->prefix . 'sam_migration_snapshots';
		$profiles_table = $GLOBALS['wpdb']->prefix . 'csp_policy_profiles';

		// restore_snapshot() only calls table_exists() for a suffix actually
		// present in the decoded snapshot data (see the array_key_exists()
		// guard before it), so with only 'csp_policy_profiles' in the
		// snapshot below, exactly two table_exists() checks happen in
		// order: the snapshot table itself, then csp_policy_profiles.
		$GLOBALS['_wpdb_get_var_queue'] = array( $snapshot_table, $profiles_table );
		$GLOBALS['_wpdb_get_row']       = array(
			'to_version'    => (int) WP_SAM_DB_VERSION,
			'snapshot_data' => wp_json_encode(
				array(
					'csp_policy_profiles' => array(
						array( 'id' => 1, 'surface' => 'frontend', 'mode' => 'report-only' ),
					),
				)
			),
		);

		$result = Rollback_Guard::restore_snapshot( 1 );

		$this->assertTrue( $result['ok'] );
		$this->assertContains( 'csp_policy_profiles', $result['tables_restored'] );
	}
}
