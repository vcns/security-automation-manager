<?php
/**
 * Schema activation and migration metadata tests.
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;
use WP_SAM\Activator;

class SchemaMigrationTest extends TestCase {

	protected function setUp(): void {
		wp_test_reset_globals();
	}

	public function test_fresh_activation_creates_expected_custom_tables(): void {
		Activator::activate();

		$schema = implode( "\n\n", $GLOBALS['_dbdelta_queries'] );

		foreach ( $this->expected_tables() as $table ) {
			$this->assertStringContainsString( "CREATE TABLE {$GLOBALS['wpdb']->prefix}{$table}", $schema );
		}

		$this->assertSame( WP_SAM_DB_VERSION, get_option( 'wp_sam_db_version' ) );
		$this->assertSame( WP_SAM_DB_VERSION, get_option( 'wp_sam_schema_verified_version' ) );
	}

	public function test_schema_v6_violation_rollup_columns_are_declared(): void {
		Activator::activate();

		$schema = implode( "\n\n", $GLOBALS['_dbdelta_queries'] );

		$this->assertStringContainsString( 'first_reported_at datetime DEFAULT NULL', $schema );
		$this->assertStringContainsString( 'last_reported_at datetime DEFAULT NULL', $schema );
		$this->assertStringContainsString( 'UNIQUE KEY fingerprint (fingerprint)', $schema );
	}

	public function test_policy_decision_ledger_columns_are_declared(): void {
		Activator::activate();

		$schema = implode( "\n\n", $GLOBALS['_dbdelta_queries'] );

		$this->assertStringContainsString( 'decision_fingerprint varchar(64) NOT NULL', $schema );
		$this->assertStringContainsString( 'suppression_active tinyint(1) NOT NULL DEFAULT 0', $schema );
		$this->assertStringContainsString( 'KEY suppression_active (suppression_active)', $schema );
	}

	public function test_policy_versions_schema_uses_safe_trigger_lookup_index_name(): void {
		Activator::activate();

		$schema = implode( "\n\n", $GLOBALS['_dbdelta_queries'] );

		$this->assertStringContainsString( 'KEY trigger_lookup (trigger_type, trigger_id)', $schema );
		$this->assertStringNotContainsString( 'KEY trigger (trigger_type, trigger_id)', $schema );
	}

	public function test_schema_v8_sort_and_filter_indexes_are_declared(): void {
		Activator::activate();

		$schema = implode( "\n\n", $GLOBALS['_dbdelta_queries'] );

		$this->assertStringContainsString( 'KEY last_seen_at (last_seen_at)', $schema );
		$this->assertStringContainsString( 'KEY source_host (source_host(191))', $schema );
		$this->assertStringContainsString( 'KEY occurrence_count (occurrence_count)', $schema );
	}

	/**
	 * @dataProvider legacy_schema_version_provider
	 */
	public function test_activation_advances_legacy_schema_versions_to_current( string $legacy_version ): void {
		update_option( 'wp_sam_db_version', $legacy_version );

		Activator::activate();

		$this->assertSame( WP_SAM_DB_VERSION, get_option( 'wp_sam_db_version' ) );
	}

	public function test_repeated_activation_remains_idempotent_for_schema_version(): void {
		Activator::activate();
		Activator::activate();

		$this->assertSame( WP_SAM_DB_VERSION, get_option( 'wp_sam_db_version' ) );
	}

	public function test_missing_table_names_reports_absent_plugin_tables(): void {
		$GLOBALS['_wpdb_get_var_queue'] = array(
			'wp_csp_policy_profiles',
			null,
			'wp_csp_hash_inventory',
			'wp_csp_violation_reports',
			'wp_sam_scan_logs',
			'wp_sam_entitlements',
			'wp_sam_processed_events',
			'wp_sam_audit_log',
			'wp_sam_policy_change_decisions',
			null,
			'wp_sam_decision_rule_evaluations',
			'wp_sam_pillar_profiles',
			'wp_sam_dependency_inventory',
		);

		$this->assertSame(
			array( 'wp_csp_source_inventory', 'wp_sam_policy_versions' ),
			Activator::get_missing_table_names()
		);
	}

	public function test_initial_policy_version_seed_stops_when_table_is_missing(): void {
		$GLOBALS['_wpdb_get_var_queue'] = array( null );

		$method = new ReflectionMethod( Activator::class, 'seed_initial_policy_versions' );
		$method->setAccessible( true );
		$method->invoke( null );

		$this->assertSame( array(), $GLOBALS['_wpdb_inserted_rows'] );
		$this->assertSame( array(), $GLOBALS['_wpdb_queries'] );
	}

	public function test_migrate_v9_table_renames_renames_old_named_table_when_present(): void {
		$GLOBALS['_wpdb_get_var_queue'] = array(
			'wp_csp_scan_logs', // old csp_scan_logs exists
			null,               // new sam_scan_logs does not exist -> rename fires
			null,               // csp_entitlements does not exist
			null,               // csp_processed_events does not exist
			null,               // csp_audit_log does not exist
			null,               // csp_policy_change_decisions does not exist
			null,               // csp_policy_versions does not exist
			null,               // csp_decision_rule_evaluations does not exist
		);

		$method = new ReflectionMethod( Activator::class, 'migrate_v9_table_renames' );
		$method->setAccessible( true );
		$method->invoke( null );

		$this->assertCount( 1, $GLOBALS['_wpdb_queries'] );
		$this->assertStringContainsString( 'RENAME TABLE wp_csp_scan_logs TO wp_sam_scan_logs', $GLOBALS['_wpdb_queries'][0] );
	}

	public function test_migrate_v9_table_renames_skips_when_old_table_absent(): void {
		$GLOBALS['_wpdb_get_var_queue'] = array_fill( 0, 7, null );

		$method = new ReflectionMethod( Activator::class, 'migrate_v9_table_renames' );
		$method->setAccessible( true );
		$method->invoke( null );

		$this->assertSame( array(), $GLOBALS['_wpdb_queries'] );
	}

	public function test_migrate_v9_option_renames_copies_old_value_to_new_key(): void {
		$GLOBALS['_wp_options']['wp_csp_cron_hour'] = 7;

		$method = new ReflectionMethod( Activator::class, 'migrate_v9_option_renames' );
		$method->setAccessible( true );
		$method->invoke( null );

		$this->assertSame( 7, get_option( 'wp_sam_cron_hour' ) );
		$this->assertSame( 7, get_option( 'wp_csp_cron_hour' ), 'old key is left in place, not deleted' );
	}

	public function test_migrate_v9_option_renames_does_not_overwrite_existing_new_key(): void {
		$GLOBALS['_wp_options']['wp_csp_cron_hour'] = 7;
		$GLOBALS['_wp_options']['wp_sam_cron_hour'] = 3;

		$method = new ReflectionMethod( Activator::class, 'migrate_v9_option_renames' );
		$method->setAccessible( true );
		$method->invoke( null );

		$this->assertSame( 3, get_option( 'wp_sam_cron_hour' ) );
	}

	public function test_migrate_remove_fenced_frame_src_directive_strips_key_from_existing_profile(): void {
		$GLOBALS['_wpdb_get_results'] = array(
			array(
				'id'         => 5,
				'directives' => wp_json_encode( array( 'default-src' => array( "'none'" ), 'fenced-frame-src' => array( "'none'" ) ) ),
			),
		);

		$method = new ReflectionMethod( Activator::class, 'migrate_remove_fenced_frame_src_directive' );
		$method->setAccessible( true );
		$method->invoke( null );

		$this->assertCount( 1, $GLOBALS['_wpdb_updated_rows'] );
		$updated = json_decode( (string) $GLOBALS['_wpdb_updated_rows'][0]['data']['directives'], true );
		$this->assertArrayNotHasKey( 'fenced-frame-src', $updated );
		$this->assertArrayHasKey( 'default-src', $updated, 'other directives must be preserved' );
		$this->assertSame( array( 'id' => 5 ), $GLOBALS['_wpdb_updated_rows'][0]['where'] );
	}

	public function test_migrate_remove_fenced_frame_src_directive_skips_profiles_without_the_key(): void {
		$GLOBALS['_wpdb_get_results'] = array(
			array(
				'id'         => 5,
				'directives' => wp_json_encode( array( 'default-src' => array( "'none'" ) ) ),
			),
		);

		$method = new ReflectionMethod( Activator::class, 'migrate_remove_fenced_frame_src_directive' );
		$method->setAccessible( true );
		$method->invoke( null );

		$this->assertSame( array(), $GLOBALS['_wpdb_updated_rows'] );
	}

	public function test_migrate_remove_fenced_frame_src_directive_handles_no_profiles_gracefully(): void {
		$GLOBALS['_wpdb_get_results'] = array();

		$method = new ReflectionMethod( Activator::class, 'migrate_remove_fenced_frame_src_directive' );
		$method->setAccessible( true );
		$method->invoke( null );

		$this->assertSame( array(), $GLOBALS['_wpdb_updated_rows'] );
	}

	public static function legacy_schema_version_provider(): array {
		return array(
			'v1' => array( '1' ),
			'v2' => array( '2' ),
			'v3' => array( '3' ),
			'v4' => array( '4' ),
			'v5' => array( '5' ),
			'v6' => array( '6' ),
			'v7' => array( '7' ),
		);
	}

	private function expected_tables(): array {
		return array(
			'csp_policy_profiles',
			'csp_source_inventory',
			'csp_hash_inventory',
			'csp_violation_reports',
			'sam_scan_logs',
			'sam_entitlements',
			'sam_processed_events',
			'sam_audit_log',
			'sam_policy_change_decisions',
			'sam_policy_versions',
			'sam_decision_rule_evaluations',
			'sam_pillar_profiles',
		);
	}
}
