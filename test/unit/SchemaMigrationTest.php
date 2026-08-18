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

	public function test_pillar_profiles_pillar_column_fits_the_longest_pillar_key(): void {
		// Regression test: sam_pillar_profiles.pillar was varchar(32), but
		// X_Permitted_Cross_Domain_Policies_Builder::PILLAR_KEY
		// ('x-permitted-cross-domain-policies') is 33 characters -- one over.
		// Depending on SQL mode, every save for that one pillar either failed
		// outright or was silently truncated to a different, unreadable key,
		// so the Overview table always showed it as "Off" no matter what an
		// admin actually toggled. Assert the column is wide enough for every
		// currently-defined pillar key, not just today's longest one.
		Activator::activate();

		$table = $GLOBALS['wpdb']->prefix . 'sam_pillar_profiles';
		$statement = null;
		foreach ( $GLOBALS['_dbdelta_queries'] as $query ) {
			if ( str_contains( $query, "CREATE TABLE {$table} " ) ) {
				$statement = $query;
				break;
			}
		}
		$this->assertNotNull( $statement, "CREATE TABLE statement for {$table} not found." );

		$matched = preg_match( '/pillar varchar\((\d+)\) NOT NULL/', $statement, $matches );
		$this->assertSame( 1, $matched, 'sam_pillar_profiles.pillar column definition not found in its own CREATE TABLE statement.' );
		$column_length = (int) $matches[1];

		$pillar_keys = array(
			\WP_SAM\Security\X_Frame_Options_Builder::PILLAR_KEY,
			\WP_SAM\Security\X_Content_Type_Options_Builder::PILLAR_KEY,
			\WP_SAM\Security\Referrer_Policy_Builder::PILLAR_KEY,
			\WP_SAM\Security\Permissions_Policy_Builder::PILLAR_KEY,
			\WP_SAM\Security\Strict_Transport_Security_Builder::PILLAR_KEY,
			\WP_SAM\Security\Reverse_Tabnabbing_Builder::PILLAR_KEY,
			\WP_SAM\Security\Dependency_Governance_Builder::PILLAR_KEY,
			\WP_SAM\Security\Cross_Origin_Resource_Policy_Builder::PILLAR_KEY,
			\WP_SAM\Security\X_Permitted_Cross_Domain_Policies_Builder::PILLAR_KEY,
			\WP_SAM\Security\Cross_Origin_Opener_Policy_Builder::PILLAR_KEY,
			\WP_SAM\Security\Cross_Origin_Embedder_Policy_Builder::PILLAR_KEY,
			\WP_SAM\Security\Internal_Script_Integrity_Builder::PILLAR_KEY,
		);

		foreach ( $pillar_keys as $pillar_key ) {
			$this->assertLessThanOrEqual(
				$column_length,
				strlen( $pillar_key ),
				"Pillar key '{$pillar_key}' (" . strlen( $pillar_key ) . ' chars) does not fit in the pillar column (' . $column_length . ' chars).'
			);
		}
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
			'wp_sam_pillar_violation_reports',
			'wp_sam_internal_asset_inventory',
			'wp_sam_certificates',
			'wp_sam_migration_snapshots',
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

	public function test_schema_v13_pillar_violation_reports_table_is_declared(): void {
		Activator::activate();

		$schema = implode( "\n\n", $GLOBALS['_dbdelta_queries'] );

		$this->assertStringContainsString( "CREATE TABLE {$GLOBALS['wpdb']->prefix}sam_pillar_violation_reports", $schema );
		$this->assertStringContainsString( 'detail longtext NOT NULL', $schema );
		$this->assertStringContainsString( 'UNIQUE KEY fingerprint (fingerprint)', $schema );
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

	// ── migrate_tighten_img_src_default() (schema v17) ───────────────────────────

	public function test_migrate_tighten_img_src_default_strips_data_from_untouched_default(): void {
		$GLOBALS['_wpdb_get_results'] = array(
			array(
				'id'         => 5,
				'directives' => wp_json_encode( array( 'default-src' => array( "'none'" ), 'img-src' => array( "'self'", 'data:' ) ) ),
			),
		);

		$method = new ReflectionMethod( Activator::class, 'migrate_tighten_img_src_default' );
		$method->setAccessible( true );
		$method->invoke( null );

		$this->assertCount( 1, $GLOBALS['_wpdb_updated_rows'] );
		$updated = json_decode( (string) $GLOBALS['_wpdb_updated_rows'][0]['data']['directives'], true );
		$this->assertSame( array( "'self'" ), $updated['img-src'] );
		$this->assertArrayHasKey( 'default-src', $updated, 'other directives must be preserved' );
		$this->assertSame( array( 'id' => 5 ), $GLOBALS['_wpdb_updated_rows'][0]['where'] );
	}

	public function test_migrate_tighten_img_src_default_skips_a_customised_img_src(): void {
		$GLOBALS['_wpdb_get_results'] = array(
			array(
				'id'         => 5,
				'directives' => wp_json_encode( array( 'img-src' => array( "'self'", 'data:', 'cdn.example.test' ) ) ),
			),
		);

		$method = new ReflectionMethod( Activator::class, 'migrate_tighten_img_src_default' );
		$method->setAccessible( true );
		$method->invoke( null );

		$this->assertSame( array(), $GLOBALS['_wpdb_updated_rows'], 'a profile the administrator already customised must be left untouched' );
	}

	public function test_migrate_tighten_img_src_default_skips_profiles_without_the_key(): void {
		$GLOBALS['_wpdb_get_results'] = array(
			array(
				'id'         => 5,
				'directives' => wp_json_encode( array( 'default-src' => array( "'none'" ) ) ),
			),
		);

		$method = new ReflectionMethod( Activator::class, 'migrate_tighten_img_src_default' );
		$method->setAccessible( true );
		$method->invoke( null );

		$this->assertSame( array(), $GLOBALS['_wpdb_updated_rows'] );
	}

	public function test_migrate_tighten_img_src_default_handles_no_profiles_gracefully(): void {
		$GLOBALS['_wpdb_get_results'] = array();

		$method = new ReflectionMethod( Activator::class, 'migrate_tighten_img_src_default' );
		$method->setAccessible( true );
		$method->invoke( null );

		$this->assertSame( array(), $GLOBALS['_wpdb_updated_rows'] );
	}

	// ── migrate_dedupe_violation_reports_by_host() (schema v14) ──────────────────

	public function test_migrate_dedupe_violation_reports_by_host_skips_when_table_missing(): void {
		$GLOBALS['_wpdb_get_var'] = null;

		$method = new ReflectionMethod( Activator::class, 'migrate_dedupe_violation_reports_by_host' );
		$method->setAccessible( true );
		$method->invoke( null );

		$this->assertSame( array(), $GLOBALS['_wpdb_updated_rows'] );
	}

	public function test_migrate_dedupe_violation_reports_by_host_noop_when_table_empty(): void {
		$table                        = $GLOBALS['wpdb']->prefix . 'csp_violation_reports';
		$GLOBALS['_wpdb_get_var']     = $table;
		$GLOBALS['_wpdb_get_results'] = array();

		$method = new ReflectionMethod( Activator::class, 'migrate_dedupe_violation_reports_by_host' );
		$method->setAccessible( true );
		$method->invoke( null );

		$this->assertSame( array(), $GLOBALS['_wpdb_updated_rows'] );
	}

	public function test_migrate_dedupe_violation_reports_by_host_backfills_single_row_group(): void {
		$table                        = $GLOBALS['wpdb']->prefix . 'csp_violation_reports';
		$GLOBALS['_wpdb_get_var']     = $table;
		$GLOBALS['_wpdb_get_results'] = array(
			array(
				'id'                => 7,
				'profile_surface'   => 'frontend',
				'blocked_uri'       => 'https://fonts.gstatic.com/s/poppins/v24/aaaa.woff2',
				'violated_directive' => 'font-src',
				'occurrence_count'  => 3,
				'first_reported_at' => '2026-08-01 00:00:00',
				'last_reported_at'  => '2026-08-01 00:00:00',
			),
		);

		$method = new ReflectionMethod( Activator::class, 'migrate_dedupe_violation_reports_by_host' );
		$method->setAccessible( true );
		$method->invoke( null );

		$this->assertCount( 1, $GLOBALS['_wpdb_updated_rows'] );
		$update = $GLOBALS['_wpdb_updated_rows'][0];
		$this->assertSame( array( 'id' => 7 ), $update['where'] );
		$this->assertSame( 'fonts.gstatic.com', $update['data']['blocked_host'] );
		// Single-row groups are backfilled only -- occurrence_count/timestamps untouched.
		$this->assertArrayNotHasKey( 'occurrence_count', $update['data'] );
	}

	public function test_migrate_dedupe_violation_reports_by_host_merges_rows_sharing_a_host(): void {
		$table                        = $GLOBALS['wpdb']->prefix . 'csp_violation_reports';
		$GLOBALS['_wpdb_get_var']     = $table;
		$GLOBALS['_wpdb_get_results'] = array(
			array(
				'id'                 => 1,
				'profile_surface'    => 'frontend',
				'blocked_uri'        => 'https://fonts.gstatic.com/s/poppins/v24/aaaa.woff2',
				'violated_directive' => 'font-src',
				'occurrence_count'   => 3,
				'first_reported_at'  => '2026-08-01 00:00:00',
				'last_reported_at'   => '2026-08-01 00:00:00',
			),
			array(
				'id'                 => 2,
				'profile_surface'    => 'frontend',
				'blocked_uri'        => 'https://fonts.gstatic.com/s/poppins/v24/bbbb.woff2',
				'violated_directive' => 'font-src',
				'occurrence_count'   => 5,
				'first_reported_at'  => '2026-07-20 00:00:00',
				'last_reported_at'   => '2026-08-10 12:00:00',
			),
		);

		$method = new ReflectionMethod( Activator::class, 'migrate_dedupe_violation_reports_by_host' );
		$method->setAccessible( true );
		$method->invoke( null );

		// Both rows collapse to a single fingerprint -- one survivor update, keyed on
		// the row most recently seen (id 2), with counts summed and earliest first-seen kept.
		$this->assertCount( 1, $GLOBALS['_wpdb_updated_rows'] );
		$update = $GLOBALS['_wpdb_updated_rows'][0];
		$this->assertSame( array( 'id' => 2 ), $update['where'] );
		$this->assertSame( 'fonts.gstatic.com', $update['data']['blocked_host'] );
		$this->assertSame( 8, $update['data']['occurrence_count'] );
		$this->assertSame( '2026-07-20 00:00:00', $update['data']['first_reported_at'] );
		$this->assertSame( '2026-08-10 12:00:00', $update['data']['last_reported_at'] );

		// The other row (id 1) is deleted.
		$this->assertStringContainsString( 'DELETE FROM', $GLOBALS['_wpdb_last_query'] );
		$this->assertStringContainsString( 'WHERE id IN (1)', $GLOBALS['_wpdb_last_query'] );
	}

	public function test_migrate_dedupe_violation_reports_by_host_leaves_keyword_rows_unmerged(): void {
		$table                        = $GLOBALS['wpdb']->prefix . 'csp_violation_reports';
		$GLOBALS['_wpdb_get_var']     = $table;
		$GLOBALS['_wpdb_get_results'] = array(
			array(
				'id'                 => 1,
				'profile_surface'    => 'frontend',
				'blocked_uri'        => 'inline',
				'violated_directive' => 'script-src',
				'occurrence_count'   => 1,
				'first_reported_at'  => '2026-08-01 00:00:00',
				'last_reported_at'   => '2026-08-01 00:00:00',
			),
			array(
				'id'                 => 2,
				'profile_surface'    => 'frontend',
				'blocked_uri'        => 'eval',
				'violated_directive' => 'script-src',
				'occurrence_count'   => 1,
				'first_reported_at'  => '2026-08-01 00:00:00',
				'last_reported_at'   => '2026-08-01 00:00:00',
			),
		);

		$method = new ReflectionMethod( Activator::class, 'migrate_dedupe_violation_reports_by_host' );
		$method->setAccessible( true );
		$method->invoke( null );

		// Different keyword values keep their own exact-value fingerprint -- two
		// independent backfills, no merge, no delete.
		$this->assertCount( 2, $GLOBALS['_wpdb_updated_rows'] );
		foreach ( $GLOBALS['_wpdb_updated_rows'] as $update ) {
			$this->assertNull( $update['data']['blocked_host'] );
		}
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
