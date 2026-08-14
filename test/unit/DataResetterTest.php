<?php
/**
 * Unit tests for the administrative CSP data reset service.
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;
use WP_SAM\Activator;
use WP_SAM\Admin\Data_Resetter;

class DataResetterTest extends TestCase {

	protected function setUp(): void {
		wp_test_reset_globals();
	}

	public function test_reset_clears_plugin_tables_and_reseeds_defaults(): void {
		$table_suffixes = Activator::get_table_suffixes();
		$table_names    = array_map(
			static fn ( string $suffix ): string => 'wp_' . $suffix,
			$table_suffixes
		);

		$GLOBALS['_wpdb_get_var_queue'] = array_merge(
			$table_names,
			array_fill( 0, 7, null ),
			// Two consecutive table_exists() checks against the same table: schema
			// v14's migrate_dedupe_violation_reports_by_host(), then the existing
			// migrate_violation_report_rollups().
			array( 'wp_csp_violation_reports' ),
			array( 'wp_csp_violation_reports' ),
			array_fill( 0, 4, '1' ),
			array( 'wp_sam_policy_versions' ),
			array_fill( 0, 4, '1' ),
			array( 'wp_csp_policy_profiles' )
		);
		$GLOBALS['_wpdb_get_var']       = 'wp_csp_policy_profiles';
		$GLOBALS['_wp_options']         = array(
			'wp_sam_db_version'          => '7',
			'wp_sam_report_endpoint_url' => 'https://public.example.com/wp-json/custom-endpoint/v1/report',
		);
		$GLOBALS['_wp_transients']      = array(
			'wp_sam_conflict_probe_ran'  => 1,
			'unrelated_plugin_transient' => 1,
		);
		$GLOBALS['_wp_cron']            = array( 'wp_sam_daily_scan' => time() + 3600 );

		$result = ( new Data_Resetter() )->reset();

		foreach ( $table_names as $table_name ) {
			$this->assertContains( "DELETE FROM {$table_name}", $GLOBALS['_wpdb_queries'] );
		}

		$this->assertSame( $table_names, array_keys( $result['tables_cleared'] ) );
		$this->assertSame( '', $GLOBALS['_wp_options']['wp_sam_report_endpoint_url'] );
		$this->assertArrayNotHasKey( 'wp_sam_conflict_probe_ran', $GLOBALS['_wp_transients'] );
		$this->assertArrayHasKey( 'unrelated_plugin_transient', $GLOBALS['_wp_transients'] );
		$this->assertArrayHasKey( 'wp_sam_daily_scan', $GLOBALS['_wp_cron'] );
		$this->assertSame( WP_SAM_DB_VERSION, $GLOBALS['_wp_options']['wp_sam_db_version'] );
		$this->assertCount( 4, $GLOBALS['_wpdb_updated_rows'] );
		$this->assertSame(
			array( 'frontend', 'admin', 'login', 'api' ),
			array_map(
				static fn ( array $row ): string => $row['where']['surface'],
				$GLOBALS['_wpdb_updated_rows']
			)
		);
	}
}
