<?php
/**
 * Unit tests for WP_SAM\Activator.
 *
 * Focuses on the parts that can run without a real database:
 *   - Default options are seeded with correct keys and values.
 *   - Default directives structure is valid and surface-specific.
 *   - Cron event is scheduled once (idempotent on repeat activate).
 *
 * create_tables() / seed_default_profiles() are skipped here because they
 * require dbDelta() and a real wpdb. Integration tests should cover those.
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;
use WP_SAM\Activator;

class ActivatorTest extends TestCase {

	protected function setUp(): void {
		wp_test_reset_globals();
	}

	// ── Default options ───────────────────────────────────────────────────────

	public function test_activate_seeds_violation_retention_days_option(): void {
		Activator::activate();

		$this->assertSame( 90, get_option( 'wp_sam_violation_retention_days' ) );
	}

	public function test_activate_seeds_learning_window_option(): void {
		Activator::activate();

		$this->assertSame( 48, get_option( 'wp_sam_learning_window_hours' ) );
		$this->assertNotEmpty( get_option( 'wp_sam_last_material_change_at' ) );
	}

	public function test_activate_seeds_blank_report_endpoint_override(): void {
		Activator::activate();

		$this->assertSame( '', get_option( 'wp_sam_report_endpoint_url' ) );
	}

	public function test_activate_seeds_direct_reporting_transport(): void {
		Activator::activate();

		$this->assertSame( 'report-uri', get_option( 'wp_sam_reporting_transport' ) );
	}

	public function test_activate_seeds_enforce_gate_violation_window_option(): void {
		Activator::activate();

		$this->assertSame( 24, get_option( 'wp_sam_enforce_gate_violation_window' ) );
	}

	public function test_activate_seeds_cron_hour_default_of_two(): void {
		Activator::activate();

		$this->assertSame( 2, get_option( 'wp_sam_cron_hour' ) );
	}

	public function test_activate_does_not_overwrite_existing_options(): void {
		// Pre-seed a custom value.
		update_option( 'wp_sam_cron_hour', 6 );

		Activator::activate();

		// add_option() is a no-op when the option already exists.
		$this->assertSame( 6, get_option( 'wp_sam_cron_hour' ) );
	}

	// ── Cron scheduling ───────────────────────────────────────────────────────

	public function test_activate_schedules_daily_scan_cron_event(): void {
		Activator::activate();

		$this->assertNotFalse( wp_next_scheduled( 'wp_sam_daily_scan' ) );
	}

	public function test_activate_does_not_double_schedule_cron_event(): void {
		// First activation schedules the event.
		Activator::activate();
		$first_timestamp = wp_next_scheduled( 'wp_sam_daily_scan' );

		// Second activation must be a no-op (cron event already exists).
		Activator::activate();
		$second_timestamp = wp_next_scheduled( 'wp_sam_daily_scan' );

		$this->assertSame( $first_timestamp, $second_timestamp );
	}

	// ── Default directives ────────────────────────────────────────────────────

	/**
	 * @dataProvider surface_provider
	 */
	public function test_default_directives_include_default_src_none( string $surface ): void {
		$directives = $this->get_default_directives( $surface );

		$this->assertArrayHasKey( 'default-src', $directives );
		$this->assertContains( "'none'", $directives['default-src'] );
	}

	/**
	 * @dataProvider surface_provider
	 */
	public function test_default_directives_include_object_src_none( string $surface ): void {
		$directives = $this->get_default_directives( $surface );

		$this->assertArrayHasKey( 'object-src', $directives );
		$this->assertContains( "'none'", $directives['object-src'] );
	}

	/**
	 * @dataProvider surface_provider
	 */
	public function test_default_directives_include_base_uri_none( string $surface ): void {
		$directives = $this->get_default_directives( $surface );

		$this->assertArrayHasKey( 'base-uri', $directives );
		$this->assertContains( "'none'", $directives['base-uri'] );
	}

	public function test_default_directives_include_upgrade_insecure_on_frontend(): void {
		$directives = $this->get_default_directives( 'frontend' );

		$this->assertArrayHasKey( 'upgrade-insecure-requests', $directives );
	}

	public function test_default_directives_omit_upgrade_insecure_on_api(): void {
		$directives = $this->get_default_directives( 'api' );

		$this->assertArrayNotHasKey( 'upgrade-insecure-requests', $directives );
	}

	public function test_default_directives_include_report_sample_in_script_src(): void {
		$directives = $this->get_default_directives( 'frontend' );

		$this->assertArrayHasKey( 'script-src', $directives );
		$this->assertContains( "'report-sample'", $directives['script-src'] );
	}

	public function test_default_directives_admin_surface_allows_self_for_frames(): void {
		$directives = $this->get_default_directives( 'admin' );

		$this->assertArrayHasKey( 'frame-src', $directives );
		$this->assertContains( "'self'", $directives['frame-src'] );
	}

	public function test_default_directives_sandbox_is_null(): void {
		$directives = $this->get_default_directives( 'frontend' );

		$this->assertArrayHasKey( 'sandbox', $directives );
		$this->assertNull( $directives['sandbox'] );
	}

	// ── Providers ─────────────────────────────────────────────────────────────

	public static function surface_provider(): array {
		return array(
			'frontend' => array( 'frontend' ),
			'admin'    => array( 'admin' ),
			'login'    => array( 'login' ),
			'api'      => array( 'api' ),
		);
	}

	// ── Pillar profile seeding ───────────────────────────────────────────────

	public function test_seed_default_pillar_profiles_inserts_enabled_rows_for_every_missing_surface(): void {
		// 9 pillars x 4 surfaces = 36 (pillar, surface) pairs, none existing yet.
		$GLOBALS['_wpdb_get_var_queue'] = array_fill( 0, 36, null );

		$this->invoke_seed_default_pillar_profiles();

		$this->assertCount( 36, $GLOBALS['_wpdb_inserted_rows'] );
		foreach ( $GLOBALS['_wpdb_inserted_rows'] as $row ) {
			$this->assertSame( 1, $row['data']['enabled'] );
		}
	}

	public function test_seed_default_pillar_profiles_skips_rows_that_already_exist(): void {
		$GLOBALS['_wpdb_get_var_queue'] = array_fill( 0, 36, 1 );

		$this->invoke_seed_default_pillar_profiles();

		$this->assertSame( array(), $GLOBALS['_wpdb_inserted_rows'] );
	}

	public function test_seed_default_pillar_profiles_x_frame_options_denies_api_and_sameorigin_elsewhere(): void {
		$GLOBALS['_wpdb_get_var_queue'] = array_fill( 0, 36, null );

		$this->invoke_seed_default_pillar_profiles();

		$rows = $this->inserted_rows_for_pillar( 'x-frame-options' );
		$this->assertSame( 'DENY', json_decode( $rows['api']['payload'], true )['value'] );
		foreach ( array( 'frontend', 'admin', 'login' ) as $surface ) {
			$this->assertSame( 'SAMEORIGIN', json_decode( $rows[ $surface ]['payload'], true )['value'] );
		}
	}

	public function test_seed_default_pillar_profiles_referrer_policy_no_referrer_on_api_only(): void {
		$GLOBALS['_wpdb_get_var_queue'] = array_fill( 0, 36, null );

		$this->invoke_seed_default_pillar_profiles();

		$rows = $this->inserted_rows_for_pillar( 'referrer-policy' );
		$this->assertSame( 'no-referrer', json_decode( $rows['api']['payload'], true )['value'] );
		$this->assertSame( 'strict-origin-when-cross-origin', json_decode( $rows['frontend']['payload'], true )['value'] );
	}

	public function test_seed_default_pillar_profiles_permissions_policy_autoplay_self_on_frontend_only_and_payment_none_everywhere(): void {
		$GLOBALS['_wpdb_get_var_queue'] = array_fill( 0, 36, null );

		$this->invoke_seed_default_pillar_profiles();

		$rows = $this->inserted_rows_for_pillar( 'permissions-policy' );
		foreach ( array( 'frontend', 'admin', 'login', 'api' ) as $surface ) {
			$directives = json_decode( $rows[ $surface ]['payload'], true )['directives'];
			$this->assertSame( 'none', $directives['payment'], "payment must be none on {$surface}" );
			$this->assertSame( 'none', $directives['geolocation'], "geolocation must be none on {$surface}" );
		}

		$frontend_directives = json_decode( $rows['frontend']['payload'], true )['directives'];
		$this->assertSame( 'self', $frontend_directives['autoplay'] );
		foreach ( array( 'admin', 'login', 'api' ) as $surface ) {
			$directives = json_decode( $rows[ $surface ]['payload'], true )['directives'];
			$this->assertSame( 'none', $directives['autoplay'], "autoplay must be none on {$surface}" );
		}
	}

	public function test_seed_default_pillar_profiles_cross_origin_resource_policy_same_site_on_api_only(): void {
		$GLOBALS['_wpdb_get_var_queue'] = array_fill( 0, 36, null );

		$this->invoke_seed_default_pillar_profiles();

		$rows = $this->inserted_rows_for_pillar( 'cross-origin-resource-policy' );
		$this->assertSame( 'same-site', json_decode( $rows['api']['payload'], true )['value'] );
		foreach ( array( 'frontend', 'admin', 'login' ) as $surface ) {
			$this->assertSame( 'cross-origin', json_decode( $rows[ $surface ]['payload'], true )['value'] );
		}
	}

	public function test_seed_default_pillar_profiles_coop_and_coep_are_unsafe_none_on_every_surface(): void {
		$GLOBALS['_wpdb_get_var_queue'] = array_fill( 0, 36, null );

		$this->invoke_seed_default_pillar_profiles();

		foreach ( array( 'cross-origin-opener-policy', 'cross-origin-embedder-policy' ) as $pillar ) {
			$rows = $this->inserted_rows_for_pillar( $pillar );
			foreach ( $rows as $surface => $row ) {
				$this->assertSame( 'unsafe-none', json_decode( $row['payload'], true )['value'], "{$pillar} on {$surface}" );
			}
		}
	}

	public function test_seed_default_pillar_profiles_x_permitted_cross_domain_policies_is_none_everywhere(): void {
		$GLOBALS['_wpdb_get_var_queue'] = array_fill( 0, 36, null );

		$this->invoke_seed_default_pillar_profiles();

		$rows = $this->inserted_rows_for_pillar( 'x-permitted-cross-domain-policies' );
		foreach ( $rows as $surface => $row ) {
			$this->assertSame( 'none', json_decode( $row['payload'], true )['value'], "surface {$surface}" );
		}
	}

	public function test_seed_default_pillar_profiles_does_not_include_hsts(): void {
		$GLOBALS['_wpdb_get_var_queue'] = array_fill( 0, 36, null );

		$this->invoke_seed_default_pillar_profiles();

		$pillars = array_unique( array_column( array_column( $GLOBALS['_wpdb_inserted_rows'], 'data' ), 'pillar' ) );
		$this->assertNotContains( 'strict-transport-security', $pillars );
	}

	// ── Automation defaults ──────────────────────────────────────────────────

	// ── Scanner vendor catalogue seed (Phase 3D) ──────────────────────────────

	public function test_seed_default_scanner_vendors_inserts_builtin_crawlers_when_missing(): void {
		$GLOBALS['_wpdb_get_var_queue'] = array( null, null ); // googlebot, bingbot both missing.

		$this->invoke_seed_default_scanner_vendors();

		$this->assertCount( 2, $GLOBALS['_wpdb_inserted_rows'] );
		$keys = array_column( array_column( $GLOBALS['_wpdb_inserted_rows'], 'data' ), 'vendor_key' );
		$this->assertSame( array( 'googlebot', 'bingbot' ), $keys );
		foreach ( $GLOBALS['_wpdb_inserted_rows'] as $row ) {
			$this->assertSame( 1, $row['data']['is_builtin'] );
			$this->assertSame( 'fcrdns', $row['data']['verification_method'] );
			$this->assertNotSame( '', $row['data']['source_url'] );
		}
	}

	public function test_seed_default_scanner_vendors_skips_rows_that_already_exist(): void {
		$GLOBALS['_wpdb_get_var_queue'] = array( 1, 1 );

		$this->invoke_seed_default_scanner_vendors();

		$this->assertSame( array(), $GLOBALS['_wpdb_inserted_rows'] );
	}

	public function test_default_automation_config_is_automatic_high_approval_with_a_positive_change_cap(): void {
		Activator::activate();

		$config = get_option( 'wp_sam_automation_config' );
		foreach ( array( 'frontend', 'admin', 'login', 'api' ) as $surface ) {
			$this->assertSame( 'automatic_high_approval', $config[ $surface ]['mode'] );
			$this->assertSame( 50, $config[ $surface ]['max_automatic_changes_per_scan'] );
		}
	}

	// ── Helpers ───────────────────────────────────────────────────────────────

	/**
	 * Invokes the private Activator::default_directives() via reflection.
	 */
	private function get_default_directives( string $surface ): array {
		$method = new ReflectionMethod( Activator::class, 'default_directives' );
		$method->setAccessible( true );
		return $method->invoke( null, $surface );
	}

	private function invoke_seed_default_pillar_profiles(): void {
		$method = new ReflectionMethod( Activator::class, 'seed_default_pillar_profiles' );
		$method->setAccessible( true );
		$method->invoke( null );
	}

	private function invoke_seed_default_scanner_vendors(): void {
		$method = new ReflectionMethod( Activator::class, 'seed_default_scanner_vendors' );
		$method->setAccessible( true );
		$method->invoke( null );
	}

	/**
	 * @return array<string,array{table:string,data:array,format:array}> inserted rows for
	 *         the given pillar, keyed by surface.
	 */
	private function inserted_rows_for_pillar( string $pillar ): array {
		$rows = array();
		foreach ( $GLOBALS['_wpdb_inserted_rows'] as $row ) {
			if ( $pillar === $row['data']['pillar'] ) {
				$rows[ $row['data']['surface'] ] = $row['data'];
			}
		}
		return $rows;
	}
}
