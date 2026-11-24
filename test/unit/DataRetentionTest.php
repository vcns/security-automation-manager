<?php
/**
 * Unit tests for WP_SAM\Data_Retention, and for everything that leans on
 * it: the one-time repair of sites whose retention a settings save had set
 * to 0, the daily purges, and uninstall dropping every table.
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;
use WP_SAM\Activator;
use WP_SAM\CSP\Scheduler;
use WP_SAM\Data_Retention;
use WP_SAM\Modules\Audit_Log;

class DataRetentionTest extends TestCase {

	protected function setUp(): void {
		wp_test_reset_globals();
	}

	// ── days() / sanitize() ──────────────────────────────────────────────────────

	public function test_days_defaults_to_ninety(): void {
		$this->assertSame( 90, Data_Retention::days() );
	}

	public function test_days_reads_the_stored_value(): void {
		update_option( Data_Retention::OPTION, '30' );

		$this->assertSame( 30, Data_Retention::days() );
	}

	/**
	 * options.php posts null for an option its form has no field for; that
	 * must keep the stored value, not become 0 ("keep everything").
	 */
	public function test_sanitize_keeps_the_stored_value_when_nothing_is_posted(): void {
		update_option( Data_Retention::OPTION, 45 );

		$this->assertSame( 45, Data_Retention::sanitize( null ) );
		$this->assertSame( 45, Data_Retention::sanitize( '' ) );
		$this->assertSame( 45, Data_Retention::sanitize( array( 'x' ) ) );
	}

	public function test_sanitize_accepts_days_and_zero(): void {
		$this->assertSame( 30, Data_Retention::sanitize( '30' ) );
		$this->assertSame( 0, Data_Retention::sanitize( '0' ) );
	}

	public function test_sanitize_caps_at_ten_years(): void {
		$this->assertSame( Data_Retention::MAX_DAYS, Data_Retention::sanitize( '999999' ) );
	}

	public function test_the_settings_group_registers_the_safe_sanitizer_not_absint(): void {
		$source = (string) file_get_contents( WP_SAM_DIR . 'includes/admin/class-admin-ui.php' );

		$this->assertMatchesRegularExpression( '/Data_Retention::OPTION\s*=>\s*array\(\s*\\\\WP_SAM\\\\Data_Retention::class,\s*\'sanitize\'\s*\)/', $source );
		$this->assertStringNotContainsString( "'wp_sam_violation_retention_days'      => 'absint'", $source );
	}

	/** Renders Control -> Automation Settings, which reads $this->plugin->gate as Admin_UI would provide. */
	private function render_automation_settings(): string {
		$_GET['tab']     = 'settings';
		$context         = new class() {
			public object $plugin;
		};
		$context->plugin = (object) array( 'gate' => new \WP_SAM\Modules\Feature_Gate() );

		$render = function (): string {
			ob_start();
			require WP_SAM_DIR . 'includes/admin/views/page-csp-dashboard.php';
			return (string) ob_get_clean();
		};
		$output = \Closure::bind( $render, $context, null )();

		unset( $_GET['tab'] );
		return $output;
	}

	public function test_the_automation_settings_form_has_a_retention_field(): void {
		$output = $this->render_automation_settings();

		$this->assertStringContainsString( 'name="wp_sam_violation_retention_days"', $output );
		$this->assertStringContainsString( 'value="90"', $output );
		$this->assertStringNotContainsString( 'Nothing is being deleted', $output );
	}

	public function test_the_automation_settings_form_warns_when_retention_keeps_everything(): void {
		update_option( Data_Retention::OPTION, 0 );

		$this->assertStringContainsString( 'Nothing is being deleted', $this->render_automation_settings() );
	}

	public function test_continuous_intelligence_says_how_long_records_are_kept(): void {
		update_option( Data_Retention::OPTION, 30 );
		$GLOBALS['_wpdb_get_var'] = 0;

		ob_start();
		require WP_SAM_DIR . 'includes/admin/views/page-intelligence.php';
		$output = (string) ob_get_clean();

		$this->assertStringContainsString( 'not seen for 30 days are deleted by the daily scan', $output );
		$this->assertStringContainsString( 'tab=settings#wp-sam-data-retention', $output );
	}

	// ── Activator::migrate_repair_zeroed_retention() ─────────────────────────────

	public function test_activate_puts_a_zeroed_retention_back_to_ninety_and_says_so(): void {
		update_option( Data_Retention::OPTION, 0 );

		Activator::activate();

		$this->assertSame( 90, (int) get_option( Data_Retention::OPTION ) );
		$this->assertContains(
			'retention_repaired',
			array_column( (array) get_option( 'wp_sam_admin_notices', array() ), 'event' )
		);
	}

	public function test_activate_leaves_a_chosen_retention_alone(): void {
		update_option( Data_Retention::OPTION, 30 );

		Activator::activate();

		$this->assertSame( 30, (int) get_option( Data_Retention::OPTION ) );
	}

	public function test_the_repair_runs_once_so_a_later_deliberate_zero_is_kept(): void {
		update_option( Data_Retention::OPTION, 0 );
		Activator::activate();

		update_option( Data_Retention::OPTION, 0 );
		Activator::activate();

		$this->assertSame( 0, (int) get_option( Data_Retention::OPTION ) );
	}

	// ── Scheduler purges ─────────────────────────────────────────────────────────

	private function run_purge( string $method ): string {
		$scheduler = new Scheduler( $this->createMock( Audit_Log::class ) );
		( new ReflectionMethod( $scheduler, $method ) )->invoke( $scheduler );
		return implode( "\n", $GLOBALS['_wpdb_queries'] ?? array() );
	}

	public function test_identities_purge_keeps_administrator_decisions(): void {
		update_option( Data_Retention::OPTION, 30 );

		$sql = $this->run_purge( 'purge_old_identities' );

		$this->assertStringContainsString( 'DELETE FROM wp_sam_scanner_identities WHERE last_seen_at < DATE_SUB(UTC_TIMESTAMP(), INTERVAL 30 DAY)', $sql );
		$this->assertStringContainsString( "verification_state NOT IN ('customer_authorised', 'explicitly_denied', 'previously_authorised_expired')", $sql );
	}

	public function test_geoip_cache_purge_uses_the_retention_window(): void {
		$sql = $this->run_purge( 'purge_stale_geoip_cache' );

		$this->assertStringContainsString( 'DELETE FROM wp_sam_geoip_cache WHERE resolved_at < DATE_SUB(UTC_TIMESTAMP(), INTERVAL 90 DAY)', $sql );
	}

	public function test_purges_do_nothing_when_retention_keeps_everything(): void {
		update_option( Data_Retention::OPTION, 0 );

		$this->assertSame( '', $this->run_purge( 'purge_old_identities' ) );
		$this->assertSame( '', $this->run_purge( 'purge_stale_geoip_cache' ) );
	}

	// ── uninstall.php ────────────────────────────────────────────────────────────

	public function test_uninstall_drops_every_table_activator_creates(): void {
		$source = (string) file_get_contents( WP_SAM_DIR . 'uninstall.php' );

		$missing = array();
		foreach ( Activator::get_table_suffixes() as $suffix ) {
			if ( ! str_contains( $source, "'{$suffix}'," ) ) {
				$missing[] = $suffix;
			}
		}

		$this->assertSame( array(), $missing, 'uninstall.php leaves these tables behind.' );
	}

	public function test_uninstall_sweeps_every_remaining_wp_sam_option_and_transient(): void {
		$source = (string) file_get_contents( WP_SAM_DIR . 'uninstall.php' );

		$this->assertStringContainsString( "esc_like( 'wp_sam_' ) . '%'", $source );
		$this->assertStringContainsString( "esc_like( '_transient_wp_sam_' ) . '%'", $source );
		$this->assertStringContainsString( "esc_like( '_transient_timeout_wp_sam_' ) . '%'", $source );
	}
}
