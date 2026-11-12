<?php
/**
 * Unit tests for WP_SAM\Intelligence\Security_Health.
 *
 * Each row-builder is invoked in isolation via reflection, rather than
 * orchestrating get_report()'s full ~15-call DB sequence in one test --
 * the row builders don't share any state, so testing them individually is
 * both simpler and more precise about which query drives which status.
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;
use WP_SAM\Intelligence\Security_Health;

class SecurityHealthTest extends TestCase {

	private Security_Health $health;

	protected function setUp(): void {
		wp_test_reset_globals();
		$this->health = new Security_Health();
	}

	private function invoke( string $method ): array {
		$ref = new ReflectionMethod( Security_Health::class, $method );
		$ref->setAccessible( true );
		return $ref->invoke( $this->health );
	}

	// ── get_report() shape ──────────────────────────────────────────────────

	public function test_get_report_includes_every_expected_row(): void {
		$GLOBALS['_wpdb_get_var']     = 0;
		$GLOBALS['_wpdb_get_row']     = null;
		$GLOBALS['_wpdb_get_results'] = array();

		$report = $this->health->get_report();

		foreach ( array( 'enforcement', 'drift', 'certificates', 'dependencies', 'exceptions', 'automation', 'evidence_freshness', 'external_verification' ) as $key ) {
			$this->assertArrayHasKey( $key, $report );
			$this->assertArrayHasKey( 'status', $report[ $key ] );
		}
	}

	// ── enforcement_row() ────────────────────────────────────────────────────
	//
	// Query order (GitHub issue #175, per-surface + exception-awareness):
	// 1. get_results() -- every csp_policy_profiles (surface, mode) row.
	// 2. get_var() -- traffic-control surfaces enforcing.
	// 3. get_var() once per CSP surface (Csp_Surfaces: frontend, admin,
	//    login -- not 'api') NOT already in 'enforce' mode --
	//    Exception_Store::has_active_for('csp_enforce', $surface).

	public function test_enforcement_is_info_when_nothing_is_enforcing(): void {
		$GLOBALS['_wpdb_get_results']   = array(); // No CSP rows -- all 3 CSP surfaces default to report-only.
		$GLOBALS['_wpdb_get_var_queue'] = array( 0, 0, 0, 0 ); // traffic=0, then 3 has_active_for checks (frontend, admin, login all default to false).

		$row = $this->invoke( 'enforcement_row' );

		$this->assertSame( 'info', $row['status'] );
		$this->assertArrayHasKey( 'per_surface', $row );
		$this->assertSame( array( 'frontend', 'admin', 'login' ), array_keys( $row['per_surface'] ) );
		$this->assertStringContainsString( 'CSP enforcing on 0/3 surfaces, Traffic Controls on 0/4', $row['value'] );
	}

	public function test_enforcement_ignores_a_stale_api_csp_profile_row(): void {
		// An older install's 'api' profile row stays in the table, but the
		// REST API isn't a CSP surface, so even an 'enforce' mode there
		// neither counts as CSP enforcing nor appears per surface.
		$GLOBALS['_wpdb_get_results']   = array( array( 'surface' => 'api', 'mode' => 'enforce' ) );
		$GLOBALS['_wpdb_get_var_queue'] = array( 0, 0, 0, 0 );

		$row = $this->invoke( 'enforcement_row' );

		$this->assertSame( 'info', $row['status'] );
		$this->assertArrayNotHasKey( 'api', $row['per_surface'] );
		$this->assertStringContainsString( 'CSP enforcing on 0/3 surfaces', $row['value'] );
	}

	public function test_enforcement_is_pass_when_something_is_enforcing(): void {
		$GLOBALS['_wpdb_get_results']   = array( array( 'surface' => 'frontend', 'mode' => 'enforce' ) );
		$GLOBALS['_wpdb_get_var_queue'] = array( 0, 0, 0 ); // traffic=0, then 2 has_active_for checks (admin/login -- frontend is already enforcing, skipped).

		$row = $this->invoke( 'enforcement_row' );

		$this->assertSame( 'pass', $row['status'] );
		$this->assertSame( 'enforce', $row['per_surface']['frontend']['mode'] );
	}

	public function test_enforcement_names_a_surface_exempted_by_an_active_exception(): void {
		$GLOBALS['_wpdb_get_results']   = array(); // All 3 CSP surfaces default to report-only.
		// traffic=0, then has_active_for() for frontend/admin/login in that
		// order -- only frontend (1) has an active exception.
		$GLOBALS['_wpdb_get_var_queue'] = array( 0, 1, 0, 0 );

		$row = $this->invoke( 'enforcement_row' );

		$this->assertSame( 'info', $row['status'] ); // Still not enforcing -- exemption doesn't fabricate a pass.
		$this->assertStringContainsString( '1 exempted via an active exception', $row['value'] );
		$this->assertTrue( $row['per_surface']['frontend']['exception_active'] );
		$this->assertFalse( $row['per_surface']['admin']['exception_active'] );
	}

	// ── drift_row() ──────────────────────────────────────────────────────────

	public function test_drift_is_info_when_no_baseline_exists(): void {
		$GLOBALS['_wpdb_get_row'] = null;

		$row = $this->invoke( 'drift_row' );

		$this->assertSame( 'info', $row['status'] );
	}

	public function test_drift_is_pass_when_baseline_exists_with_no_open_drift(): void {
		$GLOBALS['_wpdb_get_row']     = array( 'id' => 1, 'is_current' => 1 );
		$GLOBALS['_wpdb_get_results'] = array();

		$row = $this->invoke( 'drift_row' );

		$this->assertSame( 'pass', $row['status'] );
	}

	public function test_drift_is_warning_when_unexplained_items_exist(): void {
		$GLOBALS['_wpdb_get_row']     = array( 'id' => 1, 'is_current' => 1 );
		$GLOBALS['_wpdb_get_results'] = array( array( 'id' => 1 ), array( 'id' => 2 ) );

		$row = $this->invoke( 'drift_row' );

		$this->assertSame( 'warning', $row['status'] );
		$this->assertStringContainsString( '2', $row['value'] );
	}

	// ── certificates_row() ───────────────────────────────────────────────────

	public function test_certificates_is_info_when_none_configured(): void {
		$GLOBALS['_wpdb_get_results'] = array();

		$row = $this->invoke( 'certificates_row' );

		$this->assertSame( 'info', $row['status'] );
	}

	public function test_certificates_is_pass_when_healthy(): void {
		$GLOBALS['_wpdb_get_results'] = array( array( 'not_after' => gmdate( 'Y-m-d H:i:s', time() + ( 60 * DAY_IN_SECONDS ) ) ) );

		$row = $this->invoke( 'certificates_row' );

		$this->assertSame( 'pass', $row['status'] );
	}

	public function test_certificates_is_warning_when_expiring_soon(): void {
		$GLOBALS['_wpdb_get_results'] = array( array( 'not_after' => gmdate( 'Y-m-d H:i:s', time() + ( 5 * DAY_IN_SECONDS ) ) ) );

		$row = $this->invoke( 'certificates_row' );

		$this->assertSame( 'warning', $row['status'] );
	}

	public function test_certificates_is_fail_when_expired(): void {
		$GLOBALS['_wpdb_get_results'] = array( array( 'not_after' => gmdate( 'Y-m-d H:i:s', time() - DAY_IN_SECONDS ) ) );

		$row = $this->invoke( 'certificates_row' );

		$this->assertSame( 'fail', $row['status'] );
	}

	public function test_certificates_expired_takes_priority_over_expiring(): void {
		$GLOBALS['_wpdb_get_results'] = array(
			array( 'not_after' => gmdate( 'Y-m-d H:i:s', time() - DAY_IN_SECONDS ) ),
			array( 'not_after' => gmdate( 'Y-m-d H:i:s', time() + ( 5 * DAY_IN_SECONDS ) ) ),
		);

		$row = $this->invoke( 'certificates_row' );

		$this->assertSame( 'fail', $row['status'] );
	}

	// ── dependencies_row() ───────────────────────────────────────────────────

	public function test_dependencies_is_pass_when_none_unclassified(): void {
		$GLOBALS['_wpdb_get_var'] = 0;

		$this->assertSame( 'pass', $this->invoke( 'dependencies_row' )['status'] );
	}

	public function test_dependencies_is_warning_when_some_unclassified(): void {
		$GLOBALS['_wpdb_get_var_queue'] = array( 3, 0 ); // unclassified=3, drifted=0.

		$this->assertSame( 'warning', $this->invoke( 'dependencies_row' )['status'] );
	}

	public function test_dependencies_fails_when_a_pinned_hash_has_drifted(): void {
		$GLOBALS['_wpdb_get_var_queue'] = array( 0, 2 ); // unclassified=0, drifted=2.

		$row = $this->invoke( 'dependencies_row' );

		$this->assertSame( 'fail', $row['status'] );
		$this->assertStringContainsString( '2 pinned hashes drifted', $row['value'] );
		$this->assertStringContainsString( 'Decide → Dependency Classification', $row['detail'] );
	}

	// ── exceptions_row() ─────────────────────────────────────────────────────

	public function test_exceptions_sums_every_source_including_formal_exceptions_and_is_always_info(): void {
		// ip_allow=1, persistent_blocks=2, dep_exceptions=3, csp_overrides=4,
		// pillar_overrides=5, formal_exceptions=6 (GitHub issue #177's real
		// sam_exceptions table) -- sum 21.
		$GLOBALS['_wpdb_get_var_queue'] = array( 1, 2, 3, 4, 5, 6 );

		$row = $this->invoke( 'exceptions_row' );

		$this->assertSame( 'info', $row['status'] );
		$this->assertStringContainsString( '21', $row['value'] );
		$this->assertStringContainsString( 'Formal exceptions', $row['detail'] );
		$this->assertStringContainsString( '6', $row['detail'] );
	}

	// ── automation_row() ─────────────────────────────────────────────────────

	public function test_automation_reports_not_configured_when_empty(): void {
		$row = $this->invoke( 'automation_row' );

		$this->assertSame( 'info', $row['status'] );
	}

	// ── evidence_freshness_row() ─────────────────────────────────────────────

	public function test_evidence_freshness_is_warning_when_no_scan_has_run(): void {
		$GLOBALS['_wpdb_get_var'] = null;

		$row = $this->invoke( 'evidence_freshness_row' );

		$this->assertSame( 'warning', $row['status'] );
	}

	public function test_evidence_freshness_is_pass_when_recent(): void {
		$GLOBALS['_wpdb_get_var'] = gmdate( 'Y-m-d H:i:s', time() - HOUR_IN_SECONDS );

		$row = $this->invoke( 'evidence_freshness_row' );

		$this->assertSame( 'pass', $row['status'] );
	}

	public function test_evidence_freshness_is_warning_when_stale(): void {
		$GLOBALS['_wpdb_get_var'] = gmdate( 'Y-m-d H:i:s', time() - ( 5 * DAY_IN_SECONDS ) );

		$row = $this->invoke( 'evidence_freshness_row' );

		$this->assertSame( 'warning', $row['status'] );
	}

	// ── external_verification_row() ─────────────────────────────────────────

	public function test_external_verification_is_always_info_and_honest_about_unavailability(): void {
		$row = $this->invoke( 'external_verification_row' );

		$this->assertSame( 'info', $row['status'] );
		$this->assertStringContainsString( 'Not available', $row['value'] );
	}

	// ── Scoring model versioning (GitHub issue #175) ────────────────────────

	public function test_model_version_is_2(): void {
		$this->assertSame( 2, Security_Health::MODEL_VERSION );
	}
}
