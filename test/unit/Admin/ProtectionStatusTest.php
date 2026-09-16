<?php
/**
 * Unit tests for WP_SAM\Admin\Protection_Status.
 *
 * areas() calls, in order: csp modes (get_col), Traffic_Policy_Store::all()
 * (get_results #1), Pillar_Registry::fetch_rows() (get_results #2) +
 * unclassified-dependency count (get_var), Baseline_Store::get_current()
 * (get_row #1) + Drift_Store::all('unexplained') (get_results #3),
 * Certificate_Store::get_config() (option) + latest_certificate() (get_row
 * #2, only reached once domains are configured).
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;
use WP_SAM\Admin\Protection_Status;

class ProtectionStatusTest extends TestCase {

	protected function setUp(): void {
		wp_test_reset_globals();
	}

	/** Empty/default fixture: no CSP modes, no traffic policies, no pillar rows, no baseline, no cert config. */
	private function reset_to_fresh_install(): void {
		$GLOBALS['_wpdb_get_col']         = array();
		$GLOBALS['_wpdb_get_results_queue'] = array( array(), array(), array() );
		$GLOBALS['_wpdb_get_var']          = 0;
		$GLOBALS['_wpdb_get_row_queue']    = array( null, null );
	}

	private function areas_by_name( array $areas ): array {
		return array_column( $areas, null, 'area' );
	}

	public function test_fresh_install_is_not_in_use_everywhere(): void {
		$this->reset_to_fresh_install();

		$areas = $this->areas_by_name( ( new Protection_Status() )->areas() );

		$this->assertCount( 5, $areas );
		foreach ( $areas as $area ) {
			$this->assertSame( Protection_Status::STATE_NOT_IN_USE, $area['state'] );
		}
	}

	public function test_csp_enforce_mode_is_protected(): void {
		$this->reset_to_fresh_install();
		$GLOBALS['_wpdb_get_col'] = array( 'report-only', 'enforce' );

		$areas = $this->areas_by_name( ( new Protection_Status() )->areas() );

		$this->assertSame( Protection_Status::STATE_PROTECTED, $areas['Browser and content protection']['state'] );
	}

	public function test_csp_report_only_mode_is_learning(): void {
		$this->reset_to_fresh_install();
		$GLOBALS['_wpdb_get_col'] = array( 'report-only' );

		$areas = $this->areas_by_name( ( new Protection_Status() )->areas() );

		$this->assertSame( Protection_Status::STATE_LEARNING, $areas['Browser and content protection']['state'] );
	}

	public function test_traffic_enforce_is_protected_and_observe_only_is_monitoring(): void {
		$this->reset_to_fresh_install();
		$GLOBALS['_wpdb_get_results_queue'][0] = array( array( 'surface' => 'frontend', 'mode' => 'observe' ) );

		$areas = $this->areas_by_name( ( new Protection_Status() )->areas() );
		$this->assertSame( Protection_Status::STATE_MONITORING, $areas['Malicious traffic']['state'] );

		$this->reset_to_fresh_install();
		$GLOBALS['_wpdb_get_results_queue'][0] = array( array( 'surface' => 'frontend', 'mode' => 'enforce' ) );

		$areas = $this->areas_by_name( ( new Protection_Status() )->areas() );
		$this->assertSame( Protection_Status::STATE_PROTECTED, $areas['Malicious traffic']['state'] );
	}

	public function test_dependency_governance_enabled_with_unclassified_items_needs_attention(): void {
		$this->reset_to_fresh_install();
		$GLOBALS['_wpdb_get_results_queue'][1] = array(
			array(
				'pillar'  => 'dependency-governance',
				'surface' => 'frontend',
				'enabled' => 1,
				'payload' => wp_json_encode( array( 'mode' => 'enforce' ) ),
			),
		);
		$GLOBALS['_wpdb_get_var'] = 3;

		$areas = $this->areas_by_name( ( new Protection_Status() )->areas() );

		$this->assertSame( Protection_Status::STATE_NEEDS_ATTENTION, $areas['Scripts and dependencies']['state'] );
	}

	public function test_dependency_governance_enabled_and_active_with_nothing_unclassified_is_protected(): void {
		$this->reset_to_fresh_install();
		$GLOBALS['_wpdb_get_results_queue'][1] = array(
			array(
				'pillar'  => 'dependency-governance',
				'surface' => 'frontend',
				'enabled' => 1,
				'payload' => wp_json_encode( array( 'mode' => 'enforce' ) ),
			),
		);
		$GLOBALS['_wpdb_get_var'] = 0;

		$areas = $this->areas_by_name( ( new Protection_Status() )->areas() );

		$this->assertSame( Protection_Status::STATE_PROTECTED, $areas['Scripts and dependencies']['state'] );
	}

	public function test_no_baseline_is_not_in_use_for_configuration_integrity(): void {
		$this->reset_to_fresh_install();

		$areas = $this->areas_by_name( ( new Protection_Status() )->areas() );

		$this->assertSame( Protection_Status::STATE_NOT_IN_USE, $areas['Configuration integrity']['state'] );
	}

	public function test_baseline_with_unexplained_drift_needs_attention_and_without_is_protected(): void {
		$this->reset_to_fresh_install();
		$GLOBALS['_wpdb_get_row_queue'][0]      = array( 'id' => 1, 'is_current' => 1 );
		$GLOBALS['_wpdb_get_results_queue'][2]  = array( array( 'id' => 1, 'risk_level' => 'high' ) );

		$areas = $this->areas_by_name( ( new Protection_Status() )->areas() );
		$this->assertSame( Protection_Status::STATE_NEEDS_ATTENTION, $areas['Configuration integrity']['state'] );

		$this->reset_to_fresh_install();
		$GLOBALS['_wpdb_get_row_queue'][0]     = array( 'id' => 1, 'is_current' => 1 );
		$GLOBALS['_wpdb_get_results_queue'][2] = array();

		$areas = $this->areas_by_name( ( new Protection_Status() )->areas() );
		$this->assertSame( Protection_Status::STATE_PROTECTED, $areas['Configuration integrity']['state'] );
	}

	/**
	 * The "missing PHP extension" branch itself (mirrors page-certificates.
	 * php's own identical check) can't be unit-tested without disabling a
	 * real PHP extension at runtime -- not possible in this environment or
	 * CI, and not attempted elsewhere in this codebase either (confirmed:
	 * no existing test exercises that check's true branch). This test only
	 * confirms the ordinary path -- extensions present, as they are here --
	 * still resolves normally rather than always reporting Unavailable.
	 */
	public function test_certificate_area_is_not_unavailable_when_required_extensions_are_present(): void {
		$this->reset_to_fresh_install();

		$areas = $this->areas_by_name( ( new Protection_Status() )->areas() );

		$this->assertNotSame( Protection_Status::STATE_UNAVAILABLE, $areas['TLS certificate']['state'] );
	}

	public function test_no_certificate_domains_configured_is_not_in_use(): void {
		$this->reset_to_fresh_install();

		$areas = $this->areas_by_name( ( new Protection_Status() )->areas() );

		$this->assertSame( Protection_Status::STATE_NOT_IN_USE, $areas['TLS certificate']['state'] );
	}

	public function test_certificate_configured_but_not_yet_issued_is_learning(): void {
		$this->reset_to_fresh_install();
		$GLOBALS['_wp_options']['wp_sam_cert_config'] = array( 'domains' => array( 'example.com' ) );
		$GLOBALS['_wpdb_get_row_queue'][1]            = null;

		$areas = $this->areas_by_name( ( new Protection_Status() )->areas() );

		$this->assertSame( Protection_Status::STATE_LEARNING, $areas['TLS certificate']['state'] );
	}

	public function test_certificate_issued_and_valid_is_protected(): void {
		$this->reset_to_fresh_install();
		$GLOBALS['_wp_options']['wp_sam_cert_config'] = array( 'domains' => array( 'example.com' ) );
		$GLOBALS['_wpdb_get_row_queue'][1]            = array(
			'not_after' => gmdate( 'Y-m-d H:i:s', time() + DAY_IN_SECONDS * 30 ),
			'domains'   => wp_json_encode( array( 'example.com' ) ),
			'key_pem'   => '',
		);

		$areas = $this->areas_by_name( ( new Protection_Status() )->areas() );

		$this->assertSame( Protection_Status::STATE_PROTECTED, $areas['TLS certificate']['state'] );
	}

	public function test_certificate_expired_needs_attention(): void {
		$this->reset_to_fresh_install();
		$GLOBALS['_wp_options']['wp_sam_cert_config'] = array( 'domains' => array( 'example.com' ) );
		$GLOBALS['_wpdb_get_row_queue'][1]            = array(
			'not_after' => gmdate( 'Y-m-d H:i:s', time() - DAY_IN_SECONDS ),
			'domains'   => wp_json_encode( array( 'example.com' ) ),
			'key_pem'   => '',
		);

		$areas = $this->areas_by_name( ( new Protection_Status() )->areas() );

		$this->assertSame( Protection_Status::STATE_NEEDS_ATTENTION, $areas['TLS certificate']['state'] );
	}
}
