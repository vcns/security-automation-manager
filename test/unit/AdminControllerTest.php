<?php
/**
 * Unit tests for WP_SAM\Rest\Admin_Controller's CSP listings: only CSP's own
 * surfaces (Csp_Surfaces) are listed -- an older install's 'api' rows stay
 * in the tables but never appear.
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;
use WP_SAM\CSP\Policy_Version_Manager;
use WP_SAM\Modules\Audit_Log;
use WP_SAM\Rest\Admin_Controller;

class AdminControllerTest extends TestCase {

	private Admin_Controller $controller;

	protected function setUp(): void {
		wp_test_reset_globals();
		$this->controller = new Admin_Controller(
			$this->createMock( Audit_Log::class ),
			$this->createMock( Policy_Version_Manager::class )
		);
	}

	public function test_list_policies_skips_a_stale_api_profile_row(): void {
		$GLOBALS['_wpdb_get_results_queue'] = array(
			array(
				array( 'surface' => 'admin', 'mode' => 'report-only' ),
				array( 'surface' => 'api', 'mode' => 'report-only' ),
				array( 'surface' => 'frontend', 'mode' => 'enforce' ),
			),
		);

		$policies = $this->controller->list_policies()->get_data()['policies'];

		$this->assertSame( array( 'admin', 'frontend' ), array_column( $policies, 'surface' ) );
	}

	public function test_list_pending_reviews_is_scoped_to_csp_surfaces(): void {
		$this->controller->list_pending_reviews();

		$this->assertStringContainsString(
			"WHERE approval_state = 'pending' AND surface IN ('frontend', 'admin', 'login')",
			(string) $GLOBALS['_wpdb_last_get_results_query']
		);
	}
}
