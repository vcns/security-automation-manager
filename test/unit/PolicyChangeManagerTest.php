<?php
/**
 * Unit tests for WP_SAM\CSP\Policy_Change_Manager.
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;
use WP_SAM\CSP\Automation_Config;
use WP_SAM\CSP\Policy_Change_Manager;
use WP_SAM\Modules\Audit_Log;

class PolicyChangeManagerTest extends TestCase {

	private Audit_Log $audit;
	private Policy_Change_Manager $manager;

	protected function setUp(): void {
		wp_test_reset_globals();
		$this->audit   = $this->createMock( Audit_Log::class );
		$this->manager = new Policy_Change_Manager( $this->audit );
	}

	public function test_high_risk_script_source_is_inserted_as_pending_proposal(): void {
		$GLOBALS['_wpdb_get_row_queue'] = array( null, null );

		$result = $this->manager->propose_source(
			'frontend',
			array(
				'directive' => 'script-src',
				'uri'       => 'https://cdn.vendor.example/app.js',
				'scheme'    => 'https',
				'host'      => 'cdn.vendor.example',
			),
			'discovery',
			'crawl',
			'Learned during scan.'
		);

		$this->assertSame( 'added', $result['status'] );
		$this->assertSame( 'high', $result['risk_level'] );
		$this->assertCount( 1, $GLOBALS['_wpdb_inserted_rows'] );

		$insert = $GLOBALS['_wpdb_inserted_rows'][0];
		$this->assertSame( 'wp_csp_source_inventory', $insert['table'] );
		$this->assertSame( 'pending', $insert['data']['approval_state'] );
		$this->assertSame( 'high', $insert['data']['risk_level'] );
		$this->assertSame( 'discovery', $insert['data']['owner_component'] );
		$this->assertSame( 1, $insert['data']['evidence_count'] );
		$this->assertNotEmpty( $insert['data']['decision_fingerprint'] );
	}

	public function test_latest_rejection_suppresses_matching_future_candidate(): void {
		$GLOBALS['_wpdb_get_row'] = array(
			'action'             => 'rejected',
			'suppression_active' => 1,
		);

		$this->assertTrue( $this->manager->is_suppressed( 'frontend', 'script-src', 'cdn.vendor.example' ) );
	}

	public function test_latest_approval_clears_prior_suppression(): void {
		$GLOBALS['_wpdb_get_row'] = array(
			'action'             => 'approved',
			'suppression_active' => 0,
		);

		$this->assertFalse( $this->manager->is_suppressed( 'frontend', 'script-src', 'cdn.vendor.example' ) );
	}

	public function test_decision_reason_is_required_before_source_update(): void {
		$this->assertFalse( $this->manager->approve_source( 7, '   ' ) );

		$this->assertSame( array(), $GLOBALS['_wpdb_updated_rows'] );
		$this->assertSame( array(), $GLOBALS['_wpdb_inserted_rows'] );
	}

	public function test_eligible_source_is_auto_approved_when_surface_automation_is_enabled(): void {
		update_option(
			'wp_sam_automation_config',
			array(
				'frontend' => array(
					'mode'                           => Automation_Config::MODE_AUTOMATIC_MEDIUM_HIGH_APPROVAL,
					'max_automatic_changes_per_scan' => 2,
					'allowed_source_schemes'         => array( 'https' ),
				),
			)
		);

		$GLOBALS['_wpdb_get_row_queue'] = array(
			null,
			null,
			array(
				'id'                   => 1,
				'surface'              => 'frontend',
				'directive'            => 'default-src',
				'source_host'          => 'static.vendor.example',
				'source_uri'           => 'https://static.vendor.example/',
				'source_scheme'        => 'https',
				'approval_state'       => 'pending',
				'decision_fingerprint' => Policy_Change_Manager::fingerprint( 'frontend', 'default-src', 'static.vendor.example' ),
				'risk_level'           => 'low',
				'risk_reason'          => 'Narrow host-source proposal.',
				'evidence_count'       => 1,
			),
			array(
				'id'                   => 1,
				'surface'              => 'frontend',
				'directive'            => 'default-src',
				'source_host'          => 'static.vendor.example',
				'source_uri'           => 'https://static.vendor.example/',
				'source_scheme'        => 'https',
				'approval_state'       => 'pending',
				'decision_fingerprint' => Policy_Change_Manager::fingerprint( 'frontend', 'default-src', 'static.vendor.example' ),
				'risk_level'           => 'low',
				'risk_reason'          => 'Narrow host-source proposal.',
				'evidence_count'       => 1,
			),
			null,
			null,
		);

		$result = $this->manager->propose_source(
			'frontend',
			array(
				'directive' => 'default-src',
				'uri'       => 'https://static.vendor.example/',
				'scheme'    => 'https',
				'host'      => 'static.vendor.example',
			),
			'discovery',
			'crawl',
			'Learned during scan.'
		);

		$this->assertSame( 'auto_approved', $result['status'] );

		$update = $GLOBALS['_wpdb_updated_rows'][0]['data'];
		$this->assertSame( 'approved', $update['approval_state'] );
		$this->assertSame( 'auto_approved', $update['last_decision'] );

		$decision_rows = array_values(
			array_filter(
				$GLOBALS['_wpdb_inserted_rows'],
				static fn( array $row ): bool => 'wp_sam_policy_change_decisions' === $row['table']
			)
		);

		$this->assertCount( 1, $decision_rows );
		$decision = $decision_rows[0]['data'];
		$this->assertSame( 'auto_approved', $decision['action'] );
		$this->assertSame( 'auto_approved', $decision['state'] );
		$this->assertSame( 'automation_engine', $decision['actor_type'] );
		$this->assertSame( 'Automatically approved by the deterministic CSP automation engine.', $decision['reason'] );
	}

	public function test_undo_returns_rejected_source_to_pending_and_clears_suppression(): void {
		$GLOBALS['_wpdb_get_row_queue'] = array(
			array(
				'id'                   => 7,
				'surface'              => 'frontend',
				'directive'            => 'script-src',
				'source_host'          => 'cdn.vendor.example',
				'source_uri'           => 'https://cdn.vendor.example/app.js',
				'approval_state'       => 'denied',
				'last_decision'        => 'rejected',
				'decision_fingerprint' => Policy_Change_Manager::fingerprint( 'frontend', 'script-src', 'cdn.vendor.example' ),
				'risk_level'           => 'high',
				'risk_reason'          => 'script-src can execute remote JavaScript',
			),
			null,
		);
		$GLOBALS['_wpdb_get_var'] = 42;

		$this->assertTrue( $this->manager->undo_source_decision( 7, 'Rejected in error.' ) );

		$this->assertCount( 1, $GLOBALS['_wpdb_updated_rows'] );
		$update = $GLOBALS['_wpdb_updated_rows'][0]['data'];
		$this->assertSame( 'pending', $update['approval_state'] );
		$this->assertSame( 'undone', $update['last_decision'] );
		$this->assertSame( 'Rejected in error.', $update['decision_reason'] );
		$this->assertArrayHasKey( 'approved_at', $update );
		$this->assertNull( $update['approved_at'] );

		$decision_rows = array_values(
			array_filter(
				$GLOBALS['_wpdb_inserted_rows'],
				static fn( array $row ): bool => 'wp_sam_policy_change_decisions' === $row['table']
			)
		);

		$this->assertCount( 1, $decision_rows );
		$decision = $decision_rows[0]['data'];
		$this->assertSame( 'undone', $decision['action'] );
		$this->assertSame( 'pending', $decision['state'] );
		$this->assertSame( 0, $decision['suppression_active'] );
		$this->assertSame( 42, $decision['reverted_decision_id'] );
		$this->assertSame( 'Rejected in error.', $decision['reason'] );
	}

	public function test_undo_returns_approved_source_to_pending(): void {
		$GLOBALS['_wpdb_get_row_queue'] = array(
			array(
				'id'                   => 8,
				'surface'              => 'frontend',
				'directive'            => 'img-src',
				'source_host'          => 'images.vendor.example',
				'source_uri'           => 'https://images.vendor.example/logo.png',
				'approval_state'       => 'approved',
				'last_decision'        => 'approved',
				'decision_fingerprint' => Policy_Change_Manager::fingerprint( 'frontend', 'img-src', 'images.vendor.example' ),
				'risk_level'           => 'low',
				'risk_reason'          => 'img-src has limited execution impact',
			),
			null,
			null,
		);
		$GLOBALS['_wpdb_get_var'] = 43;

		$this->assertTrue( $this->manager->undo_source_decision( 8, 'Approved the wrong image CDN.' ) );

		$update = $GLOBALS['_wpdb_updated_rows'][0]['data'];
		$this->assertSame( 'pending', $update['approval_state'] );
		$this->assertSame( 'undone', $update['last_decision'] );
		$this->assertNull( $update['approved_at'] );

		$decision_rows = array_values(
			array_filter(
				$GLOBALS['_wpdb_inserted_rows'],
				static fn( array $row ): bool => 'wp_sam_policy_change_decisions' === $row['table']
			)
		);

		$this->assertCount( 1, $decision_rows );
		$decision = $decision_rows[0]['data'];
		$this->assertSame( 'undone', $decision['action'] );
		$this->assertSame( 'pending', $decision['state'] );
		$this->assertSame( 0, $decision['suppression_active'] );
		$this->assertSame( 43, $decision['reverted_decision_id'] );
	}

	public function test_revert_marks_source_denied_and_records_suppression_decision(): void {
		$GLOBALS['_wpdb_get_row'] = array(
			'id'                   => 7,
			'surface'              => 'frontend',
			'directive'            => 'connect-src',
			'source_host'          => 'api.vendor.example',
			'source_uri'           => 'https://api.vendor.example/v1',
			'decision_fingerprint' => Policy_Change_Manager::fingerprint( 'frontend', 'connect-src', 'api.vendor.example' ),
			'risk_level'           => 'high',
			'risk_reason'          => 'connect-src can materially change connection behavior',
		);

		$this->assertTrue( $this->manager->revert_source( 7, 'No longer required.' ) );

		$this->assertCount( 1, $GLOBALS['_wpdb_updated_rows'] );
		$this->assertSame( 'wp_csp_source_inventory', $GLOBALS['_wpdb_updated_rows'][0]['table'] );
		$this->assertSame( 'denied', $GLOBALS['_wpdb_updated_rows'][0]['data']['approval_state'] );
		$this->assertSame( 'reverted', $GLOBALS['_wpdb_updated_rows'][0]['data']['last_decision'] );

		$decision_rows = array_values(
			array_filter(
				$GLOBALS['_wpdb_inserted_rows'],
				static fn( array $row ): bool => 'wp_sam_policy_change_decisions' === $row['table']
			)
		);

		$this->assertCount( 1, $decision_rows );
		$decision = $decision_rows[0]['data'];
		$this->assertSame( 'reverted', $decision['action'] );
		$this->assertSame( 'reverted', $decision['state'] );
		$this->assertSame( 'administrator', $decision['actor_type'] );
		$this->assertSame( '1.0.0', $decision['decision_engine_version'] );
		$this->assertSame( 1, $decision['suppression_active'] );
		$this->assertSame( 'No longer required.', $decision['reason'] );
	}
}
