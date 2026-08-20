<?php
/**
 * Unit tests for WP_SAM\Certificates\Renewal_Scheduler.
 *
 * Renewal_Scheduler itself only wires cron hooks and self-schedules -- it
 * owns none of the "30-day threshold" / "already expired" / "malformed
 * expiry" decision logic (that's Certificate_Store::renewal_due(), tested in
 * CertificateStoreTest.php) and none of the "successful/failed renewal
 * recording" logic (that's Certificate_Manager::record_run(), tested in
 * CertificateManagerTest.php). What's actually testable here is duplicate-
 * scheduling prevention and correct hook wiring.
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;
use WP_SAM\Certificates\Certificate_Manager;
use WP_SAM\Certificates\Certificate_Store;
use WP_SAM\Certificates\Challenge_Http;
use WP_SAM\Certificates\Deployer;
use WP_SAM\Certificates\Renewal_Scheduler;
use WP_SAM\Modules\Audit_Log;

class RenewalSchedulerTest extends TestCase {

	private Renewal_Scheduler $scheduler;

	protected function setUp(): void {
		wp_test_reset_globals();
		$manager = new Certificate_Manager(
			new Certificate_Store(),
			new Challenge_Http(),
			new Deployer( new Audit_Log() ),
			new Audit_Log()
		);
		$this->scheduler = new Renewal_Scheduler( $manager );
	}

	public function test_register_wires_both_hooks(): void {
		$this->scheduler->register();

		$this->assertArrayHasKey( Renewal_Scheduler::ISSUE_HOOK, $GLOBALS['_wp_actions'] );
		$this->assertArrayHasKey( Renewal_Scheduler::RENEWAL_HOOK, $GLOBALS['_wp_actions'] );
	}

	public function test_register_schedules_the_daily_renewal_check_when_not_already_scheduled(): void {
		$this->assertArrayNotHasKey( Renewal_Scheduler::RENEWAL_HOOK, $GLOBALS['_wp_cron'] );

		$this->scheduler->register();

		$this->assertArrayHasKey( Renewal_Scheduler::RENEWAL_HOOK, $GLOBALS['_wp_cron'] );
	}

	public function test_register_does_not_reschedule_when_already_scheduled(): void {
		$GLOBALS['_wp_cron'][ Renewal_Scheduler::RENEWAL_HOOK ] = 12345;

		$this->scheduler->register();

		$this->assertSame( 12345, $GLOBALS['_wp_cron'][ Renewal_Scheduler::RENEWAL_HOOK ], 'an existing schedule must be left untouched, not replaced' );
	}

	public function test_register_heals_a_cleared_cron_table(): void {
		// Simulates a site that updated in place without a deactivate/
		// reactivate cycle, or whose cron table was cleared some other way --
		// register() is called on every plugins_loaded, not just activation.
		unset( $GLOBALS['_wp_cron'][ Renewal_Scheduler::RENEWAL_HOOK ] );

		$this->scheduler->register();

		$this->assertArrayHasKey( Renewal_Scheduler::RENEWAL_HOOK, $GLOBALS['_wp_cron'] );
	}

	// ── Duplicate scheduling prevention: queue_issue_now() ────────────────────

	public function test_queue_issue_now_schedules_a_single_event_when_none_is_pending(): void {
		$this->scheduler->queue_issue_now();

		$this->assertArrayHasKey( Renewal_Scheduler::ISSUE_HOOK, $GLOBALS['_wp_cron'] );
		$this->assertSame( 1, $GLOBALS['_wp_spawn_cron_calls'] );
	}

	public function test_queue_issue_now_does_not_double_schedule(): void {
		$this->scheduler->queue_issue_now();
		$first_timestamp = $GLOBALS['_wp_cron'][ Renewal_Scheduler::ISSUE_HOOK ];

		$this->scheduler->queue_issue_now();

		$this->assertSame( $first_timestamp, $GLOBALS['_wp_cron'][ Renewal_Scheduler::ISSUE_HOOK ], 'a second call before the first event fires must not reschedule' );
		$this->assertSame( 2, $GLOBALS['_wp_spawn_cron_calls'], 'cron is still nudged on every call, even when scheduling itself is a no-op' );
	}
}
