<?php
/**
 * Regression coverage for Audit_Log's admin-notice queue de-duplication.
 *
 * Confirmed in production, 2026-08-21 (staging.alltimetech.co.uk): a
 * recurring hourly condition (hash_budget_exceeded / hash_learning_rate_limited)
 * logged once per hour for several days while nobody visited wp-admin.
 * Since display_admin_notices() only drains the wp_sam_admin_notices
 * queue on an actual admin page load, the entire unattended backlog --
 * 15+ near-identical banners -- appeared at once on the next visit. The
 * fix de-duplicates by component/event so at most one notice per event
 * type is ever queued, always reflecting its most recent occurrence.
 */

declare( strict_types=1 );

use WP_SAM\Modules\Audit_Log;

class AuditLogTest extends PHPUnit\Framework\TestCase {

	protected function setUp(): void {
		wp_test_reset_globals();
	}

	private function queued_notices(): array {
		return get_option( 'wp_sam_admin_notices', array() );
	}

	public function test_a_repeated_event_replaces_the_existing_queued_notice_instead_of_duplicating(): void {
		$audit = new Audit_Log();

		$audit->log( 'policy_builder', 'hash_budget_exceeded', 'Dropped 1056 hash(es).', 'warning' );
		$audit->log( 'policy_builder', 'hash_budget_exceeded', 'Dropped 1085 hash(es).', 'warning' );
		$audit->log( 'policy_builder', 'hash_budget_exceeded', 'Dropped 1115 hash(es).', 'warning' );

		$notices = $this->queued_notices();
		$this->assertCount( 1, $notices, 'three occurrences of the same component/event must collapse into a single queued notice' );
		$this->assertSame( 'Dropped 1115 hash(es).', $notices[0]['detail'], 'the queued notice must reflect the most recent occurrence, not the first' );
	}

	public function test_different_events_are_queued_separately(): void {
		$audit = new Audit_Log();

		$audit->log( 'policy_builder', 'hash_budget_exceeded', 'Dropped 1056 hash(es).', 'warning' );
		$audit->log( 'hash_manager', 'hash_learning_rate_limited', 'Learning paused.', 'warning' );

		$notices = $this->queued_notices();
		$this->assertCount( 2, $notices, 'distinct component/event pairs must not be collapsed into each other' );
	}

	public function test_repeated_events_interleaved_with_a_distinct_event_still_deduplicate(): void {
		$audit = new Audit_Log();

		// Mirrors the production sequence: two recurring events firing in
		// alternation over several hours.
		$audit->log( 'policy_builder', 'hash_budget_exceeded', 'Dropped 1056 hash(es).', 'warning' );
		$audit->log( 'hash_manager', 'hash_learning_rate_limited', 'Learning paused (1st hour).', 'warning' );
		$audit->log( 'policy_builder', 'hash_budget_exceeded', 'Dropped 1085 hash(es).', 'warning' );
		$audit->log( 'hash_manager', 'hash_learning_rate_limited', 'Learning paused (2nd hour).', 'warning' );
		$audit->log( 'policy_builder', 'hash_budget_exceeded', 'Dropped 1115 hash(es).', 'warning' );

		$notices = $this->queued_notices();
		$this->assertCount( 2, $notices, 'only two distinct event types occurred, regardless of how many times each recurred' );

		$by_event = array();
		foreach ( $notices as $notice ) {
			$by_event[ $notice['event'] ] = $notice['detail'];
		}
		$this->assertSame( 'Dropped 1115 hash(es).', $by_event['hash_budget_exceeded'] ?? null );
		$this->assertSame( 'Learning paused (2nd hour).', $by_event['hash_learning_rate_limited'] ?? null );
	}

	public function test_info_severity_is_never_queued(): void {
		$audit = new Audit_Log();

		$audit->log( 'policy_builder', 'some_event', 'Just for the record.', 'info' );

		$this->assertSame( array(), $this->queued_notices() );
	}

	public function test_twenty_distinct_events_are_still_capped(): void {
		$audit = new Audit_Log();

		for ( $i = 0; $i < 25; $i++ ) {
			$audit->log( 'component', "event_{$i}", "detail {$i}", 'warning' );
		}

		$notices = $this->queued_notices();
		$this->assertCount( 20, $notices, 'genuinely distinct event types are still capped at 20 to bound option growth' );
		$this->assertSame( 'event_24', $notices[ count( $notices ) - 1 ]['event'], 'the cap must keep the most recent entries, not the oldest' );
	}
}
