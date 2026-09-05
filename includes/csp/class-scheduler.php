<?php
/**
 * WP Cron integration for scheduled policy rescans.
 *
 * Implements §4.10 of the directive:
 *   - Registers the wp_sam_daily_scan hook.
 *   - Runs Discovery scan, Hash_Manager audit, and Policy_Builder diff.
 *   - Writes results to the scan log via Audit_Log.
 *   - Sends admin email notification on policy changes (optional).
 */

declare( strict_types=1 );

namespace WP_SAM\CSP;

use WP_SAM\Intelligence\Ads_Txt_Store;
use WP_SAM\Intelligence\Agents_Rules_Store;
use WP_SAM\Intelligence\App_Ads_Txt_Store;
use WP_SAM\Intelligence\Baseline_State_Builder;
use WP_SAM\Intelligence\Baseline_Store;
use WP_SAM\Intelligence\Campaign_Detector;
use WP_SAM\Intelligence\Campaign_Store;
use WP_SAM\Intelligence\Change_Log_Store;
use WP_SAM\Intelligence\Drift_Scanner;
use WP_SAM\Intelligence\Drift_Store;
use WP_SAM\Intelligence\Event_Store;
use WP_SAM\Intelligence\Humans_Txt_Store;
use WP_SAM\Intelligence\Robots_Rules_Store;
use WP_SAM\Intelligence\Security_Txt_Store;
use WP_SAM\Intelligence\Tor_Exit_List_Store;
use WP_SAM\Modules\Audit_Log;
use WP_SAM\Modules\Feature_Gate;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Scheduler {

	private Audit_Log $audit;

	public function __construct( Audit_Log $audit ) {
		$this->audit = $audit;
	}

	// ── Bootstrap ─────────────────────────────────────────────────────────────

	public function register(): void {
		add_action( 'wp_sam_daily_scan', array( $this, 'run_daily_scan' ) );
	}

	// ── Scan runner ───────────────────────────────────────────────────────────

	/**
	 * Main cron callback. Performs a full discovery + hash audit cycle.
	 */
	public function run_daily_scan(): void {
		$scan_id = $this->audit->start_scan( 'scheduled' );

		try {
			$plugin   = \WP_SAM\Plugin::instance();
			$gate     = $plugin->gate;
			$hash_mgr = $plugin->hash_manager;

			$discovery = new Discovery( $this->audit, $gate );

			$discovery_results = $discovery->run_scan();

			// Retrieve hashes observed during this request (may be empty on CLI
			// cron runs where no page was rendered and no buffer was flushed).
			// Hash_Manager::retire_stale() is a no-op when the map is empty,
			// which is safe: hashes are retired only when we have positive
			// evidence that the content changed, not on absence of evidence.
			$current_hashes = $hash_mgr->get_captured_hashes();
			$hash_retired   = $hash_mgr->retire_stale( $current_hashes, 'frontend' );

			$results = array(
				'sources_added'   => $discovery_results['sources_added'],
				'sources_removed' => 0,
				'hashes_added'    => 0,
				'hashes_removed'  => $hash_retired,
				'policy_changed'  => $discovery_results['sources_added'] > 0 || $hash_retired > 0,
			);

			$this->audit->finish_scan( $scan_id, $results );
			$this->maybe_notify( $results );
			$this->purge_old_violations();
			$this->purge_old_pillar_violations();
			$this->purge_old_request_events();
			$this->purge_stale_traffic_blocks();
			$hash_mgr->prune_stale_by_age();
			$this->run_drift_scan( $plugin );
			$this->run_campaign_scan();
			$this->refresh_tor_exit_list();
			$this->purge_stale_asn_cache();
			$this->refresh_robots_rules();
			$this->refresh_agents_rules();
			$this->refresh_security_txt();
			$this->refresh_humans_txt();
			$this->refresh_ads_txt();
			$this->refresh_app_ads_txt();

		} catch ( \Throwable $e ) {
			$this->audit->finish_scan( $scan_id, array(), 'failed' );
			$this->audit->log( 'scheduler', 'scan_exception', $e->getMessage(), 'error' );
		}
	}

	/**
	 * Triggers an immediate on-demand scan (§4.11 Manual Rescan).
	 * Called from Admin_UI AJAX handler.
	 *
	 * @return array  Scan result summary.
	 */
	public function run_manual_scan(): array {
		$scan_id = $this->audit->start_scan( 'manual' );

		try {
			$plugin   = \WP_SAM\Plugin::instance();
			$gate     = $plugin->gate;
			$hash_mgr = $plugin->hash_manager;

			$discovery = new Discovery( $this->audit, $gate );

			$dr = $discovery->run_scan();

			// Same rationale as run_daily_scan(): pass the real capture map.
			// If the admin triggered a manual scan from the dashboard, the
			// buffer hooks will have fired during the admin page render and
			// get_captured_hashes() will contain the admin surface's inline blocks.
			$current_hashes = $hash_mgr->get_captured_hashes();
			$hr             = $hash_mgr->retire_stale( $current_hashes, 'frontend' );

			$results = array(
				'sources_added'   => $dr['sources_added'],
				'sources_removed' => 0,
				'hashes_added'    => 0,
				'hashes_removed'  => $hr,
				'policy_changed'  => $dr['sources_added'] > 0 || $hr > 0,
			);

			$this->audit->finish_scan( $scan_id, $results );
			return $results;

		} catch ( \Throwable $e ) {
			$this->audit->finish_scan( $scan_id, array(), 'failed' );
			$this->audit->log( 'scheduler', 'manual_scan_exception', $e->getMessage(), 'error' );
			return array( 'error' => $e->getMessage() );
		}
	}

	// ── Data retention ────────────────────────────────────────────────────────

	/**
	 * Purges violation reports older than wp_sam_violation_retention_days (default 90).
	 * A value of 0 means keep forever. Runs after every daily cron scan (R10).
	 */
	private function purge_old_violations(): void {
		$days = (int) get_option( 'wp_sam_violation_retention_days', 90 );
		if ( $days <= 0 ) {
			return;
		}

		global $wpdb;
		$table   = $wpdb->prefix . 'csp_violation_reports';
		$deleted = $wpdb->query(
			$wpdb->prepare(
				// phpcs:ignore WordPress.DB.DirectDatabaseQuery,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				"DELETE FROM {$table} WHERE reported_at < DATE_SUB(UTC_TIMESTAMP(), INTERVAL %d DAY)",
				$days
			)
		);

		if ( $deleted > 0 ) {
			$this->audit->log(
				'scheduler',
				'violations_purged',
				sprintf( 'Purged %d violation report(s) older than %d days.', $deleted, $days ),
				'info'
			);
		}
	}

	/**
	 * Same retention window as CSP violation reports (wp_sam_violation_retention_days)
	 * -- one retention setting for all violation data, not a second option to configure.
	 */
	private function purge_old_pillar_violations(): void {
		$days = (int) get_option( 'wp_sam_violation_retention_days', 90 );
		if ( $days <= 0 ) {
			return;
		}

		global $wpdb;
		$table   = $wpdb->prefix . 'sam_pillar_violation_reports';
		$deleted = $wpdb->query(
			$wpdb->prepare(
				// phpcs:ignore WordPress.DB.DirectDatabaseQuery,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				"DELETE FROM {$table} WHERE last_seen_at < DATE_SUB(UTC_TIMESTAMP(), INTERVAL %d DAY)",
				$days
			)
		);

		if ( $deleted > 0 ) {
			$this->audit->log(
				'scheduler',
				'pillar_violations_purged',
				sprintf( 'Purged %d pillar violation report(s) older than %d days.', $deleted, $days ),
				'info'
			);
		}
	}

	/**
	 * Same retention window as CSP violation reports and pillar violation
	 * reports (wp_sam_violation_retention_days) -- one retention setting for
	 * all violation/event data, not a new option for the Request Observation
	 * Framework's own table.
	 */
	private function purge_old_request_events(): void {
		$days = (int) get_option( 'wp_sam_violation_retention_days', 90 );
		if ( $days <= 0 ) {
			return;
		}

		global $wpdb;
		$table   = $wpdb->prefix . 'sam_request_events';
		$deleted = $wpdb->query(
			$wpdb->prepare(
				// phpcs:ignore WordPress.DB.DirectDatabaseQuery,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				"DELETE FROM {$table} WHERE last_seen_at < DATE_SUB(UTC_TIMESTAMP(), INTERVAL %d DAY)",
				$days
			)
		);

		if ( $deleted > 0 ) {
			$this->audit->log(
				'scheduler',
				'request_events_purged',
				sprintf( 'Purged %d request observation event(s) older than %d days.', $deleted, $days ),
				'info'
			);
		}
	}

	/**
	 * Deletes non-persistent Traffic_Block_Store rows (Phase 3E) not seen
	 * again within 30 days -- a source that stopped offending shouldn't be
	 * penalised forever. is_persistent = 1 rows are an explicit
	 * administrator decision (Traffic_Block_Store::set_persistent()) and
	 * are never touched here; only Traffic_Block_Store::release() or a
	 * direct admin action can undo one.
	 */
	private function purge_stale_traffic_blocks(): void {
		global $wpdb;
		$table   = $wpdb->prefix . 'sam_traffic_blocks';
		$deleted = $wpdb->query(
			$wpdb->prepare(
				// phpcs:ignore WordPress.DB.DirectDatabaseQuery,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				"DELETE FROM {$table} WHERE is_persistent = 0 AND last_seen_at < DATE_SUB(UTC_TIMESTAMP(), INTERVAL %d DAY)",
				30
			)
		);

		if ( $deleted > 0 ) {
			$this->audit->log(
				'scheduler',
				'traffic_blocks_purged',
				sprintf( 'Purged %d stale traffic block record(s) not seen again within 30 days.', $deleted ),
				'info'
			);
		}
	}

	/**
	 * Diffs current state against the approved baseline, if one exists
	 * (Phase 3F). A no-op when no baseline has ever been approved --
	 * Drift_Scanner::scan() itself reports that rather than this class
	 * needing to check first. Failures here are caught by the outer
	 * try/catch in run_daily_scan() like every other step.
	 */
	private function run_drift_scan( \WP_SAM\Plugin $plugin ): void {
		$scanner = new Drift_Scanner(
			new Baseline_State_Builder( $plugin->policy_builder ),
			new Baseline_Store(),
			new Drift_Store(),
			new Change_Log_Store()
		);
		$result  = $scanner->scan();

		if ( 'scanned' === $result['status'] && $result['drift_count'] > 0 ) {
			$this->audit->log(
				'scheduler',
				'drift_detected',
				sprintf( 'Drift scan found %d difference(s) from the approved baseline.', $result['drift_count'] ),
				'info'
			);
		}
	}

	/**
	 * Correlates recent request-observation events for a possible
	 * coordinated campaign (Phase 3J, §14). Observe-only: never blocks
	 * anything -- see Campaign_Detector's own docblock.
	 */
	private function run_campaign_scan(): void {
		$detector = new Campaign_Detector( new Event_Store(), new Campaign_Store() );
		$result   = $detector->scan();

		if ( $result['campaigns_detected'] > 0 ) {
			$this->audit->log(
				'scheduler',
				'campaign_detected',
				sprintf( 'Campaign scan found %d possible coordinated campaign(s).', $result['campaigns_detected'] ),
				'info'
			);
		}
	}

	/**
	 * Prunes stale sam_asn_cache rows (Phase 4A, second increment). Not a
	 * correctness requirement -- Asn_Lookup_Store::resolve() already
	 * ignores a row past its 30-day TTL and re-resolves it live -- purely
	 * housekeeping so the cache table doesn't grow unbounded over a long
	 * time horizon. Same retention window as request events/violations
	 * (wp_sam_violation_retention_days), not a new option.
	 */
	private function purge_stale_asn_cache(): void {
		$days = (int) get_option( 'wp_sam_violation_retention_days', 90 );
		if ( $days <= 0 ) {
			return;
		}

		global $wpdb;
		$table   = $wpdb->prefix . 'sam_asn_cache';
		$deleted = $wpdb->query(
			$wpdb->prepare(
				// phpcs:ignore WordPress.DB.DirectDatabaseQuery,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				"DELETE FROM {$table} WHERE resolved_at < DATE_SUB(UTC_TIMESTAMP(), INTERVAL %d DAY)",
				$days
			)
		);

		if ( $deleted > 0 ) {
			$this->audit->log(
				'scheduler',
				'asn_cache_purged',
				sprintf( 'Purged %d stale ASN cache entries older than %d days.', $deleted, $days ),
				'info'
			);
		}
	}

	/**
	 * Refreshes the Tor exit-node list (Phase 4A, .roadmap/phase4_plan.md).
	 * A fetch failure is logged but never treated as fatal to the rest of
	 * the daily scan -- Tor_Exit_List_Store::refresh() itself already
	 * guarantees a failed fetch leaves existing data untouched.
	 */
	private function refresh_tor_exit_list(): void {
		$result = ( new Tor_Exit_List_Store() )->refresh();

		$this->audit->log(
			'scheduler',
			'refreshed' === $result['status'] ? 'tor_exit_list_refreshed' : 'tor_exit_list_refresh_failed',
			(string) $result['message'],
			'refreshed' === $result['status'] ? 'info' : 'warning'
		);
	}

	/**
	 * Refreshes this site's own cached robots.txt disallow rules (Phase 4C,
	 * .roadmap/phase4_plan.md -- see Robots_Rules_Store's own docblock). A
	 * fetch failure is logged but never fatal to the rest of the daily
	 * scan -- Robots_Rules_Store::refresh() itself already guarantees a
	 * failed fetch leaves existing cached rules untouched.
	 */
	private function refresh_robots_rules(): void {
		$result = ( new Robots_Rules_Store() )->refresh();

		$this->audit->log(
			'scheduler',
			'refreshed' === $result['status'] ? 'robots_rules_refreshed' : 'robots_rules_refresh_failed',
			(string) $result['message'],
			'refreshed' === $result['status'] ? 'info' : 'warning'
		);
	}

	/**
	 * Refreshes the remaining four well-known files this plugin tracks
	 * alongside robots.txt (Phase 4C extension, user-requested): agents.txt,
	 * security.txt, humans.txt, ads.txt, and app-ads.txt. Same daily cadence
	 * and "never fatal to the rest of the scan" reasoning as refresh_robots_
	 * rules() above -- each store's own refresh() already guarantees a fetch
	 * failure never clears already-cached data.
	 */
	private function refresh_agents_rules(): void {
		$result = ( new Agents_Rules_Store() )->refresh();

		$this->audit->log(
			'scheduler',
			'refreshed' === $result['status'] ? 'agents_rules_refreshed' : 'agents_rules_refresh_failed',
			(string) $result['message'],
			'refreshed' === $result['status'] ? 'info' : 'warning'
		);
	}

	private function refresh_security_txt(): void {
		$result = ( new Security_Txt_Store() )->refresh();

		$this->audit->log(
			'scheduler',
			'refreshed' === $result['status'] ? 'security_txt_refreshed' : 'security_txt_refresh_failed',
			(string) $result['message'],
			'refreshed' === $result['status'] ? 'info' : 'warning'
		);
	}

	private function refresh_humans_txt(): void {
		$result = ( new Humans_Txt_Store() )->refresh();

		$this->audit->log(
			'scheduler',
			'refreshed' === $result['status'] ? 'humans_txt_refreshed' : 'humans_txt_refresh_failed',
			(string) $result['message'],
			'refreshed' === $result['status'] ? 'info' : 'warning'
		);
	}

	private function refresh_ads_txt(): void {
		$result = ( new Ads_Txt_Store() )->refresh();

		$this->audit->log(
			'scheduler',
			'refreshed' === $result['status'] ? 'ads_txt_refreshed' : 'ads_txt_refresh_failed',
			(string) $result['message'],
			'refreshed' === $result['status'] ? 'info' : 'warning'
		);
	}

	private function refresh_app_ads_txt(): void {
		$result = ( new App_Ads_Txt_Store() )->refresh();

		$this->audit->log(
			'scheduler',
			'refreshed' === $result['status'] ? 'app_ads_txt_refreshed' : 'app_ads_txt_refresh_failed',
			(string) $result['message'],
			'refreshed' === $result['status'] ? 'info' : 'warning'
		);
	}

	// ── Notification ──────────────────────────────────────────────────────────

	private function maybe_notify( array $results ): void {
		if ( empty( $results['policy_changed'] ) ) {
			return;
		}
		$email = (string) get_option( 'wp_sam_notify_email', get_option( 'admin_email' ) );
		if ( empty( $email ) || ! is_email( $email ) ) {
			return;
		}
		$subject = sprintf(
			/* translators: %s: site name */
			__( '[%s] CSP Automation: policy changed after scheduled scan', 'vcns-security-automation-manager' ),
			get_bloginfo( 'name' )
		);
		$message = sprintf(
			/* translators: 1: sources added, 2: hashes removed */
			__( "The scheduled CSP rescan completed.\n\nSources added: %1\$d\nHashes retired: %2\$d\n\nReview the dashboard: %3\$s", 'vcns-security-automation-manager' ),
			$results['sources_added'],
			$results['hashes_removed'],
			admin_url( 'admin.php?page=security-automation-manager-dashboard' )
		);
		wp_mail( $email, $subject, $message );
	}
}
