<?php
/**
 * Daily re-check of every pinned third-party file's content against the
 * hash an administrator approved for it.
 *
 * Complements, rather than replaces, Dependency_Integrity_Monitor. That
 * class reads this site's own homepage and compares the markup's integrity
 * attribute with expected_sri -- it catches the markup and SAM disagreeing.
 * It cannot catch the case that breaks sites in practice: a vendor updates
 * a pinned file in place, the markup's integrity attribute and SAM's
 * expected_sri still agree with each other, and every browser silently
 * refuses the new file because its content no longer matches either. Only
 * re-hashing the file itself shows that, which is what this class does.
 *
 * For each 'immutable_pinned' row with an expected_sri, it fetches
 * pinned_url (falling back to last_seen_url for rows pinned before schema
 * v48) through Dependency_Sri_Fetcher -- https only, same origin as the row,
 * 10 second timeout, TLS verified, 5 MB cap -- and hashes it with the same
 * algorithm as expected_sri's prefix:
 *   - match: drift fields cleared, integrity_checked_at set;
 *   - mismatch: drift_detected_at (first detection kept while the row stays
 *     drifted) and drift_observed_sri recorded, and one Audit_Log warning
 *     per newly observed hash (shown as an admin notice linking to
 *     Decide → Dependency Classification);
 *   - fetch failure: recorded only as integrity_check_error, never as
 *     drift -- a vendor outage or a blocked outbound request says nothing
 *     about whether the file changed.
 *
 * Read-and-flag only. Nothing here changes expected_sri or a row's
 * classification; the administrator decides (Admin_UI::
 * ajax_reapprove_dependency_sri(), or reclassifying the row).
 *
 * Bounded: at most MAX_ROWS_PER_RUN rows per run, least recently attempted
 * first, so a large inventory is covered over several days instead of in
 * one long request. Self-scheduling like Intelligence\Exception_Scheduler.
 */

declare( strict_types=1 );

namespace WP_SAM\Security;

use WP_SAM\Modules\Audit_Log;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Pinned_Dependency_Checker {

	public const CHECK_HOOK = 'wp_sam_dependency_hash_check';

	public const MAX_ROWS_PER_RUN = 25;

	/** A row attempted more recently than this is skipped (e.g. a cron double-fire). */
	private const MIN_RECHECK_SECONDS = 20 * HOUR_IN_SECONDS;

	private Audit_Log $audit;

	public function __construct( ?Audit_Log $audit = null ) {
		$this->audit = null !== $audit ? $audit : new Audit_Log();
	}

	public function register(): void {
		add_action( self::CHECK_HOOK, array( $this, 'run_check' ) );

		if ( ! wp_next_scheduled( self::CHECK_HOOK ) ) {
			wp_schedule_event( time() + HOUR_IN_SECONDS, 'daily', self::CHECK_HOOK );
		}
	}

	/**
	 * @return array{checked:int, matched:int, drifted:int, failed:int}
	 */
	public function run_check(): array {
		$summary = array(
			'checked' => 0,
			'matched' => 0,
			'drifted' => 0,
			'failed'  => 0,
		);

		$rows = $this->load_due_rows();
		/** @var array<string, array{ok:bool, hash?:string, error?:string}> $memo per-run cache keyed by algorithm + URL */
		$memo = array();

		foreach ( $rows as $row ) {
			$expected  = trim( (string) ( $row['expected_sri'] ?? '' ) );
			$algorithm = Dependency_Sri_Fetcher::algorithm_of( $expected );
			if ( null === $algorithm ) {
				continue;
			}

			++$summary['checked'];

			$url = trim( (string) ( $row['pinned_url'] ?? '' ) );
			if ( '' === $url ) {
				$url = trim( (string) ( $row['last_seen_url'] ?? '' ) );
			}

			$memo_key = $algorithm . ' ' . $url;
			if ( ! isset( $memo[ $memo_key ] ) ) {
				$memo[ $memo_key ] = Dependency_Sri_Fetcher::fetch_and_hash( $url, (string) $row['origin'], $algorithm );
			}
			$result = $memo[ $memo_key ];

			if ( empty( $result['ok'] ) ) {
				++$summary['failed'];
				$this->record_failure( (int) $row['id'], (string) ( $result['error'] ?? Dependency_Sri_Fetcher::ERROR_FETCH_FAILED ) );
				continue;
			}

			$observed = (string) $result['hash'];
			if ( hash_equals( $expected, $observed ) ) {
				++$summary['matched'];
				$this->record_match( (int) $row['id'] );
				continue;
			}

			++$summary['drifted'];
			$this->record_drift( $row, $url, $observed );
		}

		return $summary;
	}

	/**
	 * Every currently drifted pinned row, for the recommendation rule, the
	 * Security Health summary and the admin page.
	 *
	 * @return array<int, array<string, mixed>>
	 */
	public static function drifted_rows(): array {
		global $wpdb;
		$table = $wpdb->prefix . 'sam_dependency_inventory';
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
		$rows = $wpdb->get_results(
			$wpdb->prepare(
				// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				"SELECT id, surface, resource_type, origin, expected_sri, pinned_url, last_seen_url, drift_detected_at, drift_observed_sri, integrity_checked_at FROM {$table} WHERE classification = %s AND drift_detected_at IS NOT NULL AND drift_observed_sri IS NOT NULL ORDER BY drift_detected_at ASC",
				'immutable_pinned'
			),
			ARRAY_A
		);
		return ! empty( $rows ) ? $rows : array();
	}

	public static function drifted_count(): int {
		global $wpdb;
		$table = $wpdb->prefix . 'sam_dependency_inventory';
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
		return (int) $wpdb->get_var(
			$wpdb->prepare(
				// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				"SELECT COUNT(*) FROM {$table} WHERE classification = %s AND drift_detected_at IS NOT NULL AND drift_observed_sri IS NOT NULL",
				'immutable_pinned'
			)
		);
	}

	// ── Internals ─────────────────────────────────────────────────────────────

	/** @return array<int, array<string, mixed>> */
	private function load_due_rows(): array {
		global $wpdb;
		$table  = $wpdb->prefix . 'sam_dependency_inventory';
		$cutoff = gmdate( 'Y-m-d H:i:s', time() - self::MIN_RECHECK_SECONDS );
		// NULL integrity_attempted_at (never checked) sorts first under ASC in MySQL.
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
		$rows = $wpdb->get_results(
			$wpdb->prepare(
				// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				"SELECT id, surface, resource_type, origin, expected_sri, pinned_url, last_seen_url, drift_detected_at, drift_observed_sri FROM {$table} WHERE classification = %s AND expected_sri IS NOT NULL AND expected_sri <> '' AND ( integrity_attempted_at IS NULL OR integrity_attempted_at < %s ) ORDER BY integrity_attempted_at ASC, id ASC LIMIT %d",
				'immutable_pinned',
				$cutoff,
				self::MAX_ROWS_PER_RUN
			),
			ARRAY_A
		);
		$rows = ! empty( $rows ) ? $rows : array();
		return array_slice( $rows, 0, self::MAX_ROWS_PER_RUN );
	}

	private function record_match( int $id ): void {
		global $wpdb;
		$now = current_time( 'mysql', true );
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- single-row write to this plugin's own table.
		$wpdb->update(
			$wpdb->prefix . 'sam_dependency_inventory',
			array(
				'integrity_checked_at'   => $now,
				'integrity_attempted_at' => $now,
				'integrity_check_error'  => null,
				'drift_detected_at'      => null,
				'drift_observed_sri'     => null,
			),
			array( 'id' => $id ),
			array( '%s', '%s', '%s', '%s', '%s' ),
			array( '%d' )
		);
	}

	private function record_failure( int $id, string $error ): void {
		global $wpdb;
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- single-row write to this plugin's own table.
		$wpdb->update(
			$wpdb->prefix . 'sam_dependency_inventory',
			array(
				'integrity_attempted_at' => current_time( 'mysql', true ),
				'integrity_check_error'  => substr( $error, 0, 64 ),
			),
			array( 'id' => $id ),
			array( '%s', '%s' ),
			array( '%d' )
		);
	}

	/** @param array<string, mixed> $row */
	private function record_drift( array $row, string $url, string $observed ): void {
		global $wpdb;
		$now            = current_time( 'mysql', true );
		$previous_seen  = trim( (string) ( $row['drift_observed_sri'] ?? '' ) );
		$first_detected = trim( (string) ( $row['drift_detected_at'] ?? '' ) );

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- single-row write to this plugin's own table.
		$wpdb->update(
			$wpdb->prefix . 'sam_dependency_inventory',
			array(
				'integrity_checked_at'   => $now,
				'integrity_attempted_at' => $now,
				'integrity_check_error'  => null,
				'drift_detected_at'      => '' !== $first_detected ? $first_detected : $now,
				'drift_observed_sri'     => $observed,
			),
			array( 'id' => (int) $row['id'] ),
			array( '%s', '%s', '%s', '%s', '%s' ),
			array( '%d' )
		);

		// One warning per newly observed hash: not repeated every day while
		// the same drift stays unresolved, but raised again if the vendor
		// changes the file a second time.
		if ( $previous_seen === $observed ) {
			return;
		}

		$vendor = Known_Vendor_Profiles::match( (string) $row['origin'], (string) ( $row['last_seen_url'] ?? '' ), (string) $row['resource_type'] );

		$this->audit->log(
			'dependency_integrity_monitor',
			'pinned_hash_drift',
			sprintf(
				'The pinned %1$s at %2$s (%3$s surface) has changed: it now hashes to %4$s, not the approved %5$s. Browsers enforcing the integrity attribute will refuse to load it. Review it under Decide → Dependency Classification, then re-approve the new hash (and update the integrity attribute in the markup that loads it) or allow this origin by host instead.%6$s',
				(string) $row['resource_type'],
				$url,
				(string) $row['surface'],
				$observed,
				trim( (string) $row['expected_sri'] ),
				null !== $vendor
					? sprintf( ' %s is a known vendor whose files change routinely; allowing it by host is usually the right fix.', $vendor['vendor'] )
					: ''
			),
			'warning'
		);
	}
}
