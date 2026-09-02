<?php
/**
 * CRUD for sam_drift_records: differences Drift_Scanner found between the
 * current approved baseline and current state (Phase 3F,
 * .roadmap/phase3_early_plan.md §19 Baseline and Drift).
 *
 * record() upserts on a fingerprint of (category, surface, item_key) only
 * -- not the value -- so a repeatedly-changing item updates the same row
 * (new_value + last_seen_at refreshed, old_value stays anchored to what
 * the baseline actually said) instead of accumulating a new row every
 * scan. disposition() is the only way an administrator's review gets
 * recorded; resolve() is the only way a row is ever marked 'resolved',
 * and only Drift_Scanner calls it, when a previously-drifted item reverts
 * to match the baseline again.
 */

declare( strict_types=1 );

namespace WP_SAM\Intelligence;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Drift_Store {

	public const DISPOSITIONS = array( 'unexplained', 'expected', 'approved', 'resolved' );

	public const RISK_LEVELS = array( 'low', 'medium', 'high', 'critical', 'unknown' );

	/** @return array<int, array<string, mixed>> */
	public function all( string $disposition_filter = '' ): array {
		global $wpdb;
		$table = $wpdb->prefix . 'sam_drift_records';

		if ( '' !== $disposition_filter && in_array( $disposition_filter, self::DISPOSITIONS, true ) ) {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.NotPrepared,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			$rows = $wpdb->get_results(
				$wpdb->prepare(
					// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
					"SELECT * FROM {$table} WHERE disposition = %s ORDER BY risk_level = 'critical' DESC, risk_level = 'high' DESC, last_seen_at DESC",
					$disposition_filter
				),
				ARRAY_A
			);
		} else {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			$rows = $wpdb->get_results( "SELECT * FROM {$table} ORDER BY risk_level = 'critical' DESC, risk_level = 'high' DESC, last_seen_at DESC", ARRAY_A );
		}

		return ! empty( $rows ) ? $rows : array();
	}

	public function record(
		string $category,
		string $surface,
		string $item_key,
		string $old_value,
		string $new_value,
		string $risk_level,
		string $risk_reason,
		string $correlated_change
	): void {
		global $wpdb;
		$table       = $wpdb->prefix . 'sam_drift_records';
		$fingerprint = $this->fingerprint( $category, $surface, $item_key );
		$now         = current_time( 'mysql', true );

		if ( ! in_array( $risk_level, self::RISK_LEVELS, true ) ) {
			$risk_level = 'unknown';
		}

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
		$existing_id = $wpdb->get_var(
			$wpdb->prepare(
				// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				"SELECT id FROM {$table} WHERE fingerprint = %s",
				$fingerprint
			)
		);

		if ( $existing_id ) {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
			$wpdb->update(
				$table,
				array(
					'new_value'         => $new_value,
					'risk_level'        => $risk_level,
					'risk_reason'       => $risk_reason,
					'correlated_change' => $correlated_change,
					'last_seen_at'      => $now,
				),
				array( 'id' => (int) $existing_id )
			);
			return;
		}

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
		$wpdb->insert(
			$table,
			array(
				'category'          => $category,
				'surface'           => $surface,
				'item_key'          => substr( $item_key, 0, 191 ),
				'old_value'         => $old_value,
				'new_value'         => $new_value,
				'risk_level'        => $risk_level,
				'risk_reason'       => $risk_reason,
				'correlated_change' => $correlated_change,
				'disposition'       => 'unexplained',
				'fingerprint'       => $fingerprint,
				'first_seen_at'     => $now,
				'last_seen_at'      => $now,
			)
		);
	}

	/** Marks a still-open drift row resolved -- only Drift_Scanner calls this, when an item reverts to match the baseline. */
	public function resolve( string $category, string $surface, string $item_key ): void {
		global $wpdb;
		$table = $wpdb->prefix . 'sam_drift_records';

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
		$wpdb->update(
			$table,
			array( 'disposition' => 'resolved' ),
			array(
				'fingerprint' => $this->fingerprint( $category, $surface, $item_key ),
			)
		);
	}

	public function disposition( int $id, string $disposition, int $admin_id, string $note ): bool {
		if ( ! in_array( $disposition, array( 'expected', 'approved' ), true ) ) {
			return false; // 'unexplained' is the default state, never re-set by an admin; 'resolved' is scanner-only.
		}
		if ( '' === trim( $note ) ) {
			return false;
		}

		global $wpdb;
		$table = $wpdb->prefix . 'sam_drift_records';

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
		$result = $wpdb->update(
			$table,
			array(
				'disposition'      => $disposition,
				'disposition_note' => sanitize_textarea_field( $note ),
				'disposition_by'   => $admin_id,
				'disposition_at'   => current_time( 'mysql', true ),
			),
			array( 'id' => $id ),
			array( '%s', '%s', '%d', '%s' ),
			array( '%d' )
		);
		return false !== $result;
	}

	private function fingerprint( string $category, string $surface, string $item_key ): string {
		return hash( 'sha256', $category . '|' . $surface . '|' . $item_key );
	}
}
