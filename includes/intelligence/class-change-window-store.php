<?php
/**
 * CRUD for sam_change_windows: a declared-intent wrapper around the
 * existing baseline/drift machinery (Phase 3J, .roadmap/phase3_early_
 * plan.md §18 Security Change Window).
 *
 * The roadmap describes an eight-step workflow. This class, together with
 * the admin_post handlers that drive it, implements:
 *   1. snapshot current security state    -- records whatever Baseline_
 *      Store::get_current() already is as baseline_id_before; does not
 *      force a fresh capture (an administrator can capture one first via
 *      the existing "Capture baseline" action if they want a precise
 *      starting point).
 *   3. record application changes         -- Change_Log_Store already runs
 *      continuously; nothing new needed.
 *   4. collect new behaviour               -- Event_Store/Request_Observer
 *      already run continuously; nothing new needed.
 *   6. present the delta                   -- close() surfaces every
 *      Drift_Store row first_seen_at at or after the window opened.
 *   7. accept new baseline                 -- left as the existing,
 *      separate "Capture baseline" action; never automatic.
 *   8. rollback point                      -- baseline_id_before remains a
 *      queryable Baseline_Store row (approve() never deletes history), so
 *      it stays available as the pre-window reference.
 * Steps 2 ("increase observation") and 5 ("run external verification") are
 * NOT implemented: step 2 has no concrete lever anywhere else in this
 * codebase to hook (detector sensitivity isn't currently tunable), and
 * step 5 depends on the central verification service Phases 3G/3H were
 * explicitly deferred for. Neither is faked.
 *
 * Only one window can be open at a time -- open() refuses a second one
 * while get_active() would return a row, so "is a change in progress" is
 * always an unambiguous question.
 */

declare( strict_types=1 );

namespace WP_SAM\Intelligence;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Change_Window_Store {

	/** @return array<string, mixed>|null */
	public function get_active(): ?array {
		global $wpdb;
		$table = $wpdb->prefix . 'sam_change_windows';
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$row = $wpdb->get_row( "SELECT * FROM {$table} WHERE status = 'open' ORDER BY opened_at DESC LIMIT 1", ARRAY_A );
		return is_array( $row ) ? $row : null;
	}

	/** @return array<int, array<string, mixed>> */
	public function all(): array {
		global $wpdb;
		$table = $wpdb->prefix . 'sam_change_windows';
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$rows = $wpdb->get_results( "SELECT * FROM {$table} ORDER BY opened_at DESC", ARRAY_A );
		return ! empty( $rows ) ? $rows : array();
	}

	/** Returns the new window's id, or 0 if a window is already open or the description is blank. */
	public function open( string $description, int $admin_id, ?int $duration_hours, ?int $baseline_id_before ): int {
		if ( '' === trim( $description ) || null !== $this->get_active() ) {
			return 0;
		}

		global $wpdb;
		$table = $wpdb->prefix . 'sam_change_windows';
		$now   = current_time( 'mysql', true );

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
		$wpdb->insert(
			$table,
			array(
				'description'        => substr( sanitize_text_field( $description ), 0, 255 ),
				'status'             => 'open',
				'baseline_id_before' => $baseline_id_before,
				'opened_by'          => $admin_id,
				'opened_at'          => $now,
				'closes_at'          => null !== $duration_hours ? gmdate( 'Y-m-d H:i:s', time() + ( $duration_hours * HOUR_IN_SECONDS ) ) : null,
			)
		);

		return (int) $wpdb->insert_id;
	}

	public function close( int $id, int $admin_id, string $note, ?int $baseline_id_after ): bool {
		global $wpdb;
		$table = $wpdb->prefix . 'sam_change_windows';

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
		$result = $wpdb->update(
			$table,
			array(
				'status'            => 'closed',
				'closed_by'         => $admin_id,
				'closed_at'         => current_time( 'mysql', true ),
				'resolution_note'   => sanitize_textarea_field( $note ),
				'baseline_id_after' => $baseline_id_after,
			),
			array(
				'id'     => $id,
				'status' => 'open',
			),
			array( '%s', '%d', '%s', '%s', '%d' ),
			array( '%d', '%s' )
		);
		return false !== $result && $result > 0;
	}
}
