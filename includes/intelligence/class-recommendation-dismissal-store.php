<?php
/**
 * Persistence for "I've seen this recommendation, don't show it again yet"
 * (Phase 4F, .roadmap/phase3_early_plan.md §22).
 *
 * Deliberately the only new table this feature needs. Recommendations are
 * always recomputed live from existing evidence (Pillar_Registry, Certificate_
 * Store, and so on) -- nothing about a recommendation's content is ever
 * persisted here, only an administrator's explicit decision not to act on
 * one yet, with a required reason (matching this codebase's consistent
 * "no silent weakening/dismissal without a reason" convention, e.g.
 * Scanner_Identity_Store::deny(), Exception_Store).
 *
 * A dismissal is not permanent: is_dismissed() compares the stored
 * dismissed_at timestamp against the recommendation's own current
 * evidence_changed_at (the freshest timestamp behind whatever triggered
 * it). If the underlying evidence has changed since the dismissal, the
 * recommendation reopens automatically -- the same "new finding after
 * dismissal reopens the notice" pattern Admin_UI::handle_dismiss_conflicts()
 * already uses for the CSP dashboard's conflict banner, generalised to a
 * per-recommendation key instead of one global option.
 *
 * Not every rule needs this store at all: a recommendation that points at
 * an existing per-item record (an unexplained Drift_Store row, an expiring
 * Exception_Store row) is "dismissed" by acting on that record directly via
 * its own existing page -- it naturally stops being produced by evaluate()
 * once the underlying row's state changes, with no dismissal row needed
 * here. This store only matters for rules with no such underlying row (a
 * quiet, live condition like "CSP frontend has been report-only and quiet
 * for 30 days").
 */

declare( strict_types=1 );

namespace WP_SAM\Intelligence;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Recommendation_Dismissal_Store {

	/**
	 * True when $key is dismissed AND that dismissal is still current --
	 * i.e. no evidence newer than the dismissal has appeared since.
	 */
	public function is_dismissed( string $key, string $evidence_changed_at ): bool {
		$row = $this->get( $key );
		if ( null === $row ) {
			return false;
		}

		return strtotime( (string) $row['dismissed_at'] ) >= strtotime( $evidence_changed_at );
	}

	/** @return array<string, mixed>|null */
	private function get( string $key ): ?array {
		global $wpdb;
		$table = $wpdb->prefix . 'sam_recommendation_dismissals';

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
		$row = $wpdb->get_row(
			$wpdb->prepare(
				// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				"SELECT * FROM {$table} WHERE recommendation_key = %s",
				$key
			),
			ARRAY_A
		);

		return is_array( $row ) ? $row : null;
	}

	/** Requires a non-empty reason -- see class docblock. */
	public function dismiss( string $key, int $user_id, string $reason ): bool {
		if ( '' === trim( $reason ) ) {
			return false;
		}

		global $wpdb;
		$table = $wpdb->prefix . 'sam_recommendation_dismissals';
		$now   = current_time( 'mysql', true );

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.NotPrepared,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$result = $wpdb->query(
			$wpdb->prepare(
				// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				"INSERT INTO {$table} (recommendation_key, dismissed_by, dismissed_at, reason)
				VALUES (%s, %d, %s, %s)
				ON DUPLICATE KEY UPDATE dismissed_by = VALUES(dismissed_by), dismissed_at = VALUES(dismissed_at), reason = VALUES(reason)",
				$key,
				$user_id,
				$now,
				sanitize_textarea_field( $reason )
			)
		);

		return false !== $result;
	}

	/** @return array<int, array<string, mixed>> every stored dismissal, most recent first. */
	public function all(): array {
		global $wpdb;
		$table = $wpdb->prefix . 'sam_recommendation_dismissals';

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$rows = $wpdb->get_results( "SELECT * FROM {$table} ORDER BY dismissed_at DESC", ARRAY_A );

		return ! empty( $rows ) ? $rows : array();
	}
}
