<?php
/**
 * CRUD for sam_campaigns: possible coordinated campaigns Campaign_Detector
 * has correlated from distributed-source request activity (Phase 3J,
 * .roadmap/phase3_early_plan.md §14 Campaign Detection).
 *
 * record() upserts on a fingerprint of (detector_id, surface) -- one row
 * per detector+surface combination currently showing the signal, refreshed
 * on every scan rather than accumulating a new row per scan run.
 *
 * status starts 'detected' (automatic, Campaign_Detector-only) and only
 * ever moves to 'acknowledged', 'dismissed', or 'blocked' via disposition(),
 * an explicit administrator action requiring a note -- same shape as
 * Drift_Store::disposition(). block_participants() is the one action with a
 * real side effect (adding each live participant IP as an explicit
 * sam_ip_rules block), and it is never called automatically -- see the
 * roadmap's explicit "Automatic blocking of a correlated campaign requires
 * explicit opt-in."
 */

declare( strict_types=1 );

namespace WP_SAM\Intelligence;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Campaign_Store {

	public const STATUSES = array( 'detected', 'acknowledged', 'dismissed', 'blocked' );

	/** @return array<int, array<string, mixed>> */
	public function all( string $status_filter = '' ): array {
		global $wpdb;
		$table = $wpdb->prefix . 'sam_campaigns';

		if ( '' !== $status_filter && in_array( $status_filter, self::STATUSES, true ) ) {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.NotPrepared,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			$rows = $wpdb->get_results(
				$wpdb->prepare(
					// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
					"SELECT * FROM {$table} WHERE status = %s ORDER BY last_detected_at DESC",
					$status_filter
				),
				ARRAY_A
			);
		} else {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			$rows = $wpdb->get_results( "SELECT * FROM {$table} ORDER BY last_detected_at DESC", ARRAY_A );
		}

		return ! empty( $rows ) ? $rows : array();
	}

	/** @return array<string, mixed>|null */
	public function get( int $id ): ?array {
		global $wpdb;
		$table = $wpdb->prefix . 'sam_campaigns';

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.NotPrepared,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$row = $wpdb->get_row(
			$wpdb->prepare(
				// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				"SELECT * FROM {$table} WHERE id = %d",
				$id
			),
			ARRAY_A
		);
		return is_array( $row ) ? $row : null;
	}

	public function record( string $detector_id, string $detector_family, string $surface, int $participant_count, int $event_count ): void {
		global $wpdb;
		$table       = $wpdb->prefix . 'sam_campaigns';
		$fingerprint = $this->fingerprint( $detector_id, $surface );
		$now         = current_time( 'mysql', true );

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
					'participant_count' => $participant_count,
					'event_count'       => $event_count,
					'last_detected_at'  => $now,
				),
				array( 'id' => (int) $existing_id )
			);
			return;
		}

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
		$wpdb->insert(
			$table,
			array(
				'detector_id'       => $detector_id,
				'detector_family'   => $detector_family,
				'surface'           => $surface,
				'participant_count' => $participant_count,
				'event_count'       => $event_count,
				'status'            => 'detected',
				'fingerprint'       => $fingerprint,
				'first_detected_at' => $now,
				'last_detected_at'  => $now,
			)
		);
	}

	public function disposition( int $id, string $status, int $admin_id, string $note ): bool {
		if ( ! in_array( $status, array( 'acknowledged', 'dismissed', 'blocked' ), true ) ) {
			return false; // 'detected' is the automatic default, never re-set by an admin.
		}
		if ( '' === trim( $note ) ) {
			return false;
		}

		global $wpdb;
		$table = $wpdb->prefix . 'sam_campaigns';

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
		$result = $wpdb->update(
			$table,
			array(
				'status'           => $status,
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

	private function fingerprint( string $detector_id, string $surface ): string {
		return hash( 'sha256', $detector_id . '|' . $surface );
	}
}
