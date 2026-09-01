<?php
/**
 * Storage for request-observation events (Request Observation Framework,
 * Layer 3: Continuous Intelligence).
 *
 * Modeled directly on Pillar_Violation_Store: named columns for what's
 * genuinely filterable/sortable (surface, detector_id, detector_family,
 * severity, confidence), a `detail` JSON blob for everything else (IP,
 * user agent, method, path, and any detector-specific evidence) since no
 * detector family exists yet to fix its evidence shape. True upsert on a
 * stable fingerprint, with the same hourly rate-limit guard
 * Pillar_Violation_Store already uses, so a single noisy detector/surface
 * pair can't flood the table.
 *
 * Writes directly to its own table rather than going through Audit_Log --
 * Audit_Log is shaped for low-frequency discrete lifecycle events (it
 * double-writes an admin-notices option and error_log() on every call),
 * wrong for something that can fire on every request.
 */

declare( strict_types=1 );

namespace WP_SAM\Intelligence;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Event_Store {

	private const MAX_PER_HOUR_PER_DETECTOR_SURFACE = 500;
	private const RATE_LIMIT_WINDOW                 = HOUR_IN_SECONDS;
	private const MAX_DETAIL_BYTES                  = 8192;

	private const SEVERITIES = array( 'low', 'medium', 'high', 'critical', 'unknown' );

	/**
	 * @param array<string,mixed> $detail Evidence fields (ip, user agent, method, path, and any
	 *                                    detector-specific data), stored as-is (size-capped) in the
	 *                                    detail JSON column.
	 */
	public function record( string $detector_id, string $detector_family, string $surface, string $severity, ?float $confidence, string $ip, array $detail ): void {
		global $wpdb;
		$table = $wpdb->prefix . 'sam_request_events';

		$detector_id     = sanitize_text_field( substr( $detector_id, 0, 64 ) );
		$detector_family = sanitize_text_field( substr( $detector_family, 0, 64 ) );
		$surface         = in_array( $surface, array( 'frontend', 'admin', 'login', 'api' ), true ) ? $surface : 'frontend';
		$severity        = in_array( $severity, self::SEVERITIES, true ) ? $severity : 'unknown';

		if ( '' === $detector_id || '' === $detector_family ) {
			return;
		}

		$rate_key = 'wp_sam_request_event_rate_' . $detector_id . '_' . $surface;
		$count    = (int) get_transient( $rate_key );
		if ( $count >= self::MAX_PER_HOUR_PER_DETECTOR_SURFACE ) {
			return;
		}
		set_transient( $rate_key, $count + 1, self::RATE_LIMIT_WINDOW );

		$detail_json = wp_json_encode( $detail );
		if ( false === $detail_json ) {
			$detail_json = '{}';
		}
		if ( strlen( $detail_json ) > self::MAX_DETAIL_BYTES ) {
			$detail_json = substr( $detail_json, 0, self::MAX_DETAIL_BYTES );
		}

		$confidence_arg = null !== $confidence ? sprintf( '%.4f', $confidence ) : '';
		$fingerprint    = hash( 'sha256', $detector_id . '|' . $surface . '|' . $ip );
		$now            = current_time( 'mysql', true );

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.NotPrepared,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$wpdb->query(
			$wpdb->prepare(
				// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				"INSERT INTO {$table} (
					surface, detector_id, detector_family, severity, confidence, detail,
					fingerprint, occurrence_count, first_seen_at, last_seen_at
				) VALUES (
					%s, %s, %s, %s, NULLIF(%s, ''), %s,
					%s, %d, %s, %s
				) ON DUPLICATE KEY UPDATE
					occurrence_count = occurrence_count + 1,
					last_seen_at = VALUES(last_seen_at),
					detail = VALUES(detail)",
				$surface,
				$detector_id,
				$detector_family,
				$severity,
				$confidence_arg,
				$detail_json,
				$fingerprint,
				1,
				$now,
				$now
			)
		);
	}
}
