<?php
/**
 * Storage for sam_change_log: a real event log of WordPress-environment
 * changes (Phase 3F, .roadmap/phase3_early_plan.md §17 Change Attribution)
 * -- which plugin/theme/core changed, and what version it went to.
 *
 * Distinct from Learning_Window, which only stamps a single "something
 * material changed" timestamp to gate CSP source re-learning. This class
 * keeps the actual history Drift_Scanner correlates drift against.
 */

declare( strict_types=1 );

namespace WP_SAM\Intelligence;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Change_Log_Store {

	public const CHANGE_TYPES = array( 'plugin_updated', 'plugin_activated', 'plugin_deactivated', 'theme_updated', 'theme_switched', 'core_updated' );

	public function record( string $change_type, string $item_name, string $old_version, string $new_version ): void {
		if ( ! in_array( $change_type, self::CHANGE_TYPES, true ) ) {
			return;
		}

		global $wpdb;
		$table = $wpdb->prefix . 'sam_change_log';

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
		$wpdb->insert(
			$table,
			array(
				'change_type' => $change_type,
				'item_name'   => substr( $item_name, 0, 191 ),
				'old_version' => substr( $old_version, 0, 64 ),
				'new_version' => substr( $new_version, 0, 64 ),
				'occurred_at' => current_time( 'mysql', true ),
			)
		);
	}

	/** @return array<int, array<string, mixed>> Every change within the last $hours, most recent first. */
	public function recent( int $hours ): array {
		global $wpdb;
		$table = $wpdb->prefix . 'sam_change_log';
		$since = gmdate( 'Y-m-d H:i:s', time() - ( max( 1, $hours ) * HOUR_IN_SECONDS ) );

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.NotPrepared,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$rows = $wpdb->get_results(
			$wpdb->prepare(
				// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				"SELECT * FROM {$table} WHERE occurred_at >= %s ORDER BY occurred_at DESC",
				$since
			),
			ARRAY_A
		);
		return ! empty( $rows ) ? $rows : array();
	}

	/** @return array<int, array<string, mixed>> */
	public function all( int $limit = 100 ): array {
		global $wpdb;
		$table = $wpdb->prefix . 'sam_change_log';

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.NotPrepared,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$rows = $wpdb->get_results(
			$wpdb->prepare(
				// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				"SELECT * FROM {$table} ORDER BY occurred_at DESC LIMIT %d",
				max( 1, $limit )
			),
			ARRAY_A
		);
		return ! empty( $rows ) ? $rows : array();
	}
}
