<?php
/**
 * CRUD for sam_honeypaths: an administrator-managed list of decoy paths
 * (Phase 3J, .roadmap/phase3_early_plan.md §15 Deception and Honey Paths).
 *
 * No hit counter lives here -- a request to a configured path is recorded
 * exactly like any other detector Finding, through Event_Store via
 * Detectors\Honeypath_Detector, not a second bookkeeping path. This class
 * only owns the decoy-path configuration itself.
 *
 * The list starts empty on every install/upgrade: disabled by default per
 * the roadmap's explicit requirement, satisfied here simply by never
 * seeding a row -- see Detectors\Honeypath_Detector's own docblock for how
 * an empty list means the detector structurally never matches anything.
 */

declare( strict_types=1 );

namespace WP_SAM\Intelligence;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Honeypath_Store {

	private const MAX_PATHS = 100;

	/** @return array<int, array<string, mixed>> */
	public function all(): array {
		global $wpdb;
		$table = $wpdb->prefix . 'sam_honeypaths';
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$rows = $wpdb->get_results( "SELECT * FROM {$table} ORDER BY created_at DESC", ARRAY_A );
		return ! empty( $rows ) ? $rows : array();
	}

	/** @return array<int, string> Just the configured paths, for Detectors\Honeypath_Detector::rules(). */
	public function paths(): array {
		return array_map(
			static fn( array $row ): string => (string) $row['path'],
			$this->all()
		);
	}

	public function add( string $path, string $description, int $admin_id ): bool {
		$path = '/' . ltrim( sanitize_text_field( $path ), '/' );
		if ( '/' === $path || '' === trim( $path, '/' ) ) {
			return false;
		}
		if ( count( $this->all() ) >= self::MAX_PATHS ) {
			return false;
		}

		global $wpdb;
		$table = $wpdb->prefix . 'sam_honeypaths';

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
		$result = $wpdb->insert(
			$table,
			array(
				'path'        => substr( $path, 0, 255 ),
				'description' => substr( sanitize_text_field( $description ), 0, 255 ),
				'created_by'  => $admin_id,
				'created_at'  => current_time( 'mysql', true ),
			)
		);
		return false !== $result;
	}

	public function delete( int $id ): bool {
		global $wpdb;
		$table = $wpdb->prefix . 'sam_honeypaths';

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
		$result = $wpdb->query(
			$wpdb->prepare(
				// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				"DELETE FROM {$table} WHERE id = %d",
				$id
			)
		);
		return false !== $result && $result > 0;
	}
}
