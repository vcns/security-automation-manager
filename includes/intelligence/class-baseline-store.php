<?php
/**
 * CRUD for sam_security_baselines: administrator-approved snapshots of
 * locally-known configuration state (Phase 3F, .roadmap/phase3_early_
 * plan.md §19 Baseline and Drift).
 *
 * Only ever written by approve(), called from an explicit "Capture
 * baseline" admin action -- there is no automatic baseline capture,
 * mirroring this plugin's report-only-until-promoted philosophy
 * elsewhere (CSP's learning window, Traffic Guard's observe/enforce
 * gate). approve() clears is_current on every prior row rather than
 * deleting it, so baseline history stays available for comparison.
 */

declare( strict_types=1 );

namespace WP_SAM\Intelligence;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Baseline_Store {

	/** @return array<string, mixed>|null */
	public function get_current(): ?array {
		global $wpdb;
		$table = $wpdb->prefix . 'sam_security_baselines';
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$row = $wpdb->get_row( "SELECT * FROM {$table} WHERE is_current = 1 LIMIT 1", ARRAY_A );
		return is_array( $row ) ? $row : null;
	}

	/** @return array<int, array<string, mixed>> */
	public function all(): array {
		global $wpdb;
		$table = $wpdb->prefix . 'sam_security_baselines';
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$rows = $wpdb->get_results( "SELECT id, version_number, state_hash, is_current, approved_by, approved_at, note FROM {$table} ORDER BY version_number DESC", ARRAY_A );
		return ! empty( $rows ) ? $rows : array();
	}

	/**
	 * Captures the given state as the new current baseline.
	 *
	 * @param array<int, array{category:string, surface:string, item_key:string, value:string}> $state
	 */
	public function approve( array $state, string $state_hash, int $admin_id, string $note ): int {
		global $wpdb;
		$table = $wpdb->prefix . 'sam_security_baselines';

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$max_version = (int) $wpdb->get_var( "SELECT MAX(version_number) FROM {$table}" );

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$wpdb->query( "UPDATE {$table} SET is_current = 0" );

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
		$wpdb->insert(
			$table,
			array(
				'version_number' => $max_version + 1,
				'state_json'     => wp_json_encode( $state ),
				'state_hash'     => $state_hash,
				'is_current'     => 1,
				'approved_by'    => $admin_id,
				'approved_at'    => current_time( 'mysql', true ),
				'note'           => sanitize_textarea_field( $note ),
			)
		);

		return (int) $wpdb->insert_id;
	}
}
