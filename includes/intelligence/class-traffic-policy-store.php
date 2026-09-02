<?php
/**
 * CRUD for sam_traffic_policies: one row per surface, controlling whether
 * Traffic_Guard only observes or actually enforces (Phase 3E,
 * .roadmap/phase3_early_plan.md §13 Traffic Protection Controls).
 *
 * Every surface seeds in 'observe' mode (Activator::seed_default_traffic_
 * policies()) and stays there until an administrator explicitly switches
 * it -- mirrors the report-only-until-promoted philosophy this plugin
 * already uses for CSP, applied to traffic enforcement.
 */

declare( strict_types=1 );

namespace WP_SAM\Intelligence;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Traffic_Policy_Store {

	public const SURFACES = array( 'frontend', 'admin', 'login', 'api' );

	public const MODES = array( 'observe', 'enforce' );

	/** @return array<string, mixed>|null */
	public function get( string $surface ): ?array {
		global $wpdb;
		$table = $wpdb->prefix . 'sam_traffic_policies';
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.NotPrepared,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$row = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM {$table} WHERE surface = %s", $surface ), ARRAY_A );
		return is_array( $row ) ? $row : null;
	}

	/** @return array<int, array<string, mixed>> */
	public function all(): array {
		global $wpdb;
		$table = $wpdb->prefix . 'sam_traffic_policies';
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$rows = $wpdb->get_results( "SELECT * FROM {$table} ORDER BY surface", ARRAY_A );
		return ! empty( $rows ) ? $rows : array();
	}

	public function update(
		string $surface,
		string $mode,
		int $rate_limit_max_requests,
		int $rate_limit_window_seconds,
		int $login_max_failed_attempts,
		int $login_lockout_seconds
	): bool {
		if ( ! in_array( $surface, self::SURFACES, true ) || ! in_array( $mode, self::MODES, true ) ) {
			return false;
		}

		global $wpdb;
		$table = $wpdb->prefix . 'sam_traffic_policies';

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
		$result = $wpdb->update(
			$table,
			array(
				'mode'                      => $mode,
				'rate_limit_max_requests'   => max( 1, $rate_limit_max_requests ),
				'rate_limit_window_seconds' => max( 1, $rate_limit_window_seconds ),
				'login_max_failed_attempts' => max( 1, $login_max_failed_attempts ),
				'login_lockout_seconds'     => max( 1, $login_lockout_seconds ),
				'updated_at'                => current_time( 'mysql', true ),
			),
			array( 'surface' => $surface ),
			array( '%s', '%d', '%d', '%d', '%d', '%s' ),
			array( '%s' )
		);
		return false !== $result;
	}

	/** True only when the surface has an explicit 'enforce' row -- a missing row is never treated as enforcing. */
	public function is_enforcing( string $surface ): bool {
		$policy = $this->get( $surface );
		return null !== $policy && 'enforce' === ( $policy['mode'] ?? '' );
	}
}
