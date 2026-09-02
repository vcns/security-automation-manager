<?php
/**
 * Per-detector admin overrides: enabled/disabled, and which control action
 * (Phase 4B, .roadmap/phase4_plan.md -- the "allowed control actions /
 * default action" field .roadmap/phase3_early_plan.md §11's shared detector
 * metadata contract specifies) an administrator wants that detector's
 * matches to trigger.
 *
 * A detector with no row here behaves exactly as it always has: enabled,
 * running its own default_control_action() (which is 'observe' unless the
 * detector class itself declares otherwise) -- this table only ever records
 * an explicit administrator override, mirroring Traffic_Policy_Store's
 * "missing row is never treated as enforcing" rule.
 *
 * A saved control_action is only ever honoured while it remains a member of
 * the detector's own allowed_control_actions() -- an admin can't configure a
 * detector to do something its class doesn't declare itself capable of
 * (e.g. Technology_Mismatch_Detector can never be set to 'enforce', per
 * .roadmap/phase3_early_plan.md §11.1's explicit "reconnaissance signal, not
 * an automatic block signal" guidance -- it never overrides
 * allowed_control_actions() away from the ['observe']-only default).
 */

declare( strict_types=1 );

namespace WP_SAM\Intelligence;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Detector_Policy_Store {

	public const ACTIONS = array( 'observe', 'enforce' );

	/** @return array<string, mixed>|null */
	public function get( string $detector_id ): ?array {
		global $wpdb;
		$table = $wpdb->prefix . 'sam_detector_policies';
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.NotPrepared,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$row = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM {$table} WHERE detector_id = %s", $detector_id ), ARRAY_A );
		return is_array( $row ) ? $row : null;
	}

	/** @return array<int, array<string, mixed>> */
	public function all(): array {
		global $wpdb;
		$table = $wpdb->prefix . 'sam_detector_policies';
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$rows = $wpdb->get_results( "SELECT * FROM {$table} ORDER BY detector_id", ARRAY_A );
		return ! empty( $rows ) ? $rows : array();
	}

	/** Missing row => enabled. Matches every detector's behaviour before this store existed. */
	public function is_enabled( string $detector_id ): bool {
		$row = $this->get( $detector_id );
		return null === $row || ! empty( $row['is_enabled'] );
	}

	/**
	 * Resolves the control action a match from $detector should actually
	 * trigger: an explicit, still-allowed admin override if one is saved,
	 * else the detector's own default.
	 */
	public function control_action_for( Detector $detector ): string {
		$row = $this->get( $detector->id() );
		if ( null !== $row && in_array( (string) $row['control_action'], $detector->allowed_control_actions(), true ) ) {
			return (string) $row['control_action'];
		}
		return $detector->default_control_action();
	}

	/**
	 * Upserts an administrator's enabled/action choice for one detector.
	 * $control_action is only accepted if it's a member of $allowed
	 * (the detector's own allowed_control_actions()) -- silently falls back
	 * to 'observe' otherwise, the same "never accept an escalation the
	 * detector didn't declare itself capable of" rule control_action_for()
	 * enforces on read.
	 */
	public function set( string $detector_id, bool $is_enabled, string $control_action, array $allowed ): bool {
		if ( ! in_array( $control_action, $allowed, true ) ) {
			$control_action = 'observe';
		}

		global $wpdb;
		$table = $wpdb->prefix . 'sam_detector_policies';
		$now   = current_time( 'mysql', true );

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.NotPrepared,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$existing_id = $wpdb->get_var( $wpdb->prepare( "SELECT id FROM {$table} WHERE detector_id = %s", $detector_id ) );

		$data = array(
			'detector_id'    => $detector_id,
			'is_enabled'     => $is_enabled ? 1 : 0,
			'control_action' => $control_action,
			'updated_at'     => $now,
		);

		if ( $existing_id ) {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
			$result = $wpdb->update( $table, $data, array( 'id' => (int) $existing_id ) );
			return false !== $result;
		}

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
		$result = $wpdb->insert( $table, $data );
		return false !== $result;
	}
}
