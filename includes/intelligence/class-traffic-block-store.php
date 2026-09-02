<?php
/**
 * Automatic progressive-response state per (ip, surface) -- Phase 3E,
 * .roadmap/phase3_early_plan.md §13.7 Progressive Response:
 *
 *   observe -> warn -> throttle -> temporary_block -> extended_block -> persistent_block
 *
 * record_violation() advances a source by exactly one stage per call, and
 * never advances past 'extended_block' on its own -- 'persistent_block'
 * (the roadmap's own wording: "administrator-reviewed persistent block")
 * can only ever be set by set_persistent(), called from an explicit admin
 * action. This mirrors Scanner_Identity_Store's separation between
 * automatic recognition and administrator decisions: automatic escalation
 * can make a source's life progressively harder, but only a human can make
 * that permanent.
 */

declare( strict_types=1 );

namespace WP_SAM\Intelligence;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Traffic_Block_Store {

	public const STAGE_ORDER = array( 'observe', 'warn', 'throttle', 'temporary_block', 'extended_block', 'persistent_block' );

	private const TEMPORARY_BLOCK_SECONDS = 900;  // 15 minutes.
	private const EXTENDED_BLOCK_SECONDS  = 3600; // 1 hour.

	/** @return array<string, mixed>|null */
	public function get( string $ip, string $surface ): ?array {
		global $wpdb;
		$table = $wpdb->prefix . 'sam_traffic_blocks';
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.NotPrepared,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$row = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM {$table} WHERE fingerprint = %s", $this->fingerprint( $ip, $surface ) ), ARRAY_A );
		return is_array( $row ) ? $row : null;
	}

	/** @return array<int, array<string, mixed>> */
	public function all_active(): array {
		global $wpdb;
		$table = $wpdb->prefix . 'sam_traffic_blocks';
		$now   = current_time( 'mysql', true );
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.NotPrepared,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$rows = $wpdb->get_results(
			$wpdb->prepare(
				// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				"SELECT * FROM {$table} WHERE is_persistent = 1 OR blocked_until > %s ORDER BY last_seen_at DESC",
				$now
			),
			ARRAY_A
		);
		return ! empty( $rows ) ? $rows : array();
	}

	/**
	 * True while this source is currently in an actively blocking stage:
	 * persistent (always), or temporary/extended with blocked_until still
	 * in the future. 'warn'/'throttle' are never blocking on their own --
	 * Traffic_Guard reads the stage directly for those.
	 */
	public function is_blocked( string $ip, string $surface ): bool {
		$row = $this->get( $ip, $surface );
		if ( null === $row ) {
			return false;
		}
		if ( ! empty( $row['is_persistent'] ) ) {
			return true;
		}
		return ! empty( $row['blocked_until'] ) && (string) $row['blocked_until'] > current_time( 'mysql', true );
	}

	/**
	 * Advances this source's stage by one step and returns the updated
	 * row. A source already at 'persistent_block' is left untouched
	 * (only bookkeeping fields change) -- see class docblock.
	 *
	 * @return array<string, mixed>
	 */
	public function record_violation( string $ip, string $surface, string $reason ): array {
		global $wpdb;
		$table       = $wpdb->prefix . 'sam_traffic_blocks';
		$now         = current_time( 'mysql', true );
		$fingerprint = $this->fingerprint( $ip, $surface );
		$existing    = $this->get( $ip, $surface );

		if ( null === $existing ) {
			$next_stage    = 'warn';
			$blocked_until = null;

			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
			$wpdb->insert(
				$table,
				array(
					'ip'               => $ip,
					'surface'          => $surface,
					'stage'            => $next_stage,
					'reason'           => substr( $reason, 0, 64 ),
					'occurrence_count' => 1,
					'blocked_until'    => $blocked_until,
					'is_persistent'    => 0,
					'fingerprint'      => $fingerprint,
					'first_seen_at'    => $now,
					'last_seen_at'     => $now,
				)
			);

			return $this->get( $ip, $surface ) ?? array();
		}

		if ( ! empty( $existing['is_persistent'] ) ) {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
			$wpdb->update(
				$table,
				array(
					'occurrence_count' => (int) $existing['occurrence_count'] + 1,
					'last_seen_at'     => $now,
				),
				array( 'fingerprint' => $fingerprint )
			);
			return $this->get( $ip, $surface ) ?? $existing;
		}

		$current_index = array_search( $existing['stage'], self::STAGE_ORDER, true );
		$current_index = false !== $current_index ? $current_index : 0;
		$next_index    = min( $current_index + 1, array_search( 'extended_block', self::STAGE_ORDER, true ) );
		$next_stage    = self::STAGE_ORDER[ $next_index ];

		$blocked_until = null;
		if ( 'temporary_block' === $next_stage ) {
			$blocked_until = gmdate( 'Y-m-d H:i:s', time() + self::TEMPORARY_BLOCK_SECONDS );
		} elseif ( 'extended_block' === $next_stage ) {
			$blocked_until = gmdate( 'Y-m-d H:i:s', time() + self::EXTENDED_BLOCK_SECONDS );
		}

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
		$wpdb->update(
			$table,
			array(
				'stage'            => $next_stage,
				'reason'           => substr( $reason, 0, 64 ),
				'occurrence_count' => (int) $existing['occurrence_count'] + 1,
				'blocked_until'    => $blocked_until,
				'last_seen_at'     => $now,
			),
			array( 'fingerprint' => $fingerprint )
		);

		return $this->get( $ip, $surface ) ?? $existing;
	}

	/** Explicit admin action only -- see class docblock. */
	public function set_persistent( int $id, int $admin_id ): bool {
		unset( $admin_id ); // Not stored on this table; the caller's admin action is what's audited.
		global $wpdb;
		$table = $wpdb->prefix . 'sam_traffic_blocks';

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
		$result = $wpdb->update(
			$table,
			array(
				'stage'         => 'persistent_block',
				'is_persistent' => 1,
				'blocked_until' => null,
			),
			array( 'id' => $id ),
			array( '%s', '%d', '%s' ),
			array( '%d' )
		);
		return false !== $result;
	}

	/** Fully releases a block, resetting the source back to 'observe'. */
	public function release( int $id ): bool {
		global $wpdb;
		$table = $wpdb->prefix . 'sam_traffic_blocks';

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
		$result = $wpdb->update(
			$table,
			array(
				'stage'         => 'observe',
				'is_persistent' => 0,
				'blocked_until' => null,
			),
			array( 'id' => $id ),
			array( '%s', '%d', '%s' ),
			array( '%d' )
		);
		return false !== $result;
	}

	private function fingerprint( string $ip, string $surface ): string {
		return hash( 'sha256', $ip . '|' . $surface );
	}
}
