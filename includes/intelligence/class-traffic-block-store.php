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
 *
 * Automatic stages also step back down (effective_stage()): every full
 * STAGE_DECAY_SECONDS without a new violation, counted from when the
 * source's last block ended, takes it one stage lower. Without this, a
 * source that once reached 'extended_block' went straight back to a
 * one-hour block on its very next violation, however long ago the first
 * episode was -- a shared office or mobile-network address could be
 * punished for weeks for one burst.
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

	/** One stage down per quiet hour: a source back at 'extended_block' is fully cleared after four. */
	public const STAGE_DECAY_SECONDS = 3600;

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
	 * The stage this row counts as now, after any decay -- see class
	 * docblock. 'persistent_block' never decays; it changes only through an
	 * administrator's release(). Pure: reads the row, writes nothing, so
	 * anything that judges a source by its stage (record_violation(),
	 * Bot_Classifier) sees the same answer.
	 *
	 * @param array<string, mixed>|null $row A sam_traffic_blocks row.
	 */
	public static function effective_stage( ?array $row, ?int $now = null ): string {
		if ( null === $row ) {
			return 'observe';
		}

		$stage = (string) ( $row['stage'] ?? 'observe' );
		$index = array_search( $stage, self::STAGE_ORDER, true );
		if ( ! empty( $row['is_persistent'] ) || false === $index || 0 === $index || 'persistent_block' === $stage ) {
			return $stage;
		}

		$quiet_since = max( self::to_timestamp( $row['last_seen_at'] ?? null ), self::to_timestamp( $row['blocked_until'] ?? null ) );
		if ( 0 === $quiet_since ) {
			return $stage;
		}

		$steps = intdiv( max( 0, ( $now ?? time() ) - $quiet_since ), self::STAGE_DECAY_SECONDS );

		return self::STAGE_ORDER[ max( 0, $index - $steps ) ];
	}

	/**
	 * Advances this source's stage by one step and returns the updated
	 * row. The step is taken from effective_stage(), so a source that has
	 * been quiet for a while restarts lower down the ladder. A source
	 * already at 'persistent_block' is left untouched (only bookkeeping
	 * fields change) -- see class docblock.
	 *
	 * A loopback or private-network address (Cidr_Matcher::is_local()) is
	 * never escalated and returns an empty array. This is the one path every
	 * automatic escalation takes (rate limits, failed logins, enforce-mode
	 * detectors), so the site's own servers, containers and load balancers
	 * never climb the ladder or show up in the Blocks list.
	 *
	 * @return array<string, mixed>
	 */
	public function record_violation( string $ip, string $surface, string $reason ): array {
		// Also covers addresses declared as this site's own (Own_Address_Store).
		if ( Own_Address_Store::includes( $ip ) ) {
			return array();
		}

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

		$current_index = array_search( self::effective_stage( $existing ), self::STAGE_ORDER, true );
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

	/** A stored UTC 'Y-m-d H:i:s' value as a Unix timestamp, or 0 if empty or unparseable. */
	private static function to_timestamp( mixed $value ): int {
		if ( ! is_string( $value ) || '' === $value ) {
			return 0;
		}
		$timestamp = strtotime( $value . ' UTC' );
		return false === $timestamp ? 0 : $timestamp;
	}

	private function fingerprint( string $ip, string $surface ): string {
		return hash( 'sha256', $ip . '|' . $surface );
	}
}
