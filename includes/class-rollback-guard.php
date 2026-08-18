<?php
/**
 * Schema-downgrade detection, pre-migration snapshots, and same-version
 * data restore -- the automatable slice of "rollback." What this class
 * cannot do is swap this plugin's own PHP files back to an older release;
 * that is a WordPress/hosting-level action outside a running plugin's
 * control. See docs/rollback-and-recovery.md for the full picture,
 * including what still requires a manual database backup restore.
 *
 * Three responsibilities:
 *   1. schema_state() -- tells Plugin::maybe_upgrade_db() whether the
 *      installed DB schema is behind, current, or AHEAD of this code's
 *      WP_SAM_DB_VERSION. "Ahead" means older plugin code has been
 *      installed over a database a newer version already migrated -- the
 *      downgrade case. Activator::activate() must never run in that state:
 *      its dbDelta() calls only know how to CREATE/ADD, not remove a
 *      column or table a newer schema added, and its migration functions
 *      (e.g. migrate_tighten_img_src_default()) assume they're moving a
 *      site forward, not backward.
 *   2. snapshot_before_migration() -- captures every row of the
 *      config-state tables (never log/ledger tables -- those are already
 *      preserved by simply never being touched) immediately before a
 *      forward migration runs, so a migration whose data effects turn out
 *      to be unwanted can be undone without reinstalling old code.
 *   3. restore_snapshot() -- restores a snapshot, but only when the
 *      running code's schema version still matches the snapshot's
 *      to_version exactly. A snapshot taken for schema 22 cannot be
 *      safely restored once the code has moved on to schema 24 -- the
 *      newer schema's columns have no snapshotted values to restore, and
 *      guessing at defaults would be exactly the kind of silent, unsafe
 *      behaviour rollback support exists to avoid. That case returns a
 *      clear refusal instead of a partial, silently-wrong restore.
 */

declare( strict_types=1 );

namespace WP_SAM;

use WP_SAM\Modules\Audit_Log;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Rollback_Guard {

	public const DOWNGRADE_OPTION = 'wp_sam_schema_downgrade_detected';

	private const MAX_SNAPSHOTS = 5;

	/**
	 * Config-state tables a snapshot captures and a restore overwrites.
	 * Deliberately excludes every log/ledger-shaped table (violation
	 * reports, scan logs, sam_audit_log itself, sam_policy_change_decisions,
	 * sam_decision_rule_evaluations, sam_processed_events) and
	 * sam_internal_asset_inventory (recomputed automatically from files,
	 * never admin-decided) -- those are preserved simply by never being
	 * part of a restore, which is the correct behaviour for an append-only
	 * or automatically-derived table, not something to snapshot and
	 * overwrite.
	 */
	public const SNAPSHOT_TABLE_SUFFIXES = array(
		'csp_policy_profiles',
		'csp_source_inventory',
		'csp_hash_inventory',
		'sam_pillar_profiles',
		'sam_dependency_inventory',
		'sam_certificates',
	);

	/**
	 * @return string One of 'up_to_date', 'upgrade_needed', 'downgrade_detected'.
	 */
	public static function schema_state(): string {
		$installed = (int) get_option( 'wp_sam_db_version', 0 );
		$code      = (int) WP_SAM_DB_VERSION;

		if ( $installed > $code ) {
			return 'downgrade_detected';
		}
		if ( $installed < $code ) {
			return 'upgrade_needed';
		}
		return 'up_to_date';
	}

	/**
	 * Records that older plugin code is running against a newer database
	 * schema. Idempotent and rate-limited to one audit-log entry per
	 * distinct (installed, code) pair -- this runs on every admin page
	 * load while the mismatch persists, and re-logging identically on
	 * every request would flood the audit log for what is, after the
	 * first detection, an unchanged, already-recorded condition.
	 */
	public static function record_downgrade_detected( int $installed, int $code ): void {
		$existing = get_option( self::DOWNGRADE_OPTION, array() );
		$existing = is_array( $existing ) ? $existing : array();

		if ( ( $existing['installed'] ?? null ) === $installed && ( $existing['code'] ?? null ) === $code ) {
			return; // Already recorded; nothing changed since.
		}

		update_option(
			self::DOWNGRADE_OPTION,
			array(
				'installed'   => $installed,
				'code'        => $code,
				'detected_at' => current_time( 'mysql', true ),
			),
			false
		);

		( new Audit_Log() )->log(
			'rollback',
			'schema_downgrade_detected',
			sprintf(
				'Installed database schema (v%1$d) is newer than the running plugin code (v%2$d). Automatic migration was refused. See the Readiness tab and docs/rollback-and-recovery.md.',
				$installed,
				$code
			),
			'error'
		);
	}

	/**
	 * Clears a previously-recorded downgrade flag once the running code's
	 * version has caught back up to (or past) the schema it was flagged
	 * against -- e.g. the administrator reinstalled the newer version
	 * after investigating. Logs the recovery so it's visible in the same
	 * audit trail as the original detection.
	 */
	public static function clear_downgrade_flag_if_resolved(): void {
		$existing = get_option( self::DOWNGRADE_OPTION, array() );
		if ( ! is_array( $existing ) || empty( $existing ) ) {
			return;
		}

		delete_option( self::DOWNGRADE_OPTION );

		( new Audit_Log() )->log(
			'rollback',
			'schema_downgrade_resolved',
			sprintf(
				'Running plugin code (v%1$d) now matches or exceeds the previously-flagged schema (v%2$d). Downgrade warning cleared.',
				(int) WP_SAM_DB_VERSION,
				(int) ( $existing['installed'] ?? 0 )
			),
			'info'
		);
	}

	/**
	 * Captures the current contents of every SNAPSHOT_TABLE_SUFFIXES table,
	 * before a forward migration is allowed to touch them. Called from
	 * Plugin::maybe_upgrade_db() only when schema_state() === 'upgrade_needed',
	 * i.e. immediately before Activator::activate() runs.
	 */
	public static function snapshot_before_migration( int $from_version, int $to_version ): void {
		global $wpdb;

		$data = array();
		foreach ( self::SNAPSHOT_TABLE_SUFFIXES as $suffix ) {
			$table = $wpdb->prefix . $suffix;
			if ( ! self::table_exists( $table ) ) {
				continue; // Table doesn't exist yet on a fresh install -- nothing to snapshot.
			}

			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			$rows            = $wpdb->get_results( "SELECT * FROM {$table}", ARRAY_A );
			$data[ $suffix ] = is_array( $rows ) ? $rows : array();
		}

		$snapshot_table = $wpdb->prefix . 'sam_migration_snapshots';
		if ( ! self::table_exists( $snapshot_table ) ) {
			return; // v22->v23 upgrade path: the snapshot table itself doesn't exist until this migration creates it.
		}

		$wpdb->insert(
			$snapshot_table,
			array(
				'from_version'  => $from_version,
				'to_version'    => $to_version,
				'snapshot_data' => wp_json_encode( $data ),
				'created_at'    => current_time( 'mysql', true ),
			),
			array( '%d', '%d', '%s', '%s' )
		);

		self::prune_old_snapshots( $snapshot_table );

		( new Audit_Log() )->log(
			'rollback',
			'migration_snapshot_taken',
			sprintf( 'Configuration snapshot captured before migrating schema v%1$d -> v%2$d.', $from_version, $to_version ),
			'info'
		);
	}

	private static function prune_old_snapshots( string $snapshot_table ): void {
		global $wpdb;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$ids = $wpdb->get_col( "SELECT id FROM {$snapshot_table} ORDER BY id DESC" );
		$ids = is_array( $ids ) ? array_map( 'intval', $ids ) : array();

		$to_delete = array_slice( $ids, self::MAX_SNAPSHOTS );
		foreach ( $to_delete as $id ) {
			$wpdb->delete( $snapshot_table, array( 'id' => $id ), array( '%d' ) );
		}
	}

	/**
	 * @return array<int,array{id:int,from_version:int,to_version:int,created_at:string,restorable:bool}>
	 */
	public static function list_snapshots(): array {
		global $wpdb;

		$snapshot_table = $wpdb->prefix . 'sam_migration_snapshots';
		if ( ! self::table_exists( $snapshot_table ) ) {
			return array();
		}

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$rows = $wpdb->get_results( "SELECT id, from_version, to_version, created_at FROM {$snapshot_table} ORDER BY id DESC", ARRAY_A );
		$rows = is_array( $rows ) ? $rows : array();

		$code = (int) WP_SAM_DB_VERSION;

		return array_map(
			static function ( array $row ) use ( $code ): array {
				return array(
					'id'           => (int) $row['id'],
					'from_version' => (int) $row['from_version'],
					'to_version'   => (int) $row['to_version'],
					'created_at'   => (string) $row['created_at'],
					'restorable'   => $code === (int) $row['to_version'],
				);
			},
			$rows
		);
	}

	/**
	 * Restores a snapshot's config-state tables, replacing every current
	 * row in each SNAPSHOT_TABLE_SUFFIXES table with the snapshotted ones.
	 * Refuses -- returning a reason rather than guessing -- when the
	 * running code's schema no longer matches exactly what the snapshot
	 * was taken for.
	 *
	 * @return array{ok:bool, reason?:string, tables_restored?:array<int,string>}
	 */
	public static function restore_snapshot( int $snapshot_id ): array {
		global $wpdb;

		$snapshot_table = $wpdb->prefix . 'sam_migration_snapshots';
		if ( ! self::table_exists( $snapshot_table ) ) {
			return array(
				'ok'     => false,
				'reason' => __( 'No snapshot history exists on this site.', 'security-automation-manager' ),
			);
		}

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.NotPrepared
		$row = $wpdb->get_row(
			// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			$wpdb->prepare( "SELECT to_version, snapshot_data FROM {$snapshot_table} WHERE id = %d", $snapshot_id ),
			ARRAY_A
		);
		if ( empty( $row ) ) {
			return array(
				'ok'     => false,
				'reason' => __( 'That snapshot no longer exists.', 'security-automation-manager' ),
			);
		}

		$snapshot_to_version = (int) $row['to_version'];
		$code_version        = (int) WP_SAM_DB_VERSION;
		if ( $snapshot_to_version !== $code_version ) {
			return array(
				'ok'     => false,
				'reason' => sprintf(
					/* translators: 1: schema version the snapshot was taken for, 2: schema version currently running */
					__( 'This snapshot was taken for schema v%1$d; the running plugin is on schema v%2$d. Restoring across a schema change is not supported automatically -- see docs/rollback-and-recovery.md for the manual recovery process.', 'security-automation-manager' ),
					$snapshot_to_version,
					$code_version
				),
			);
		}

		$data = json_decode( (string) $row['snapshot_data'], true );
		if ( ! is_array( $data ) ) {
			return array(
				'ok'     => false,
				'reason' => __( 'That snapshot is corrupted and cannot be restored.', 'security-automation-manager' ),
			);
		}

		$restored = array();
		foreach ( self::SNAPSHOT_TABLE_SUFFIXES as $suffix ) {
			if ( ! array_key_exists( $suffix, $data ) || ! is_array( $data[ $suffix ] ) ) {
				continue;
			}

			$table = $wpdb->prefix . $suffix;
			if ( ! self::table_exists( $table ) ) {
				continue;
			}

			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			$wpdb->query( "DELETE FROM {$table}" );

			foreach ( $data[ $suffix ] as $snapshotted_row ) {
				if ( ! is_array( $snapshotted_row ) ) {
					continue;
				}
				$wpdb->insert( $table, $snapshotted_row );
			}

			$restored[] = $suffix;
		}

		( new Audit_Log() )->log(
			'rollback',
			'snapshot_restored',
			sprintf( 'Restored configuration snapshot #%1$d (schema v%2$d) covering: %3$s.', $snapshot_id, $snapshot_to_version, implode( ', ', $restored ) ),
			'warning'
		);

		return array(
			'ok'              => true,
			'tables_restored' => $restored,
		);
	}

	private static function table_exists( string $table ): bool {
		global $wpdb;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
		return $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $table ) ) === $table;
	}
}
