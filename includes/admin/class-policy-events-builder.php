<?php
/**
 * Builds the merged Policy Changes timeline from three heterogeneous sources
 * (decision ledger, policy version snapshots, discovery audit events),
 * pushing filters down to SQL where the underlying column is real and
 * skipping a source query entirely when the active filters can never match it.
 */

declare( strict_types=1 );

namespace WP_SAM\Admin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Policy_Events_Builder {

	/**
	 * Per-source row cap. Not a page size -- a safety valve so an unbounded
	 * scan can't happen. If a source query returns exactly this many rows,
	 * the result is flagged 'truncated' and the caller should disclose it.
	 */
	public const SOURCE_CAP = 5000;

	/**
	 * Runs the (possibly skipped) three source queries per the push-down/skip
	 * matrix, normalises each into the shared event row shape, and returns
	 * [ 'events' => array, 'truncated' => bool ].
	 *
	 * $filters keys (all optional): type[], event[], surface[], directive[],
	 * host, risk[], policy_version, suppression ('' | 'active'), actor[],
	 * detail, when_from, when_to.
	 */
	public static function fetch( \wpdb $wpdb, array $filters ): array {
		$type_labels  = $filters['type'] ?? array();
		$event_labels = $filters['event'] ?? array();
		$surface      = $filters['surface'] ?? array();
		$directive    = $filters['directive'] ?? array();
		$host         = $filters['host'] ?? '';
		$risk         = $filters['risk'] ?? array();
		$policy_ver   = $filters['policy_version'] ?? '';
		$suppression  = $filters['suppression'] ?? '';
		$actor        = $filters['actor'] ?? array();
		$detail       = $filters['detail'] ?? '';
		$when_from    = $filters['when_from'] ?? '';
		$when_to      = $filters['when_to'] ?? '';

		$decision_label  = __( 'Decision', 'vcns-security-automation-manager' );
		$version_label   = __( 'Policy version', 'vcns-security-automation-manager' );
		$discovery_label = __( 'Discovery', 'vcns-security-automation-manager' );
		$snapshot_label  = __( 'Snapshot', 'vcns-security-automation-manager' );

		$run_decisions = empty( $type_labels ) || in_array( $decision_label, $type_labels, true );
		$run_versions  = empty( $type_labels ) || in_array( $version_label, $type_labels, true );
		$run_discovery = empty( $type_labels ) || in_array( $discovery_label, $type_labels, true );

		// Surface only exists on Decision/Policy-version rows; Directive/Host/Risk only exist on Decision rows.
		if ( ! empty( $surface ) ) {
			$run_discovery = false;
		}
		if ( ! empty( $directive ) || '' !== $host || ! empty( $risk ) ) {
			$run_versions  = false;
			$run_discovery = false;
		}
		if ( 'active' === $suppression ) {
			$run_versions = false; // policy-version rows have no suppression concept.
		}

		$decision_actions = array();
		$discovery_events = array();
		if ( ! empty( $event_labels ) ) {
			foreach ( self::DECISION_ACTIONS as $action ) {
				if ( in_array( ucfirst( $action ), $event_labels, true ) ) {
					$decision_actions[] = $action;
				}
			}
			if ( empty( $decision_actions ) ) {
				$run_decisions = false;
			}

			if ( ! in_array( $snapshot_label, $event_labels, true ) ) {
				$run_versions = false;
			}

			foreach ( self::DISCOVERY_EVENTS as $raw_event ) {
				if ( in_array( self::discovery_event_label( $raw_event ), $event_labels, true ) ) {
					$discovery_events[] = $raw_event;
				}
			}
			if ( empty( $discovery_events ) ) {
				$run_discovery = false;
			}
		}

		$events    = array();
		$truncated = false;

		if ( $run_decisions ) {
			array_push(
				$events,
				...self::fetch_decisions( $wpdb, $surface, $directive, $host, $risk, $decision_actions, $policy_ver, $suppression, $actor, $detail, $when_from, $when_to, $truncated )
			);
		}

		if ( $run_versions ) {
			array_push(
				$events,
				...self::fetch_versions( $wpdb, $surface, $policy_ver, $actor, $detail, $when_from, $when_to, $truncated )
			);
		}

		if ( $run_discovery ) {
			array_push(
				$events,
				...self::fetch_discovery( $wpdb, $discovery_events, $suppression, $actor, $detail, $when_from, $when_to, $truncated )
			);
		}

		return array(
			'events'    => $events,
			'truncated' => $truncated,
		);
	}

	/**
	 * In-memory comparator over the merged array. Fields: when, event, type,
	 * actor, surface, directive, host, risk, policy_version, suppression, detail.
	 */
	public static function sort( array $events, string $sort_key, string $dir ): array {
		$field_map = array(
			'when'           => 'created_at',
			'event'          => 'event',
			'type'           => 'type',
			'actor'          => 'actor',
			'surface'        => 'surface',
			'directive'      => 'directive',
			'host'           => 'source',
			'risk'           => 'risk_level',
			'policy_version' => 'policy_version',
			'suppression'    => 'suppression',
			'detail'         => 'detail',
		);

		$field     = $field_map[ $sort_key ] ?? 'created_at';
		$direction = ( 'ASC' === strtoupper( $dir ) ) ? 1 : -1;

		usort(
			$events,
			static function ( array $a, array $b ) use ( $field, $direction ): int {
				return $direction * strcmp( (string) ( $a[ $field ] ?? '' ), (string) ( $b[ $field ] ?? '' ) );
			}
		);

		return $events;
	}

	// ── Per-source fetchers ─────────────────────────────────────────────────────

	private const DECISION_ACTIONS = array( 'approved', 'rejected', 'reverted', 'undone' );
	private const DISCOVERY_EVENTS = array( 'source_proposed', 'proposal_suppressed' );

	private static function discovery_event_label( string $raw_event ): string {
		return 'proposal_suppressed' === $raw_event
			? __( 'Suppressed proposal', 'vcns-security-automation-manager' )
			: __( 'Proposed source', 'vcns-security-automation-manager' );
	}

	private static function fetch_decisions( \wpdb $wpdb, array $surface, array $directive, string $host, array $risk, array $actions, string $policy_ver, string $suppression, array $actor, string $detail, string $when_from, string $when_to, bool &$truncated ): array {
		$where = array( '1=1' );
		$args  = array();

		self::append( $where, $args, Table_Query::multi_select_where( 'surface', $surface ) );
		self::append( $where, $args, Table_Query::multi_select_where( 'directive', $directive ) );
		self::append( $where, $args, Table_Query::like_where( $wpdb, 'source_host', $host ) );
		self::append( $where, $args, Table_Query::multi_select_where( 'risk_level', $risk ) );
		self::append( $where, $args, Table_Query::multi_select_where( 'action', $actions ) );
		self::append( $where, $args, Table_Query::multi_select_where( 'actor_type', $actor ) );
		self::append( $where, $args, Table_Query::like_where( $wpdb, 'reason', $detail ) );
		self::append( $where, $args, Table_Query::date_range_where( 'created_at', $when_from, $when_to ) );
		if ( '' !== $policy_ver ) {
			self::append( $where, $args, Table_Query::like_where( $wpdb, 'CAST(policy_version_id AS CHAR)', $policy_ver ) );
		}
		if ( 'active' === $suppression ) {
			$where[] = 'suppression_active = 1';
		}

		$sql    = "SELECT * FROM {$wpdb->prefix}sam_policy_change_decisions WHERE " . implode( ' AND ', $where ) . ' ORDER BY created_at DESC LIMIT %d';
		$args[] = self::SOURCE_CAP;
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.PreparedSQL.NotPrepared,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$rows = $wpdb->get_results( $wpdb->prepare( $sql, ...$args ), ARRAY_A );
		$rows = ! empty( $rows ) ? $rows : array();
		if ( count( $rows ) === self::SOURCE_CAP ) {
			$truncated = true;
		}

		$events = array();
		foreach ( $rows as $decision ) {
			$events[] = array(
				'created_at'     => (string) $decision['created_at'],
				'event'          => ucfirst( (string) $decision['action'] ),
				'type'           => __( 'Decision', 'vcns-security-automation-manager' ),
				'actor'          => (string) ( $decision['actor_type'] ?? 'administrator' ),
				'surface'        => (string) $decision['surface'],
				'directive'      => (string) $decision['directive'],
				'source'         => (string) $decision['source_host'],
				'risk_level'     => (string) $decision['risk_level'],
				'risk_reason'    => (string) $decision['risk_reason'],
				'policy_version' => ! empty( $decision['policy_version_id'] ) ? (string) $decision['policy_version_id'] : '',
				'suppression'    => ! empty( $decision['suppression_active'] ) ? __( 'Active', 'vcns-security-automation-manager' ) : '',
				'detail'         => (string) $decision['reason'],
			);
		}

		return $events;
	}

	private static function fetch_versions( \wpdb $wpdb, array $surface, string $policy_ver, array $actor, string $detail, string $when_from, string $when_to, bool &$truncated ): array {
		$where = array( '1=1' );
		$args  = array();

		self::append( $where, $args, Table_Query::multi_select_where( 'surface', $surface ) );
		self::append( $where, $args, Table_Query::like_where( $wpdb, 'version_number', $policy_ver ) );
		self::append( $where, $args, Table_Query::date_range_where( 'created_at', $when_from, $when_to ) );

		$sql    = "SELECT id, surface, version_number, mode, trigger_type, trigger_id, software_version, created_at FROM {$wpdb->prefix}sam_policy_versions WHERE " . implode( ' AND ', $where ) . ' ORDER BY created_at DESC LIMIT %d';
		$args[] = self::SOURCE_CAP;
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.PreparedSQL.NotPrepared,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$rows = $wpdb->get_results( $wpdb->prepare( $sql, ...$args ), ARRAY_A );
		$rows = ! empty( $rows ) ? $rows : array();
		if ( count( $rows ) === self::SOURCE_CAP ) {
			$truncated = true;
		}

		$events = array();
		foreach ( $rows as $version ) {
			$actor_label = 'decision' === (string) $version['trigger_type'] ? __( 'system', 'vcns-security-automation-manager' ) : (string) $version['trigger_type'];
			if ( ! empty( $actor ) && ! in_array( $actor_label, $actor, true ) ) {
				continue;
			}

			$detail_text = sprintf(
				/* translators: 1: policy mode, 2: trigger type, 3: trigger identifier */
				__( 'Captured %1$s policy snapshot from %2$s trigger %3$s.', 'vcns-security-automation-manager' ),
				(string) $version['mode'],
				(string) $version['trigger_type'],
				! empty( $version['trigger_id'] ) ? '#' . (string) $version['trigger_id'] : __( 'without an ID', 'vcns-security-automation-manager' )
			);
			if ( '' !== $detail && false === stripos( $detail_text, $detail ) ) {
				continue;
			}

			$events[] = array(
				'created_at'     => (string) $version['created_at'],
				'event'          => __( 'Snapshot', 'vcns-security-automation-manager' ),
				'type'           => __( 'Policy version', 'vcns-security-automation-manager' ),
				'actor'          => $actor_label,
				'surface'        => (string) $version['surface'],
				'directive'      => '',
				'source'         => '',
				'risk_level'     => '',
				'risk_reason'    => '',
				'policy_version' => (string) $version['version_number'],
				'suppression'    => '',
				'detail'         => $detail_text,
			);
		}

		return $events;
	}

	private static function fetch_discovery( \wpdb $wpdb, array $events_wanted, string $suppression, array $actor, string $detail, string $when_from, string $when_to, bool &$truncated ): array {
		$where = array( "component = 'policy_change'" );
		$args  = array();

		if ( ! empty( $events_wanted ) ) {
			self::append( $where, $args, Table_Query::multi_select_where( 'event', $events_wanted ) );
		} else {
			$where[] = "event IN ('source_proposed', 'proposal_suppressed')";
		}
		if ( 'active' === $suppression ) {
			$where[] = "event = 'proposal_suppressed'";
		}
		self::append( $where, $args, Table_Query::like_where( $wpdb, 'detail', $detail ) );
		self::append( $where, $args, Table_Query::date_range_where( 'created_at', $when_from, $when_to ) );

		$sql    = "SELECT id, component, event, detail, severity, user_id, created_at FROM {$wpdb->prefix}sam_audit_log WHERE " . implode( ' AND ', $where ) . ' ORDER BY created_at DESC LIMIT %d';
		$args[] = self::SOURCE_CAP;
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.PreparedSQL.NotPrepared,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$rows = $wpdb->get_results( $wpdb->prepare( $sql, ...$args ), ARRAY_A );
		$rows = ! empty( $rows ) ? $rows : array();
		if ( count( $rows ) === self::SOURCE_CAP ) {
			$truncated = true;
		}

		$events = array();
		foreach ( $rows as $audit_event ) {
			$actor_label = empty( $audit_event['user_id'] ) ? __( 'system', 'vcns-security-automation-manager' ) : __( 'administrator', 'vcns-security-automation-manager' );
			if ( ! empty( $actor ) && ! in_array( $actor_label, $actor, true ) ) {
				continue;
			}

			$events[] = array(
				'created_at'     => (string) $audit_event['created_at'],
				'event'          => self::discovery_event_label( (string) $audit_event['event'] ),
				'type'           => __( 'Discovery', 'vcns-security-automation-manager' ),
				'actor'          => $actor_label,
				'surface'        => '',
				'directive'      => '',
				'source'         => '',
				'risk_level'     => '',
				'risk_reason'    => '',
				'policy_version' => '',
				'suppression'    => 'proposal_suppressed' === (string) $audit_event['event'] ? __( 'Active', 'vcns-security-automation-manager' ) : '',
				'detail'         => (string) $audit_event['detail'],
			);
		}

		return $events;
	}

	private static function append( array &$where, array &$args, ?array $fragment ): void {
		if ( null === $fragment ) {
			return;
		}
		$where[] = $fragment['sql'];
		array_push( $args, ...$fragment['args'] );
	}
}
