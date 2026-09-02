<?php
/**
 * Builds the merged Change Attribution timeline from three heterogeneous
 * sources -- site changes (Change_Log_Store), security drift (Drift_Store),
 * and possible campaigns (Campaign_Store) -- normalised into one
 * chronological view (Phase 3J, .roadmap/phase3_early_plan.md §17, extending
 * Phase 3F's original Change Attribution work). Modeled directly on
 * Policy_Events_Builder, which already solves this same "merge several
 * tables into one sorted timeline" problem for the CSP dashboard, but
 * without that class's filter push-down/skip matrix -- three small, capped
 * queries per call is cheap enough here not to need it.
 *
 * Every row's `detail` text is worded as correlation, never causation --
 * "Correlates with X", never "caused by X" -- per the roadmap's explicit
 * "must not claim causation where only correlation exists." A row simply
 * near another row in time is the entire signal; this class draws no
 * stronger conclusion than that ordering.
 */

declare( strict_types=1 );

namespace WP_SAM\Admin;

use WP_SAM\Intelligence\Campaign_Store;
use WP_SAM\Intelligence\Change_Log_Store;
use WP_SAM\Intelligence\Drift_Store;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Change_Timeline_Builder {

	/** Per-source row cap -- a safety valve, not a page size. */
	public const SOURCE_CAP = 200;

	/** @return array<int, array{when:string, type:string, event:string, risk_level:string, detail:string}> */
	public static function fetch( Change_Log_Store $change_log, Drift_Store $drift, Campaign_Store $campaigns ): array {
		$events = array();

		foreach ( $change_log->all( self::SOURCE_CAP ) as $change ) {
			$events[] = array(
				'when'       => (string) $change['occurred_at'],
				'type'       => __( 'Site change', 'vcns-security-automation-manager' ),
				'event'      => self::change_type_label( (string) $change['change_type'] ),
				'risk_level' => '',
				'detail'     => self::change_detail( $change ),
			);
		}

		foreach ( array_slice( $drift->all(), 0, self::SOURCE_CAP ) as $item ) {
			$events[] = array(
				'when'       => (string) $item['first_seen_at'],
				'type'       => __( 'Security drift', 'vcns-security-automation-manager' ),
				'event'      => sprintf(
					/* translators: 1: drift category, 2: item key */
					__( '%1$s changed: %2$s', 'vcns-security-automation-manager' ),
					ucfirst( str_replace( '_', ' ', (string) $item['category'] ) ),
					(string) $item['item_key']
				),
				'risk_level' => (string) $item['risk_level'],
				'detail'     => '' !== (string) $item['correlated_change']
					? (string) $item['correlated_change']
					: __( 'No correlated site change found nearby in time.', 'vcns-security-automation-manager' ),
			);
		}

		foreach ( array_slice( $campaigns->all(), 0, self::SOURCE_CAP ) as $campaign ) {
			$events[] = array(
				'when'       => (string) $campaign['first_detected_at'],
				'type'       => __( 'Possible campaign', 'vcns-security-automation-manager' ),
				'event'      => sprintf(
					/* translators: 1: detector id, 2: surface */
					__( 'Distributed activity against %1$s (%2$s)', 'vcns-security-automation-manager' ),
					(string) $campaign['detector_id'],
					(string) $campaign['surface']
				),
				'risk_level' => 'high',
				'detail'     => sprintf(
					/* translators: %d: number of distinct source IPs */
					__( 'Correlates with %d distinct source IPs against the same detector and surface.', 'vcns-security-automation-manager' ),
					(int) $campaign['participant_count']
				),
			);
		}

		usort(
			$events,
			static fn( array $a, array $b ): int => strcmp( (string) $b['when'], (string) $a['when'] )
		);

		return $events;
	}

	private static function change_type_label( string $change_type ): string {
		$labels = array(
			'plugin_updated'        => __( 'Plugin updated', 'vcns-security-automation-manager' ),
			'plugin_activated'      => __( 'Plugin activated', 'vcns-security-automation-manager' ),
			'plugin_deactivated'    => __( 'Plugin deactivated', 'vcns-security-automation-manager' ),
			'theme_updated'         => __( 'Theme updated', 'vcns-security-automation-manager' ),
			'theme_switched'        => __( 'Theme switched', 'vcns-security-automation-manager' ),
			'core_updated'          => __( 'WordPress core updated', 'vcns-security-automation-manager' ),
			'admin_account_created' => __( 'New administrator account', 'vcns-security-automation-manager' ),
			'admin_role_granted'    => __( 'Administrator role granted', 'vcns-security-automation-manager' ),
		);
		return $labels[ $change_type ] ?? $change_type;
	}

	/** @param array<string, mixed> $change */
	private static function change_detail( array $change ): string {
		$name = (string) $change['item_name'];
		$old  = (string) $change['old_version'];
		$new  = (string) $change['new_version'];

		if ( '' !== $old && '' !== $new ) {
			return sprintf(
				/* translators: 1: item name, 2: old value, 3: new value */
				__( '%1$s: %2$s -> %3$s', 'vcns-security-automation-manager' ),
				$name,
				$old,
				$new
			);
		}

		return $name;
	}
}
