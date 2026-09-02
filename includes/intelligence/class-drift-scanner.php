<?php
/**
 * Diffs current state (Baseline_State_Builder) against the current
 * approved baseline (Baseline_Store) and records differences into
 * Drift_Store (Phase 3F, .roadmap/phase3_early_plan.md §19 Baseline and
 * Drift, §17 Change Attribution).
 *
 * Correlation with Change_Log_Store is deliberately worded as
 * correlation, never causation (§17: "must not claim causation where
 * only correlation exists") -- every note here reads as "X occurred
 * around the same time", never "X caused this".
 *
 * scan() with no approved baseline does nothing (no drift without
 * something to diff against) -- it returns a status the caller can use to
 * prompt "capture an initial baseline" rather than silently no-op'ing.
 */

declare( strict_types=1 );

namespace WP_SAM\Intelligence;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Drift_Scanner {

	/** How far back to look for a plausibly-related Change_Log_Store entry. */
	private const CORRELATION_WINDOW_HOURS = 48;

	private Baseline_State_Builder $state_builder;
	private Baseline_Store $baselines;
	private Drift_Store $drifts;
	private Change_Log_Store $change_log;

	public function __construct(
		Baseline_State_Builder $state_builder,
		Baseline_Store $baselines,
		Drift_Store $drifts,
		Change_Log_Store $change_log
	) {
		$this->state_builder = $state_builder;
		$this->baselines     = $baselines;
		$this->drifts        = $drifts;
		$this->change_log    = $change_log;
	}

	/** @return array{status:string, drift_count:int} */
	public function scan(): array {
		$baseline = $this->baselines->get_current();
		if ( null === $baseline ) {
			return array(
				'status'      => 'no_baseline',
				'drift_count' => 0,
			);
		}

		$baseline_state = json_decode( (string) $baseline['state_json'], true );
		$baseline_state = is_array( $baseline_state ) ? $baseline_state : array();

		$baseline_map = $this->to_map( $baseline_state );
		$current_map  = $this->to_map( $this->state_builder->build() );

		$all_keys   = array_unique( array_merge( array_keys( $baseline_map ), array_keys( $current_map ) ) );
		$recent_log = $this->change_log->recent( self::CORRELATION_WINDOW_HOURS );

		$drift_count = 0;
		foreach ( $all_keys as $key ) {
			$old                                   = $baseline_map[ $key ] ?? null;
			$new                                   = $current_map[ $key ] ?? null;
			list( $category, $surface, $item_key ) = $this->parse_key( $key );

			$old_value = null !== $old ? (string) $old['value'] : '';
			$new_value = null !== $new ? (string) $new['value'] : '';

			if ( $old_value === $new_value ) {
				$this->drifts->resolve( $category, $surface, $item_key );
				continue;
			}

			list( $risk, $reason ) = $this->classify_risk( $category, $old, $new );
			$correlated            = $this->correlate( $category, $item_key, $recent_log );

			$this->drifts->record( $category, $surface, $item_key, $old_value, $new_value, $risk, $reason, $correlated );
			++$drift_count;
		}

		return array(
			'status'      => 'scanned',
			'drift_count' => $drift_count,
		);
	}

	/**
	 * @param array<int, array{category:string, surface:string, item_key:string, value:string}> $state
	 * @return array<string, array{category:string, surface:string, item_key:string, value:string}>
	 */
	private function to_map( array $state ): array {
		$map = array();
		foreach ( $state as $row ) {
			$key         = $row['category'] . '|' . $row['surface'] . '|' . $row['item_key'];
			$map[ $key ] = $row;
		}
		return $map;
	}

	/** @return array{0:string, 1:string, 2:string} */
	private function parse_key( string $key ): array {
		$parts = explode( '|', $key, 3 );
		return array(
			$parts[0] ?? '',
			$parts[1] ?? '',
			$parts[2] ?? '',
		);
	}

	/** @return array{0:string, 1:string} [risk_level, risk_reason] */
	private function classify_risk( string $category, ?array $old, ?array $current ): array {
		switch ( $category ) {
			case 'core_version':
			case 'plugin_version':
			case 'theme_version':
				return array( 'low', __( 'A version number changed -- typically routine maintenance.', 'vcns-security-automation-manager' ) );

			case 'csp_header':
				return array( 'medium', __( 'The effective Content Security Policy for this surface changed.', 'vcns-security-automation-manager' ) );

			case 'pillar':
				return array( 'medium', __( 'A security header toggle or value changed.', 'vcns-security-automation-manager' ) );

			case 'dependency':
				return null === $old
					? array( 'medium', __( 'A new external script/style origin was observed.', 'vcns-security-automation-manager' ) )
					: array( 'low', __( "An external origin's review classification changed.", 'vcns-security-automation-manager' ) );

			case 'internal_asset':
				return null === $current
					? array( 'medium', __( 'A first-party file this site was tracking no longer exists.', 'vcns-security-automation-manager' ) )
					: array( 'high', __( "A first-party file's integrity hash changed -- confirm this matches an intentional update before dismissing it.", 'vcns-security-automation-manager' ) );

			case 'certificate':
				return array( 'high', __( "This certificate's recorded state changed.", 'vcns-security-automation-manager' ) );

			default:
				return array( 'unknown', '' );
		}
	}

	/**
	 * Worded as correlation only -- see class docblock.
	 *
	 * @param array<int, array<string, mixed>> $recent_log
	 */
	private function correlate( string $category, string $item_key, array $recent_log ): string {
		if ( empty( $recent_log ) ) {
			return '';
		}

		$type_for_category = array(
			'core_version'   => 'core_updated',
			'plugin_version' => array( 'plugin_updated', 'plugin_activated', 'plugin_deactivated' ),
			'theme_version'  => array( 'theme_updated', 'theme_switched' ),
		);

		if ( isset( $type_for_category[ $category ] ) ) {
			$wanted_types = (array) $type_for_category[ $category ];
			foreach ( $recent_log as $entry ) {
				if ( in_array( (string) $entry['change_type'], $wanted_types, true ) && (string) $entry['item_name'] === $item_key ) {
					return $this->format_correlation( $entry );
				}
			}
			return '';
		}

		if ( 'internal_asset' === $category ) {
			foreach ( $recent_log as $entry ) {
				$name = (string) $entry['item_name'];
				if ( '' !== $name && str_contains( $item_key, $name ) ) {
					return $this->format_correlation( $entry );
				}
			}
		}

		// Every other category (csp_header, pillar, dependency, certificate): no
		// direct item-identity match is possible, so only a loose, honestly-
		// hedged note is offered -- never a specific "caused by X" claim.
		$closest = $recent_log[0];
		return sprintf(
			/* translators: %s: human-readable relative time, e.g. "12 minutes ago" */
			__( 'A site change was recorded %s -- see the Change Log to check whether it\'s related.', 'vcns-security-automation-manager' ),
			human_time_diff( strtotime( (string) $closest['occurred_at'] ), time() ) . ' ' . __( 'ago', 'vcns-security-automation-manager' )
		);
	}

	private function format_correlation( array $entry ): string {
		return sprintf(
			/* translators: 1: change type label, 2: human-readable relative time */
			__( 'Correlates with a recorded %1$s %2$s ago.', 'vcns-security-automation-manager' ),
			str_replace( '_', ' ', (string) $entry['change_type'] ),
			human_time_diff( strtotime( (string) $entry['occurred_at'] ), time() )
		);
	}
}
