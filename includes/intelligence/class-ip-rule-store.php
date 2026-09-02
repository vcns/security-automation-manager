<?php
/**
 * CRUD and lookup for sam_ip_rules: an administrator-entered CIDR allow/
 * block list (Phase 3E, .roadmap/phase3_early_plan.md §13.3 Firewalling).
 *
 * A deliberate admin decision, so match() applies regardless of the
 * surface's observe/enforce mode -- the same reasoning Scanner_Identity_
 * Store's docblock gives for why an explicit decision is never silently
 * overridden by automatic detection. Traffic_Guard is the only caller that
 * decides what to actually DO with a match; this class only answers
 * "is there a rule for this IP".
 */

declare( strict_types=1 );

namespace WP_SAM\Intelligence;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Ip_Rule_Store {

	public const LIST_TYPES = array( 'block', 'allow' );

	/** @return array<int, array<string, mixed>> */
	public function all(): array {
		global $wpdb;
		$table = $wpdb->prefix . 'sam_ip_rules';
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$rows = $wpdb->get_results( "SELECT * FROM {$table} ORDER BY created_at DESC", ARRAY_A );
		return ! empty( $rows ) ? $rows : array();
	}

	public function add( string $list_type, string $cidr, string $surface, string $reason, int $created_by, ?int $expires_in_seconds = null ): bool {
		if ( ! in_array( $list_type, self::LIST_TYPES, true ) || '' === trim( $cidr ) ) {
			return false;
		}

		global $wpdb;
		$table = $wpdb->prefix . 'sam_ip_rules';
		$now   = current_time( 'mysql', true );

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
		$result = $wpdb->insert(
			$table,
			array(
				'list_type'  => $list_type,
				'cidr'       => sanitize_text_field( $cidr ),
				'surface'    => sanitize_key( $surface ),
				'reason'     => sanitize_textarea_field( $reason ),
				'created_by' => $created_by,
				'created_at' => $now,
				'expires_at' => null !== $expires_in_seconds ? gmdate( 'Y-m-d H:i:s', time() + $expires_in_seconds ) : null,
			)
		);
		return false !== $result;
	}

	public function delete( int $id ): bool {
		global $wpdb;
		$table = $wpdb->prefix . 'sam_ip_rules';

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

	/**
	 * Returns the first matching, non-expired rule for this IP + surface
	 * (rules scoped to '' apply to every surface), or null if none match.
	 * 'block' rules are checked first: an explicit block always wins over
	 * an explicit allow for the same address, since a narrower/later
	 * admin decision to block should never be silently defeated by an
	 * older, broader allow rule.
	 *
	 * @return array<string, mixed>|null
	 */
	public function match( string $ip, string $surface ): ?array {
		$now   = current_time( 'mysql', true );
		$rules = $this->all();

		foreach ( array( 'block', 'allow' ) as $wanted_type ) {
			foreach ( $rules as $rule ) {
				if ( $wanted_type !== $rule['list_type'] ) {
					continue;
				}
				if ( '' !== (string) $rule['surface'] && $surface !== $rule['surface'] ) {
					continue;
				}
				if ( ! empty( $rule['expires_at'] ) && (string) $rule['expires_at'] < $now ) {
					continue;
				}
				if ( Cidr_Matcher::ip_in_cidr( $ip, $this->normalise_cidr( (string) $rule['cidr'] ) ) ) {
					return $rule;
				}
			}
		}

		return null;
	}

	/** Accepts a bare IP (no "/N") as shorthand for an exact-address match. */
	private function normalise_cidr( string $cidr ): string {
		if ( str_contains( $cidr, '/' ) ) {
			return $cidr;
		}
		return str_contains( $cidr, ':' ) ? $cidr . '/128' : $cidr . '/32';
	}
}
