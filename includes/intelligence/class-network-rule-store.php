<?php
/**
 * CRUD and lookup for sam_network_rules: an administrator-entered ASN/
 * country block list (Phase 4A extension, .roadmap/phase3_early_plan.md
 * §13.3 Firewalling -- the "traffic control filtering" half of Geo-IP/ASN
 * awareness that Phase 4A itself shipped as evidence-only).
 *
 * A deliberate admin decision, so match() applies regardless of the
 * surface's observe/enforce mode -- the same reasoning Ip_Rule_Store's
 * docblock gives for why an explicit decision is never silently overridden
 * by automatic detection. Traffic_Guard is the only caller that decides
 * what to actually DO with a match; this class only answers "is there a
 * rule for this ASN/country".
 *
 * Block-only, deliberately: unlike Ip_Rule_Store there is no 'allow' rule
 * type here. An ASN or country is too coarse a unit to usefully "allow" --
 * a single trusted IP within an otherwise-blocked country already works via
 * a narrower Ip_Rule_Store allow entry, which Traffic_Guard checks first
 * and which always wins.
 */

declare( strict_types=1 );

namespace WP_SAM\Intelligence;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Network_Rule_Store {

	public const RULE_TYPES = array( 'asn', 'country' );

	/** @return array<int, array<string, mixed>> */
	public function all(): array {
		global $wpdb;
		$table = $wpdb->prefix . 'sam_network_rules';
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$rows = $wpdb->get_results( "SELECT * FROM {$table} ORDER BY created_at DESC", ARRAY_A );
		return ! empty( $rows ) ? $rows : array();
	}

	/**
	 * Cheap existence check so Traffic_Guard can skip resolving ASN/Geo-IP
	 * for a request entirely on the (default) site with no rules configured
	 * -- see Traffic_Guard's own docblock for why that lookup must stay
	 * opt-in-cost, not unconditional.
	 */
	public function has_any(): bool {
		global $wpdb;
		$table = $wpdb->prefix . 'sam_network_rules';
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		return null !== $wpdb->get_var( "SELECT id FROM {$table} LIMIT 1" );
	}

	public function add( string $rule_type, string $value, string $surface, string $reason, int $created_by ): bool {
		$value = $this->normalise_value( $rule_type, $value );
		if ( ! in_array( $rule_type, self::RULE_TYPES, true ) || '' === $value || '' === trim( $reason ) ) {
			return false;
		}

		global $wpdb;
		$table = $wpdb->prefix . 'sam_network_rules';

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
		$result = $wpdb->insert(
			$table,
			array(
				'rule_type'  => $rule_type,
				'value'      => $value,
				'surface'    => sanitize_key( $surface ),
				'reason'     => sanitize_textarea_field( $reason ),
				'created_by' => $created_by,
				'created_at' => current_time( 'mysql', true ),
			)
		);
		return false !== $result;
	}

	public function delete( int $id ): bool {
		global $wpdb;
		$table = $wpdb->prefix . 'sam_network_rules';

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
	 * Returns the first matching rule for this ASN/country + surface (rules
	 * scoped to '' apply to every surface), or null if none match. Either
	 * $asn or $country may be null (e.g. Geo-IP not configured) -- a null
	 * value simply never matches an 'asn' or 'country' rule respectively.
	 *
	 * @return array<string, mixed>|null
	 */
	public function match( ?int $asn, ?string $country, string $surface ): ?array {
		$rules = $this->all();

		foreach ( $rules as $rule ) {
			if ( '' !== (string) $rule['surface'] && $surface !== $rule['surface'] ) {
				continue;
			}

			if ( 'asn' === $rule['rule_type'] && null !== $asn && (string) $asn === (string) $rule['value'] ) {
				return $rule;
			}

			if ( 'country' === $rule['rule_type'] && null !== $country && strcasecmp( $country, (string) $rule['value'] ) === 0 ) {
				return $rule;
			}
		}

		return null;
	}

	/** Strips a leading "AS"/"as" prefix from an ASN (e.g. "AS15169" -> "15169"); uppercases a country code. */
	private function normalise_value( string $rule_type, string $value ): string {
		$value = trim( $value );

		if ( 'asn' === $rule_type ) {
			$value = preg_replace( '/^as/i', '', $value ) ?? $value;
			return ctype_digit( $value ) ? $value : '';
		}

		if ( 'country' === $rule_type ) {
			$value = strtoupper( $value );
			return 1 === preg_match( '/^[A-Z]{2}$/', $value ) ? $value : '';
		}

		return '';
	}
}
