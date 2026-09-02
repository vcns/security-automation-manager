<?php
/**
 * CRUD for sam_scanner_vendors: the known-identity catalogue Identity_Resolver
 * matches claimed identities against (.roadmap/phase3_early_plan.md §9
 * Commercial Scanner Intelligence, §9.2 Authoritative Sources).
 *
 * Deliberately ships with only a small, built-in seed of well-documented
 * search/AI crawlers (see Activator::seed_default_scanner_vendors(),
 * extended Phase 4C for GPTBot/ClaudeBot/CCBot/PerplexityBot, .roadmap/
 * phase3_early_plan.md §10): verified by forward-confirmed reverse DNS
 * against a vendor-published hostname suffix where the vendor documents
 * one, else by the vendor's own published IP-range JSON -- never a
 * hardcoded IP range, in either case. Commercial scanner vendors (Qualys,
 * Tenable, Rapid7, etc., listed in §9) are NOT seeded with fabricated
 * network data: their published ranges change over time and asserting
 * stale or guessed ranges in a security product would be worse than
 * asserting nothing. Administrators add those themselves, with a
 * mandatory source_url per §9.2, once they have a range they trust.
 *
 * Built-in rows (is_builtin = 1) can be edited (e.g. to add a
 * vendor-published CIDR range once verified) but not deleted, since
 * Identity_Resolver's is_available()-style category logic assumes the
 * built-in crawler entries always exist.
 */

declare( strict_types=1 );

namespace WP_SAM\Intelligence;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Scanner_Vendor_Store {

	public const CATEGORIES = array( 'known_commercial_scanner', 'known_research_scanner', 'known_crawler', 'custom' );

	public const VERIFICATION_METHODS = array( 'none', 'cidr', 'fcrdns' );

	/** @return array<int, array<string, mixed>> */
	public function all(): array {
		global $wpdb;
		$table = $wpdb->prefix . 'sam_scanner_vendors';
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$rows = $wpdb->get_results( "SELECT * FROM {$table} ORDER BY vendor_name", ARRAY_A );
		$rows = ! empty( $rows ) ? $rows : array();

		return array_map( array( $this, 'hydrate' ), $rows );
	}

	/** @return array<string, mixed>|null */
	public function get( string $vendor_key ): ?array {
		global $wpdb;
		$table = $wpdb->prefix . 'sam_scanner_vendors';
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.NotPrepared,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$row = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM {$table} WHERE vendor_key = %s", $vendor_key ), ARRAY_A );
		return is_array( $row ) ? $this->hydrate( $row ) : null;
	}

	/**
	 * Inserts a new vendor, or updates an existing one addressed by
	 * vendor_key. Always writes is_builtin = 0 for a brand-new row --
	 * built-in rows only ever come from Activator's seed step.
	 *
	 * @param array<string> $rdns_suffixes
	 * @param array<string> $cidr_ranges
	 */
	public function upsert(
		string $vendor_key,
		string $vendor_name,
		string $category,
		string $ua_pattern,
		array $rdns_suffixes,
		array $cidr_ranges,
		string $source_url,
		string $verification_method,
		string $notes
	): bool {
		global $wpdb;
		$table = $wpdb->prefix . 'sam_scanner_vendors';

		$vendor_key = sanitize_key( $vendor_key );
		if ( '' === $vendor_key || '' === trim( $vendor_name ) ) {
			return false;
		}
		if ( ! in_array( $category, self::CATEGORIES, true ) ) {
			$category = 'custom';
		}
		if ( ! in_array( $verification_method, self::VERIFICATION_METHODS, true ) ) {
			$verification_method = 'none';
		}

		$now      = current_time( 'mysql', true );
		$existing = $this->get( $vendor_key );

		$data = array(
			'vendor_key'          => $vendor_key,
			'vendor_name'         => sanitize_text_field( $vendor_name ),
			'category'            => $category,
			'ua_pattern'          => substr( sanitize_text_field( $ua_pattern ), 0, 255 ),
			'rdns_suffixes'       => wp_json_encode( array_values( array_filter( array_map( 'sanitize_text_field', $rdns_suffixes ) ) ) ),
			'cidr_ranges'         => wp_json_encode( array_values( array_filter( array_map( 'sanitize_text_field', $cidr_ranges ) ) ) ),
			'source_url'          => esc_url_raw( $source_url ),
			'verification_method' => $verification_method,
			'notes'               => sanitize_textarea_field( $notes ),
			'updated_at'          => $now,
		);

		if ( null !== $existing ) {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
			$result = $wpdb->update( $table, $data, array( 'vendor_key' => $vendor_key ) );
			return false !== $result;
		}

		$data['is_builtin'] = 0;
		$data['created_at'] = $now;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
		$result = $wpdb->insert( $table, $data );
		return false !== $result;
	}

	/** Refuses to delete a built-in row -- see class docblock. */
	public function delete( string $vendor_key ): bool {
		$existing = $this->get( $vendor_key );
		if ( null === $existing || ! empty( $existing['is_builtin'] ) ) {
			return false;
		}

		global $wpdb;
		$table = $wpdb->prefix . 'sam_scanner_vendors';
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.NotPrepared,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$result = $wpdb->query(
			$wpdb->prepare(
				// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				"DELETE FROM {$table} WHERE vendor_key = %s",
				sanitize_key( $vendor_key )
			)
		);
		return false !== $result && $result > 0;
	}

	/** @param array<string, mixed> $row */
	private function hydrate( array $row ): array {
		$rdns  = json_decode( (string) ( $row['rdns_suffixes'] ?? '[]' ), true );
		$cidrs = json_decode( (string) ( $row['cidr_ranges'] ?? '[]' ), true );

		$row['rdns_suffixes'] = is_array( $rdns ) ? $rdns : array();
		$row['cidr_ranges']   = is_array( $cidrs ) ? $cidrs : array();
		$row['is_builtin']    = ! empty( $row['is_builtin'] );

		return $row;
	}
}
