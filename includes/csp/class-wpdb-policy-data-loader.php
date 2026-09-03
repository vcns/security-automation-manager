<?php
/**
 * Real, wpdb-backed implementation of Policy_Data_Loader -- Policy_
 * Builder's default collaborator when none is injected. Relocated
 * verbatim from Policy_Builder's own former protected load_profile()/
 * load_approved_hashes()/load_approved_sources() methods (GitHub issue
 * #170); the query logic itself is unchanged, only where it lives.
 */

declare( strict_types=1 );

namespace WP_SAM\CSP;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Wpdb_Policy_Data_Loader implements Policy_Data_Loader {

	public function load_profile( string $surface ): ?array {
		global $wpdb;
		$table = $wpdb->prefix . 'csp_policy_profiles';
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$row = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM {$table} WHERE surface = %s LIMIT 1", $surface ), ARRAY_A );
		return ! empty( $row ) ? $row : null;
	}

	/**
	 * ORDER BY last_seen_at DESC, id DESC: Policy_Builder::build_policy_
	 * string()'s hash-append loop relies on most-recently-seen rows coming
	 * first, so its byte-budget cutoff drops the oldest hashes rather than
	 * an arbitrary subset. `last_seen_at` is a datetime column (one-second
	 * resolution) and many rows commonly get bumped to the exact same
	 * second by the same page render, so ORDER BY on that column alone
	 * leaves the relative order of everything tied on a timestamp
	 * unspecified by SQL -- confirmed in production, 2026-08-19: the same
	 * ~1,027-row backlog produced a "Dropped 34" cutoff on one request and
	 * "Dropped 985" on another moments later, because the arbitrary tie
	 * order happened to place a different mix of cheap (style-src-attr,
	 * single-directive) vs expensive (script-src/style-src, doubled)
	 * hashes before the cutoff each time. `id DESC` breaks ties
	 * deterministically (a row's id never changes on reactivation), so the
	 * same DB state now always produces the same cutoff, not just "some"
	 * cutoff. The LIMIT is a generous, defense-in-depth ceiling on rows
	 * loaded into PHP memory in the first place -- not the primary safety
	 * mechanism (that's Policy_Builder's byte budget) -- so it's set well
	 * above MAX_HASH_TOKEN_BUDGET_BYTES could ever actually use.
	 */
	public function load_approved_hashes( string $surface ): array {
		global $wpdb;
		$table = $wpdb->prefix . 'csp_hash_inventory';
		$rows  = $wpdb->get_results(
			$wpdb->prepare(
				// phpcs:ignore WordPress.DB.DirectDatabaseQuery,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				"SELECT directive, hash_algo, hash_value FROM {$table} WHERE surface = %s AND status = 'active' ORDER BY last_seen_at DESC, id DESC LIMIT 2000",
				$surface
			),
			ARRAY_A
		);
		return ! empty( $rows ) ? $rows : array();
	}

	public function load_approved_sources( string $surface ): array {
		global $wpdb;
		$table = $wpdb->prefix . 'csp_source_inventory';
		$rows  = $wpdb->get_results(
			$wpdb->prepare(
				// phpcs:ignore WordPress.DB.DirectDatabaseQuery,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				"SELECT directive, source_host, source_scheme FROM {$table} WHERE surface = %s AND approval_state = 'approved'",
				$surface
			),
			ARRAY_A
		);
		return ! empty( $rows ) ? $rows : array();
	}
}
