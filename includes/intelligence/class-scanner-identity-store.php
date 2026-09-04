<?php
/**
 * Storage for resolved request identities (Phase 3D, .roadmap/phase3_early_
 * plan.md §8 Identity Verification, §9.1 Scanner Trust States).
 *
 * Modeled on Event_Store: named columns for what's filterable/sortable, a
 * stable fingerprint (ip + claimed identity) with upsert-on-conflict, and
 * the same hourly per-key rate-limit guard so a single noisy source can't
 * flood the table.
 *
 * The one rule this class exists to enforce: recognition is never
 * authorisation (§9, "Recognition is not authorisation"). record() -- the
 * automatic, per-request path Identity_Resolver calls -- only ever writes
 * an automatic verification_state (unknown / known_commercial_scanner /
 * known_research_scanner / known_crawler / identity_conflict / loopback).
 * If a row
 * already carries an administrator decision (customer_authorised /
 * explicitly_denied / previously_authorised_expired), record() refreshes
 * occurrence/last_seen bookkeeping only and leaves that decision alone --
 * a decision is data an administrator entered and record() must never
 * silently overwrite it just because the same traffic recurred. Only
 * authorise()/deny()/clear_decision(), called exclusively from an explicit
 * admin action, may set or clear a decision state.
 *
 * recent_paths (schema v36, Phase 4C -- URI-pattern signal, .roadmap/
 * phase3_early_plan.md §10) holds this identity's last MAX_RECENT_PATHS
 * request paths as a JSON array, oldest first -- bounded, never grown
 * without limit, and read by Uri_Pattern_Analyzer to recognise sequential/
 * enumerating access (e.g. /product/101, /product/102, /product/103) as
 * its own signal, and to answer §10's "log the fact they're hitting the
 * endpoint" plainly on the Identities admin view.
 */

declare( strict_types=1 );

namespace WP_SAM\Intelligence;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Scanner_Identity_Store {

	private const MAX_PER_HOUR_PER_KEY = 500;
	private const RATE_LIMIT_WINDOW    = HOUR_IN_SECONDS;

	/** Bounded so recent_paths can never grow without limit -- see class docblock. */
	public const MAX_RECENT_PATHS = 10;

	public const AUTOMATIC_STATES = array( 'unknown', 'known_commercial_scanner', 'known_research_scanner', 'known_crawler', 'identity_conflict', 'loopback' );

	public const DECISION_STATES = array( 'customer_authorised', 'explicitly_denied', 'previously_authorised_expired' );

	/**
	 * Automatic, per-request recognition write. See class docblock for why
	 * this never touches an existing decision state.
	 */
	public function record(
		string $ip,
		string $claimed_identity,
		string $user_agent,
		string $vendor_key,
		string $surface,
		string $verification_state,
		?bool $network_match,
		string $path = ''
	): void {
		global $wpdb;
		$table = $wpdb->prefix . 'sam_scanner_identities';

		if ( '' === $ip ) {
			return;
		}
		if ( ! in_array( $verification_state, self::AUTOMATIC_STATES, true ) ) {
			$verification_state = 'unknown';
		}
		$surface = in_array( $surface, array( 'frontend', 'admin', 'login', 'api' ), true ) ? $surface : 'frontend';

		$fingerprint = hash( 'sha256', $ip . '|' . $claimed_identity );

		$rate_key = 'wp_sam_scanner_identity_rate_' . substr( $fingerprint, 0, 32 );
		$count    = (int) get_transient( $rate_key );
		if ( $count >= self::MAX_PER_HOUR_PER_KEY ) {
			return;
		}
		set_transient( $rate_key, $count + 1, self::RATE_LIMIT_WINDOW );

		$now = current_time( 'mysql', true );

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.NotPrepared,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$existing       = $wpdb->get_row( $wpdb->prepare( "SELECT verification_state, recent_paths FROM {$table} WHERE fingerprint = %s", $fingerprint ), ARRAY_A );
		$existing_state = is_array( $existing ) ? (string) ( $existing['verification_state'] ?? '' ) : null;
		$recent_paths   = $this->append_recent_path( is_array( $existing ) ? (string) ( $existing['recent_paths'] ?? '' ) : '', $path );

		if ( is_string( $existing_state ) && in_array( $existing_state, self::DECISION_STATES, true ) ) {
			// wpdb::update() can't express `occurrence_count = occurrence_count + 1`, so this is a direct query.
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.NotPrepared,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			$wpdb->query(
				$wpdb->prepare(
					// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
					"UPDATE {$table} SET occurrence_count = occurrence_count + 1, last_seen_at = %s, recent_paths = %s WHERE fingerprint = %s",
					$now,
					$recent_paths,
					$fingerprint
				)
			);
			return;
		}

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.NotPrepared,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$wpdb->query(
			$wpdb->prepare(
				// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				"INSERT INTO {$table} (
					ip, claimed_identity, user_agent, vendor_key, surface, verification_state,
					network_match, fingerprint, occurrence_count, first_seen_at, last_seen_at, recent_paths
				) VALUES (
					%s, %s, %s, %s, %s, %s,
					%s, %s, %d, %s, %s, %s
				) ON DUPLICATE KEY UPDATE
					occurrence_count = occurrence_count + 1,
					last_seen_at = VALUES(last_seen_at),
					user_agent = VALUES(user_agent),
					verification_state = VALUES(verification_state),
					network_match = VALUES(network_match),
					recent_paths = VALUES(recent_paths)",
				$ip,
				substr( $claimed_identity, 0, 128 ),
				substr( $user_agent, 0, 512 ),
				substr( $vendor_key, 0, 64 ),
				$surface,
				$verification_state,
				null === $network_match ? null : ( $network_match ? 1 : 0 ),
				$fingerprint,
				1,
				$now,
				$now,
				$recent_paths
			)
		);
	}

	/**
	 * Appends $path to the existing JSON-encoded recent_paths array,
	 * keeping only the most recent MAX_RECENT_PATHS entries (oldest
	 * dropped first) -- see class docblock.
	 */
	private function append_recent_path( string $existing_json, string $path ): string {
		$paths = json_decode( $existing_json, true );
		if ( ! is_array( $paths ) ) {
			$paths = array();
		}

		if ( '' !== $path ) {
			$paths[] = substr( $path, 0, 255 );
		}

		if ( count( $paths ) > self::MAX_RECENT_PATHS ) {
			$paths = array_slice( $paths, -self::MAX_RECENT_PATHS );
		}

		$encoded = wp_json_encode( array_values( $paths ) );
		return false !== $encoded ? $encoded : '[]';
	}

	public function authorise( int $id, int $user_id, string $note ): bool {
		return $this->set_decision( $id, 'customer_authorised', $user_id, $note );
	}

	public function deny( int $id, int $user_id, string $note ): bool {
		return $this->set_decision( $id, 'explicitly_denied', $user_id, $note );
	}

	/** Reverts a row back to automatic recognition -- clears the decision so record() resumes updating it. */
	public function clear_decision( int $id, int $user_id, string $note ): bool {
		return $this->set_decision( $id, 'unknown', $user_id, $note );
	}

	private function set_decision( int $id, string $state, int $user_id, string $note ): bool {
		if ( '' === trim( $note ) ) {
			return false;
		}

		global $wpdb;
		$table = $wpdb->prefix . 'sam_scanner_identities';

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
		$result = $wpdb->update(
			$table,
			array(
				'verification_state' => $state,
				'authorised_by'      => $user_id,
				'authorised_at'      => current_time( 'mysql', true ),
				'decision_note'      => sanitize_textarea_field( $note ),
			),
			array( 'id' => $id ),
			array( '%s', '%d', '%s', '%s' ),
			array( '%d' )
		);
		return false !== $result;
	}
}
