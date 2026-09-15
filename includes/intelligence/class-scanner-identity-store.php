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
 *
 * recent_seen_at (schema v43, Phase 4C carried-forward item -- the
 * "timing" signal §10's own list names) holds this identity's last
 * MAX_RECENT_PATHS request timestamps as a JSON array, oldest first,
 * appended in lockstep with recent_paths on every record() call (so the
 * two stay index-aligned). Read by Request_Timing_Analyzer to recognise
 * suspiciously uniform inter-request intervals -- the timing signature of
 * a scripted client sleeping a fixed duration between requests, rather
 * than a person's naturally irregular browsing.
 *
 * recent_errors (schema v44, Phase 4C carried-forward item -- the
 * "repeated errors" signal §10's own list names) holds this identity's
 * last MAX_RECENT_PATHS request outcomes as a JSON array of 0/1 ints,
 * oldest first, appended in lockstep with recent_paths/recent_seen_at.
 * Unlike those two, $is_error is never optional/null here -- "this
 * request was not an error" is itself meaningful information, not an
 * unknown. Read by Repeated_Error_Analyzer to recognise a source whose
 * recent requests were disproportionately 4xx/5xx responses -- the
 * classic signature of a scanner probing for paths that don't exist or
 * aren't allowed, distinct from Uri_Pattern_Analyzer's enumeration signal
 * (which is about a *pattern* in what's requested, not whether it existed).
 *
 * asn/asn_org/geo_country/geo_region/geo_city (schema v42, Phase 4A
 * carried-forward item) are optional -- record() only receives them on a
 * request where Network_Intelligence_Resolver was already resolved (i.e.
 * some detector already produced a finding this request; see Request_
 * Observer's own §33 performance gate, unchanged by this). A null value
 * passed here never overwrites an already-known value -- see the
 * COALESCE-based upsert below -- so an identity's network fields only
 * ever fill in over time, never flicker back to unknown. Confirmed
 * directly against a live install: wpdb::prepare() does NOT preserve a
 * PHP null as SQL NULL for %d/%s -- it casts to 0/'' -- so the upsert
 * treats 0 (asn) and '' (the rest) as the "unknown" sentinel via NULLIF,
 * rather than relying on a real NULL ever reaching the query.
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
		string $path = '',
		?int $asn = null,
		?string $asn_org = null,
		?string $geo_country = null,
		?string $geo_region = null,
		?string $geo_city = null,
		bool $is_error = false
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
		$existing       = $wpdb->get_row( $wpdb->prepare( "SELECT verification_state, recent_paths, recent_seen_at, recent_errors FROM {$table} WHERE fingerprint = %s", $fingerprint ), ARRAY_A );
		$existing_state = is_array( $existing ) ? (string) ( $existing['verification_state'] ?? '' ) : null;
		$recent_paths   = $this->append_recent_path( is_array( $existing ) ? (string) ( $existing['recent_paths'] ?? '' ) : '', $path );
		$recent_seen_at = $this->append_recent_timestamp( is_array( $existing ) ? (string) ( $existing['recent_seen_at'] ?? '' ) : '', $now );
		$recent_errors  = $this->append_recent_error( is_array( $existing ) ? (string) ( $existing['recent_errors'] ?? '' ) : '', $is_error );

		if ( is_string( $existing_state ) && in_array( $existing_state, self::DECISION_STATES, true ) ) {
			// wpdb::update() can't express `occurrence_count = occurrence_count + 1`, so this is a direct query.
			// COALESCE/NULLIF: a null/empty incoming network-intelligence value
			// never overwrites an already-known one -- see class docblock.
			// NULLIF(..., 0) rather than relying on wpdb::prepare() preserving
			// a PHP null as SQL NULL for %d -- it doesn't; %d casts null to
			// the integer 0 (confirmed directly against a live install, not
			// assumed), so 0 is used as the "no value" sentinel instead. Safe
			// because a real ASN is never 0.
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.NotPrepared,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			$wpdb->query(
				$wpdb->prepare(
					// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
					"UPDATE {$table} SET occurrence_count = occurrence_count + 1, last_seen_at = %s, recent_paths = %s, recent_seen_at = %s, recent_errors = %s,
						asn = COALESCE(NULLIF(%d, 0), asn),
						asn_org = COALESCE(NULLIF(%s, ''), asn_org),
						geo_country = COALESCE(NULLIF(%s, ''), geo_country),
						geo_region = COALESCE(NULLIF(%s, ''), geo_region),
						geo_city = COALESCE(NULLIF(%s, ''), geo_city)
					WHERE fingerprint = %s",
					$now,
					$recent_paths,
					$recent_seen_at,
					$recent_errors,
					$asn ?? 0,
					$asn_org ?? '',
					$geo_country ?? '',
					$geo_region ?? '',
					$geo_city ?? '',
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
					network_match, fingerprint, occurrence_count, first_seen_at, last_seen_at, recent_paths, recent_seen_at, recent_errors,
					asn, asn_org, geo_country, geo_region, geo_city
				) VALUES (
					%s, %s, %s, %s, %s, %s,
					%s, %s, %d, %s, %s, %s, %s, %s,
					%d, %s, %s, %s, %s
				) ON DUPLICATE KEY UPDATE
					occurrence_count = occurrence_count + 1,
					last_seen_at = VALUES(last_seen_at),
					user_agent = VALUES(user_agent),
					verification_state = VALUES(verification_state),
					network_match = VALUES(network_match),
					recent_paths = VALUES(recent_paths),
					recent_seen_at = VALUES(recent_seen_at),
					recent_errors = VALUES(recent_errors),
					asn = COALESCE(NULLIF(VALUES(asn), 0), asn),
					asn_org = COALESCE(NULLIF(VALUES(asn_org), ''), asn_org),
					geo_country = COALESCE(NULLIF(VALUES(geo_country), ''), geo_country),
					geo_region = COALESCE(NULLIF(VALUES(geo_region), ''), geo_region),
					geo_city = COALESCE(NULLIF(VALUES(geo_city), ''), geo_city)",
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
				$recent_paths,
				$recent_seen_at,
				$recent_errors,
				$asn ?? 0,
				$asn_org ?? '',
				$geo_country ?? '',
				$geo_region ?? '',
				$geo_city ?? ''
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

	/**
	 * Appends $timestamp (a MySQL datetime string) to the existing JSON-
	 * encoded recent_seen_at array, keeping only the most recent
	 * MAX_RECENT_PATHS entries -- mirrors append_recent_path() exactly, so
	 * the two arrays stay index-aligned entry-for-entry.
	 */
	private function append_recent_timestamp( string $existing_json, string $timestamp ): string {
		$timestamps = json_decode( $existing_json, true );
		if ( ! is_array( $timestamps ) ) {
			$timestamps = array();
		}

		$timestamps[] = $timestamp;

		if ( count( $timestamps ) > self::MAX_RECENT_PATHS ) {
			$timestamps = array_slice( $timestamps, -self::MAX_RECENT_PATHS );
		}

		$encoded = wp_json_encode( array_values( $timestamps ) );
		return false !== $encoded ? $encoded : '[]';
	}

	/**
	 * Appends $is_error (as 1/0) to the existing JSON-encoded recent_errors
	 * array, keeping only the most recent MAX_RECENT_PATHS entries -- same
	 * bound as recent_paths/recent_seen_at, but always appends (a "not an
	 * error" outcome is itself recorded, unlike a blank path).
	 */
	private function append_recent_error( string $existing_json, bool $is_error ): string {
		$errors = json_decode( $existing_json, true );
		if ( ! is_array( $errors ) ) {
			$errors = array();
		}

		$errors[] = $is_error ? 1 : 0;

		if ( count( $errors ) > self::MAX_RECENT_PATHS ) {
			$errors = array_slice( $errors, -self::MAX_RECENT_PATHS );
		}

		$encoded = wp_json_encode( array_values( $errors ) );
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
