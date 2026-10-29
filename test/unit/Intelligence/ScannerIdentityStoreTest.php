<?php
/**
 * Unit tests for WP_SAM\Intelligence\Scanner_Identity_Store.
 *
 * The single most important behaviour under test: record() (the automatic,
 * per-request path) must never overwrite a decision an administrator
 * already made. See the class's own docblock -- "recognition is not
 * authorisation".
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;
use WP_SAM\Intelligence\Identity_Resolver;
use WP_SAM\Intelligence\Own_Address_Store;
use WP_SAM\Intelligence\Scanner_Identity_Store;
use WP_SAM\Intelligence\Scanner_Vendor_Store;

class ScannerIdentityStoreTest extends TestCase {

	private Scanner_Identity_Store $store;

	protected function setUp(): void {
		wp_test_reset_globals();
		$this->store = new Scanner_Identity_Store();
	}

	public function test_record_does_nothing_for_an_empty_ip(): void {
		$this->store->record( '', 'Googlebot', 'ua', 'googlebot', 'frontend', 'known_crawler', null );

		$this->assertSame( array(), $GLOBALS['_wpdb_queries'] );
	}

	public function test_record_inserts_a_new_row_with_an_automatic_state(): void {
		$GLOBALS['_wpdb_get_row'] = null; // No existing row.

		$this->store->record( '203.0.113.42', 'Googlebot', 'Mozilla/5.0 Googlebot', 'googlebot', 'frontend', 'known_crawler', true );

		$this->assertCount( 1, $GLOBALS['_wpdb_queries'] );
		$this->assertStringContainsString( "'known_crawler'", $GLOBALS['_wpdb_queries'][0] );
		$this->assertStringContainsString( "'googlebot'", $GLOBALS['_wpdb_queries'][0] );
	}

	public function test_record_clamps_an_unrecognised_state_to_unknown(): void {
		$GLOBALS['_wpdb_get_row'] = null;

		$this->store->record( '203.0.113.42', '', '', '', 'frontend', 'not-a-real-state', null );

		$this->assertStringContainsString( "'unknown'", $GLOBALS['_wpdb_queries'][0] );
	}

	public function test_record_never_overwrites_an_existing_authorisation_decision(): void {
		$GLOBALS['_wpdb_get_row'] = array( 'verification_state' => 'customer_authorised', 'recent_paths' => '[]' );

		$this->store->record( '203.0.113.42', 'Qualys', 'QualysGuard', 'qualys', 'frontend', 'known_commercial_scanner', true );

		$this->assertCount( 1, $GLOBALS['_wpdb_queries'] );
		// The bookkeeping-only path must never mention verification_state --
		// only occurrence_count/last_seen_at/recent_paths may change.
		$this->assertStringNotContainsString( 'verification_state', $GLOBALS['_wpdb_queries'][0] );
		$this->assertStringContainsString( 'occurrence_count = occurrence_count + 1', $GLOBALS['_wpdb_queries'][0] );
	}

	public function test_record_never_overwrites_an_explicit_denial(): void {
		$GLOBALS['_wpdb_get_row'] = array( 'verification_state' => 'explicitly_denied', 'recent_paths' => '[]' );

		$this->store->record( '203.0.113.42', 'Qualys', 'QualysGuard', 'qualys', 'frontend', 'known_commercial_scanner', true );

		$this->assertStringNotContainsString( 'verification_state', $GLOBALS['_wpdb_queries'][0] );
	}

	public function test_record_updates_normally_when_existing_state_is_automatic(): void {
		$GLOBALS['_wpdb_get_row'] = array( 'verification_state' => 'known_crawler', 'recent_paths' => '[]' ); // An automatic state, not a decision.

		$this->store->record( '203.0.113.42', 'Googlebot', 'ua', 'googlebot', 'frontend', 'known_crawler', true );

		// Falls through to the normal INSERT ... ON DUPLICATE KEY UPDATE path,
		// which does set verification_state.
		$this->assertStringContainsString( 'verification_state', $GLOBALS['_wpdb_queries'][0] );
	}

	public function test_record_is_rate_limited_per_fingerprint(): void {
		$GLOBALS['_wpdb_get_row'] = null;

		for ( $i = 0; $i < 505; $i++ ) {
			$this->store->record( '203.0.113.42', 'Googlebot', 'ua', 'googlebot', 'frontend', 'known_crawler', true );
		}

		$this->assertCount( 500, $GLOBALS['_wpdb_queries'] );
	}

	// ── recent_paths (Phase 4C, URI-pattern signal) ─────────────────────────
	//
	// The wpdb stub's prepare() addslashes() every %s substitution, so a
	// JSON-encoded value's own escaping is backslash-escaped again when
	// embedded as a SQL string literal -- compute the expected substring
	// the same way (addslashes(wp_json_encode(...))) rather than hand-
	// typing escape sequences. See RequestObserverTest's own note on the
	// same gotcha.

	public function test_record_appends_the_current_path_on_first_insert(): void {
		$GLOBALS['_wpdb_get_row'] = null;

		$this->store->record( '203.0.113.42', 'Googlebot', 'ua', 'googlebot', 'frontend', 'known_crawler', true, '/product/101' );

		$expected = addslashes( (string) wp_json_encode( array( '/product/101' ) ) );
		$this->assertStringContainsString( $expected, $GLOBALS['_wpdb_queries'][0] );
	}

	public function test_record_appends_to_existing_recent_paths(): void {
		$GLOBALS['_wpdb_get_row'] = array(
			'verification_state' => 'known_crawler',
			'recent_paths'       => wp_json_encode( array( '/product/101', '/product/102' ) ),
		);

		$this->store->record( '203.0.113.42', 'Googlebot', 'ua', 'googlebot', 'frontend', 'known_crawler', true, '/product/103' );

		$expected = addslashes( (string) wp_json_encode( array( '/product/101', '/product/102', '/product/103' ) ) );
		$this->assertStringContainsString( $expected, $GLOBALS['_wpdb_queries'][0] );
	}

	public function test_record_trims_recent_paths_to_the_configured_maximum(): void {
		$existing = array();
		for ( $i = 1; $i <= Scanner_Identity_Store::MAX_RECENT_PATHS; $i++ ) {
			$existing[] = '/product/' . $i;
		}
		$GLOBALS['_wpdb_get_row'] = array(
			'verification_state' => 'known_crawler',
			'recent_paths'       => wp_json_encode( $existing ),
		);

		$this->store->record( '203.0.113.42', 'Googlebot', 'ua', 'googlebot', 'frontend', 'known_crawler', true, '/product/999' );

		// Oldest entry (/product/1) dropped to make room -- array stays at MAX_RECENT_PATHS.
		$expected_trimmed   = array_slice( $existing, 1 );
		$expected_trimmed[] = '/product/999';
		$expected           = addslashes( (string) wp_json_encode( $expected_trimmed ) );
		$this->assertStringContainsString( $expected, $GLOBALS['_wpdb_queries'][0] );
	}

	public function test_record_still_appends_the_path_when_a_decision_state_blocks_the_verification_state_update(): void {
		$GLOBALS['_wpdb_get_row'] = array( 'verification_state' => 'customer_authorised', 'recent_paths' => '[]' );

		$this->store->record( '203.0.113.42', 'Qualys', 'ua', 'qualys', 'frontend', 'known_commercial_scanner', true, '/scan-target' );

		$expected = addslashes( (string) wp_json_encode( array( '/scan-target' ) ) );
		$this->assertStringContainsString( $expected, $GLOBALS['_wpdb_queries'][0] );
	}

	public function test_record_with_an_empty_path_does_not_add_a_blank_entry(): void {
		$GLOBALS['_wpdb_get_row'] = null;

		$this->store->record( '203.0.113.42', 'Googlebot', 'ua', 'googlebot', 'frontend', 'known_crawler', true );

		$this->assertStringContainsString( "'[]'", $GLOBALS['_wpdb_queries'][0] );
	}

	// ── recent_seen_at (schema v43, Phase 4C carried-forward item -- timing) ─

	public function test_record_appends_a_timestamp_on_first_insert(): void {
		$GLOBALS['_wpdb_get_row'] = null;

		$this->store->record( '203.0.113.42', 'Googlebot', 'ua', 'googlebot', 'frontend', 'known_crawler', true, '/product/101' );

		// current_time( 'mysql', true ) is whatever "now" resolves to in the
		// stub -- just prove a single-entry JSON timestamp array landed
		// (the same escaped-quote shape recent_paths' own single entry
		// already uses), rather than pin an exact, time-dependent value.
		$this->assertMatchesRegularExpression( '/\[\\\\"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\\\\"\]/', $GLOBALS['_wpdb_queries'][0] );
		$this->assertStringContainsString( 'recent_seen_at = VALUES(recent_seen_at)', $GLOBALS['_wpdb_queries'][0] );
	}

	public function test_record_appends_to_existing_recent_seen_at(): void {
		$GLOBALS['_wpdb_get_row'] = array(
			'verification_state' => 'known_crawler',
			'recent_paths'       => wp_json_encode( array( '/product/101' ) ),
			'recent_seen_at'     => wp_json_encode( array( '2026-01-01 00:00:00' ) ),
		);

		$this->store->record( '203.0.113.42', 'Googlebot', 'ua', 'googlebot', 'frontend', 'known_crawler', true, '/product/102' );

		$this->assertStringContainsString( addslashes( '2026-01-01 00:00:00' ), $GLOBALS['_wpdb_queries'][0] );
	}

	public function test_record_trims_recent_seen_at_to_the_configured_maximum(): void {
		$existing = array();
		for ( $i = 1; $i <= Scanner_Identity_Store::MAX_RECENT_PATHS; $i++ ) {
			$existing[] = sprintf( '2026-01-01 00:00:%02d', $i );
		}
		$GLOBALS['_wpdb_get_row'] = array(
			'verification_state' => 'known_crawler',
			'recent_paths'       => '[]',
			'recent_seen_at'     => wp_json_encode( $existing ),
		);

		$this->store->record( '203.0.113.42', 'Googlebot', 'ua', 'googlebot', 'frontend', 'known_crawler', true );

		// Oldest entry (...:01) dropped to make room for the new one.
		$this->assertStringNotContainsString( addslashes( '2026-01-01 00:00:01' ), $GLOBALS['_wpdb_queries'][0] );
		$this->assertStringContainsString( addslashes( '2026-01-01 00:00:10' ), $GLOBALS['_wpdb_queries'][0] );
	}

	public function test_record_still_appends_a_timestamp_when_a_decision_state_blocks_the_verification_state_update(): void {
		$GLOBALS['_wpdb_get_row'] = array(
			'verification_state' => 'customer_authorised',
			'recent_paths'       => '[]',
			'recent_seen_at'     => '[]',
		);

		$this->store->record( '203.0.113.42', 'Qualys', 'ua', 'qualys', 'frontend', 'known_commercial_scanner', true, '/scan-target' );

		$this->assertStringContainsString( 'recent_seen_at', $GLOBALS['_wpdb_queries'][0] );
	}

	// ── recent_errors (schema v44, Phase 4C carried-forward item) ───────────

	public function test_record_appends_a_1_for_an_error_on_first_insert(): void {
		$GLOBALS['_wpdb_get_row'] = null;

		$this->store->record( '203.0.113.42', 'Googlebot', 'ua', 'googlebot', 'frontend', 'known_crawler', true, '', null, null, null, null, null, true );

		$this->assertStringContainsString( "'[1]'", $GLOBALS['_wpdb_queries'][0] );
	}

	public function test_record_appends_a_0_for_a_non_error_on_first_insert(): void {
		$GLOBALS['_wpdb_get_row'] = null;

		$this->store->record( '203.0.113.42', 'Googlebot', 'ua', 'googlebot', 'frontend', 'known_crawler', true, '', null, null, null, null, null, false );

		$this->assertStringContainsString( "'[0]'", $GLOBALS['_wpdb_queries'][0] );
	}

	public function test_record_defaults_is_error_to_false_when_not_provided(): void {
		$GLOBALS['_wpdb_get_row'] = null;

		$this->store->record( '203.0.113.42', 'Googlebot', 'ua', 'googlebot', 'frontend', 'known_crawler', true );

		$this->assertStringContainsString( "'[0]'", $GLOBALS['_wpdb_queries'][0] );
	}

	public function test_record_appends_to_existing_recent_errors(): void {
		$GLOBALS['_wpdb_get_row'] = array(
			'verification_state' => 'known_crawler',
			'recent_paths'       => '[]',
			'recent_seen_at'     => '[]',
			'recent_errors'      => wp_json_encode( array( 0, 1 ) ),
		);

		$this->store->record( '203.0.113.42', 'Googlebot', 'ua', 'googlebot', 'frontend', 'known_crawler', true, '', null, null, null, null, null, true );

		$this->assertStringContainsString( "'[0,1,1]'", $GLOBALS['_wpdb_queries'][0] );
	}

	public function test_record_trims_recent_errors_to_the_configured_maximum(): void {
		$existing = array_fill( 0, Scanner_Identity_Store::MAX_RECENT_PATHS, 0 );
		$GLOBALS['_wpdb_get_row'] = array(
			'verification_state' => 'known_crawler',
			'recent_paths'       => '[]',
			'recent_seen_at'     => '[]',
			'recent_errors'      => wp_json_encode( $existing ),
		);

		$this->store->record( '203.0.113.42', 'Googlebot', 'ua', 'googlebot', 'frontend', 'known_crawler', true, '', null, null, null, null, null, true );

		// Still MAX_RECENT_PATHS entries -- the oldest 0 dropped to make
		// room for the new 1.
		$count = Scanner_Identity_Store::MAX_RECENT_PATHS;
		$expected = wp_json_encode( array_merge( array_fill( 0, $count - 1, 0 ), array( 1 ) ) );
		$this->assertStringContainsString( addslashes( (string) $expected ), $GLOBALS['_wpdb_queries'][0] );
	}

	public function test_record_still_appends_an_error_flag_when_a_decision_state_blocks_the_verification_state_update(): void {
		$GLOBALS['_wpdb_get_row'] = array(
			'verification_state' => 'customer_authorised',
			'recent_paths'       => '[]',
			'recent_seen_at'     => '[]',
			'recent_errors'      => '[]',
		);

		$this->store->record( '203.0.113.42', 'Qualys', 'ua', 'qualys', 'frontend', 'known_commercial_scanner', true, '', null, null, null, null, null, true );

		$this->assertStringContainsString( "'[1]'", $GLOBALS['_wpdb_queries'][0] );
	}

	// ── asn/asn_org/geo_* (schema v42, Phase 4A carried-forward item) ───────

	public function test_record_persists_network_fields_when_provided_on_first_insert(): void {
		$GLOBALS['_wpdb_get_row'] = null;

		$this->store->record( '203.0.113.42', 'Googlebot', 'ua', 'googlebot', 'frontend', 'known_crawler', true, '', 15169, 'Google LLC', 'US', 'California', 'Mountain View' );

		$query = $GLOBALS['_wpdb_queries'][0];
		$this->assertStringContainsString( '15169', $query );
		$this->assertStringContainsString( "'Google LLC'", $query );
		$this->assertStringContainsString( "'US'", $query );
		$this->assertStringContainsString( "'California'", $query );
		$this->assertStringContainsString( "'Mountain View'", $query );
	}

	public function test_record_insert_path_never_overwrites_network_fields_with_a_null_value(): void {
		$GLOBALS['_wpdb_get_row'] = null;

		$this->store->record( '203.0.113.42', 'Googlebot', 'ua', 'googlebot', 'frontend', 'known_crawler', true );

		// No detector finding this request => no network resolution => these
		// arguments default to null -- the ON DUPLICATE KEY UPDATE clause must
		// still guard with COALESCE/NULLIF so a *later* row with real data
		// isn't clobbered back to unknown on a subsequent request that has none.
		$query = $GLOBALS['_wpdb_queries'][0];
		$this->assertStringContainsString( 'asn = COALESCE(NULLIF(VALUES(asn), 0), asn)', $query );
		$this->assertStringContainsString( "asn_org = COALESCE(NULLIF(VALUES(asn_org), ''), asn_org)", $query );
		$this->assertStringContainsString( "geo_country = COALESCE(NULLIF(VALUES(geo_country), ''), geo_country)", $query );
	}

	public function test_record_decision_state_path_also_updates_network_fields_via_coalesce(): void {
		$GLOBALS['_wpdb_get_row'] = array( 'verification_state' => 'customer_authorised', 'recent_paths' => '[]' );

		$this->store->record( '203.0.113.42', 'Qualys', 'ua', 'qualys', 'frontend', 'known_commercial_scanner', true, '', 12345, 'Some ISP', 'GB' );

		$query = $GLOBALS['_wpdb_queries'][0];
		// Still must not touch verification_state -- an admin decision stands.
		$this->assertStringNotContainsString( 'verification_state', $query );
		$this->assertStringContainsString( 'asn = COALESCE(', $query );
		$this->assertStringContainsString( "'Some ISP'", $query );
		$this->assertStringContainsString( "'GB'", $query );
	}

	public function test_authorise_requires_a_non_empty_note(): void {
		$this->assertFalse( $this->store->authorise( 1, 5, '' ) );
		$this->assertFalse( $this->store->authorise( 1, 5, '   ' ) );
		$this->assertSame( array(), $GLOBALS['_wpdb_updated_rows'] );
	}

	public function test_authorise_writes_the_decision_with_a_reason(): void {
		$ok = $this->store->authorise( 42, 5, 'Confirmed via our contracted pentest vendor.' );

		$this->assertTrue( $ok );
		$this->assertCount( 1, $GLOBALS['_wpdb_updated_rows'] );
		$row = $GLOBALS['_wpdb_updated_rows'][0];
		$this->assertSame( 'customer_authorised', $row['data']['verification_state'] );
		$this->assertSame( 5, $row['data']['authorised_by'] );
		$this->assertSame( array( 'id' => 42 ), $row['where'] );
	}

	public function test_deny_writes_the_explicitly_denied_state(): void {
		$this->store->deny( 42, 5, 'Not one of ours.' );

		$this->assertSame( 'explicitly_denied', $GLOBALS['_wpdb_updated_rows'][0]['data']['verification_state'] );
	}

	public function test_clear_decision_requires_a_reason_and_reverts_to_unknown(): void {
		$this->assertFalse( $this->store->clear_decision( 42, 5, '' ) );

		$ok = $this->store->clear_decision( 42, 5, 'Mistaken denial.' );

		$this->assertTrue( $ok );
		$this->assertSame( 'unknown', $GLOBALS['_wpdb_updated_rows'][0]['data']['verification_state'] );
	}

	public function test_recent_wp_cron_callers_skips_addresses_already_treated_as_this_site(): void {
		\WP_SAM\Intelligence\Own_Address_Store::save( '185.177.72.38' );
		$GLOBALS['_wpdb_get_col'] = array( '10.16.17.55', '185.199.223.7', '185.177.72.38', '203.0.113.9' );

		$this->assertSame( array( '185.199.223.7', '203.0.113.9' ), $this->store->recent_wp_cron_callers() );
	}

	public function test_recent_wp_cron_callers_returns_at_most_the_limit(): void {
		$GLOBALS['_wpdb_get_col'] = array( '203.0.113.1', '203.0.113.2', '203.0.113.3' );

		$this->assertSame( array( '203.0.113.1', '203.0.113.2' ), $this->store->recent_wp_cron_callers( 30, 2 ) );
	}

	// ── relabel_own_addresses() ───────────────────────────────────────────

	private function identity_row( int $id, string $ip, string $state, string $claimed = '', string $user_agent = 'curl/8.0' ): array {
		return array(
			'id'                 => $id,
			'ip'                 => $ip,
			'claimed_identity'   => $claimed,
			'user_agent'         => $user_agent,
			'verification_state' => $state,
		);
	}

	private function resolver(): Identity_Resolver {
		return new Identity_Resolver( new Scanner_Vendor_Store() );
	}

	/** @return array<int, string> The UPDATE statements relabel_own_addresses() issued. */
	private function relabel_updates(): array {
		return array_values( array_filter( $GLOBALS['_wpdb_queries'], static fn( string $sql ): bool => str_starts_with( $sql, 'UPDATE' ) ) );
	}

	public function test_relabel_marks_every_row_from_a_newly_listed_address_as_this_sites_own(): void {
		update_option( Own_Address_Store::OPTION, array( '198.51.100.0/24' ) );
		$GLOBALS['_wpdb_get_results_queue'] = array(
			array(
				$this->identity_row( 1, '198.51.100.7', 'unknown' ),
				// First recorded under a crawler's name: later requests go to the unnamed row.
				$this->identity_row( 2, '198.51.100.7', 'known_crawler', 'Googlebot', 'Mozilla/5.0 Googlebot' ),
				$this->identity_row( 3, '203.0.113.9', 'unknown' ),
				$this->identity_row( 4, '198.51.100.8', 'loopback' ),
			),
		);

		$GLOBALS['_wpdb_query_result'] = 2; // Rows the one UPDATE affects.

		$this->assertSame( 2, $this->store->relabel_own_addresses( $this->resolver() ) );

		$updates = $this->relabel_updates();
		$this->assertCount( 1, $updates );
		$this->assertStringContainsString( "SET verification_state = 'loopback' WHERE id IN (1, 2)", $updates[0] );
	}

	public function test_relabel_never_reads_or_changes_a_row_with_an_administrator_decision(): void {
		update_option( Own_Address_Store::OPTION, array( '198.51.100.0/24' ) );

		$this->store->relabel_own_addresses( $this->resolver() );

		$select = $GLOBALS['_wpdb_get_results_log'][0];
		foreach ( Scanner_Identity_Store::AUTOMATIC_STATES as $state ) {
			$this->assertStringContainsString( "'{$state}'", $select );
		}
		foreach ( Scanner_Identity_Store::DECISION_STATES as $state ) {
			$this->assertStringNotContainsString( "'{$state}'", $select );
		}
		$this->assertSame( array(), $this->relabel_updates() );
	}

	public function test_relabel_returns_an_address_taken_off_the_list_to_how_a_request_from_it_is_labelled_now(): void {
		update_option( Own_Address_Store::OPTION, array() );
		$GLOBALS['_wpdb_get_results_queue'] = array(
			array(
				$this->identity_row( 5, '198.51.100.7', 'loopback' ),
				$this->identity_row( 6, '198.51.100.7', 'loopback', 'Googlebot', 'Mozilla/5.0 Googlebot' ),
				// Private addresses are always this site's own.
				$this->identity_row( 7, '10.16.17.55', 'loopback' ),
			),
			// Scanner_Vendor_Store::all(), read by the resolver for row 6.
			array(
				array(
					'vendor_key'          => 'googlebot',
					'vendor_name'         => 'Googlebot',
					'category'            => 'known_crawler',
					'ua_pattern'          => 'Googlebot',
					'rdns_suffixes'       => '[]',
					'cidr_ranges'         => '[]',
					'source_url'          => '',
					'verification_method' => 'none',
					'notes'               => '',
					'is_builtin'          => 1,
				),
			),
		);

		$this->assertSame( 2, $this->store->relabel_own_addresses( $this->resolver() ) );

		$updates = $this->relabel_updates();
		$this->assertCount( 2, $updates );
		$this->assertStringContainsString( "SET verification_state = 'unknown' WHERE id IN (5)", $updates[0] );
		$this->assertStringContainsString( "SET verification_state = 'known_crawler' WHERE id IN (6)", $updates[1] );
	}

	public function test_relabel_reads_the_table_in_batches_after_the_last_id_seen(): void {
		update_option( Own_Address_Store::OPTION, array( '198.51.100.0/24' ) );
		$full_batch = array();
		for ( $id = 1; $id <= 1000; $id++ ) {
			$full_batch[] = $this->identity_row( $id, '203.0.113.9', 'unknown' );
		}
		$GLOBALS['_wpdb_get_results_queue'] = array(
			$full_batch,
			array( $this->identity_row( 1001, '198.51.100.7', 'unknown' ) ),
		);

		$this->store->relabel_own_addresses( $this->resolver() );

		$this->assertCount( 2, $GLOBALS['_wpdb_get_results_log'] );
		$this->assertStringContainsString( 'WHERE id > 0 ', $GLOBALS['_wpdb_get_results_log'][0] );
		$this->assertStringContainsString( 'WHERE id > 1000 ', $GLOBALS['_wpdb_get_results_log'][1] );
		$this->assertStringContainsString( 'WHERE id IN (1001)', $this->relabel_updates()[0] );
	}
}
