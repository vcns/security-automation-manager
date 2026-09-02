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
use WP_SAM\Intelligence\Scanner_Identity_Store;

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
		$GLOBALS['_wpdb_get_var'] = null; // No existing row.

		$this->store->record( '203.0.113.42', 'Googlebot', 'Mozilla/5.0 Googlebot', 'googlebot', 'frontend', 'known_crawler', true );

		$this->assertCount( 1, $GLOBALS['_wpdb_queries'] );
		$this->assertStringContainsString( "'known_crawler'", $GLOBALS['_wpdb_queries'][0] );
		$this->assertStringContainsString( "'googlebot'", $GLOBALS['_wpdb_queries'][0] );
	}

	public function test_record_clamps_an_unrecognised_state_to_unknown(): void {
		$GLOBALS['_wpdb_get_var'] = null;

		$this->store->record( '203.0.113.42', '', '', '', 'frontend', 'not-a-real-state', null );

		$this->assertStringContainsString( "'unknown'", $GLOBALS['_wpdb_queries'][0] );
	}

	public function test_record_never_overwrites_an_existing_authorisation_decision(): void {
		$GLOBALS['_wpdb_get_var'] = 'customer_authorised';

		$this->store->record( '203.0.113.42', 'Qualys', 'QualysGuard', 'qualys', 'frontend', 'known_commercial_scanner', true );

		$this->assertCount( 1, $GLOBALS['_wpdb_queries'] );
		// The bookkeeping-only path must never mention verification_state --
		// only occurrence_count/last_seen_at may change.
		$this->assertStringNotContainsString( 'verification_state', $GLOBALS['_wpdb_queries'][0] );
		$this->assertStringContainsString( 'occurrence_count = occurrence_count + 1', $GLOBALS['_wpdb_queries'][0] );
	}

	public function test_record_never_overwrites_an_explicit_denial(): void {
		$GLOBALS['_wpdb_get_var'] = 'explicitly_denied';

		$this->store->record( '203.0.113.42', 'Qualys', 'QualysGuard', 'qualys', 'frontend', 'known_commercial_scanner', true );

		$this->assertStringNotContainsString( 'verification_state', $GLOBALS['_wpdb_queries'][0] );
	}

	public function test_record_updates_normally_when_existing_state_is_automatic(): void {
		$GLOBALS['_wpdb_get_var'] = 'known_crawler'; // An automatic state, not a decision.

		$this->store->record( '203.0.113.42', 'Googlebot', 'ua', 'googlebot', 'frontend', 'known_crawler', true );

		// Falls through to the normal INSERT ... ON DUPLICATE KEY UPDATE path,
		// which does set verification_state.
		$this->assertStringContainsString( 'verification_state', $GLOBALS['_wpdb_queries'][0] );
	}

	public function test_record_is_rate_limited_per_fingerprint(): void {
		$GLOBALS['_wpdb_get_var'] = null;

		for ( $i = 0; $i < 505; $i++ ) {
			$this->store->record( '203.0.113.42', 'Googlebot', 'ua', 'googlebot', 'frontend', 'known_crawler', true );
		}

		$this->assertCount( 500, $GLOBALS['_wpdb_queries'] );
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
}
