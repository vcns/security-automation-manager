<?php
/**
 * Unit tests for WP_SAM\Intelligence\Bot_Classifier.
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;
use WP_SAM\Intelligence\Bot_Classifier;

class BotClassifierTest extends TestCase {

	private Bot_Classifier $classifier;

	protected function setUp(): void {
		wp_test_reset_globals();
		$this->classifier = new Bot_Classifier();
	}

	/** @param array<string, mixed> $overrides */
	private function identity( array $overrides = array() ): array {
		return array_merge(
			array(
				'verification_state' => 'unknown',
				'network_match'      => null,
			),
			$overrides
		);
	}

	public function test_admin_authorised_decision_wins_regardless_of_network_match(): void {
		$identity = $this->identity( array( 'verification_state' => 'customer_authorised', 'network_match' => 0 ) );

		$this->assertSame( 'admin_authorised', $this->classifier->classify( $identity, null ) );
	}

	public function test_admin_denied_decision_wins_regardless_of_network_match(): void {
		$identity = $this->identity( array( 'verification_state' => 'explicitly_denied', 'network_match' => 1 ) );

		$this->assertSame( 'admin_denied', $this->classifier->classify( $identity, null ) );
	}

	public function test_admin_authorisation_expired_decision(): void {
		$identity = $this->identity( array( 'verification_state' => 'previously_authorised_expired' ) );

		$this->assertSame( 'admin_authorisation_expired', $this->classifier->classify( $identity, null ) );
	}

	// ── Loopback recognition ──────────────────────────────────────────────────

	public function test_loopback_state_classifies_as_loopback(): void {
		$identity = $this->identity( array( 'verification_state' => 'loopback' ) );

		$this->assertSame( 'loopback', $this->classifier->classify( $identity, null ) );
	}

	public function test_loopback_state_is_checked_ahead_of_a_rate_escalated_block(): void {
		// A loopback self-request can't sensibly be "aggressive" -- the
		// loopback recognition takes priority over the traffic block.
		$identity = $this->identity( array( 'verification_state' => 'loopback' ) );
		$block    = array( 'stage' => 'persistent_block' );

		$this->assertSame( 'loopback', $this->classifier->classify( $identity, $block ) );
	}

	public function test_admin_decision_wins_over_loopback_recognition(): void {
		// An administrator can still explicitly deny a loopback source (e.g.
		// a site where a reverse proxy makes every visitor look like
		// loopback) -- a decision always wins over automatic recognition.
		$identity = $this->identity( array( 'verification_state' => 'explicitly_denied' ) );

		$this->assertSame( 'admin_denied', $this->classifier->classify( $identity, null ) );
	}

	public function test_known_crawler_with_network_match_is_verified(): void {
		$identity = $this->identity( array( 'verification_state' => 'known_crawler', 'network_match' => 1 ) );

		$this->assertSame( 'verified_crawler', $this->classifier->classify( $identity, null ) );
	}

	public function test_known_crawler_without_network_match_is_unverified_claim(): void {
		$identity = $this->identity( array( 'verification_state' => 'known_crawler', 'network_match' => 0 ) );

		$this->assertSame( 'claimed_crawler_unverified', $this->classifier->classify( $identity, null ) );
	}

	public function test_known_crawler_with_null_network_match_is_unverified_claim(): void {
		// No network verification has been attempted yet -- can't be
		// asserted as verified just because it hasn't been disproven.
		$identity = $this->identity( array( 'verification_state' => 'known_crawler', 'network_match' => null ) );

		$this->assertSame( 'claimed_crawler_unverified', $this->classifier->classify( $identity, null ) );
	}

	public function test_known_commercial_scanner_and_known_research_scanner_use_the_same_rule(): void {
		$commercial = $this->identity( array( 'verification_state' => 'known_commercial_scanner', 'network_match' => 1 ) );
		$research   = $this->identity( array( 'verification_state' => 'known_research_scanner', 'network_match' => 0 ) );

		$this->assertSame( 'verified_crawler', $this->classifier->classify( $commercial, null ) );
		$this->assertSame( 'claimed_crawler_unverified', $this->classifier->classify( $research, null ) );
	}

	public function test_unknown_identity_with_no_traffic_block_is_unclassified(): void {
		$this->assertSame( 'unclassified', $this->classifier->classify( $this->identity(), null ) );
	}

	public function test_unknown_identity_with_an_observe_stage_block_is_still_unclassified(): void {
		$block = array( 'stage' => 'observe' );

		$this->assertSame( 'unclassified', $this->classifier->classify( $this->identity(), $block ) );
	}

	public function test_unknown_identity_with_a_warn_stage_block_is_still_unclassified(): void {
		// 'warn' is logged-only, never visitor-facing -- not yet "aggressive".
		$block = array( 'stage' => 'warn' );

		$this->assertSame( 'unclassified', $this->classifier->classify( $this->identity(), $block ) );
	}

	public function test_unknown_identity_escalated_to_throttle_is_aggressive(): void {
		$block = array( 'stage' => 'throttle' );

		$this->assertSame( 'aggressive_unidentified', $this->classifier->classify( $this->identity(), $block ) );
	}

	public function test_unknown_identity_escalated_to_persistent_block_is_aggressive(): void {
		$block = array( 'stage' => 'persistent_block' );

		$this->assertSame( 'aggressive_unidentified', $this->classifier->classify( $this->identity(), $block ) );
	}

	public function test_identity_conflict_state_falls_back_to_the_rate_based_rule(): void {
		// Not one of KNOWN_STATES or a decision state -- treated the same
		// as 'unknown' until this state is actually wired up elsewhere.
		$identity = $this->identity( array( 'verification_state' => 'identity_conflict' ) );
		$block    = array( 'stage' => 'temporary_block' );

		$this->assertSame( 'aggressive_unidentified', $this->classifier->classify( $identity, $block ) );
	}

	// ── URI-pattern signal (Phase 4C) ────────────────────────────────────────

	public function test_unrecognised_source_with_a_sequential_path_pattern_is_enumerating(): void {
		$identity = $this->identity(
			array(
				'recent_paths' => wp_json_encode( array( '/product/101', '/product/102', '/product/103', '/product/104' ) ),
			)
		);

		$this->assertSame( 'enumerating_scraper', $this->classifier->classify( $identity, null ) );
	}

	public function test_enumeration_check_wins_over_rate_escalation(): void {
		// Both signals are present -- enumeration is checked first and
		// takes priority, per the class's own documented order.
		$identity = $this->identity(
			array(
				'recent_paths' => wp_json_encode( array( '/product/1', '/product/2', '/product/3', '/product/4' ) ),
			)
		);
		$block = array( 'stage' => 'temporary_block' );

		$this->assertSame( 'enumerating_scraper', $this->classifier->classify( $identity, $block ) );
	}

	public function test_a_known_crawlers_enumeration_is_never_flagged(): void {
		// A search engine systematically walking a site's posts is normal,
		// expected crawler behaviour -- recent_paths is never even
		// consulted once a known vendor match has already been decided.
		$identity = $this->identity(
			array(
				'verification_state' => 'known_crawler',
				'network_match'      => 1,
				'recent_paths'       => wp_json_encode( array( '/post/1', '/post/2', '/post/3', '/post/4' ) ),
			)
		);

		$this->assertSame( 'verified_crawler', $this->classifier->classify( $identity, null ) );
	}

	public function test_missing_recent_paths_is_treated_as_no_pattern(): void {
		$identity = $this->identity(); // No 'recent_paths' key at all.

		$this->assertSame( 'unclassified', $this->classifier->classify( $identity, null ) );
	}

	public function test_malformed_recent_paths_json_is_treated_as_no_pattern(): void {
		$identity = $this->identity( array( 'recent_paths' => 'not valid json' ) );

		$this->assertSame( 'unclassified', $this->classifier->classify( $identity, null ) );
	}
}
