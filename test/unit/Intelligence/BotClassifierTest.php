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
}
