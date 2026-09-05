<?php
/**
 * Unit tests for WP_SAM\Intelligence\Traffic_Guard -- this plugin's first
 * active request-blocking capability. Focuses on the safety properties the
 * class docblock promises (default-safety, admin exemption, explicit rules
 * always applying) plus the core escalation/rate-limit wiring; the full
 * stage-transition matrix is already covered by TrafficBlockStoreTest.
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;
use WP_SAM\Intelligence\Asn_Lookup_Store;
use WP_SAM\Intelligence\Geo_Ip_Store;
use WP_SAM\Intelligence\Ip_Rule_Store;
use WP_SAM\Intelligence\Network_Intelligence_Resolver;
use WP_SAM\Intelligence\Network_Rule_Store;
use WP_SAM\Intelligence\Rate_Limiter;
use WP_SAM\Intelligence\Tor_Exit_List_Store;
use WP_SAM\Intelligence\Traffic_Block_Store;
use WP_SAM\Intelligence\Traffic_Guard;
use WP_SAM\Intelligence\Traffic_Policy_Store;

class TrafficGuardTest extends TestCase {

	private Traffic_Guard $guard;

	protected function setUp(): void {
		wp_test_reset_globals();
		$this->guard = new Traffic_Guard(
			new Traffic_Policy_Store(),
			new Ip_Rule_Store(),
			new Traffic_Block_Store(),
			new Rate_Limiter(),
			new Network_Rule_Store(),
			new Network_Intelligence_Resolver( new Tor_Exit_List_Store(), new Asn_Lookup_Store(), new Geo_Ip_Store() )
		);
	}

	private function policy_row( array $overrides = array() ): array {
		return array_merge(
			array(
				'surface'                    => 'frontend',
				'mode'                        => 'observe',
				'rate_limit_max_requests'     => 300,
				'rate_limit_window_seconds'   => 60,
				'login_max_failed_attempts'   => 10,
				'login_lockout_seconds'       => 900,
			),
			$overrides
		);
	}

	private function block_row( array $overrides = array() ): array {
		return array_merge(
			array(
				'id'               => 1,
				'ip'               => '203.0.113.42',
				'surface'          => 'frontend',
				'stage'            => 'temporary_block',
				'reason'           => 'rate_limit',
				'occurrence_count' => 3,
				'blocked_until'    => gmdate( 'Y-m-d H:i:s', time() + 600 ),
				'is_persistent'    => 0,
				'fingerprint'      => 'x',
				'first_seen_at'    => '2026-09-02 00:00:00',
				'last_seen_at'     => '2026-09-02 00:00:00',
			),
			$overrides
		);
	}

	public function test_empty_ip_is_always_allowed(): void {
		$verdict = $this->guard->decide( '', 'frontend', false );

		$this->assertSame( 'allow', $verdict['action'] );
	}

	public function test_explicit_block_rule_blocks_even_a_privileged_user(): void {
		$GLOBALS['_wpdb_get_results'] = array(
			array( 'id' => 1, 'list_type' => 'block', 'cidr' => '203.0.113.42', 'surface' => '', 'expires_at' => null ),
		);

		$verdict = $this->guard->decide( '203.0.113.42', 'frontend', true );

		$this->assertSame( 'block', $verdict['action'] );
		$this->assertSame( 'ip_rule_block', $verdict['reason'] );
	}

	public function test_explicit_allow_rule_bypasses_an_active_automatic_block(): void {
		// Allow rule short-circuits before any block-store lookup happens.
		$GLOBALS['_wpdb_get_results'] = array(
			array( 'id' => 1, 'list_type' => 'allow', 'cidr' => '203.0.113.42', 'surface' => '', 'expires_at' => null ),
		);

		$verdict = $this->guard->decide( '203.0.113.42', 'frontend', false );

		$this->assertSame( 'allow', $verdict['action'] );
	}

	// ── Loopback exemption ────────────────────────────────────────────────────

	public function test_loopback_ipv4_source_is_never_blocked_by_automatic_escalation(): void {
		$GLOBALS['_wpdb_get_results'] = array(); // No IP rules.

		$verdict = $this->guard->decide( '127.0.0.1', 'frontend', false );

		$this->assertSame( 'allow', $verdict['action'] );
	}

	public function test_loopback_ipv6_source_is_never_blocked_by_automatic_escalation(): void {
		$GLOBALS['_wpdb_get_results'] = array(); // No IP rules.

		$verdict = $this->guard->decide( '::1', 'frontend', false );

		$this->assertSame( 'allow', $verdict['action'] );
	}

	public function test_loopback_source_never_reaches_the_rate_limiter_even_when_already_escalated(): void {
		// An existing stray block record for a loopback address (e.g. from
		// before this exemption existed) must become inert, not just future
		// escalations -- no _wpdb_get_row_queue entries means the test fails
		// loudly if decide() ever reaches Traffic_Block_Store::get().
		$GLOBALS['_wpdb_get_results'] = array();

		$verdict = $this->guard->decide( '127.0.0.1', 'admin', false );

		$this->assertSame( 'allow', $verdict['action'] );
		$this->assertFalse( $verdict['would_block'] );
	}

	public function test_explicit_block_rule_still_applies_to_a_loopback_source(): void {
		// The one documented escape hatch (Identity_Resolver's own docblock):
		// an administrator can still explicitly deny a loopback source.
		$GLOBALS['_wpdb_get_results'] = array(
			array( 'id' => 1, 'list_type' => 'block', 'cidr' => '127.0.0.1', 'surface' => '', 'expires_at' => null ),
		);

		$verdict = $this->guard->decide( '127.0.0.1', 'frontend', false );

		$this->assertSame( 'block', $verdict['action'] );
		$this->assertSame( 'ip_rule_block', $verdict['reason'] );
	}

	// ── Network (ASN/country) rules ──────────────────────────────────────────

	public function test_network_rule_blocks_a_matching_asn_even_for_a_privileged_user(): void {
		$GLOBALS['_wpdb_get_var_queue']     = array( 1, 1 ); // Network_Rule_Store::has_any() => true; Tor_Exit_List_Store::is_exit_node() (inside resolve(), irrelevant to this test) => true.
		$GLOBALS['_wpdb_get_row']           = array( 'asn' => 15169, 'asn_org' => 'GOOGLE' ); // Asn_Lookup_Store cache hit -- no live DNS lookup.
		$GLOBALS['_wpdb_get_results_queue'] = array(
			array(), // Ip_Rule_Store::all() -- no IP rules.
			array( array( 'id' => 1, 'rule_type' => 'asn', 'value' => '15169', 'surface' => '' ) ), // Network_Rule_Store::all().
		);

		$verdict = $this->guard->decide( '203.0.113.42', 'frontend', true );

		$this->assertSame( 'block', $verdict['action'] );
		$this->assertSame( 'network_rule_block', $verdict['reason'] );
		$this->assertSame( 'persistent_block', $verdict['stage'] );
	}

	public function test_no_network_rules_configured_never_calls_the_network_resolver(): void {
		// has_any() => false (default null): the ASN/Geo-IP lookup this
		// would otherwise trigger must never run -- see Traffic_Guard's own
		// docblock for why that cost must stay opt-in.
		$GLOBALS['_wpdb_get_results_queue'] = array( array() ); // Ip_Rule_Store::all() -- no IP rules.
		$GLOBALS['_wpdb_get_row_queue']     = array(
			$this->policy_row( array( 'mode' => 'observe' ) ), // is_enforcing()
			null, // Traffic_Block_Store::get() -- no existing block.
			$this->policy_row( array( 'mode' => 'observe' ) ), // get(surface) for thresholds.
		);

		$verdict = $this->guard->decide( '203.0.113.42', 'frontend', false );

		$this->assertSame( 'allow', $verdict['action'] );
	}

	public function test_privileged_user_is_exempt_from_an_active_automatic_block(): void {
		$GLOBALS['_wpdb_get_row_queue'] = array(
			$this->policy_row( array( 'mode' => 'enforce' ) ),
			$this->block_row(),
		);

		$verdict = $this->guard->decide( '203.0.113.42', 'frontend', true );

		$this->assertSame( 'allow', $verdict['action'] );
	}

	public function test_observe_mode_never_actually_blocks_despite_an_active_block(): void {
		$GLOBALS['_wpdb_get_row_queue'] = array(
			$this->policy_row( array( 'mode' => 'observe' ) ),
			$this->block_row(),
		);

		$verdict = $this->guard->decide( '203.0.113.42', 'frontend', false );

		$this->assertSame( 'allow', $verdict['action'] );
		$this->assertTrue( $verdict['would_block'] );
	}

	public function test_enforce_mode_blocks_a_non_privileged_source_with_an_active_block(): void {
		$GLOBALS['_wpdb_get_row_queue'] = array(
			$this->policy_row( array( 'mode' => 'enforce' ) ),
			$this->block_row(),
		);

		$verdict = $this->guard->decide( '203.0.113.42', 'frontend', false );

		$this->assertSame( 'block', $verdict['action'] );
		$this->assertGreaterThan( 0, $verdict['retry_after_seconds'] );
	}

	public function test_rate_limit_exceeded_escalates_a_fresh_source_to_warn_and_still_allows(): void {
		$GLOBALS['_wp_transients']['wp_sam_rate_frontend_' . md5( '203.0.113.42' )] = 500; // Already way over.
		$GLOBALS['_wpdb_get_row_queue'] = array(
			$this->policy_row( array( 'mode' => 'observe' ) ), // is_enforcing()
			null, // Traffic_Block_Store::get() -- no existing block.
			$this->policy_row( array( 'mode' => 'observe' ) ), // get() for thresholds.
			null, // record_violation()'s internal existing check.
			array( 'id' => 1, 'ip' => '203.0.113.42', 'surface' => 'frontend', 'stage' => 'warn', 'blocked_until' => null, 'reason' => 'rate_limit', 'occurrence_count' => 1, 'is_persistent' => 0 ),
		);

		$verdict = $this->guard->decide( '203.0.113.42', 'frontend', false );

		$this->assertSame( 'allow', $verdict['action'] );
		$this->assertSame( 'warn', $verdict['stage'] );
		$this->assertCount( 1, $GLOBALS['_wpdb_inserted_rows'] ); // record_violation() actually wrote a row.
	}

	public function test_privileged_user_over_the_rate_limit_is_allowed_and_never_escalated(): void {
		$GLOBALS['_wp_transients']['wp_sam_rate_frontend_' . md5( '203.0.113.42' )] = 500;
		$GLOBALS['_wpdb_get_row_queue'] = array(
			$this->policy_row( array( 'mode' => 'enforce' ) ),
			null,
			$this->policy_row( array( 'mode' => 'enforce' ) ),
		);

		$verdict = $this->guard->decide( '203.0.113.42', 'frontend', true );

		$this->assertSame( 'allow', $verdict['action'] );
		$this->assertSame( array(), $GLOBALS['_wpdb_inserted_rows'] ); // No escalation for a privileged session.
	}

	public function test_missing_policy_row_defaults_to_allow(): void {
		$GLOBALS['_wpdb_get_row_queue'] = array(
			null, // is_enforcing(): no policy row.
			null, // Traffic_Block_Store::get(): no existing block.
			null, // get(surface) for thresholds: still nothing.
		);

		$verdict = $this->guard->decide( '203.0.113.42', 'frontend', false );

		$this->assertSame( 'allow', $verdict['action'] );
	}

	// ── on_login_failed() ────────────────────────────────────────────────────

	public function test_login_failure_does_not_escalate_before_the_threshold(): void {
		$_SERVER['REMOTE_ADDR'] = '203.0.113.42';
		$GLOBALS['_wpdb_get_row'] = $this->policy_row( array( 'surface' => 'login', 'login_max_failed_attempts' => 10 ) );

		$this->guard->on_login_failed( 'admin' );

		$this->assertSame( array(), $GLOBALS['_wpdb_inserted_rows'] );
		unset( $_SERVER['REMOTE_ADDR'] );
	}

	public function test_login_failure_escalates_once_past_the_threshold(): void {
		$_SERVER['REMOTE_ADDR'] = '203.0.113.42';
		$GLOBALS['_wp_transients']['wp_sam_rate_login_failed_' . md5( '203.0.113.42' )] = 10; // Already at the limit.
		$GLOBALS['_wpdb_get_row_queue'] = array(
			$this->policy_row( array( 'surface' => 'login', 'login_max_failed_attempts' => 10, 'login_lockout_seconds' => 900 ) ),
			null, // Traffic_Block_Store::record_violation()'s existing check.
			$this->block_row( array( 'surface' => 'login', 'stage' => 'warn' ) ),
		);

		$this->guard->on_login_failed( 'admin' );

		$this->assertCount( 1, $GLOBALS['_wpdb_inserted_rows'] );
		unset( $_SERVER['REMOTE_ADDR'] );
	}
}
