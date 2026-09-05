<?php
/**
 * Smoke/regression coverage for includes/admin/views/page-traffic.php's
 * Custom Rules tab (Phase 4C extension -- fail2ban-style custom detection
 * rules). No test previously rendered this view file at all; the other
 * tabs (Policy/IP Rules/Blocks/Network Intelligence/Detectors) are a
 * pre-existing gap outside this coverage's scope.
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;
use WP_SAM\Admin\Admin_UI;

class PageTrafficTest extends TestCase {

	protected function setUp(): void {
		wp_test_reset_globals();
	}

	public function test_custom_rules_tab_renders_without_fatal_when_empty(): void {
		$_GET['tab'] = 'custom-rules';
		$GLOBALS['_wpdb_get_results'] = array();

		ob_start();
		require WP_SAM_DIR . 'includes/admin/views/page-traffic.php';
		$output = (string) ob_get_clean();

		unset( $_GET['tab'] );

		$this->assertStringContainsString( 'Custom Rules', $output );
		$this->assertStringContainsString( 'No custom rules yet.', $output );
		$this->assertStringContainsString( 'wp_sam_custom_rule_save', $output );
		$this->assertStringContainsString( 'wp-sam-custom-rule-test-button', $output );
	}

	public function test_custom_rules_tab_lists_a_stored_rule(): void {
		$_GET['tab'] = 'custom-rules';
		$GLOBALS['_wpdb_get_results'] = array(
			array(
				'id'            => 3,
				'name'          => 'Old backup file probe',
				'pattern'       => '/\.bak$/i',
				'subject_field' => 'request_uri',
				'severity'      => 'high',
				'surfaces'      => '[]',
				'description'   => '',
			),
		);

		ob_start();
		require WP_SAM_DIR . 'includes/admin/views/page-traffic.php';
		$output = (string) ob_get_clean();

		unset( $_GET['tab'] );

		$this->assertStringContainsString( 'Old backup file probe', $output );
		$this->assertStringContainsString( 'custom_3', $output );
		$this->assertStringContainsString( 'All', $output );
	}

	public function test_custom_rules_tab_shows_validation_errors_from_a_failed_save(): void {
		$_GET['tab']              = 'custom-rules';
		$GLOBALS['_wpdb_get_results'] = array();
		set_transient( 'wp_sam_custom_rule_errors_' . get_current_user_id(), array( 'Pattern is required.' ) );
		set_transient( 'wp_sam_custom_rule_input_' . get_current_user_id(), array( 'name' => 'Half-typed rule' ) );

		ob_start();
		require WP_SAM_DIR . 'includes/admin/views/page-traffic.php';
		$output = (string) ob_get_clean();

		unset( $_GET['tab'] );

		$this->assertStringContainsString( 'Rule not saved', $output );
		$this->assertStringContainsString( 'Pattern is required.', $output );
		$this->assertStringContainsString( 'Half-typed rule', $output );
	}

	public function test_custom_rules_tab_prefills_the_form_when_editing(): void {
		$_GET['tab']  = 'custom-rules';
		$_GET['edit'] = '3';
		$GLOBALS['_wpdb_get_results'] = array();
		$GLOBALS['_wpdb_get_row']     = array(
			'id'            => 3,
			'name'          => 'Old backup file probe',
			'pattern'       => '/\.bak$/i',
			'subject_field' => 'path',
			'severity'      => 'high',
			'surfaces'      => '["frontend"]',
			'description'   => 'Notes here',
		);

		ob_start();
		require WP_SAM_DIR . 'includes/admin/views/page-traffic.php';
		$output = (string) ob_get_clean();

		unset( $_GET['tab'], $_GET['edit'] );

		$this->assertStringContainsString( 'Edit rule', $output );
		$this->assertStringContainsString( 'value="Old backup file probe"', $output );
		$this->assertStringContainsString( 'Notes here', $output );
	}

	// ── Network Intelligence tab -- Network Rules sub-tab ───────────────────

	public function test_network_intelligence_tab_renders_without_a_network_rule(): void {
		$_GET['tab']    = 'network-intelligence';
		$_GET['subtab'] = 'network-rules';
		$GLOBALS['_wpdb_get_results'] = array();

		ob_start();
		require WP_SAM_DIR . 'includes/admin/views/page-traffic.php';
		$output = (string) ob_get_clean();

		unset( $_GET['tab'], $_GET['subtab'] );

		$this->assertStringContainsString( 'Network Rules', $output );
		$this->assertStringContainsString( 'No network rules yet.', $output );
		$this->assertStringContainsString( 'wp_sam_network_rule_add', $output );
	}

	public function test_network_intelligence_tab_lists_a_stored_network_rule(): void {
		$_GET['tab']    = 'network-intelligence';
		$_GET['subtab'] = 'network-rules';
		$GLOBALS['_wpdb_get_results'] = array(
			array(
				'id'        => 4,
				'rule_type' => 'asn',
				'value'     => '15169',
				'surface'   => '',
				'reason'    => 'Known scraper network',
			),
		);

		ob_start();
		require WP_SAM_DIR . 'includes/admin/views/page-traffic.php';
		$output = (string) ob_get_clean();

		unset( $_GET['tab'], $_GET['subtab'] );

		$this->assertStringContainsString( 'AS15169', $output );
		$this->assertStringContainsString( 'Known scraper network', $output );
		$this->assertStringContainsString( 'wp_sam_network_rule_delete', $output );
	}

	// ── Network Intelligence tab -- Geo-IP sub-tab's Country Block List ─────

	public function test_geoip_subtab_renders_country_grid_with_nothing_blocked(): void {
		$_GET['tab']    = 'network-intelligence';
		$_GET['subtab'] = 'geoip';
		$GLOBALS['_wpdb_get_results'] = array(); // Network_Rule_Store::all() -- no rules.

		ob_start();
		require WP_SAM_DIR . 'includes/admin/views/page-traffic.php';
		$output = (string) ob_get_clean();

		unset( $_GET['tab'], $_GET['subtab'] );

		$this->assertStringContainsString( 'Country Block List', $output );
		$this->assertStringContainsString( 'wp_sam_geoip_country_block_save', $output );
		$this->assertStringContainsString( 'value="CN"', $output );
		$this->assertStringNotContainsString( 'checked', $output );
	}

	public function test_geoip_subtab_pre_checks_an_existing_all_surface_country_block(): void {
		$_GET['tab']    = 'network-intelligence';
		$_GET['subtab'] = 'geoip';
		$GLOBALS['_wpdb_get_results'] = array(
			array(
				'id'        => 9,
				'rule_type' => 'country',
				'value'     => 'CN',
				'surface'   => '',
				'reason'    => 'Blocked via Geo-IP country list',
			),
		);

		ob_start();
		require WP_SAM_DIR . 'includes/admin/views/page-traffic.php';
		$output = (string) ob_get_clean();

		unset( $_GET['tab'], $_GET['subtab'] );

		$this->assertMatchesRegularExpression( '/value="CN"\s+checked/', $output );
	}

	public function test_geoip_subtab_shows_the_lockout_warning_from_a_pending_transient(): void {
		$_GET['tab']    = 'network-intelligence';
		$_GET['subtab'] = 'geoip';
		$GLOBALS['_wpdb_get_results'] = array();
		set_transient(
			'wp_sam_geoip_lockout_pending_' . get_current_user_id(),
			array(
				'countries' => array( 'CN' ),
				'message'   => 'Your own current IP address (203.0.113.42) resolves to China.',
			)
		);

		ob_start();
		require WP_SAM_DIR . 'includes/admin/views/page-traffic.php';
		$output = (string) ob_get_clean();

		unset( $_GET['tab'], $_GET['subtab'] );

		$this->assertStringContainsString( 'This could lock you out of wp-admin', $output );
		$this->assertStringContainsString( 'resolves to China', $output );
		$this->assertStringContainsString( 'confirm_lockout_risk', $output );
		$this->assertMatchesRegularExpression( '/value="CN"\s+checked/', $output );
	}

	public function test_geoip_lockout_warning_survives_a_plain_get_render(): void {
		// The transient must only ever be cleared by a real save (success
		// or an explicit resubmission), never by the view simply being
		// rendered again -- an admin refreshing the page, opening a second
		// tab, or following the warning's own advice to check IP Rules
		// first and coming back must not silently lose the warning.
		$_GET['tab']    = 'network-intelligence';
		$_GET['subtab'] = 'geoip';
		$GLOBALS['_wpdb_get_results'] = array();
		set_transient(
			Admin_UI::GEOIP_LOCKOUT_TRANSIENT_PREFIX . get_current_user_id(),
			array(
				'countries' => array( 'CN' ),
				'message'   => 'Your own current IP address (203.0.113.42) resolves to China.',
			)
		);

		ob_start();
		require WP_SAM_DIR . 'includes/admin/views/page-traffic.php';
		ob_get_clean();

		ob_start();
		require WP_SAM_DIR . 'includes/admin/views/page-traffic.php';
		$second_render = (string) ob_get_clean();

		unset( $_GET['tab'], $_GET['subtab'] );

		$this->assertStringContainsString( 'This could lock you out of wp-admin', $second_render );
	}

	// ── Network Intelligence tab -- legacy lookup URL params ────────────────

	public function test_lookup_ip_param_without_an_explicit_subtab_lands_on_asn(): void {
		$_GET['tab']       = 'network-intelligence';
		$_GET['lookup_ip'] = '203.0.113.42';
		$GLOBALS['_wpdb_get_results'] = array();
		$GLOBALS['_wpdb_get_row']     = array( 'asn' => 15169, 'asn_org' => 'GOOGLE' ); // Asn_Lookup_Store cache hit -- no live DNS lookup.

		ob_start();
		require WP_SAM_DIR . 'includes/admin/views/page-traffic.php';
		$output = (string) ob_get_clean();

		unset( $_GET['tab'], $_GET['lookup_ip'] );

		$this->assertStringContainsString( 'AS15169', $output );
		$this->assertStringNotContainsString( 'IPinfo API token', $output );
	}

	public function test_geo_lookup_ip_param_without_an_explicit_subtab_lands_on_geoip(): void {
		$_GET['tab']           = 'network-intelligence';
		$_GET['geo_lookup_ip'] = '203.0.113.42';
		$GLOBALS['_wpdb_get_results'] = array();

		ob_start();
		require WP_SAM_DIR . 'includes/admin/views/page-traffic.php';
		$output = (string) ob_get_clean();

		unset( $_GET['tab'], $_GET['geo_lookup_ip'] );

		$this->assertStringContainsString( 'IPinfo API token', $output );
		$this->assertStringContainsString( 'Country Block List', $output );
	}

	public function test_subtab_param_still_wins_over_a_legacy_lookup_ip_param(): void {
		$_GET['tab']       = 'network-intelligence';
		$_GET['subtab']    = 'tor';
		$_GET['lookup_ip'] = '203.0.113.42';
		$GLOBALS['_wpdb_get_results'] = array();

		ob_start();
		require WP_SAM_DIR . 'includes/admin/views/page-traffic.php';
		$output = (string) ob_get_clean();

		unset( $_GET['tab'], $_GET['subtab'], $_GET['lookup_ip'] );

		$this->assertStringContainsString( 'Known exit nodes', $output );
		$this->assertStringNotContainsString( 'AS15169', $output );
	}

	// ── Network Intelligence tab -- network-rules self-lockout warning ──────

	public function test_network_rules_subtab_shows_the_lockout_warning_from_a_pending_transient(): void {
		$_GET['tab']    = 'network-intelligence';
		$_GET['subtab'] = 'network-rules';
		$GLOBALS['_wpdb_get_results'] = array();
		set_transient(
			Admin_UI::NETWORK_RULE_LOCKOUT_TRANSIENT_PREFIX . get_current_user_id(),
			array(
				'rule_type' => 'country',
				'value'     => 'CN',
				'surface'   => '',
				'reason'    => 'Testing',
				'message'   => 'Your own current IP address (203.0.113.42) resolves to China.',
			)
		);

		ob_start();
		require WP_SAM_DIR . 'includes/admin/views/page-traffic.php';
		$output = (string) ob_get_clean();

		unset( $_GET['tab'], $_GET['subtab'] );

		$this->assertStringContainsString( 'This could lock you out of wp-admin', $output );
		$this->assertStringContainsString( 'resolves to China', $output );
		$this->assertStringContainsString( 'confirm_lockout_risk', $output );
		$this->assertStringContainsString( 'value="CN"', $output );
	}
}
