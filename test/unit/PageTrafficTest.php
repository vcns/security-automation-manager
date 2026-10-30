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

	// ── Detectors tab ─────────────────────────────────────────────────────

	public function test_detectors_tab_shows_a_description_and_a_fixed_control_action_tooltip(): void {
		$_GET['tab'] = 'detectors';
		\WP_SAM\Intelligence\Detector_Registry::reset();
		\WP_SAM\Intelligence\Detector_Registry::register( new \WP_SAM\Intelligence\Detectors\Sql_Injection_Detector() );
		$GLOBALS['_wpdb_get_results'] = array();

		ob_start();
		require WP_SAM_DIR . 'includes/admin/views/page-traffic.php';
		$output = (string) ob_get_clean();

		unset( $_GET['tab'] );
		\WP_SAM\Intelligence\Detector_Registry::reset();

		$this->assertStringContainsString( 'Flags SQL tautologies', $output );
		$this->assertStringContainsString( 'wp-sam-meta-icon', $output );
		$this->assertStringContainsString( 'this family has no Enforce mode', $output );
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

	// ── Network Intelligence tab -- one table row per source/file ───────────

	/** The HTML of the first table carrying $class, or '' when there is none. */
	private function table_with_class( string $output, string $class ): string {
		return 1 === preg_match( '/<table class="[^"]*\b' . preg_quote( $class, '/' ) . '\b.*?<\/table>/s', $output, $match ) ? $match[0] : '';
	}

	public function test_tor_subtab_renders_as_one_table_row_with_its_refresh_button(): void {
		$_GET['tab'] = 'network-intelligence';

		ob_start();
		require WP_SAM_DIR . 'includes/admin/views/page-traffic.php';
		$output = (string) ob_get_clean();

		unset( $_GET['tab'] );

		$table = $this->table_with_class( $output, 'wp-sam-tor-table' );
		$this->assertStringContainsString( 'Known exit nodes', $table );
		$this->assertSame( 1, substr_count( $table, '<tr>' ) - 1 ); // One header row, one data row.
		$this->assertStringContainsString( 'value="wp_sam_tor_list_refresh"', $table );
		$this->assertStringContainsString( 'nothing here blocks a visitor', $table );
		$this->assertStringNotContainsString( 'wp-sam-stat-row', $output );
		$this->assertStringNotContainsString( 'max-width:600px', $output );
	}

	public function test_well_known_subtab_renders_every_file_as_a_row_of_one_table(): void {
		$_GET['tab']    = 'network-intelligence';
		$_GET['subtab'] = 'well-known';
		$GLOBALS['_wpdb_get_results'] = array();

		ob_start();
		require WP_SAM_DIR . 'includes/admin/views/page-traffic.php';
		$output = (string) ob_get_clean();

		unset( $_GET['tab'], $_GET['subtab'] );

		$this->assertSame( 1, substr_count( $output, 'wp-sam-well-known-table' ) );
		$table = $this->table_with_class( $output, 'wp-sam-well-known-table' );
		$this->assertSame( 6, substr_count( $table, '<tr>' ) - 1 );
		foreach ( array( 'Robots.txt', 'Agents.txt', 'Security.txt', 'Humans.txt', 'Ads.txt', 'App-Ads.txt' ) as $well_known_label ) {
			$this->assertStringContainsString( '>' . $well_known_label . '<', $table );
		}
		foreach ( array( 'robots_rules', 'agents_rules', 'security_txt', 'humans_txt', 'ads_txt', 'app_ads_txt' ) as $refresh ) {
			$this->assertStringContainsString( 'value="wp_sam_' . $refresh . '_refresh"', $table );
		}
		$this->assertStringNotContainsString( 'wp-sam-stat-row', $output );
		$this->assertStringNotContainsString( 'max-width:600px', $output );
		$this->assertStringNotContainsString( 'width:200px', $output );
	}

	public function test_well_known_subtab_flags_an_expired_security_txt_in_its_row(): void {
		$_GET['tab']    = 'network-intelligence';
		$_GET['subtab'] = 'well-known';
		$GLOBALS['_wpdb_get_results'] = array();
		update_option( 'wp_sam_security_txt_last_fetch_status', 'success' );
		update_option( 'wp_sam_security_txt_fields', array( 'Expires' => array( '2020-01-01T00:00:00Z' ) ) );

		ob_start();
		require WP_SAM_DIR . 'includes/admin/views/page-traffic.php';
		$output = (string) ob_get_clean();

		unset( $_GET['tab'], $_GET['subtab'] );

		$table = $this->table_with_class( $output, 'wp-sam-well-known-table' );
		$this->assertStringContainsString( 'Present, expires 2020-01-01T00:00:00Z', $table );
		$this->assertStringContainsString( '(expired)', $table );
	}

	public function test_well_known_subtab_shows_an_absent_file_as_absent_not_failed(): void {
		$_GET['tab']    = 'network-intelligence';
		$_GET['subtab'] = 'well-known';
		$GLOBALS['_wpdb_get_results'] = array();
		update_option( 'wp_sam_agents_rules_last_fetch_status', 'absent' );

		ob_start();
		require WP_SAM_DIR . 'includes/admin/views/page-traffic.php';
		$output = (string) ob_get_clean();

		unset( $_GET['tab'], $_GET['subtab'] );

		$this->assertStringContainsString( 'Absent', $output );
		$this->assertStringNotContainsString( 'Failed', $output );
	}

	// ── Network Intelligence tab -- Well-Known Files editor ──────────────────

	/** Renders the Well-Known Files sub-tab with extra query args. */
	private function render_well_known( array $args = array() ): string {
		$_GET = array_merge(
			array(
				'tab'    => 'network-intelligence',
				'subtab' => 'well-known',
			),
			$args
		);
		$GLOBALS['_wpdb_get_results'] = array();

		ob_start();
		require WP_SAM_DIR . 'includes/admin/views/page-traffic.php';
		$output = (string) ob_get_clean();

		$_GET = array();
		return $output;
	}

	public function test_well_known_table_has_no_about_column_and_links_each_file_to_its_editor(): void {
		update_option( 'wp_sam_ads_txt_last_fetch_status', 'absent' );

		$table = $this->table_with_class( $this->render_well_known(), 'wp-sam-well-known-table' );

		$this->assertStringNotContainsString( '>About<', $table );
		$this->assertStringNotContainsString( 'Refreshed automatically once a day', $table );
		foreach ( array( 'robots', 'agents', 'security', 'humans', 'ads', 'app-ads' ) as $key ) {
			$this->assertMatchesRegularExpression( '#subtab=well-known&(amp;)?file=' . preg_quote( $key, '#' ) . '"#', $table );
		}
		$this->assertMatchesRegularExpression( '#file=ads"[^>]*>Create</a>#', $table, 'An absent file is created, not edited.' );
		$this->assertMatchesRegularExpression( '#file=robots"[^>]*>Edit</a>#', $table );
	}

	public function test_well_known_table_says_which_files_this_plugin_serves(): void {
		$store = new \WP_SAM\Intelligence\Well_Known_File_Store();
		$store->save( 'humans', "Site: Example\n", 1 );
		$store->record_check( 'humans', \WP_SAM\Intelligence\Well_Known_File_Store::CHECK_SERVED );
		$store->save( 'ads', "example.com, 1, DIRECT\n", 1 );
		$store->record_check( 'ads', \WP_SAM\Intelligence\Well_Known_File_Store::CHECK_NOT_SERVED );

		$table = $this->table_with_class( $this->render_well_known(), 'wp-sam-well-known-table' );

		$this->assertSame( 1, substr_count( $table, 'Served by this plugin' ) );
		$this->assertStringContainsString( 'Saved here, but visitors get another version', $table );
	}

	public function test_well_known_table_confirms_a_file_is_no_longer_served(): void {
		$output = $this->render_well_known( array( 'removed' => 'security' ) );

		$this->assertStringContainsString( 'This plugin no longer serves Security.txt.', $output );
	}

	public function test_well_known_editor_replaces_the_table_and_starts_from_the_first_template(): void {
		$output = $this->render_well_known( array( 'file' => 'robots' ) );

		$this->assertStringNotContainsString( 'wp-sam-well-known-table', $output );
		$this->assertStringContainsString( '>Robots.txt</h3>', $output );
		$this->assertStringContainsString( 'value="wp_sam_well_known_save"', $output );
		$this->assertStringContainsString( 'name="file" value="robots"', $output );
		$this->assertStringContainsString( '>WordPress default</a>', $output );
		$this->assertStringContainsString( '>Block AI training crawlers</a>', $output );
		$this->assertStringContainsString( 'value="Save and serve"', $output );
		$this->assertStringContainsString( 'starts from the WordPress default template', $output );
		$this->assertStringContainsString( "User-agent: *\nDisallow: /wp-admin/", $output );
		$this->assertStringNotContainsString( 'Stop serving', $output );
	}

	public function test_well_known_editor_opens_with_what_the_site_serves_now(): void {
		$GLOBALS['_wp_remote_get_response'] = array(
			'response' => array( 'code' => 200 ),
			'body'     => "/* TEAM */\nDeveloper: Someone\n",
		);

		$output = $this->render_well_known( array( 'file' => 'humans' ) );

		$this->assertStringContainsString( 'Developer: Someone', $output );
		$this->assertStringContainsString( 'Showing what the site serves now.', $output );
	}

	public function test_well_known_editor_fills_the_box_with_a_chosen_template(): void {
		$output = $this->render_well_known(
			array(
				'file'     => 'ads',
				'template' => 'no-ads',
			)
		);

		$this->assertStringContainsString( 'placeholder.example.com, placeholder, DIRECT, placeholder', $output );
	}

	public function test_well_known_editor_shows_the_saved_version_with_a_stop_serving_button(): void {
		( new \WP_SAM\Intelligence\Well_Known_File_Store() )->save( 'humans', "Site: Saved here\n", 1 );

		$output = $this->render_well_known(
			array(
				'file'  => 'humans',
				'saved' => 'served',
			)
		);

		$this->assertStringContainsString( 'Site: Saved here', $output );
		$this->assertStringContainsString( 'Saved. Visitors now get this version.', $output );
		$this->assertStringContainsString( 'value="wp_sam_well_known_remove"', $output );
		$this->assertStringContainsString( 'value="Stop serving"', $output );
		$this->assertStringContainsString( '>Saved version</a>', $output );
		$this->assertStringContainsString( 'value="Save"', $output );
	}

	public function test_well_known_editor_keeps_text_that_failed_to_save(): void {
		set_transient( 'wp_sam_well_known_errors_' . get_current_user_id(), array( 'Line 1 isn\'t a "Field: value" rule: oops' ) );
		set_transient( 'wp_sam_well_known_input_' . get_current_user_id(), "oops\n" );

		$output = $this->render_well_known( array( 'file' => 'robots' ) );

		$this->assertStringContainsString( 'File not saved:', $output );
		$this->assertStringContainsString( 'rule: oops', $output );
		$this->assertMatchesRegularExpression( '#<textarea[^>]*>oops\s*</textarea>#', $output );
	}

	public function test_well_known_editor_names_an_seo_plugin_that_also_writes_robots_txt(): void {
		add_filter( 'wp_sam_robots_txt_writer', static fn () => 'Yoast SEO' );

		$robots = $this->render_well_known( array( 'file' => 'robots' ) );
		$ads    = $this->render_well_known( array( 'file' => 'ads' ) );

		$this->assertStringContainsString( 'Yoast SEO also writes robots.txt.', $robots );
		$this->assertStringNotContainsString( 'Yoast SEO', $ads );
	}

	public function test_an_unknown_file_shows_the_table_instead_of_an_editor(): void {
		$output = $this->render_well_known( array( 'file' => 'sitemap' ) );

		$this->assertStringContainsString( 'wp-sam-well-known-table', $output );
		$this->assertStringNotContainsString( 'wp_sam_well_known_save', $output );
	}

	// ── Network Intelligence tab -- Geo-IP sub-tab's Country Block List ─────

	/**
	 * The grid has to grow downwards. A height cap on a multi-column box
	 * adds overflow columns to the right instead of scrolling, and with a
	 * 4-column cap as well it hid most countries behind a horizontal
	 * scrollbar and left a wide empty band in every column.
	 */
	public function test_country_grid_css_has_no_height_or_column_count_cap(): void {
		$css = (string) file_get_contents( WP_SAM_DIR . 'assets/css/admin.css' );

		$this->assertSame( 1, preg_match( '/^\.wp-sam-country-grid \{([^}]*)\}/m', $css, $rule ) );
		$this->assertStringContainsString( 'column-width', $rule[1] );
		$this->assertStringNotContainsString( 'max-height', $rule[1] );
		$this->assertStringNotContainsString( 'column-count', $rule[1] );
		$this->assertDoesNotMatchRegularExpression( '/\bcolumns:/', $rule[1] );
	}

	private function render_geoip_subtab(): string {
		$_GET['tab']                  = 'network-intelligence';
		$_GET['subtab']               = 'geoip';
		$GLOBALS['_wpdb_get_results'] = array();

		ob_start();
		require WP_SAM_DIR . 'includes/admin/views/page-traffic.php';
		$output = (string) ob_get_clean();

		unset( $_GET['tab'], $_GET['subtab'] );
		return $output;
	}

	public function test_geoip_subtab_puts_provider_status_and_token_form_in_one_table_row(): void {
		$output = $this->render_geoip_subtab();

		$table = $this->table_with_class( $output, 'wp-sam-geoip-provider-table' );
		$this->assertSame( 1, substr_count( $table, '<tr>' ) - 1 );
		$this->assertStringContainsString( 'Disabled -- no token configured', $table );
		$this->assertStringContainsString( 'https://ipinfo.io/signup', $table );
		$this->assertStringContainsString( 'name="action" value="wp_sam_geoip_save_token"', $table );
		$this->assertStringContainsString( 'id="ipinfo_token"', $table );
		$this->assertStringContainsString( 'Save Token', $table );
	}

	public function test_geoip_subtab_offers_every_sanctions_list_until_a_site_country_is_chosen(): void {
		$output = $this->render_geoip_subtab();

		$this->assertStringContainsString( 'Where does this website operate?', $output );
		$this->assertStringContainsString( 'name="action" value="wp_sam_site_country_save"', $output );
		$this->assertStringContainsString( '<select id="wp-sam-site-country-select" name="site_country"', $output );
		$this->assertStringContainsString( 'Not chosen: offer every sanctions list', $output );
		foreach ( array( 'un-sanctions', 'eu-sanctions', 'uk-sanctions', 'us-ofac-comprehensive', 'jp-sanctions' ) as $key ) {
			$this->assertStringContainsString( 'value="' . $key . '"', $output );
		}
		$this->assertStringNotContainsString( 'narrowed to those that bind', $output );
	}

	public function test_geoip_subtab_narrows_the_sanctions_lists_to_the_site_country(): void {
		update_option( 'wp_sam_site_country', 'FR' );

		$output = $this->render_geoip_subtab();

		$this->assertStringContainsString( "value=\"FR\" selected='selected'", $output );
		$this->assertStringContainsString( 'value="un-sanctions"', $output );
		$this->assertStringContainsString( 'value="eu-sanctions"', $output );
		$this->assertStringNotContainsString( 'value="uk-sanctions"', $output );
		$this->assertStringNotContainsString( 'data-wp-sam-country-group-details="uk-sanctions"', $output );
		$this->assertStringContainsString( 'value="eu"', $output, 'Blocs and regions are never narrowed.' );
		$this->assertStringContainsString( 'Sanctions lists are narrowed to those that bind in France.', $output );
	}

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
		$this->assertMatchesRegularExpression( '/id="wp-sam-country-count"[^>]*>1</', $output );
	}

	public function test_geoip_subtab_renders_the_select_by_group_control_without_posting_it(): void {
		$_GET['tab']    = 'network-intelligence';
		$_GET['subtab'] = 'geoip';
		$GLOBALS['_wpdb_get_results'] = array();

		ob_start();
		require WP_SAM_DIR . 'includes/admin/views/page-traffic.php';
		$output = (string) ob_get_clean();

		unset( $_GET['tab'], $_GET['subtab'] );

		$this->assertStringContainsString( 'Select by group', $output );
		$this->assertStringContainsString( '<label for="wp-sam-country-group-select">', $output );
		// No name attribute: the group choice is never submitted.
		$this->assertStringContainsString( '<select id="wp-sam-country-group-select" aria-describedby="wp-sam-country-group-details">', $output );
		$this->assertStringContainsString( '<optgroup label="Continents (UN M49 regions)">', $output );
		$this->assertStringContainsString( '<optgroup label="Sanctions (snapshot)">', $output );
		$this->assertStringContainsString( 'value="eu" data-codes="AT BE BG', $output );
		$this->assertStringContainsString( 'Tick all in group', $output );
		$this->assertStringContainsString( 'Untick all in group', $output );
		$this->assertStringContainsString( 'data-wp-sam-country-group-details="uk-sanctions" hidden', $output );
		$this->assertStringContainsString( 'not in itself a requirement to block all traffic', $output );
		$this->assertStringContainsString( 'never updated automatically', $output );
		$this->assertMatchesRegularExpression( '/id="wp-sam-country-count"[^>]*>0</', $output );
		$this->assertStringContainsString( 'id="wp-sam-country-grid"', $output );
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

	public function test_ip_rules_tab_shows_the_own_addresses_form_with_saved_entries(): void {
		$_GET['tab'] = 'ip-rules';
		\WP_SAM\Intelligence\Own_Address_Store::save( "185.199.223.7\n203.0.113.32/28" );
		$GLOBALS['_wpdb_get_results'] = array();
		$GLOBALS['_wpdb_get_col']     = array();

		ob_start();
		require WP_SAM_DIR . 'includes/admin/views/page-traffic.php';
		$output = (string) ob_get_clean();

		unset( $_GET['tab'] );

		$this->assertStringContainsString( 'id="wp-sam-own-addresses"', $output );
		$this->assertStringContainsString( 'wp_sam_own_addresses_save', $output );
		$this->assertStringContainsString( "185.199.223.7\n203.0.113.32/28</textarea>", $output );
		$this->assertStringNotContainsString( 'Seen calling /wp-cron.php', $output );
	}

	public function test_own_addresses_saved_notice_says_how_many_identities_were_relabelled(): void {
		$_GET['tab']                  = 'ip-rules';
		$_GET['own_saved']            = '1';
		$_GET['own_relabelled']       = '3';
		$GLOBALS['_wpdb_get_results'] = array();
		$GLOBALS['_wpdb_get_col']     = array();

		ob_start();
		require WP_SAM_DIR . 'includes/admin/views/page-traffic.php';
		$output = (string) ob_get_clean();

		$_GET['own_relabelled'] = '0';
		ob_start();
		require WP_SAM_DIR . 'includes/admin/views/page-traffic.php';
		$unchanged = (string) ob_get_clean();

		unset( $_GET['tab'], $_GET['own_saved'], $_GET['own_relabelled'] );

		$this->assertStringContainsString( '3 identities on Observe → Continuous Intelligence → Identities were relabelled to match.', $output );
		$this->assertStringContainsString( 'Saved.', $unchanged );
		$this->assertStringNotContainsString( 'relabelled to match', $unchanged );
	}

	public function test_ip_rules_tab_suggests_wp_cron_callers_not_yet_listed(): void {
		$_GET['tab'] = 'ip-rules';
		\WP_SAM\Intelligence\Own_Address_Store::save( '185.177.72.38' );
		$GLOBALS['_wpdb_get_results'] = array();
		$GLOBALS['_wpdb_get_col']     = array( '185.199.223.7', '185.177.72.38' );

		ob_start();
		require WP_SAM_DIR . 'includes/admin/views/page-traffic.php';
		$output = (string) ob_get_clean();

		unset( $_GET['tab'] );

		$this->assertStringContainsString( 'Seen calling /wp-cron.php in the last 30 days: <code>185.199.223.7</code>.', $output );
	}

	public function test_ip_rules_tab_lists_entries_that_were_not_saved_once(): void {
		$_GET['tab'] = 'ip-rules';
		$GLOBALS['_wpdb_get_results'] = array();
		$GLOBALS['_wpdb_get_col']     = array();
		set_transient(
			'wp_sam_own_addresses_rejected_' . get_current_user_id(),
			array( array( 'entry' => '0.0.0.0/0', 'reason' => 'Too broad: the widest range accepted is /16.' ) )
		);

		ob_start();
		require WP_SAM_DIR . 'includes/admin/views/page-traffic.php';
		$output = (string) ob_get_clean();

		unset( $_GET['tab'] );

		$this->assertStringContainsString( '<code>0.0.0.0/0</code> -- Too broad', $output );
		$this->assertFalse( get_transient( 'wp_sam_own_addresses_rejected_' . get_current_user_id() ) );
	}

	/**
	 * Help text spans the page's width on every tab, as it already did on
	 * Network Intelligence. A max-width:700px on the Policy, IP Rules and
	 * Blocks paragraphs left a wide empty band beside them.
	 *
	 * @dataProvider tab_provider
	 */
	public function test_help_text_is_not_width_capped( string $tab, string $subtab = '' ): void {
		$_GET['tab']                  = $tab;
		$GLOBALS['_wpdb_get_results'] = array();
		if ( '' !== $subtab ) {
			$_GET['subtab'] = $subtab;
		}

		ob_start();
		require WP_SAM_DIR . 'includes/admin/views/page-traffic.php';
		$output = (string) ob_get_clean();

		unset( $_GET['tab'], $_GET['subtab'] );

		$this->assertStringContainsString( '<p class="description"', $output );
		$this->assertDoesNotMatchRegularExpression( '/<p class="description"[^>]*max-width/', $output );
	}

	public static function tab_provider(): array {
		return array(
			'policy'               => array( 'policy' ),
			'ip-rules'             => array( 'ip-rules' ),
			'blocks'               => array( 'blocks' ),
			// Tor Exit List, the default sub-tab, keeps its help text in its table row.
			'network-intelligence' => array( 'network-intelligence', 'asn' ),
			'detectors'            => array( 'detectors' ),
			'custom-rules'         => array( 'custom-rules' ),
		);
	}
}
