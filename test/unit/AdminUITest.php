<?php
/**
 * Unit tests for WP_SAM\Admin\Admin_UI.
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;
use WP_SAM\Admin\Admin_UI;
use WP_SAM\Admin\Pillar_Registry;
use WP_SAM\Plugin;

class AdminUITest extends TestCase {

	protected function setUp(): void {
		wp_test_reset_globals();
	}

	public function test_plugin_action_links_include_settings_link(): void {
		$ui = $this->make_admin_ui();

		$links = $ui->add_plugin_action_links(
			array(
				'deactivate' => '<a href="#">Deactivate</a>',
			)
		);

		$this->assertArrayHasKey( 'settings', $links );
		$this->assertArrayHasKey( 'reset', $links );
		$this->assertStringContainsString( 'admin.php?page=security-automation-manager-dashboard', $links['settings'] );
		$this->assertStringContainsString( 'tab=settings', $links['settings'] );
		$this->assertStringContainsString( 'admin.php?page=security-automation-manager&tab=recovery#wp-sam-reset', $links['reset'] );
		$this->assertStringContainsString( 'Settings', $links['settings'] );
		$this->assertStringContainsString( 'Reset', $links['reset'] );
		$this->assertSame( 'settings', array_key_first( $links ) );
	}

	public function test_plugin_row_meta_describes_update_posture(): void {
		$ui = $this->make_admin_ui();

		$links = $ui->add_plugin_row_meta(
			array( '<a href="https://example.com">Visit plugin site</a>' ),
			plugin_basename( WP_SAM_FILE )
		);

		$this->assertStringContainsString( 'WordPress.org package', implode( ' ', $links ) );
		$this->assertStringContainsString( 'no custom updater', implode( ' ', $links ) );
	}

	public function test_plugin_row_meta_ignores_other_plugins(): void {
		$ui       = $this->make_admin_ui();
		$original = array( '<a href="https://example.com">Visit plugin site</a>' );

		$links = $ui->add_plugin_row_meta( $original, 'other-plugin/other-plugin.php' );

		$this->assertSame( $original, $links );
	}

	public function test_dashboard_uses_review_queue_and_policy_timeline_language(): void {
		$view = file_get_contents( dirname( __DIR__, 2 ) . '/includes/admin/views/page-csp-dashboard.php' );

		$this->assertIsString( $view );
		$this->assertStringContainsString( "'For Review'", $view );
		$this->assertStringContainsString( 'This timeline shows proposal activity', $view );
		$this->assertStringContainsString( 'Proposed source', $view );
		$this->assertStringContainsString( 'Policy version', $view );
		$this->assertStringContainsString( "'Automation'", $view );
		$this->assertStringContainsString( 'wp-sam-automation-mode', $view );
		$this->assertStringNotContainsString( "'Strict-Dynamic'", $view );
	}

	public function test_sanitize_policy_header_name_accepts_origin_header(): void {
		$ui = $this->make_admin_ui();

		$this->assertSame( 'X-Origin-CSP-Policy', $ui->sanitize_policy_header_name( 'X-Origin-CSP-Policy' ) );
	}

	public function test_sanitize_policy_header_name_rejects_header_injection(): void {
		$ui = $this->make_admin_ui();

		$this->assertSame( '', $ui->sanitize_policy_header_name( "X-Origin-CSP\r\nContent-Length" ) );
	}

	public function test_overview_view_renders_pillar_status_table(): void {
		$view = file_get_contents( dirname( __DIR__, 2 ) . '/includes/admin/views/page-overview.php' );

		$this->assertIsString( $view );
		$this->assertStringContainsString( 'Security Automation Manager', $view );
		$this->assertStringContainsString( 'Content Security Policy', $view );
		$this->assertStringContainsString( 'security-automation-manager-dashboard', $view );
		$this->assertStringContainsString( 'tab=policy-audit', $view );
		$this->assertStringContainsString( 'Layer 1: Governance and Operations', $view );
		$this->assertStringContainsString( 'Layer 2: Controlled Automation', $view );
		$this->assertStringContainsString( 'Layer 3: Continuous Intelligence', $view );
		$this->assertStringContainsString( 'security-automation-manager-intelligence', $view );
		$this->assertStringNotContainsString( 'Planned for a future phase.', $view );
		$this->assertStringContainsString( 'Layer 4: Browser Security Policies', $view );
		$this->assertStringContainsString( 'Layer 5: Transport & Certificate Trust', $view );
		$this->assertStringContainsString( 'tab=settings', $view );
		$this->assertStringContainsString( 'security-automation-manager-certificates', $view );
		$this->assertStringContainsString( 'Pillar_Registry::pillars()', $view );
		$this->assertStringContainsString( "'readiness'", $view );
		$this->assertStringContainsString( "'about'", $view );
		$this->assertStringContainsString( 'wp-sam-reset', $view );
	}

	/**
	 * Regression test for Pillar_Registry::pillars() -- the single source of
	 * truth the Overview view now sorts and renders directly (replacing a
	 * view-local $simple_pillars array that had already drifted from reality
	 * once: it disagreed with Activator::seed_default_pillar_profiles() about
	 * which pillars exist, and separately omitted Internal Script Integrity
	 * from this exact regression test's own hand-maintained label list).
	 */
	public function test_overview_pillar_rows_sort_alphabetically_by_label(): void {
		$labels = array_map(
			static fn( array $pillar ): string => $pillar['label'],
			Pillar_Registry::pillars()
		);

		$this->assertSame(
			array(
				'Cache-Control',
				'Cross-Origin-Embedder-Policy',
				'Cross-Origin-Opener-Policy',
				'Cross-Origin-Resource-Policy',
				'External Scripts',
				'Information Masking',
				'Internal Script Integrity',
				'Permissions-Policy',
				'Referrer-Policy',
				'Reverse Tabnabbing Protection',
				'Strict-Transport-Security',
				'X-Content-Type-Options',
				'X-Frame-Options',
				'X-Permitted-Cross-Domain-Policies',
			),
			array_values( $labels )
		);
	}

	/**
	 * WordPress derives a submenu's hook suffix from sanitize_title() of the
	 * top-level menu's *title text*, not its slug -- since the top-level menu
	 * title is now "Security Automation Manager" (not "CSP Manager"), every
	 * submenu hook must carry that prefix, not the old "csp-manager_page_" one.
	 */
	public function test_plugin_page_hooks_use_new_top_level_title_prefix(): void {
		$ui     = $this->make_admin_ui();
		$method = new ReflectionMethod( Admin_UI::class, 'plugin_page_hooks' );
		$method->setAccessible( true );

		$hooks = $method->invoke( $ui );

		$this->assertContains( 'toplevel_page_security-automation-manager', $hooks );
		$this->assertContains( 'security-automation-manager_page_security-automation-manager-hsts', $hooks );
		$this->assertContains( 'security-automation-manager_page_security-automation-manager-reverse-tabnabbing', $hooks );
		$this->assertContains( 'security-automation-manager_page_security-automation-manager-scripts', $hooks );
		$this->assertNotContains( 'security-automation-manager_page_security-automation-manager-policy-audit', $hooks );
		foreach ( $hooks as $hook ) {
			if ( 'toplevel_page_security-automation-manager' === $hook ) {
				continue;
			}
			$this->assertStringStartsWith( 'security-automation-manager_page_', $hook );
			$this->assertStringNotContainsString( 'csp-manager_page_', $hook );
		}
	}

	public function test_plugin_page_hooks_includes_lifecycle_pages(): void {
		$ui     = $this->make_admin_ui();
		$method = new ReflectionMethod( Admin_UI::class, 'plugin_page_hooks' );
		$method->setAccessible( true );

		$hooks = $method->invoke( $ui );

		$this->assertContains( 'security-automation-manager_page_security-automation-manager-observe', $hooks );
		$this->assertContains( 'security-automation-manager_page_security-automation-manager-decide', $hooks );
		$this->assertContains( 'security-automation-manager_page_security-automation-manager-control', $hooks );
		$this->assertContains( 'security-automation-manager_page_security-automation-manager-verify', $hooks );
	}

	public function test_add_menu_pages_registers_settings_first_then_lifecycle_pages_in_roadmap_order(): void {
		wp_test_reset_globals();
		$ui = $this->make_admin_ui();

		$ui->add_menu_pages();

		$titles = array_column( $GLOBALS['_wp_submenu_pages']['security-automation-manager'], 'menu_title' );

		// Settings registers first deliberately (see add_menu_pages()'s own
		// comment -- avoids a real WordPress auto-inserted duplicate parent
		// link), then the four lifecycle pages in the roadmap's own order.
		$this->assertSame( array( 'Settings', 'Observe', 'Decide', 'Control', 'Verify' ), array_slice( $titles, 0, 5 ) );
	}

	/**
	 * All thirteen technology-standard pages must still be REGISTERED (same as
	 * before this change) -- they're hidden from the rendered menu via CSS
	 * (print_hidden_menu_css()), not via removal, specifically because
	 * removal breaks direct URL access in real WordPress (see
	 * add_menu_pages()'s own comment). This test guards the "still
	 * registered" half; test_print_hidden_menu_css_* guards the "actually
	 * hidden" half.
	 */
	public function test_add_menu_pages_keeps_pillar_pages_registered(): void {
		wp_test_reset_globals();
		$ui = $this->make_admin_ui();

		$ui->add_menu_pages();

		$registered_slugs = array_column( $GLOBALS['_wp_submenu_pages']['security-automation-manager'], 'menu_slug' );

		foreach (
			array(
				'security-automation-manager-certificates',
				'security-automation-manager-intelligence',
				'security-automation-manager-cross-origin',
				'security-automation-manager-dashboard',
				'security-automation-manager-hsts',
				'security-automation-manager-information-masking',
				'security-automation-manager-cache-control',
				'security-automation-manager-permissions-policy',
				'security-automation-manager-referrer-policy',
				'security-automation-manager-reverse-tabnabbing',
				'security-automation-manager-scripts',
				'security-automation-manager-xcto',
				'security-automation-manager-xfo',
			) as $pillar_slug
		) {
			$this->assertContains( $pillar_slug, $registered_slugs, "{$pillar_slug} should still be registered (reachable at its URL)" );
		}
	}

	public function test_add_menu_pages_renames_overview_entry_to_settings(): void {
		wp_test_reset_globals();
		$ui = $this->make_admin_ui();

		$ui->add_menu_pages();

		$settings_entries = array_values(
			array_filter(
				$GLOBALS['_wp_submenu_pages']['security-automation-manager'],
				static fn( array $item ): bool => 'security-automation-manager' === $item['menu_slug']
			)
		);

		$this->assertCount( 1, $settings_entries );
		$this->assertSame( 'Settings', $settings_entries[0]['menu_title'] );
		$this->assertSame( 'Settings', $settings_entries[0]['page_title'] );
	}

	public function test_print_hidden_menu_css_hides_every_pillar_page(): void {
		$ui = $this->make_admin_ui();

		ob_start();
		$ui->print_hidden_menu_css();
		$css = (string) ob_get_clean();

		foreach (
			array(
				'security-automation-manager-certificates',
				'security-automation-manager-intelligence',
				'security-automation-manager-cross-origin',
				'security-automation-manager-dashboard',
				'security-automation-manager-hsts',
				'security-automation-manager-information-masking',
				'security-automation-manager-cache-control',
				'security-automation-manager-permissions-policy',
				'security-automation-manager-referrer-policy',
				'security-automation-manager-reverse-tabnabbing',
				'security-automation-manager-scripts',
				'security-automation-manager-xcto',
				'security-automation-manager-xfo',
			) as $pillar_slug
		) {
			$this->assertStringContainsString( 'page=' . $pillar_slug, $css );
		}
	}

	public function test_print_hidden_menu_css_does_not_hide_lifecycle_or_settings_pages(): void {
		$ui = $this->make_admin_ui();

		ob_start();
		$ui->print_hidden_menu_css();
		$css = (string) ob_get_clean();

		foreach (
			array(
				'security-automation-manager-observe',
				'security-automation-manager-decide',
				'security-automation-manager-control',
				'security-automation-manager-verify',
			) as $visible_slug
		) {
			$this->assertStringNotContainsString( 'page=' . $visible_slug, $css );
		}
	}

	// ── filter_admin_footer_text() ──────────────────────────────────────────

	public function test_filter_admin_footer_text_returns_the_string_unchanged(): void {
		$ui = $this->make_admin_ui();

		$this->assertSame( 'Thank you.', $ui->filter_admin_footer_text( 'Thank you.' ) );
	}

	/**
	 * Regression test: a fatal TypeError shipped in production because this
	 * method was typed `string $text`, but admin_footer_text runs through
	 * every plugin's filter callbacks in sequence and WordPress does not
	 * enforce that an earlier callback returns a string -- a misbehaving
	 * plugin/theme returning null here fataled every wp-admin page load.
	 */
	public function test_filter_admin_footer_text_tolerates_null_from_an_earlier_filter(): void {
		$ui = $this->make_admin_ui();

		$this->assertSame( '', $ui->filter_admin_footer_text( null ) );
	}

	public function test_filter_admin_footer_text_tolerates_non_string_types(): void {
		$ui = $this->make_admin_ui();

		$this->assertSame( '', $ui->filter_admin_footer_text( array( 'unexpected' ) ) );
		$this->assertSame( '', $ui->filter_admin_footer_text( 42 ) );
	}

	/**
	 * WP_SAM_DISTRIBUTION_CHANNEL is defined once, globally, in test/bootstrap.php
	 * as 'wordpress-org' and PHP constants can't be redefined per-test -- so this
	 * only ever exercises the WordPress.org branch of the view. That's still the
	 * one this issue's hard requirement is about: a WordPress.org build must never
	 * display or use the GitHub update service, and this proves the view's early
	 * channel branch actually withholds every GitHub-specific field rather than
	 * just labeling the channel correctly. Update Channel is now the Updates tab
	 * on the Overview page rather than its own submenu, so this renders
	 * page-overview.php with tab=updates -- the real require() chain
	 * Admin_UI::render_overview() actually uses.
	 */
	public function test_updates_tab_omits_github_fields_on_wordpress_org_build(): void {
		$_GET['tab'] = 'updates';

		ob_start();
		require WP_SAM_DIR . 'includes/admin/views/page-overview.php';
		$output = (string) ob_get_clean();

		unset( $_GET['tab'] );

		$this->assertStringContainsString( WP_SAM_VERSION, $output );
		$this->assertStringContainsString( 'WordPress.org', $output );
		$this->assertStringNotContainsString( 'Update manifest URL', $output );
		$this->assertStringNotContainsString( 'Package checksum verification status', $output );
		$this->assertStringNotContainsString( 'VCNS GitHub', $output );
	}

	/**
	 * Regression test for a fatal that reached production: scripts-external.php
	 * and scripts-internal.php reference namespaced classes (Table_Query,
	 * Dependency_Governance_Builder) with no `use` import of their own. PHP's
	 * `use` imports are per-file, not inherited through require() -- the
	 * parent page-scripts.php having the right imports does not help the
	 * partial it requires. Rendering page-scripts.php itself (not the partial
	 * directly) is what actually proves the real require() chain works.
	 */
	public function test_scripts_external_tab_renders_without_fatal(): void {
		$_GET['tab'] = 'external';

		ob_start();
		require WP_SAM_DIR . 'includes/admin/views/page-scripts.php';
		$output = (string) ob_get_clean();

		unset( $_GET['tab'] );

		$this->assertStringContainsString( 'Origin', $output );
	}

	public function test_scripts_internal_tab_renders_without_fatal(): void {
		$_GET['tab'] = 'internal';

		ob_start();
		require WP_SAM_DIR . 'includes/admin/views/page-scripts.php';
		$output = (string) ob_get_clean();

		unset( $_GET['tab'] );

		$this->assertStringContainsString( 'Hash inventory', $output );
	}

	public function test_information_masking_page_renders_without_fatal(): void {
		wp_test_reset_globals();

		ob_start();
		require WP_SAM_DIR . 'includes/admin/views/page-information-masking.php';
		$output = (string) ob_get_clean();

		$this->assertStringContainsString( 'Information Masking', $output );
		$this->assertStringContainsString( 'wp-sam-pillar-enabled', $output );
		$this->assertStringContainsString( 'X-Powered-By', $output );
		$this->assertStringContainsString( 'Not yet checked', $output );
		$this->assertStringContainsString( 'wp_sam_information_masking_check', $output );
	}

	public function test_information_masking_page_shows_diagnostic_results(): void {
		wp_test_reset_globals();
		update_option(
			'wp_sam_information_masking_diagnostic',
			array(
				'x-powered-by' => 'masked',
				'server'       => 'present',
				'x-pingback'   => 'masked',
			)
		);
		update_option( 'wp_sam_information_masking_checked_at', '2026-09-02 10:00:00' );
		update_option( 'wp_sam_information_masking_last_status', 'success' );

		ob_start();
		require WP_SAM_DIR . 'includes/admin/views/page-information-masking.php';
		$output = (string) ob_get_clean();

		$this->assertStringContainsString( 'Masked', $output );
		$this->assertStringContainsString( 'Present', $output );
		$this->assertStringContainsString( '2026-09-02 10:00:00', $output );
	}

	public function test_cache_control_page_renders_without_fatal_when_unblocked(): void {
		wp_test_reset_globals();

		ob_start();
		require WP_SAM_DIR . 'includes/admin/views/page-cache-control.php';
		$output = (string) ob_get_clean();

		$this->assertStringContainsString( 'Cache-Control', $output );
		$this->assertStringContainsString( 'wp-sam-pillar-enabled', $output );
		$this->assertStringContainsString( 'wp-sam-pillar-value', $output );
		$this->assertStringContainsString( 'wp_sam_cache_control_cdn_acknowledge', $output );
		$this->assertStringNotContainsString( "disabled='disabled'", $output );
	}

	public function test_cache_control_page_shows_a_warning_and_disables_controls_when_blocked(): void {
		wp_test_reset_globals();
		update_option( 'wp_sam_cache_control_cdn_acknowledged', true );

		ob_start();
		require WP_SAM_DIR . 'includes/admin/views/page-cache-control.php';
		$output = (string) ob_get_clean();

		$this->assertStringContainsString( 'This pillar is currently disabled.', $output );
		$this->assertStringContainsString( 'CDN or edge cache has been acknowledged', $output );
		$this->assertStringContainsString( "disabled='disabled'", $output );
	}

	public function test_observe_view_renders_without_fatal(): void {
		wp_test_reset_globals();

		ob_start();
		require WP_SAM_DIR . 'includes/admin/views/page-observe.php';
		$output = (string) ob_get_clean();

		$this->assertStringContainsString( 'Observe', $output );
		$this->assertStringContainsString( 'security-automation-manager-intelligence', $output );
	}

	public function test_decide_view_renders_without_fatal(): void {
		wp_test_reset_globals();

		ob_start();
		require WP_SAM_DIR . 'includes/admin/views/page-decide.php';
		$output = (string) ob_get_clean();

		$this->assertStringContainsString( 'Decide', $output );
		$this->assertStringContainsString( 'tab=sources', $output );
	}

	public function test_control_view_renders_without_fatal(): void {
		ob_start();
		require WP_SAM_DIR . 'includes/admin/views/page-control.php';
		$output = (string) ob_get_clean();

		$this->assertStringContainsString( 'Control', $output );
		$this->assertStringContainsString( 'Manage Traffic Controls', $output );
		$this->assertStringContainsString( 'security-automation-manager-traffic', $output );
	}

	public function test_verify_view_renders_without_fatal(): void {
		ob_start();
		require WP_SAM_DIR . 'includes/admin/views/page-verify.php';
		$output = (string) ob_get_clean();

		$this->assertStringContainsString( 'Verify', $output );
		$this->assertStringContainsString( 'planned for a future phase', $output );
		$this->assertStringContainsString( 'security-automation-manager-baseline', $output );
	}

	/**
	 * Regression coverage for the same class of fatal test_scripts_external_tab_
	 * renders_without_fatal() guards against, for the two tabs (COOP/COEP) that
	 * gained a report-only mode selector and a Report-Only Evidence table --
	 * new use of Table_Query and the mode_extractor static callables, in a file
	 * that previously only rendered a plain enabled+value picker.
	 */
	public function test_cross_origin_coep_tab_renders_without_fatal(): void {
		$_GET['tab'] = 'coep';

		ob_start();
		require WP_SAM_DIR . 'includes/admin/views/page-cross-origin.php';
		$output = (string) ob_get_clean();

		unset( $_GET['tab'] );

		$this->assertStringContainsString( 'Cross-Origin-Embedder-Policy', $output );
		$this->assertStringContainsString( 'Report-Only Evidence', $output );
		$this->assertStringContainsString( 'wp-sam-pillar-mode', $output );
	}

	public function test_cross_origin_coop_tab_renders_without_fatal(): void {
		$_GET['tab'] = 'coop';

		ob_start();
		require WP_SAM_DIR . 'includes/admin/views/page-cross-origin.php';
		$output = (string) ob_get_clean();

		unset( $_GET['tab'] );

		$this->assertStringContainsString( 'Cross-Origin-Opener-Policy', $output );
		$this->assertStringContainsString( 'Report-Only Evidence', $output );
		$this->assertStringContainsString( 'wp-sam-pillar-mode', $output );
	}

	public function test_cross_origin_corp_tab_renders_without_fatal(): void {
		$_GET['tab'] = 'corp';

		ob_start();
		require WP_SAM_DIR . 'includes/admin/views/page-cross-origin.php';
		$output = (string) ob_get_clean();

		unset( $_GET['tab'] );

		$this->assertStringContainsString( 'Cross-Origin-Resource-Policy', $output );
		$this->assertStringNotContainsString( 'Report-Only Evidence', $output );
		$this->assertStringContainsString( 'wp-sam-pillar-enabled', $output );
	}

	public function test_cross_origin_xpcdp_tab_renders_without_fatal(): void {
		$_GET['tab'] = 'xpcdp';

		ob_start();
		require WP_SAM_DIR . 'includes/admin/views/page-cross-origin.php';
		$output = (string) ob_get_clean();

		unset( $_GET['tab'] );

		$this->assertStringContainsString( 'X-Permitted-Cross-Domain-Policies', $output );
		$this->assertStringNotContainsString( 'Report-Only Evidence', $output );
		$this->assertStringContainsString( 'wp-sam-pillar-enabled', $output );
	}

	// ── display_admin_notices() ────────────────────────────────────────────────

	public function test_display_admin_notices_shows_a_plain_english_summary_for_known_events(): void {
		// Confirmed in production, 2026-08-19: this exact event's raw detail
		// ("Hash_Manager", "exact-content dedup", "csp_hash_inventory",
		// "source_file/source_context") reached ordinary site owners
		// verbatim in a wp-admin banner. A known event must show a plain-
		// English summary as the primary text instead.
		update_option(
			'wp_sam_admin_notices',
			array(
				array(
					'component' => 'hash_manager',
					'event'     => 'hash_learning_rate_limited',
					'detail'    => 'More than 30 new inline-script/style hashes were captured for surface "admin" within one hour.',
					'severity'  => 'error',
				),
			)
		);

		$ui = $this->make_admin_ui();

		ob_start();
		$ui->display_admin_notices();
		$output = (string) ob_get_clean();

		$this->assertStringContainsString( 'paused itself', $output );
		$this->assertStringNotContainsString( 'Hash_Manager', $output );
		$this->assertStringNotContainsString( 'csp_hash_inventory', $output );
	}

	public function test_display_admin_notices_keeps_the_technical_detail_available_but_collapsed(): void {
		update_option(
			'wp_sam_admin_notices',
			array(
				array(
					'component' => 'hash_manager',
					'event'     => 'hash_learning_rate_limited',
					'detail'    => 'More than 30 new inline-script/style hashes were captured for surface "admin" within one hour.',
					'severity'  => 'error',
				),
			)
		);

		$ui = $this->make_admin_ui();

		ob_start();
		$ui->display_admin_notices();
		$output = (string) ob_get_clean();

		$this->assertStringContainsString( '<details>', $output );
		$this->assertStringContainsString( 'captured for surface', $output );
	}

	public function test_display_admin_notices_falls_back_to_raw_detail_for_unlisted_events(): void {
		// Only events actually found to need simplification are listed in
		// ADMIN_NOTICE_SUMMARIES -- anything else keeps today's behaviour
		// rather than silently losing detail because it wasn't added yet.
		update_option(
			'wp_sam_admin_notices',
			array(
				array(
					'component' => 'discovery',
					'event'     => 'crawl_failed',
					'detail'    => 'Failed to fetch https://example.com/: some error',
					'severity'  => 'warning',
				),
			)
		);

		$ui = $this->make_admin_ui();

		ob_start();
		$ui->display_admin_notices();
		$output = (string) ob_get_clean();

		$this->assertStringContainsString( 'discovery/crawl_failed', $output );
		$this->assertStringContainsString( 'Failed to fetch', $output );
		$this->assertStringNotContainsString( '<details>', $output );
	}

	private function make_admin_ui(): Admin_UI {
		$reflection = new ReflectionClass( Plugin::class );

		return new Admin_UI( $reflection->newInstanceWithoutConstructor() );
	}
}
