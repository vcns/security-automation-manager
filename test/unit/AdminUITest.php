<?php
/**
 * Unit tests for WP_SAM\Admin\Admin_UI.
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;
use WP_SAM\Admin\Admin_UI;
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
		$this->assertStringContainsString( 'admin.php?page=security-automation-manager&tab=readiness#wp-sam-reset', $links['reset'] );
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
		$this->assertStringContainsString( 'security-automation-manager-hsts', $view );
		$this->assertStringContainsString( 'security-automation-manager-reverse-tabnabbing', $view );
		$this->assertStringContainsString( 'security-automation-manager-scripts', $view );
		$this->assertStringContainsString( "'readiness'", $view );
		$this->assertStringContainsString( "'about'", $view );
		$this->assertStringContainsString( 'wp-sam-reset', $view );
	}

	/**
	 * Regression test for the underlying $simple_pillars array, extracted and
	 * sorted the same way page-overview.php sorts it at render time -- the
	 * view itself isn't executed here (it needs a live WP_SAM\Security\*
	 * builder set and $wpdb), so this proves the alphabetical-by-label
	 * ordering the view relies on actually produces the expected row order,
	 * with "Content Security Policy" (rendered as a separate hardcoded row
	 * before this array) sorting first on its own merit.
	 */
	public function test_overview_pillar_rows_sort_alphabetically_by_label(): void {
		$labels = array(
			'Content Security Policy',
			'X-Frame-Options',
			'X-Content-Type-Options',
			'Referrer-Policy',
			'Permissions-Policy',
			'Strict-Transport-Security',
			'Reverse Tabnabbing Protection',
			'External Scripts',
			'Cross-Origin-Resource-Policy',
			'X-Permitted-Cross-Domain-Policies',
			'Cross-Origin-Opener-Policy',
			'Cross-Origin-Embedder-Policy',
		);

		usort( $labels, static fn( string $a, string $b ): int => strcasecmp( $a, $b ) );

		$this->assertSame(
			array(
				'Content Security Policy',
				'Cross-Origin-Embedder-Policy',
				'Cross-Origin-Opener-Policy',
				'Cross-Origin-Resource-Policy',
				'External Scripts',
				'Permissions-Policy',
				'Referrer-Policy',
				'Reverse Tabnabbing Protection',
				'Strict-Transport-Security',
				'X-Content-Type-Options',
				'X-Frame-Options',
				'X-Permitted-Cross-Domain-Policies',
			),
			$labels
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

	private function make_admin_ui(): Admin_UI {
		$reflection = new ReflectionClass( Plugin::class );

		return new Admin_UI( $reflection->newInstanceWithoutConstructor() );
	}
}
