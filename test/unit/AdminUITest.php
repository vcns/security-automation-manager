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
		$this->assertStringContainsString( 'admin.php?page=security-automation-manager-readiness#wp-sam-reset', $links['reset'] );
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
		$this->assertStringContainsString( 'security-automation-manager-external-scripts', $view );
		$this->assertStringContainsString( 'security-automation-manager-readiness', $view );
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
		$this->assertContains( 'security-automation-manager_page_security-automation-manager-external-scripts', $hooks );
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

	private function make_admin_ui(): Admin_UI {
		$reflection = new ReflectionClass( Plugin::class );

		return new Admin_UI( $reflection->newInstanceWithoutConstructor() );
	}
}
