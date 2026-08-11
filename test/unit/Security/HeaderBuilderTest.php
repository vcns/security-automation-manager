<?php
/**
 * Unit tests for WP_SAM\Security\Header_Builder::register(), exercised
 * through the simplest concrete subclass (X_Content_Type_Options_Builder)
 * since the hook-wiring logic under test lives entirely in the shared
 * abstract base.
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;
use WP_SAM\Security\X_Content_Type_Options_Builder;

class HeaderBuilderTest extends TestCase {

	protected function setUp(): void {
		wp_test_reset_globals();
	}

	public function test_register_hooks_send_headers(): void {
		( new X_Content_Type_Options_Builder() )->register();

		$this->assertArrayHasKey( 'send_headers', $GLOBALS['_wp_actions'] );
	}

	public function test_register_hooks_wp_redirect(): void {
		( new X_Content_Type_Options_Builder() )->register();

		$this->assertArrayHasKey( 'wp_redirect', $GLOBALS['_wp_actions'] );
	}

	/**
	 * Regression test: wp-login.php is a standalone entry point that never
	 * calls wp() / WP::main(), so send_headers -- fired only from
	 * WP::send_headers() -- never runs there. Every header pillar (CSP,
	 * X-Frame-Options, Permissions-Policy, etc.) silently skipped the login
	 * surface entirely until login_init was added here, even when a profile
	 * was configured and enabled for it. Confirmed live: staging.alltimetech.co.uk's
	 * wp-login.php response carried none of this plugin's headers at all,
	 * while its frontend response carried the full set including
	 * Permissions-Policy -- login_init is the hook WordPress itself
	 * documents as the substitute for code that must run early on that page.
	 */
	public function test_register_hooks_login_init_so_headers_apply_on_wp_login_php(): void {
		( new X_Content_Type_Options_Builder() )->register();

		$this->assertArrayHasKey( 'login_init', $GLOBALS['_wp_actions'] );

		$registered_methods = array_map(
			static fn( array $entry ): mixed => is_array( $entry[0] ) ? $entry[0][1] : $entry[0],
			$GLOBALS['_wp_actions']['login_init']
		);
		$this->assertContains( 'emit_header', $registered_methods );
	}
}
