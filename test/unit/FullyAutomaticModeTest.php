<?php
/**
 * Unit tests for includes/extensions/fully-automatic-mode.php.
 *
 * Confirms the direct-Stripe checkout path (secret/price/webhook option
 * registration, the AJAX checkout-session handler) is genuinely gone, not
 * just unreachable -- see this file's own docblock and docs/threat-model.md's
 * "Stripe secret storage" finding. Each test that needs the extension's
 * hooks registered calls require() (never require_once) directly, matching
 * CommercialServicesSchemaTest.php's own established pattern -- setUp()'s
 * wp_test_reset_globals() clears $GLOBALS['_wp_actions'] before every test,
 * so require_once would silently no-op after the first test in this file.
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;
use WP_SAM\CSP\Automation_Mode_Registry;
use WP_SAM\Modules\Feature_Gate;

class FullyAutomaticModeTest extends TestCase {

	protected function setUp(): void {
		wp_test_reset_globals();
		// reset() + register_defaults(), not reset() alone -- Automation_Mode_
		// Registry is process-wide static state; leaving it empty after this
		// test class runs would break any later test file in the same
		// PHPUnit process that expects the 3 free defaults to be present
		// (see AutomationConfigTest.php/DecisionEngineTest.php's own setUp()
		// for the same established pattern).
		Automation_Mode_Registry::reset();
		Automation_Mode_Registry::register_defaults();
	}

	public function test_registers_the_fully_automatic_mode(): void {
		require WP_SAM_DIR . 'includes/extensions/fully-automatic-mode.php';

		do_action( 'wp_sam_register_automation_modes', new Feature_Gate() );

		$this->assertContains( 'fully_automatic', Automation_Mode_Registry::keys() );
	}

	public function test_mode_is_unavailable_with_no_entitlement_source(): void {
		// The real production state today on every build -- see this file's
		// own docblock: commercial-services.php has nothing to populate
		// Feature_Gate's entitlements with in any distributed channel.
		require WP_SAM_DIR . 'includes/extensions/fully-automatic-mode.php';

		do_action( 'wp_sam_register_automation_modes', new Feature_Gate() );

		$this->assertFalse( Automation_Mode_Registry::is_available( 'fully_automatic' ) );
	}

	public function test_no_longer_registers_any_stripe_option(): void {
		require WP_SAM_DIR . 'includes/extensions/fully-automatic-mode.php';

		$names = apply_filters( 'wp_sam_option_names', array() );

		foreach ( $names as $name ) {
			$this->assertStringNotContainsString( 'stripe', $name );
		}
		$this->assertNotContains( 'wp_sam_webhook_secret', $names );
	}

	public function test_no_longer_registers_the_checkout_ajax_handler(): void {
		require WP_SAM_DIR . 'includes/extensions/fully-automatic-mode.php';

		$this->assertArrayNotHasKey( 'wp_ajax_wp_sam_create_checkout_session', $GLOBALS['_wp_actions'] );
	}

	public function test_upgrade_notice_never_renders_a_stripe_settings_form(): void {
		require WP_SAM_DIR . 'includes/extensions/fully-automatic-mode.php';
		Automation_Mode_Registry::register( 'fully_automatic', 'Fully Automatic', array( 'low' ), static fn(): bool => false );

		ob_start();
		do_action( 'wp_sam_automation_upgrade_notice', true );
		$output = (string) ob_get_clean();

		$this->assertStringContainsString( 'Fully Automatic', $output );
		$this->assertStringContainsString( 'Upgrading is not available in this build', $output );
		$this->assertStringNotContainsString( 'Secret Key', $output );
		$this->assertStringNotContainsString( 'wp_sam_stripe', $output );
		$this->assertStringNotContainsString( 'Subscribe', $output );
	}

	public function test_upgrade_notice_is_silent_once_the_mode_is_available(): void {
		require WP_SAM_DIR . 'includes/extensions/fully-automatic-mode.php';
		Automation_Mode_Registry::register( 'fully_automatic', 'Fully Automatic', array( 'low' ), static fn(): bool => true );

		ob_start();
		do_action( 'wp_sam_automation_upgrade_notice', true );
		$output = (string) ob_get_clean();

		$this->assertSame( '', $output );
	}
}
