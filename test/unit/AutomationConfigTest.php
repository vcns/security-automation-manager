<?php
/**
 * Unit tests for WP_SAM\CSP\Automation_Config.
 *
 * This suite never loads includes/extensions/ (nothing in the test harness
 * requires that directory), so Automation_Mode_Registry only ever has the
 * three free modes register_defaults() adds -- by construction, exactly the
 * WordPress.org-channel scenario, not merely a simulation of it. Tests that
 * need a paid-mode scenario register one directly via
 * Automation_Mode_Registry::register(), proving the generic mechanism works
 * for any mode, not a hardcoded "fully_automatic" special case.
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;
use WP_SAM\CSP\Automation_Config;
use WP_SAM\CSP\Automation_Mode_Registry;

class AutomationConfigTest extends TestCase {

	protected function setUp(): void {
		wp_test_reset_globals();
		Automation_Mode_Registry::reset();
		Automation_Mode_Registry::register_defaults();
	}

	public function test_defaults_are_automatic_high_approval(): void {
		$config = ( new Automation_Config() )->all();

		foreach ( Automation_Config::SURFACES as $surface ) {
			$this->assertSame( Automation_Config::MODE_AUTOMATIC_HIGH_APPROVAL, $config[ $surface ]['mode'] );
			// Must be positive alongside a non-manual default mode -- see
			// DEFAULT_SURFACE_CONFIG's own docblock for why 0 here would
			// silently disable automation despite the mode claiming it's on.
			$this->assertSame( 50, $config[ $surface ]['max_automatic_changes_per_scan'] );
		}
	}

	public function test_invalid_mode_normalises_to_manual(): void {
		update_option(
			'wp_sam_automation_config',
			array(
				'frontend' => array(
					'mode'                   => 'reckless',
					'allowed_source_schemes' => array( 'HTTPS', 'javascript:' ),
				),
			)
		);

		$config = ( new Automation_Config() )->for_surface( 'frontend' );

		$this->assertSame( 'manual', $config['mode'] );
		$this->assertSame( array( 'https', 'javascript:' ), $config['allowed_source_schemes'] );
	}

	public function test_admin_input_can_enable_automatic_surface_automation(): void {
		$config = ( new Automation_Config() )->normalise_admin_input(
			array(
				'frontend' => array(
					'mode'                           => Automation_Config::MODE_AUTOMATIC_MEDIUM_HIGH_APPROVAL,
					'max_automatic_changes_per_scan' => '5',
					'enabled_directives'             => array( 'DEFAULT-SRC', 'img-src' ),
					'allowed_source_schemes'         => array( 'HTTPS', 'wss' ),
				),
			)
		);

		$this->assertSame( Automation_Config::MODE_AUTOMATIC_MEDIUM_HIGH_APPROVAL, $config['frontend']['mode'] );
		$this->assertSame( 5, $config['frontend']['max_automatic_changes_per_scan'] );
		$this->assertSame( array( 'default-src', 'img-src' ), $config['frontend']['enabled_directives'] );
		$this->assertSame( array( 'https', 'wss' ), $config['frontend']['allowed_source_schemes'] );
		$this->assertSame( Automation_Config::MODE_AUTOMATIC_HIGH_APPROVAL, $config['admin']['mode'] );
	}

	public function test_legacy_modes_normalise_to_new_approval_postures(): void {
		update_option(
			'wp_sam_automation_config',
			array(
				'frontend' => array( 'mode' => 'conservative' ),
				'admin'    => array( 'mode' => 'balanced' ),
				'login'    => array( 'mode' => 'expert' ),
			)
		);

		// 'expert' is a legacy alias only a paid-mode extension registers
		// (see includes/extensions/) -- unregistered here, so it resolves
		// to a mode nothing recognises and normalises to manual, exactly
		// like any other unrecognised string.
		$config = ( new Automation_Config() )->all();

		$this->assertSame( Automation_Config::MODE_AUTOMATIC_MEDIUM_HIGH_APPROVAL, $config['frontend']['mode'] );
		$this->assertSame( Automation_Config::MODE_AUTOMATIC_HIGH_APPROVAL, $config['admin']['mode'] );
		$this->assertSame( Automation_Config::MODE_MANUAL, $config['login']['mode'] );
	}

	// ── Paid-mode gating (generic -- not specific to any one paid mode) ──────

	/**
	 * "fully_automatic" is a bare string here deliberately, not a shared
	 * constant -- Automation_Config defines no such constant any more (see
	 * its own docblock). Nothing in this suite ever registers it, so this
	 * proves the WordPress.org-channel behaviour: submitting that exact
	 * identifier is indistinguishable from submitting any other
	 * unrecognised string.
	 */
	public function test_an_unregistered_paid_mode_identifier_normalises_to_manual(): void {
		$config = ( new Automation_Config() )->update_surface_mode( 'frontend', 'fully_automatic' );

		$this->assertSame( Automation_Config::MODE_MANUAL, $config['frontend']['mode'] );
	}

	public function test_a_registered_but_unavailable_paid_mode_downgrades_to_high_approval(): void {
		Automation_Mode_Registry::register( 'test_paid_mode', 'Test Paid Mode', array( 'low', 'medium', 'high' ), static fn(): bool => false );

		$config = ( new Automation_Config() )->update_surface_mode( 'frontend', 'test_paid_mode' );

		$this->assertSame( Automation_Config::MODE_AUTOMATIC_HIGH_APPROVAL, $config['frontend']['mode'] );
	}

	public function test_a_registered_and_available_paid_mode_is_accepted(): void {
		Automation_Mode_Registry::register( 'test_paid_mode', 'Test Paid Mode', array( 'low', 'medium', 'high' ), static fn(): bool => true );

		$config = ( new Automation_Config() )->update_surface_mode( 'frontend', 'test_paid_mode' );

		$this->assertSame( 'test_paid_mode', $config['frontend']['mode'] );
	}

	public function test_mode_labels_reflects_only_what_is_registered(): void {
		$labels = Automation_Config::mode_labels();

		$this->assertArrayHasKey( Automation_Config::MODE_MANUAL, $labels );
		$this->assertArrayHasKey( Automation_Config::MODE_AUTOMATIC_HIGH_APPROVAL, $labels );
		$this->assertArrayNotHasKey( 'fully_automatic', $labels );
		$this->assertArrayNotHasKey( 'test_paid_mode', $labels );

		Automation_Mode_Registry::register( 'test_paid_mode', 'Test Paid Mode', array( 'low' ) );
		$this->assertArrayHasKey( 'test_paid_mode', Automation_Config::mode_labels() );
	}

	public function test_dashboard_mode_update_seeds_change_cap_for_automatic_modes(): void {
		$automation = new Automation_Config();
		$config     = $automation->update_surface_mode( 'frontend', Automation_Config::MODE_AUTOMATIC_HIGH_APPROVAL );

		$this->assertSame( Automation_Config::MODE_AUTOMATIC_HIGH_APPROVAL, $config['frontend']['mode'] );
		$this->assertSame( 50, $config['frontend']['max_automatic_changes_per_scan'] );

		$config = $automation->update_surface_mode( 'frontend', Automation_Config::MODE_MANUAL );

		$this->assertSame( Automation_Config::MODE_MANUAL, $config['frontend']['mode'] );
		$this->assertSame( 0, $config['frontend']['max_automatic_changes_per_scan'] );
	}
}
