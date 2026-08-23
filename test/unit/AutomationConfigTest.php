<?php
/**
 * Unit tests for WP_SAM\CSP\Automation_Config.
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;
use WP_SAM\CSP\Automation_Config;
use WP_SAM\Modules\Feature_Gate;

class AutomationConfigTest extends TestCase {

	protected function setUp(): void {
		wp_test_reset_globals();
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

		// No gate injected -- free-tier default. "expert" maps to
		// Fully Automatic, which is a paid feature, so it downgrades to
		// the highest free posture instead of passing through unchanged.
		$config = ( new Automation_Config() )->all();

		$this->assertSame( Automation_Config::MODE_AUTOMATIC_MEDIUM_HIGH_APPROVAL, $config['frontend']['mode'] );
		$this->assertSame( Automation_Config::MODE_AUTOMATIC_HIGH_APPROVAL, $config['admin']['mode'] );
		$this->assertSame( Automation_Config::MODE_AUTOMATIC_HIGH_APPROVAL, $config['login']['mode'] );
	}

	// ── Fully Automatic gating ───────────────────────────────────────────────

	public function test_fully_automatic_downgrades_to_high_approval_without_entitlement(): void {
		$config = ( new Automation_Config() )->update_surface_mode( 'frontend', Automation_Config::MODE_FULLY_AUTOMATIC );

		$this->assertSame( Automation_Config::MODE_AUTOMATIC_HIGH_APPROVAL, $config['frontend']['mode'] );
	}

	/**
	 * Fully Automatic is a paid, GitHub-channel-only feature: a pro
	 * entitlement alone is necessary but not sufficient -- the distribution
	 * channel must also offer it. WP_SAM_DISTRIBUTION_CHANNEL is defined
	 * once, globally, in test/bootstrap.php as 'wordpress-org' and PHP
	 * constants can't be redefined per-test (same limitation documented in
	 * AdminUITest::test_updates_tab_omits_github_fields_on_wordpress_org_build),
	 * so this only ever exercises the WordPress.org/.com branch. That's
	 * still the one this requirement is actually about: even a genuinely
	 * pro-entitled site must never see Fully Automatic accepted on that
	 * channel.
	 */
	public function test_fully_automatic_stays_downgraded_on_wordpress_org_channel_even_with_a_pro_entitlement(): void {
		$entitlements = new class() {
			public function get_for_site( string $product_key ): ?array {
				return array( 'tier' => 'pro' );
			}
		};

		$gate   = new Feature_Gate( $entitlements );
		$config = ( new Automation_Config( $gate ) )->update_surface_mode( 'frontend', Automation_Config::MODE_FULLY_AUTOMATIC );

		$this->assertSame( Automation_Config::MODE_AUTOMATIC_HIGH_APPROVAL, $config['frontend']['mode'] );
	}

	public function test_channel_offers_fully_automatic_is_false_on_the_wordpress_org_channel(): void {
		// See the docblock above for why this suite can only exercise the
		// wordpress-org branch of this check.
		$this->assertFalse( Automation_Config::channel_offers_fully_automatic() );
	}

	public function test_mode_labels_omits_fully_automatic_on_the_wordpress_org_channel(): void {
		$this->assertArrayNotHasKey( Automation_Config::MODE_FULLY_AUTOMATIC, Automation_Config::mode_labels() );
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
