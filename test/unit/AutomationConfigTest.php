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

	public function test_defaults_are_manual(): void {
		$config = ( new Automation_Config() )->all();

		foreach ( Automation_Config::SURFACES as $surface ) {
			$this->assertSame( 'manual', $config[ $surface ]['mode'] );
			$this->assertSame( 0, $config[ $surface ]['max_automatic_changes_per_scan'] );
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
		$this->assertSame( 'manual', $config['admin']['mode'] );
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

	public function test_fully_automatic_is_accepted_with_a_pro_entitlement(): void {
		$entitlements = new class() {
			public function get_for_site( string $product_key ): ?array {
				return array( 'tier' => 'pro' );
			}
		};

		$gate   = new Feature_Gate( $entitlements );
		$config = ( new Automation_Config( $gate ) )->update_surface_mode( 'frontend', Automation_Config::MODE_FULLY_AUTOMATIC );

		$this->assertSame( Automation_Config::MODE_FULLY_AUTOMATIC, $config['frontend']['mode'] );
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
