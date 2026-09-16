<?php
/**
 * Unit tests for WP_SAM\Admin\Presentation_Preferences.
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;
use WP_SAM\Admin\Presentation_Preferences;

class PresentationPreferencesTest extends TestCase {

	protected function setUp(): void {
		wp_test_reset_globals();
	}

	public function test_defaults_when_no_meta_stored(): void {
		$prefs = Presentation_Preferences::get_for_user( 7 );

		$this->assertSame( '', $prefs['onboarding_state'] );
		$this->assertSame( '', $prefs['relationship'] );
		$this->assertSame( '', $prefs['security_familiarity'] );
		$this->assertSame( 'balanced', $prefs['presentation_depth'] );
		$this->assertSame( 'overall', $prefs['landing_emphasis'] );
		$this->assertFalse( Presentation_Preferences::has_completed_onboarding( 7 ) );
	}

	public function test_invalid_stored_value_falls_back_to_default(): void {
		update_user_meta( 7, 'wp_sam_presentation_depth', 'ludicrous' );
		update_user_meta( 7, 'wp_sam_landing_emphasis', 'anything-goes' );
		update_user_meta( 7, 'wp_sam_relationship', 'not-on-the-list' );

		$prefs = Presentation_Preferences::get_for_user( 7 );

		$this->assertSame( 'balanced', $prefs['presentation_depth'] );
		$this->assertSame( 'overall', $prefs['landing_emphasis'] );
		$this->assertSame( '', $prefs['relationship'] );
	}

	public function test_save_for_user_normalises_bad_input_per_field(): void {
		$saved = Presentation_Preferences::save_for_user(
			7,
			array(
				'relationship'         => 'developer',
				'security_familiarity' => 'not-a-real-level',
				'presentation_depth'   => 'technical',
				'landing_emphasis'     => 'nonsense',
			)
		);

		$this->assertSame( 'developer', $saved['relationship'] );
		$this->assertSame( '', $saved['security_familiarity'] );
		$this->assertSame( 'technical', $saved['presentation_depth'] );
		$this->assertSame( 'overall', $saved['landing_emphasis'] );
		$this->assertSame( 'completed', $saved['onboarding_state'] );
		$this->assertTrue( Presentation_Preferences::has_completed_onboarding( 7 ) );
	}

	public function test_two_users_never_see_each_others_preferences(): void {
		Presentation_Preferences::save_for_user(
			1,
			array(
				'relationship'         => 'owner_manager',
				'security_familiarity' => 'new',
				'presentation_depth'   => 'simple',
				'landing_emphasis'     => 'protection',
			)
		);
		Presentation_Preferences::save_for_user(
			2,
			array(
				'relationship'         => 'developer',
				'security_familiarity' => 'specialist',
				'presentation_depth'   => 'technical',
				'landing_emphasis'     => 'technical',
			)
		);

		$user_one = Presentation_Preferences::get_for_user( 1 );
		$user_two = Presentation_Preferences::get_for_user( 2 );

		$this->assertSame( 'owner_manager', $user_one['relationship'] );
		$this->assertSame( 'simple', $user_one['presentation_depth'] );
		$this->assertSame( 'developer', $user_two['relationship'] );
		$this->assertSame( 'technical', $user_two['presentation_depth'] );
	}

	public function test_skip_sets_only_skipped_state_and_defaults(): void {
		$skipped = Presentation_Preferences::skip_for_user( 7 );

		$this->assertSame( 'skipped', $skipped['onboarding_state'] );
		$this->assertSame( 'balanced', $skipped['presentation_depth'] );
		$this->assertSame( 'overall', $skipped['landing_emphasis'] );
		$this->assertSame( '', $skipped['relationship'] );
		$this->assertSame( '', $skipped['security_familiarity'] );
		$this->assertTrue( Presentation_Preferences::has_completed_onboarding( 7 ) );
	}

	public function test_get_for_user_defaults_to_current_user_id(): void {
		$GLOBALS['_wp_current_user_id'] = 42;
		Presentation_Preferences::save_for_user( 42, array( 'presentation_depth' => 'technical' ) );

		$this->assertSame( 'technical', Presentation_Preferences::get_for_user()['presentation_depth'] );
	}

	public function test_depth_label_covers_all_three_depths(): void {
		$this->assertSame( 'Simple', Presentation_Preferences::depth_label( 'simple' ) );
		$this->assertSame( 'Balanced', Presentation_Preferences::depth_label( 'balanced' ) );
		$this->assertSame( 'Technical', Presentation_Preferences::depth_label( 'technical' ) );
	}
}
