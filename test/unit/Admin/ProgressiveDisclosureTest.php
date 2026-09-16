<?php
/**
 * Unit tests for the Customer-Centred Administration Experience's
 * progressive-disclosure behaviour (spec §12): a Technical-depth user's
 * render opens the "Technical details" <details> blocks by default, a
 * Simple/Balanced-depth user's does not, and critical/decision-consequence
 * text is present in every depth -- never hidden inside a collapsed block.
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;
use WP_SAM\Intelligence\Recommendation_Registry;

class ProgressiveDisclosureTest extends TestCase {

	protected function setUp(): void {
		wp_test_reset_globals();
		$GLOBALS['_wp_current_user_can']['manage_options'] = true;
		Recommendation_Registry::reset();
		\WP_SAM\CSP\Automation_Mode_Registry::register_defaults();
	}

	private function render_overview_tab_for_user( int $user_id, string $depth, string $familiarity = '' ): string {
		\WP_SAM\Admin\Presentation_Preferences::save_for_user(
			$user_id,
			array(
				'presentation_depth'   => $depth,
				'security_familiarity' => $familiarity,
			)
		);
		$GLOBALS['_wp_current_user_id'] = $user_id;

		$GLOBALS['_wpdb_get_var']     = 0;
		$GLOBALS['_wpdb_get_results'] = array();
		$GLOBALS['_wpdb_get_row']     = null;
		$GLOBALS['_wpdb_get_col']     = array();

		$plugin = \WP_SAM\Plugin::instance();
		if ( ! isset( $plugin->cert_manager ) ) {
			$plugin->cert_manager = ( new ReflectionClass( \WP_SAM\Certificates\Certificate_Manager::class ) )->newInstanceWithoutConstructor();
		}
		$admin_ui    = new \WP_SAM\Admin\Admin_UI( $plugin );
		$_GET['tab'] = 'overview';

		ob_start();
		$admin_ui->render_overview();
		$output = (string) ob_get_clean();
		unset( $_GET['tab'] );

		return $output;
	}

	public function test_technical_depth_opens_details_blocks_by_default(): void {
		$output = $this->render_overview_tab_for_user( 101, 'technical' );

		// One <details open="open"> per Protection Status row (5 areas) at minimum.
		$this->assertGreaterThanOrEqual( 5, substr_count( $output, '<details open="open">' ) );
		$this->assertStringNotContainsString( '<details>', $output );
	}

	public function test_simple_and_balanced_depth_do_not_open_details_blocks(): void {
		foreach ( array( 'simple', 'balanced' ) as $depth ) {
			$output = $this->render_overview_tab_for_user( 102, $depth );

			$this->assertStringNotContainsString( '<details open="open">', $output );
			$this->assertGreaterThanOrEqual( 5, substr_count( $output, '<details>' ) );
		}
	}

	public function test_technical_name_is_present_in_markup_at_every_depth(): void {
		foreach ( array( 'simple', 'balanced', 'technical' ) as $depth ) {
			$output = $this->render_overview_tab_for_user( 103, $depth );

			$this->assertStringContainsString( 'Content Security Policy (CSP)', $output );
		}
	}

	public function test_new_familiarity_adds_expanded_help_text(): void {
		$output = $this->render_overview_tab_for_user( 104, 'balanced', 'new' );

		$this->assertStringContainsString( 'New to this?', $output );
	}

	public function test_comfortable_familiarity_does_not_add_expanded_help_text(): void {
		$output = $this->render_overview_tab_for_user( 105, 'balanced', 'comfortable' );

		$this->assertStringNotContainsString( 'New to this?', $output );
	}

	public function test_scorecard_and_protection_status_headings_present_regardless_of_depth(): void {
		foreach ( array( 'simple', 'balanced', 'technical' ) as $depth ) {
			$output = $this->render_overview_tab_for_user( 106, $depth );

			$this->assertStringContainsString( 'Protection status', $output );
			$this->assertStringContainsString( 'wp-sam-scorecard', $output );
		}
	}
}
