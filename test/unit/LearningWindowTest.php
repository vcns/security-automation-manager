<?php
/**
 * Unit tests for WP_SAM\CSP\Learning_Window.
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;
use WP_SAM\CSP\Learning_Window;

class LearningWindowTest extends TestCase {

	protected function setUp(): void {
		wp_test_reset_globals();
	}

	public function test_missing_material_change_clock_is_initialised_once(): void {
		$window = new Learning_Window();

		$last_change = $window->last_material_change_at();

		$this->assertNotEmpty( $last_change );
		$this->assertSame( $last_change, get_option( Learning_Window::OPTION_LAST_CHANGE ) );
	}

	public function test_window_locks_after_configured_hours(): void {
		update_option( Learning_Window::OPTION_LAST_CHANGE, gmdate( 'Y-m-d H:i:s', time() - ( 49 * HOUR_IN_SECONDS ) ) );
		update_option( Learning_Window::OPTION_WINDOW_HOURS, 48 );

		$window = new Learning_Window();

		$this->assertFalse( $window->is_open() );
	}

	/**
	 * @dataProvider provide_material_upgrader_types
	 */
	public function test_upgrader_completion_reopens_window_for_theme_and_core_updates( string $type ): void {
		update_option( Learning_Window::OPTION_LAST_CHANGE, gmdate( 'Y-m-d H:i:s', time() - ( 49 * HOUR_IN_SECONDS ) ) );
		update_option( Learning_Window::OPTION_WINDOW_HOURS, 48 );

		$window = new Learning_Window();
		$this->assertFalse( $window->is_open(), 'Precondition: window starts closed.' );

		$window->mark_upgrader_change( new stdClass(), array( 'type' => $type ) );

		$this->assertTrue( $window->is_open() );
	}

	public static function provide_material_upgrader_types(): array {
		return array(
			'plugin' => array( 'plugin' ),
			'theme'  => array( 'theme' ),
			'core'   => array( 'core' ),
		);
	}

	public function test_upgrader_completion_ignores_unrecognised_types(): void {
		update_option( Learning_Window::OPTION_LAST_CHANGE, gmdate( 'Y-m-d H:i:s', time() - ( 49 * HOUR_IN_SECONDS ) ) );
		update_option( Learning_Window::OPTION_WINDOW_HOURS, 48 );

		$window = new Learning_Window();

		$window->mark_upgrader_change( new stdClass(), array( 'type' => 'translation' ) );

		$this->assertFalse( $window->is_open() );
	}
}
