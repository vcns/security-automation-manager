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

	public function test_registers_on_every_post_type_save_and_the_customizer(): void {
		( new Learning_Window() )->register();

		$this->assertArrayHasKey( 'save_post', $GLOBALS['_wp_actions'] );
		$this->assertArrayHasKey( 'customize_save_after', $GLOBALS['_wp_actions'] );
		$this->assertArrayNotHasKey( 'save_post_post', $GLOBALS['_wp_actions'] );
		$this->assertArrayNotHasKey( 'save_post_page', $GLOBALS['_wp_actions'] );
	}

	/**
	 * @dataProvider provide_saves_that_reopen_the_window
	 */
	public function test_publishing_visible_content_reopens_window( string $post_type ): void {
		$GLOBALS['_wp_viewable_post_types'][] = 'product';
		$window                               = $this->closed_window();

		$window->mark_post_change( 42, $this->post( $post_type, 'publish' ), true );

		$this->assertTrue( $window->is_open() );
	}

	public static function provide_saves_that_reopen_the_window(): array {
		return array(
			'post'                      => array( 'post' ),
			'page'                      => array( 'page' ),
			'public custom post type'   => array( 'product' ),
			'block template'            => array( 'wp_template' ),
			'block template part'       => array( 'wp_template_part' ),
			'global styles'             => array( 'wp_global_styles' ),
			'navigation menu'           => array( 'wp_navigation' ),
			'synced pattern'            => array( 'wp_block' ),
		);
	}

	/**
	 * @dataProvider provide_saves_that_leave_the_window_closed
	 */
	public function test_saves_visitors_cannot_see_leave_window_closed( string $post_type, string $status ): void {
		$window = $this->closed_window();

		$window->mark_post_change( 42, $this->post( $post_type, $status ), true );

		$this->assertFalse( $window->is_open() );
	}

	public static function provide_saves_that_leave_the_window_closed(): array {
		return array(
			'draft post'                => array( 'post', 'draft' ),
			'auto-draft page'           => array( 'page', 'auto-draft' ),
			'private page'              => array( 'page', 'private' ),
			'non-public post type'      => array( 'shop_order', 'publish' ),
			'attachment'                => array( 'attachment', 'publish' ),
			'draft template'            => array( 'wp_template', 'draft' ),
		);
	}

	public function test_upgrader_completion_ignores_unrecognised_types(): void {
		update_option( Learning_Window::OPTION_LAST_CHANGE, gmdate( 'Y-m-d H:i:s', time() - ( 49 * HOUR_IN_SECONDS ) ) );
		update_option( Learning_Window::OPTION_WINDOW_HOURS, 48 );

		$window = new Learning_Window();

		$window->mark_upgrader_change( new stdClass(), array( 'type' => 'translation' ) );

		$this->assertFalse( $window->is_open() );
	}

	private function closed_window(): Learning_Window {
		update_option( Learning_Window::OPTION_LAST_CHANGE, gmdate( 'Y-m-d H:i:s', time() - ( 49 * HOUR_IN_SECONDS ) ) );
		update_option( Learning_Window::OPTION_WINDOW_HOURS, 48 );

		$window = new Learning_Window();
		$this->assertFalse( $window->is_open(), 'Precondition: window starts closed.' );

		return $window;
	}

	private function post( string $post_type, string $status ): object {
		return (object) array(
			'post_type'   => $post_type,
			'post_status' => $status,
		);
	}
}
