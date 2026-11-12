<?php
/**
 * The CSP Profiles/automation AJAX handlers in Admin_UI only accept CSP's
 * own surfaces (Csp_Surfaces::ALL): 'api' is rejected exactly like any
 * unknown surface, before anything is written. Other pillars' handlers
 * still accept 'api' -- the last test pins that so this change can't creep
 * into them.
 *
 * Relies on the bootstrap's throwing wp_send_json_*() stubs
 * (WP_SAM_Test_Json_Response), so the response is caught and nothing after
 * it runs, as with core's die-ing originals.
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;
use WP_SAM\Admin\Admin_UI;
use WP_SAM\CSP\Policy_Builder;
use WP_SAM\Modules\Audit_Log;
use WP_SAM\Plugin;

class CspSurfaceAjaxHandlersTest extends TestCase {

	protected function setUp(): void {
		wp_test_reset_globals();
		$GLOBALS['_wp_current_user_can'] = array( 'manage_options' => true );
		$_POST                           = array();
	}

	protected function tearDown(): void {
		$_POST = array();
	}

	/** @return array<string, array{0: string, 1: array<string, string>}> handler => extra POST fields (besides surface) */
	public static function csp_handlers(): array {
		return array(
			'mode toggle'     => array( 'ajax_toggle_mode', array( 'mode' => 'report-only' ) ),
			'trusted types'   => array( 'ajax_set_trusted_types', array( 'enabled' => '1' ) ),
			'bypass flag'     => array( 'ajax_set_bypass_flag', array( 'enabled' => '1' ) ),
			'automation mode' => array( 'ajax_set_automation_mode', array( 'mode' => 'manual' ) ),
		);
	}

	/**
	 * @dataProvider csp_handlers
	 * @param array<string, string> $fields
	 */
	public function test_csp_handler_rejects_the_api_surface( string $handler, array $fields ): void {
		$response = $this->call( $handler, array_merge( $this->with_valid_flag( $handler, $fields ), array( 'surface' => 'api' ) ) );

		$this->assertFalse( $response->success );
		$this->assertSame( 'Invalid surface.', $response->data['message'] ?? null );
		$this->assertSame( array(), $GLOBALS['_wpdb_updated_rows'] );
		$this->assertSame( array(), $GLOBALS['_wpdb_queries'] );
		$this->assertArrayNotHasKey( 'wp_sam_automation_config', $GLOBALS['_wp_options'] );
	}

	/**
	 * @dataProvider csp_handlers
	 * @param array<string, string> $fields
	 */
	public function test_csp_handler_rejects_api_the_same_way_as_an_unknown_surface( string $handler, array $fields ): void {
		$fields  = $this->with_valid_flag( $handler, $fields );
		$api     = $this->call( $handler, array_merge( $fields, array( 'surface' => 'api' ) ) );
		$unknown = $this->call( $handler, array_merge( $fields, array( 'surface' => 'not-a-surface' ) ) );

		$this->assertEquals( $unknown->data, $api->data );
	}

	public function test_csp_handler_still_accepts_a_csp_surface(): void {
		$response = $this->call( 'ajax_set_trusted_types', array( 'surface' => 'frontend', 'enabled' => '1' ) );

		$this->assertTrue( $response->success );
		$this->assertCount( 1, $GLOBALS['_wpdb_updated_rows'] );
		$this->assertSame( array( 'surface' => 'frontend' ), $GLOBALS['_wpdb_updated_rows'][0]['where'] );
	}

	public function test_non_csp_pillar_handler_still_accepts_the_api_surface(): void {
		$response = $this->call( 'ajax_set_hsts', array( 'surface' => 'api', 'enabled' => '1' ) );

		$this->assertTrue( $response->success );
		$this->assertCount( 1, $GLOBALS['_wpdb_queries'] );
		$this->assertStringContainsString( "'api'", $GLOBALS['_wpdb_queries'][0] );
	}

	/**
	 * @param array<string, string> $fields
	 * @return array<string, string>
	 */
	private function with_valid_flag( string $handler, array $fields ): array {
		// A real catalog key, so the bypass-flag handler can only fail on the surface.
		if ( 'ajax_set_bypass_flag' === $handler ) {
			$fields['flag'] = (string) array_key_first( Policy_Builder::BYPASS_CATALOG );
		}
		return $fields;
	}

	/** @param array<string, string> $post */
	private function call( string $handler, array $post ): WP_SAM_Test_Json_Response {
		wp_test_reset_globals();
		$GLOBALS['_wp_current_user_can'] = array( 'manage_options' => true );
		$_POST                           = $post;

		$reflection    = new ReflectionClass( Plugin::class );
		$plugin        = $reflection->newInstanceWithoutConstructor();
		$plugin->audit = new Audit_Log();

		try {
			( new Admin_UI( $plugin ) )->$handler();
		} catch ( WP_SAM_Test_Json_Response $response ) {
			return $response;
		}

		$this->fail( "{$handler}() returned without sending a JSON response." );
	}
}
