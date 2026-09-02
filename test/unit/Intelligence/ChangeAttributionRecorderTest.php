<?php
/**
 * Unit tests for WP_SAM\Intelligence\Change_Attribution_Recorder.
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;
use WP_SAM\Intelligence\Change_Attribution_Recorder;
use WP_SAM\Intelligence\Change_Log_Store;

class ChangeAttributionRecorderTest extends TestCase {

	private Change_Attribution_Recorder $recorder;

	protected function setUp(): void {
		wp_test_reset_globals();
		$this->recorder = new Change_Attribution_Recorder( new Change_Log_Store() );
	}

	public function test_register_hooks_the_four_wordpress_change_events(): void {
		$this->recorder->register();

		$this->assertArrayHasKey( 'upgrader_process_complete', $GLOBALS['_wp_actions'] );
		$this->assertArrayHasKey( 'activated_plugin', $GLOBALS['_wp_actions'] );
		$this->assertArrayHasKey( 'deactivated_plugin', $GLOBALS['_wp_actions'] );
		$this->assertArrayHasKey( 'switch_theme', $GLOBALS['_wp_actions'] );
	}

	public function test_plugin_upgrade_via_plural_key_records_each_plugin(): void {
		$GLOBALS['_wp_plugin_data'] = array(
			WP_PLUGIN_DIR . '/akismet/akismet.php' => array( 'Version' => '5.3' ),
			WP_PLUGIN_DIR . '/hello.php'           => array( 'Version' => '1.7' ),
		);

		$this->recorder->on_upgrader_process_complete(
			new stdClass(),
			array(
				'type'    => 'plugin',
				'action'  => 'update',
				'plugins' => array( 'akismet/akismet.php', 'hello.php' ),
			)
		);

		$this->assertCount( 2, $GLOBALS['_wpdb_inserted_rows'] );
		$this->assertSame( 'plugin_updated', $GLOBALS['_wpdb_inserted_rows'][0]['data']['change_type'] );
		$this->assertSame( '5.3', $GLOBALS['_wpdb_inserted_rows'][0]['data']['new_version'] );
	}

	public function test_plugin_upgrade_via_singular_key_records_one_plugin(): void {
		$GLOBALS['_wp_plugin_data'] = array( WP_PLUGIN_DIR . '/akismet/akismet.php' => array( 'Version' => '5.3' ) );

		$this->recorder->on_upgrader_process_complete(
			new stdClass(),
			array(
				'type'   => 'plugin',
				'plugin' => 'akismet/akismet.php',
			)
		);

		$this->assertCount( 1, $GLOBALS['_wpdb_inserted_rows'] );
	}

	public function test_theme_upgrade_records_the_new_version(): void {
		$GLOBALS['_wp_themes'] = array( 'twentytwentyfive' => new WP_Theme( 'twentytwentyfive', '1.1' ) );

		$this->recorder->on_upgrader_process_complete(
			new stdClass(),
			array(
				'type'   => 'theme',
				'themes' => array( 'twentytwentyfive' ),
			)
		);

		$this->assertCount( 1, $GLOBALS['_wpdb_inserted_rows'] );
		$data = $GLOBALS['_wpdb_inserted_rows'][0]['data'];
		$this->assertSame( 'theme_updated', $data['change_type'] );
		$this->assertSame( '1.1', $data['new_version'] );
	}

	public function test_core_upgrade_records_the_wordpress_item(): void {
		$this->recorder->on_upgrader_process_complete( new stdClass(), array( 'type' => 'core' ) );

		$this->assertCount( 1, $GLOBALS['_wpdb_inserted_rows'] );
		$this->assertSame( 'core_updated', $GLOBALS['_wpdb_inserted_rows'][0]['data']['change_type'] );
		$this->assertSame( 'core', $GLOBALS['_wpdb_inserted_rows'][0]['data']['item_name'] );
	}

	public function test_translation_upgrade_records_nothing(): void {
		$this->recorder->on_upgrader_process_complete( new stdClass(), array( 'type' => 'translation' ) );

		$this->assertSame( array(), $GLOBALS['_wpdb_inserted_rows'] );
	}

	public function test_plugin_activation_records_activated_type(): void {
		$GLOBALS['_wp_plugin_data'] = array( WP_PLUGIN_DIR . '/akismet/akismet.php' => array( 'Version' => '5.3' ) );

		$this->recorder->on_plugin_activated( 'akismet/akismet.php' );

		$this->assertSame( 'plugin_activated', $GLOBALS['_wpdb_inserted_rows'][0]['data']['change_type'] );
	}

	public function test_plugin_deactivation_records_deactivated_type(): void {
		$GLOBALS['_wp_plugin_data'] = array( WP_PLUGIN_DIR . '/akismet/akismet.php' => array( 'Version' => '5.3' ) );

		$this->recorder->on_plugin_deactivated( 'akismet/akismet.php' );

		$data = $GLOBALS['_wpdb_inserted_rows'][0]['data'];
		$this->assertSame( 'plugin_deactivated', $data['change_type'] );
		$this->assertSame( '5.3', $data['old_version'] );
	}

	public function test_switch_theme_records_old_and_new_version(): void {
		$old = new WP_Theme( 'old-theme', '1.0' );
		$new = new WP_Theme( 'new-theme', '2.0' );

		$this->recorder->on_switch_theme( 'New Theme', $new, $old );

		$data = $GLOBALS['_wpdb_inserted_rows'][0]['data'];
		$this->assertSame( 'theme_switched', $data['change_type'] );
		$this->assertSame( 'new-theme', $data['item_name'] );
		$this->assertSame( '1.0', $data['old_version'] );
		$this->assertSame( '2.0', $data['new_version'] );
	}
}
