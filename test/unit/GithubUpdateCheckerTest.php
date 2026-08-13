<?php
/**
 * Unit tests for WP_SAM\Modules\Github_Update_Checker.
 */

declare( strict_types=1 );

use PHPUnit\Framework\Attributes\RunInSeparateProcess;
use PHPUnit\Framework\TestCase;
use WP_SAM\Modules\Github_Update_Checker;

class GithubUpdateCheckerTest extends TestCase {

	protected function setUp(): void {
		wp_test_reset_globals();
	}

	public function test_new_manifest_version_populates_native_update_response(): void {
		$GLOBALS['_wp_remote_get_response'] = $this->response( $this->manifest( '2.4.22' ) );

		$checker   = new Github_Update_Checker();
		$transient = (object) array(
			'checked'   => array( WP_SAM_PLUGIN_BASENAME => WP_SAM_VERSION ),
			'response'  => array(),
			'no_update' => array(),
		);

		$result = $checker->inject_update( $transient );

		$item = $result->response[ WP_SAM_PLUGIN_BASENAME ] ?? null;
		$this->assertIsObject( $item );
		$this->assertSame( '2.4.22', $item->new_version );
		$this->assertSame( 'https://vcns.github.io/wp-updates/security-automation-manager/security-automation-manager-github-v2.4.22.zip', $item->package );
		$this->assertArrayNotHasKey( WP_SAM_PLUGIN_BASENAME, $result->no_update );
	}

	public function test_current_manifest_version_populates_no_update_without_package(): void {
		$GLOBALS['_wp_remote_get_response'] = $this->response( $this->manifest( WP_SAM_VERSION ) );

		$checker   = new Github_Update_Checker();
		$transient = (object) array(
			'checked'   => array( WP_SAM_PLUGIN_BASENAME => WP_SAM_VERSION ),
			'response'  => array(),
			'no_update' => array(),
		);

		$result = $checker->inject_update( $transient );

		$item = $result->no_update[ WP_SAM_PLUGIN_BASENAME ] ?? null;
		$this->assertIsObject( $item );
		$this->assertSame( WP_SAM_VERSION, $item->new_version );
		$this->assertSame( '', $item->package );
		$this->assertArrayNotHasKey( WP_SAM_PLUGIN_BASENAME, $result->response );
	}

	public function test_invalid_manifest_does_not_offer_update(): void {
		$manifest                 = $this->manifest( '2.4.22' );
		$manifest['download_url'] = 'https://example.com/security-automation-manager.zip';

		$GLOBALS['_wp_remote_get_response'] = $this->response( $manifest );

		$checker   = new Github_Update_Checker();
		$transient = (object) array(
			'checked'   => array( WP_SAM_PLUGIN_BASENAME => WP_SAM_VERSION ),
			'response'  => array(),
			'no_update' => array(),
		);

		$result = $checker->inject_update( $transient );

		$this->assertSame( array(), $result->response );
		$this->assertSame( array(), $result->no_update );
	}

	public function test_path_traversal_in_download_url_does_not_offer_update(): void {
		$manifest                 = $this->manifest( '2.4.22' );
		$manifest['download_url'] = 'https://vcns.github.io/wp-updates/security-automation-manager/../some-other-product/evil.zip';

		$GLOBALS['_wp_remote_get_response'] = $this->response( $manifest );

		$checker   = new Github_Update_Checker();
		$transient = (object) array(
			'checked'   => array( WP_SAM_PLUGIN_BASENAME => WP_SAM_VERSION ),
			'response'  => array(),
			'no_update' => array(),
		);

		$result = $checker->inject_update( $transient );

		$this->assertSame( array(), $result->response );
		$this->assertSame( array(), $result->no_update );
	}

	public function test_plugin_information_modal_uses_manifest_sections(): void {
		$GLOBALS['_wp_remote_get_response'] = $this->response( $this->manifest( '2.4.22' ) );

		$checker = new Github_Update_Checker();
		$args    = (object) array( 'slug' => 'security-automation-manager' );

		$result = $checker->plugin_info( false, 'plugin_information', $args );

		$this->assertIsObject( $result );
		$this->assertSame( 'CSP Automation Manager', $result->name );
		$this->assertSame( '2.4.22', $result->version );
		$this->assertSame( 'Release notes', $result->sections['changelog'] );
	}

	public function test_package_download_is_verified_against_manifest_checksum(): void {
		$tmp     = tempnam( sys_get_temp_dir(), 'wp-sam-update-' );
		$content = 'verified package';
		file_put_contents( $tmp, $content );

		$manifest                 = $this->manifest( '2.4.22' );
		$manifest['sha256']       = hash( 'sha256', $content );
		$package                  = $manifest['download_url'];
		$GLOBALS['_wp_remote_get_response']   = $this->response( $manifest );
		$GLOBALS['_wp_download_url_response'] = $tmp;

		$checker = new Github_Update_Checker();
		$result  = $checker->verify_package_download(
			false,
			$package,
			new stdClass(),
			array( 'plugin' => WP_SAM_PLUGIN_BASENAME )
		);

		$this->assertSame( $tmp, $result );
		$this->assertSame( $package, $GLOBALS['_wp_download_url_requests'][0]['url'] );

		if ( is_file( $tmp ) ) {
			unlink( $tmp );
		}
	}

	public function test_checksum_mismatch_returns_error_and_deletes_download(): void {
		$tmp = tempnam( sys_get_temp_dir(), 'wp-sam-update-' );
		file_put_contents( $tmp, 'tampered package' );

		$manifest                           = $this->manifest( '2.4.22' );
		$GLOBALS['_wp_remote_get_response'] = $this->response( $manifest );
		$GLOBALS['_wp_download_url_response'] = $tmp;

		$checker = new Github_Update_Checker();
		$result  = $checker->verify_package_download(
			false,
			$manifest['download_url'],
			new stdClass(),
			array( 'plugins' => array( WP_SAM_PLUGIN_BASENAME ) )
		);

		$this->assertInstanceOf( WP_Error::class, $result );
		$this->assertSame( 'wp_sam_update_checksum_mismatch', $result->get_error_code() );
		$this->assertContains( $tmp, $GLOBALS['_wp_deleted_files'] );
		$this->assertFileDoesNotExist( $tmp );
	}

	public function test_register_wires_native_update_hooks(): void {
		$checker = new Github_Update_Checker();

		$checker->register();

		$this->assertArrayHasKey( 'pre_set_site_transient_update_plugins', $GLOBALS['_wp_actions'] );
		$this->assertArrayHasKey( 'plugins_api', $GLOBALS['_wp_actions'] );
		$this->assertArrayHasKey( 'upgrader_pre_download', $GLOBALS['_wp_actions'] );
		$this->assertArrayHasKey( 'auto_update_plugin', $GLOBALS['_wp_actions'] );
	}

	public function test_auto_update_kill_switch_defers_when_constant_is_absent(): void {
		$checker = new Github_Update_Checker();
		$item    = (object) array( 'plugin' => WP_SAM_PLUGIN_BASENAME );

		$this->assertTrue( $checker->auto_update_gate( true, $item ) );
		$this->assertFalse( $checker->auto_update_gate( false, $item ) );
	}

	/**
	 * WP_SAM_DISABLE_AUTO_UPDATE is a raw global constant, and PHP constants
	 * can't be undefined once set -- defining it here would leak into every
	 * other test in the same process if run in-process. Isolated so this is
	 * the one test in the suite where the "kill switch engaged" branch is
	 * actually exercised, closing the gap the standard run left: only the
	 * constant-absent pass-through path was previously covered.
	 */
	#[RunInSeparateProcess]
	public function test_auto_update_kill_switch_blocks_when_constant_is_true(): void {
		define( 'WP_SAM_DISABLE_AUTO_UPDATE', true );

		$checker = new Github_Update_Checker();
		$item    = (object) array( 'plugin' => WP_SAM_PLUGIN_BASENAME );

		$this->assertFalse( $checker->auto_update_gate( true, $item ) );
		$this->assertFalse( $checker->auto_update_gate( false, $item ) );
	}

	// ── Update Channel diagnostics ───────────────────────────────────────────

	public function test_a_successful_check_records_diagnostics(): void {
		$GLOBALS['_wp_remote_get_response'] = $this->response( $this->manifest( '2.4.22' ) );

		( new Github_Update_Checker() )->get_remote_info();

		$diagnostics = get_option( Github_Update_Checker::DIAGNOSTICS_OPTION );
		$this->assertSame( 'success', $diagnostics['last_check_result'] );
		$this->assertSame( '2.4.22', $diagnostics['available_version'] );
		$this->assertNotEmpty( $diagnostics['last_check_success_at'] );
		$this->assertArrayNotHasKey( 'last_check_failure_at', $diagnostics );
	}

	public function test_invalid_manifest_records_failure_diagnostics(): void {
		$manifest                 = $this->manifest( '2.4.22' );
		$manifest['download_url'] = 'https://example.com/security-automation-manager.zip';
		$GLOBALS['_wp_remote_get_response'] = $this->response( $manifest );

		( new Github_Update_Checker() )->get_remote_info();

		$diagnostics = get_option( Github_Update_Checker::DIAGNOSTICS_OPTION );
		$this->assertSame( 'invalid_manifest', $diagnostics['last_check_result'] );
		$this->assertNotEmpty( $diagnostics['last_check_failure_at'] );
	}

	public function test_http_error_records_failure_diagnostics(): void {
		$GLOBALS['_wp_remote_get_response'] = array(
			'response' => array( 'code' => 500 ),
			'body'     => '',
		);

		( new Github_Update_Checker() )->get_remote_info();

		$diagnostics = get_option( Github_Update_Checker::DIAGNOSTICS_OPTION );
		$this->assertSame( 'http_error', $diagnostics['last_check_result'] );
		$this->assertNotEmpty( $diagnostics['last_check_failure_at'] );
	}

	public function test_verified_checksum_records_diagnostics(): void {
		$tmp     = tempnam( sys_get_temp_dir(), 'wp-sam-update-' );
		$content = 'verified package';
		file_put_contents( $tmp, $content );

		$manifest                             = $this->manifest( '2.4.22' );
		$manifest['sha256']                   = hash( 'sha256', $content );
		$GLOBALS['_wp_remote_get_response']   = $this->response( $manifest );
		$GLOBALS['_wp_download_url_response'] = $tmp;

		( new Github_Update_Checker() )->verify_package_download(
			false,
			$manifest['download_url'],
			new stdClass(),
			array( 'plugin' => WP_SAM_PLUGIN_BASENAME )
		);

		$diagnostics = get_option( Github_Update_Checker::DIAGNOSTICS_OPTION );
		$this->assertSame( 'verified', $diagnostics['last_checksum_result'] );
		$this->assertNotEmpty( $diagnostics['last_checksum_at'] );

		if ( is_file( $tmp ) ) {
			unlink( $tmp );
		}
	}

	public function test_checksum_mismatch_records_diagnostics(): void {
		$tmp = tempnam( sys_get_temp_dir(), 'wp-sam-update-' );
		file_put_contents( $tmp, 'tampered package' );

		$manifest                             = $this->manifest( '2.4.22' );
		$GLOBALS['_wp_remote_get_response']   = $this->response( $manifest );
		$GLOBALS['_wp_download_url_response'] = $tmp;

		( new Github_Update_Checker() )->verify_package_download(
			false,
			$manifest['download_url'],
			new stdClass(),
			array( 'plugins' => array( WP_SAM_PLUGIN_BASENAME ) )
		);

		$diagnostics = get_option( Github_Update_Checker::DIAGNOSTICS_OPTION );
		$this->assertSame( 'mismatch', $diagnostics['last_checksum_result'] );
	}

	public function test_after_update_records_a_successful_result(): void {
		$upgrader = (object) array(
			'result' => array( 'source' => '/tmp/x', 'destination' => '/tmp/y' ),
		);

		( new Github_Update_Checker() )->after_update(
			$upgrader,
			array(
				'type'    => 'plugin',
				'action'  => 'update',
				'plugins' => array( WP_SAM_PLUGIN_BASENAME ),
			)
		);

		$diagnostics = get_option( Github_Update_Checker::DIAGNOSTICS_OPTION );
		$this->assertSame( 'success', $diagnostics['last_applied_result'] );
		$this->assertNotEmpty( $diagnostics['last_applied_at'] );
	}

	public function test_after_update_records_failure_result_from_wp_error(): void {
		$upgrader = (object) array(
			'result' => new WP_Error( 'download_failed', 'Package download failed.' ),
		);

		( new Github_Update_Checker() )->after_update(
			$upgrader,
			array(
				'type'    => 'plugin',
				'action'  => 'update',
				'plugins' => array( WP_SAM_PLUGIN_BASENAME ),
			)
		);

		$diagnostics = get_option( Github_Update_Checker::DIAGNOSTICS_OPTION );
		$this->assertSame( 'failure', $diagnostics['last_applied_result'] );
	}

	public function test_after_update_ignores_unrelated_plugin_updates(): void {
		( new Github_Update_Checker() )->after_update(
			(object) array( 'result' => array() ),
			array(
				'type'    => 'plugin',
				'action'  => 'update',
				'plugins' => array( 'some-other-plugin/some-other-plugin.php' ),
			)
		);

		$this->assertFalse( get_option( Github_Update_Checker::DIAGNOSTICS_OPTION ) );
	}

	private function response( array $manifest ): array {
		return array(
			'response' => array( 'code' => 200 ),
			'body'     => (string) wp_json_encode( $manifest ),
		);
	}

	private function manifest( string $version ): array {
		return array(
			'name'            => 'CSP Automation Manager',
			'slug'            => 'security-automation-manager',
			'version'         => $version,
			'author'          => 'VCNS Tech Ltd',
			'author_homepage' => 'https://vcns.tech',
			'requires'        => '6.4',
			'tested'          => '7.0',
			'requires_php'    => '8.1',
			'download_url'    => 'https://vcns.github.io/wp-updates/security-automation-manager/security-automation-manager-github-v' . $version . '.zip',
			'sha256'          => str_repeat( 'a', 64 ),
			'last_updated'    => '2026-08-04',
			'homepage'        => 'https://github.com/vcns/security-automation-manager',
			'sections'        => array(
				'description' => 'Description',
				'changelog'   => 'Release notes',
			),
		);
	}
}
