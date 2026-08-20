<?php
/**
 * Unit tests for WP_SAM\Certificates\Deployer.
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;
use WP_SAM\Modules\Audit_Log;
use WP_SAM\Certificates\Deployer;

class DeployerTest extends TestCase {

	private Deployer $deployer;
	private string $fullchain;
	private array $export_dirs = array();

	protected function setUp(): void {
		wp_test_reset_globals();
		$this->deployer = new Deployer( new Audit_Log() );
		$this->fullchain = "-----BEGIN CERTIFICATE-----\nleafcertdata\n-----END CERTIFICATE-----\n"
			. "-----BEGIN CERTIFICATE-----\nintermediatecertdata\n-----END CERTIFICATE-----\n";
	}

	protected function tearDown(): void {
		foreach ( $this->export_dirs as $dir ) {
			foreach ( array( $dir . '/privkey.pem', $dir . '/fullchain.pem' ) as $f ) {
				if ( is_file( $f ) ) {
					unlink( $f );
				}
			}
			if ( is_dir( $dir ) ) {
				rmdir( $dir );
			}
		}
	}

	private function fresh_export_dir(): string {
		$dir = sys_get_temp_dir() . '/wp-sam-deployer-test-' . bin2hex( random_bytes( 6 ) );
		$this->export_dirs[] = $dir;
		return $dir;
	}

	private function base_config( array $overrides = array() ): array {
		return array_merge(
			array(
				'deployment'   => 'download',
				'export_path'  => '',
				'cpanel_host'  => '',
				'cpanel_user'  => '',
				'cpanel_token' => '',
			),
			$overrides
		);
	}

	// ── Manual-download behaviour ──────────────────────────────────────────────

	public function test_download_mode_is_a_silent_no_op(): void {
		$this->deployer->deploy( $this->base_config( array( 'deployment' => 'download' ) ), 'example.com', 'key-pem', $this->fullchain );

		$this->assertEmpty( $GLOBALS['_wp_remote_post_requests'] );
		$this->assertEmpty( $GLOBALS['_wp_deleted_files'] );
	}

	public function test_unknown_deployment_mode_is_also_a_silent_no_op(): void {
		$this->deployer->deploy( $this->base_config( array( 'deployment' => 'something-unrecognised' ) ), 'example.com', 'key-pem', $this->fullchain );

		$this->assertEmpty( $GLOBALS['_wp_remote_post_requests'] );
	}

	// ── cPanel UAPI request construction ───────────────────────────────────────

	public function test_cpanel_deployment_constructs_the_expected_request(): void {
		$GLOBALS['_wp_remote_post_response'] = array(
			'response' => array( 'code' => 200 ),
			'body'     => (string) wp_json_encode( array( 'status' => 1 ) ),
		);

		$this->deployer->deploy(
			$this->base_config(
				array(
					'deployment'   => 'cpanel',
					'cpanel_host'  => 'host.example.com',
					'cpanel_user'  => 'exampleuser',
					'cpanel_token' => 'secret-token',
				)
			),
			'example.com',
			'-----BEGIN PRIVATE KEY-----keydata-----END PRIVATE KEY-----',
			$this->fullchain
		);

		$this->assertCount( 1, $GLOBALS['_wp_remote_post_requests'] );
		$request = $GLOBALS['_wp_remote_post_requests'][0];

		$this->assertSame( 'https://host.example.com:2083/execute/SSL/install_ssl', $request['url'], 'default cPanel port 2083 must be appended when the host has none' );
		$this->assertSame( 'cpanel exampleuser:secret-token', $request['args']['headers']['Authorization'] );
		$this->assertSame( 'example.com', $request['args']['body']['domain'] );
		$this->assertStringContainsString( 'leafcertdata', $request['args']['body']['cert'] );
		$this->assertStringNotContainsString( 'leafcertdata', $request['args']['body']['cabundle'], 'the leaf certificate must go in cert, not cabundle' );
		$this->assertStringContainsString( 'intermediatecertdata', $request['args']['body']['cabundle'] );
		$this->assertSame( '-----BEGIN PRIVATE KEY-----keydata-----END PRIVATE KEY-----', $request['args']['body']['key'] );
	}

	public function test_cpanel_deployment_preserves_an_explicit_port(): void {
		$GLOBALS['_wp_remote_post_response'] = array(
			'response' => array( 'code' => 200 ),
			'body'     => (string) wp_json_encode( array( 'status' => 1 ) ),
		);

		$this->deployer->deploy(
			$this->base_config(
				array(
					'deployment'   => 'cpanel',
					'cpanel_host'  => 'host.example.com:8443',
					'cpanel_user'  => 'u',
					'cpanel_token' => 't',
				)
			),
			'example.com',
			'key',
			$this->fullchain
		);

		$this->assertSame( 'https://host.example.com:8443/execute/SSL/install_ssl', $GLOBALS['_wp_remote_post_requests'][0]['url'] );
	}

	public function test_cpanel_deployment_logs_success_to_the_audit_log(): void {
		$GLOBALS['_wp_remote_post_response'] = array(
			'response' => array( 'code' => 200 ),
			'body'     => (string) wp_json_encode( array( 'status' => 1 ) ),
		);
		$GLOBALS['_wpdb_get_var'] = $GLOBALS['wpdb']->prefix . 'sam_audit_log'; // table_exists() guard in Audit_Log::write_to_db().

		$this->deployer->deploy(
			$this->base_config( array( 'deployment' => 'cpanel', 'cpanel_host' => 'h', 'cpanel_user' => 'u', 'cpanel_token' => 't' ) ),
			'example.com',
			'key',
			$this->fullchain
		);

		$logged = array_filter(
			$GLOBALS['_wpdb_inserted_rows'],
			static fn( array $row ): bool => str_contains( $row['table'], 'sam_audit_log' )
		);
		$this->assertNotEmpty( $logged, 'Audit_Log writes via $wpdb->insert' );
		$this->assertSame( 'cert_deployed', array_values( $logged )[0]['data']['event'] );
	}

	// ── Authentication failure ─────────────────────────────────────────────────

	public function test_cpanel_deployment_with_missing_credentials_throws_before_any_request(): void {
		$this->expectException( RuntimeException::class );
		$this->expectExceptionMessage( 'host, user, or API token is missing' );

		try {
			$this->deployer->deploy(
				$this->base_config( array( 'deployment' => 'cpanel', 'cpanel_host' => '', 'cpanel_user' => 'u', 'cpanel_token' => 't' ) ),
				'example.com',
				'key',
				$this->fullchain
			);
		} finally {
			$this->assertEmpty( $GLOBALS['_wp_remote_post_requests'], 'no HTTP request should be attempted when credentials are incomplete' );
		}
	}

	public function test_cpanel_transport_error_throws(): void {
		$GLOBALS['_wp_remote_post_response'] = new WP_Error( 'http_request_failed', 'Connection refused' );

		$this->expectException( RuntimeException::class );
		$this->expectExceptionMessage( 'transport error' );

		$this->deployer->deploy(
			$this->base_config( array( 'deployment' => 'cpanel', 'cpanel_host' => 'h', 'cpanel_user' => 'u', 'cpanel_token' => 't' ) ),
			'example.com',
			'key',
			$this->fullchain
		);
	}

	public function test_cpanel_deployment_failure_response_is_surfaced(): void {
		$GLOBALS['_wp_remote_post_response'] = array(
			'response' => array( 'code' => 200 ),
			'body'     => (string) wp_json_encode( array( 'status' => 0, 'errors' => array( 'Invalid API token' ) ) ),
		);

		$this->expectException( RuntimeException::class );
		$this->expectExceptionMessage( 'Invalid API token' );

		$this->deployer->deploy(
			$this->base_config( array( 'deployment' => 'cpanel', 'cpanel_host' => 'h', 'cpanel_user' => 'u', 'cpanel_token' => 't' ) ),
			'example.com',
			'key',
			$this->fullchain
		);
	}

	public function test_cpanel_deployment_with_no_certificate_blocks_in_fullchain_throws(): void {
		$this->expectException( RuntimeException::class );
		$this->expectExceptionMessage( 'no certificate blocks' );

		$this->deployer->deploy(
			$this->base_config( array( 'deployment' => 'cpanel', 'cpanel_host' => 'h', 'cpanel_user' => 'u', 'cpanel_token' => 't' ) ),
			'example.com',
			'key',
			'not a pem at all'
		);
	}

	// ── Export directory: webroot traversal rejection ──────────────────────────

	public function test_export_inside_the_webroot_is_rejected(): void {
		// ABSPATH in the test environment is test/bootstrap.php's own directory;
		// test/unit/ genuinely exists beneath it.
		$inside = rtrim( ABSPATH, '/' ) . '/unit';

		$this->expectException( RuntimeException::class );
		$this->expectExceptionMessage( 'OUTSIDE the web root' );

		$this->deployer->deploy(
			$this->base_config( array( 'deployment' => 'export', 'export_path' => $inside ) ),
			'example.com',
			'keydata',
			$this->fullchain
		);
	}

	public function test_export_path_equal_to_the_webroot_itself_is_rejected(): void {
		$this->expectException( RuntimeException::class );
		$this->expectExceptionMessage( 'OUTSIDE the web root' );

		$this->deployer->deploy(
			$this->base_config( array( 'deployment' => 'export', 'export_path' => rtrim( ABSPATH, '/' ) ) ),
			'example.com',
			'keydata',
			$this->fullchain
		);
	}

	// ── Export directory: permitted deployment ──────────────────────────────────

	public function test_export_outside_the_webroot_writes_both_pem_files(): void {
		$dir = $this->fresh_export_dir();

		$this->deployer->deploy(
			$this->base_config( array( 'deployment' => 'export', 'export_path' => $dir ) ),
			'example.com',
			'the-private-key',
			$this->fullchain
		);

		$this->assertFileExists( $dir . '/privkey.pem' );
		$this->assertFileExists( $dir . '/fullchain.pem' );
		$this->assertSame( 'the-private-key', file_get_contents( $dir . '/privkey.pem' ) );
		$this->assertSame( $this->fullchain, file_get_contents( $dir . '/fullchain.pem' ) );
	}

	public function test_export_creates_the_directory_when_missing(): void {
		$dir = $this->fresh_export_dir();
		$this->assertDirectoryDoesNotExist( $dir );

		$this->deployer->deploy(
			$this->base_config( array( 'deployment' => 'export', 'export_path' => $dir ) ),
			'example.com',
			'key',
			$this->fullchain
		);

		$this->assertDirectoryExists( $dir );
	}

	// ── Partial deployment failure ───────────────────────────────────────────────

	public function test_export_with_no_configured_path_throws_before_writing_anything(): void {
		$this->expectException( RuntimeException::class );
		$this->expectExceptionMessage( 'no export path is configured' );

		$this->deployer->deploy(
			$this->base_config( array( 'deployment' => 'export', 'export_path' => '' ) ),
			'example.com',
			'key',
			$this->fullchain
		);
	}

	public function test_export_directory_creation_failure_throws_and_writes_nothing(): void {
		// A file, not a directory, already occupies the target path -- is_dir()
		// is false and wp_mkdir_p() genuinely cannot create a directory there,
		// reproducing a real "path exists but isn't usable" deployment failure
		// without relying on platform-specific permission semantics.
		$blocking_file = sys_get_temp_dir() . '/wp-sam-deployer-blocking-' . bin2hex( random_bytes( 6 ) );
		file_put_contents( $blocking_file, 'x' );

		try {
			$this->expectException( RuntimeException::class );
			$this->expectExceptionMessage( 'does not exist and could not be created' );

			$this->deployer->deploy(
				$this->base_config( array( 'deployment' => 'export', 'export_path' => $blocking_file ) ),
				'example.com',
				'key',
				$this->fullchain
			);
		} finally {
			unlink( $blocking_file );
		}
	}
}
