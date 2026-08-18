<?php
/**
 * Unit tests for WP_SAM\Config_Portability's allowlist enforcement: import
 * never writes a table or option outside PORTABLE_TABLE_SUFFIXES /
 * PORTABLE_OPTIONS, and certificate secrets are never read from or written
 * by an uploaded export regardless of what the file contains.
 *
 * What this file deliberately does NOT test: a real export/import round-trip
 * against real table rows. test/bootstrap.php's wpdb stub is a
 * pre-programmed response queue, not an in-memory database.
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;
use WP_SAM\Certificates\Certificate_Store;
use WP_SAM\Config_Portability;
use WP_SAM\Modules\Audit_Log;

class ConfigPortabilityTest extends TestCase {

	private Config_Portability $portability;

	protected function setUp(): void {
		wp_test_reset_globals();
		$this->portability = new Config_Portability( new Audit_Log() );
	}

	public function test_validate_rejects_a_non_array_payload(): void {
		$result = $this->portability->validate( 'not an array' );

		$this->assertFalse( $result['ok'] );
		$this->assertArrayHasKey( 'reason', $result );
	}

	public function test_validate_rejects_an_unrecognised_format_version(): void {
		$result = $this->portability->validate(
			array(
				'format_version' => 2,
				'tables'         => array(),
			)
		);

		$this->assertFalse( $result['ok'] );
	}

	public function test_validate_rejects_a_payload_with_no_tables_key(): void {
		$result = $this->portability->validate(
			array( 'format_version' => Config_Portability::FORMAT_VERSION )
		);

		$this->assertFalse( $result['ok'] );
	}

	public function test_validate_accepts_a_well_formed_payload_and_summarises_it(): void {
		$result = $this->portability->validate(
			array(
				'format_version' => Config_Portability::FORMAT_VERSION,
				'options'        => array( 'wp_sam_cron_hour' => 3 ),
				'tables'         => array(
					'csp_policy_profiles' => array(
						array( 'surface' => 'frontend', 'mode' => 'report-only' ),
					),
				),
			)
		);

		$this->assertTrue( $result['ok'] );
		$this->assertSame( 1, $result['summary']['tables'] );
		$this->assertSame( 1, $result['summary']['rows'] );
		$this->assertSame( 1, $result['summary']['options'] );
	}

	public function test_apply_only_imports_tables_on_the_allowlist(): void {
		// table_exists() is only ever consulted for a suffix already on
		// PORTABLE_TABLE_SUFFIXES -- a suffix from an untrusted file that
		// isn't on that list is never even looked up, let alone written.
		$GLOBALS['_wpdb_get_var_queue'] = array( $GLOBALS['wpdb']->prefix . 'csp_policy_profiles' );

		$result = $this->portability->apply(
			array(
				'tables' => array(
					'csp_policy_profiles' => array( array( 'surface' => 'frontend', 'mode' => 'report-only' ) ),
					// Not on PORTABLE_TABLE_SUFFIXES -- must never be touched,
					// even though it is a real table this plugin owns.
					'sam_certificates'     => array( array( 'domain' => 'example.com' ) ),
				),
			)
		);

		$this->assertSame( array( 'csp_policy_profiles' ), $result['tables_imported'] );
		foreach ( $GLOBALS['_wpdb_queries'] ?? array() as $query ) {
			$this->assertStringNotContainsString( 'sam_certificates', $query );
		}
		foreach ( $GLOBALS['_wpdb_inserted_rows'] ?? array() as $row ) {
			$this->assertStringNotContainsString( 'sam_certificates', $row['table'] );
		}
	}

	public function test_apply_only_imports_options_on_the_allowlist(): void {
		$this->portability->apply(
			array(
				'tables'  => array(),
				'options' => array(
					'wp_sam_cron_hour' => 5,
					// Not on PORTABLE_OPTIONS -- code-tied, must never be
					// overwritten by an uploaded file from another site.
					'wp_sam_db_version' => 999,
				),
			)
		);

		$this->assertSame( 5, get_option( 'wp_sam_cron_hour' ) );
		$this->assertFalse( isset( $GLOBALS['_wp_options']['wp_sam_db_version'] ) );
	}

	public function test_apply_reports_which_options_were_actually_imported(): void {
		$result = $this->portability->apply(
			array(
				'tables'  => array(),
				'options' => array(
					'wp_sam_cron_hour'  => 5,
					'wp_sam_db_version' => 999,
				),
			)
		);

		$this->assertSame( array( 'wp_sam_cron_hour' ), $result['options_imported'] );
	}

	public function test_export_never_includes_certificate_secret_fields(): void {
		( new Certificate_Store() )->save_config(
			array(
				'domains'         => array( 'example.com' ),
				'provider'        => 'cloudflare',
				'cpanel_token'    => 'cpanel-secret',
				'dns_credentials' => array( 'api_token' => 'cf-secret' ),
			)
		);

		$export = $this->portability->export();

		$this->assertArrayNotHasKey( 'cpanel_token', $export['cert_config'] );
		$this->assertArrayNotHasKey( 'dns_credentials', $export['cert_config'] );
		$this->assertArrayNotHasKey( 'custom_key_pem', $export['cert_config'] );
		$this->assertSame( array( 'example.com' ), $export['cert_config']['domains'] );
	}

	public function test_apply_cert_config_never_writes_secret_fields_from_an_imported_file(): void {
		( new Certificate_Store() )->save_config(
			array(
				'domains'         => array( 'original.example' ),
				'provider'        => 'cloudflare',
				'cpanel_token'    => 'original-token',
				'dns_credentials' => array( 'api_token' => 'original-cred' ),
			)
		);

		// A hand-edited or malicious import file that includes secret
		// fields anyway -- apply() must strip them before they ever reach
		// Certificate_Store::save_config().
		$this->portability->apply(
			array(
				'tables'      => array(),
				'cert_config' => array(
					'domains'         => array( 'attacker.example' ),
					'cpanel_token'    => 'attacker-supplied-token',
					'dns_credentials' => array( 'api_token' => 'attacker-supplied-cred' ),
				),
			)
		);

		$config = ( new Certificate_Store() )->get_config();
		$this->assertSame( array( 'attacker.example' ), $config['domains'], 'Non-secret fields are still imported.' );
		$this->assertSame( 'original-token', $config['cpanel_token'], 'Secret fields must survive an import untouched.' );
		$this->assertSame( 'original-cred', $config['dns_credentials']['api_token'], 'Secret fields must survive an import untouched.' );
	}
}
