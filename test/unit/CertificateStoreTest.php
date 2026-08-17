<?php
/**
 * Unit tests for WP_SAM\Certificates\Certificate_Store configuration
 * persistence: secrets must be sealed at rest, empty submissions must keep
 * stored secrets, and account keys must round-trip.
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;
use WP_SAM\Certificates\Certificate_Store;
use WP_SAM\Certificates\Credential_Vault;

class CertificateStoreTest extends TestCase {

	private Certificate_Store $store;

	protected function setUp(): void {
		wp_test_reset_globals();
		$this->store = new Certificate_Store();
	}

	public function test_secrets_are_sealed_at_rest_and_unsealed_on_read(): void {
		$this->store->save_config(
			array(
				'domains'         => array( 'example.com' ),
				'provider'        => 'cloudflare',
				'cpanel_token'    => 'cpanel-secret',
				'dns_credentials' => array( 'api_token' => 'cf-secret' ),
			)
		);

		$raw = $GLOBALS['_wp_options'][ Certificate_Store::CONFIG_OPTION ];
		$this->assertStringNotContainsString( 'cf-secret', (string) wp_json_encode( $raw ) );
		$this->assertStringNotContainsString( 'cpanel-secret', (string) wp_json_encode( $raw ) );
		$this->assertTrue( Credential_Vault::is_sealed( (string) $raw['dns_credentials']['api_token'] ) );

		$config = $this->store->get_config();
		$this->assertSame( 'cf-secret', $config['dns_credentials']['api_token'] );
		$this->assertSame( 'cpanel-secret', $config['cpanel_token'] );
	}

	public function test_blank_secret_submission_keeps_stored_value(): void {
		$this->store->save_config(
			array(
				'cpanel_token'    => 'original-token',
				'dns_credentials' => array( 'api_token' => 'original-cred' ),
			)
		);

		// A settings form re-submission with untouched password fields.
		$this->store->save_config(
			array(
				'cpanel_token'    => '',
				'dns_credentials' => array( 'api_token' => '' ),
			)
		);

		$config = $this->store->get_config();
		$this->assertSame( 'original-token', $config['cpanel_token'] );
		$this->assertSame( 'original-cred', $config['dns_credentials']['api_token'] );
	}

	public function test_account_key_is_created_once_and_persists(): void {
		$first  = $this->store->get_account( 'staging' );
		$second = $this->store->get_account( 'staging' );

		$this->assertSame( $first['key_pem'], $second['key_pem'] );
		$this->assertStringContainsString( 'PRIVATE KEY', $first['key_pem'] );

		// Stored form must be sealed, never plaintext PEM.
		$raw = $GLOBALS['_wp_options'][ Certificate_Store::ACCOUNT_KEY_OPTION ];
		$this->assertStringNotContainsString( 'PRIVATE KEY', (string) $raw['staging']['key_pem'] );

		$this->store->save_account_kid( 'staging', 'https://acme/acct/123' );
		$this->assertSame( 'https://acme/acct/123', $this->store->get_account( 'staging' )['kid'] );
	}

	public function test_environments_get_distinct_account_keys(): void {
		$this->assertNotSame(
			$this->store->get_account( 'staging' )['key_pem'],
			$this->store->get_account( 'production' )['key_pem']
		);
	}
}
