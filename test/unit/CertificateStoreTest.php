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

	public function test_custom_key_is_sealed_kept_on_blank_and_cleared_on_null(): void {
		$pem = "-----BEGIN PRIVATE KEY-----\nfakekeymaterial\n-----END PRIVATE KEY-----";

		$this->store->save_config( array( 'custom_key_pem' => $pem ) );

		$raw = $GLOBALS['_wp_options'][ Certificate_Store::CONFIG_OPTION ];
		$this->assertStringNotContainsString( 'fakekeymaterial', (string) wp_json_encode( $raw ) );
		$this->assertSame( $pem, $this->store->get_config()['custom_key_pem'] );

		// Blank submission keeps the stored key.
		$this->store->save_config( array( 'custom_key_pem' => '' ) );
		$this->assertSame( $pem, $this->store->get_config()['custom_key_pem'] );

		// null is the explicit clear sentinel.
		$this->store->save_config( array( 'custom_key_pem' => null ) );
		$this->assertSame( '', $this->store->get_config()['custom_key_pem'] );
	}

	public function test_environments_get_distinct_account_keys(): void {
		$this->assertNotSame(
			$this->store->get_account( 'staging' )['key_pem'],
			$this->store->get_account( 'production' )['key_pem']
		);
	}

	// ── renewal_due(): the actual home of the "30-day renewal threshold"
	// family of scenarios (Renewal_Scheduler itself only wires cron hooks;
	// RenewalSchedulerTest.php covers that separately). ─────────────────────

	public function test_renewal_is_due_when_no_certificate_has_ever_been_issued(): void {
		$GLOBALS['_wpdb_get_row'] = null;

		$this->assertTrue( $this->store->renewal_due() );
	}

	public function test_renewal_is_not_due_when_comfortably_outside_the_window(): void {
		$GLOBALS['_wpdb_get_row'] = $this->fake_certificate_row( time() + ( 60 * DAY_IN_SECONDS ) );

		$this->assertFalse( $this->store->renewal_due() );
	}

	public function test_renewal_is_due_at_the_threshold_boundary(): void {
		// 29 days out: inside the default 30-day window.
		$GLOBALS['_wpdb_get_row'] = $this->fake_certificate_row( time() + ( 29 * DAY_IN_SECONDS ) );

		$this->assertTrue( $this->store->renewal_due() );
	}

	public function test_renewal_is_not_due_just_outside_the_threshold_boundary(): void {
		// 31 days out: outside the default 30-day window.
		$GLOBALS['_wpdb_get_row'] = $this->fake_certificate_row( time() + ( 31 * DAY_IN_SECONDS ) );

		$this->assertFalse( $this->store->renewal_due() );
	}

	public function test_renewal_is_due_for_an_already_expired_certificate(): void {
		$GLOBALS['_wpdb_get_row'] = $this->fake_certificate_row( time() - DAY_IN_SECONDS );

		$this->assertTrue( $this->store->renewal_due() );
	}

	public function test_renewal_is_due_when_the_expiry_date_is_missing(): void {
		$row = $this->fake_certificate_row( time() + ( 60 * DAY_IN_SECONDS ) );
		$row['not_after'] = null;
		$GLOBALS['_wpdb_get_row'] = $row;

		$this->assertTrue( $this->store->renewal_due() );
	}

	public function test_renewal_is_due_when_the_expiry_date_is_malformed(): void {
		$row = $this->fake_certificate_row( time() + ( 60 * DAY_IN_SECONDS ) );
		$row['not_after'] = 'not-a-date-at-all';
		$GLOBALS['_wpdb_get_row'] = $row;

		// strtotime('not-a-date-at-all UTC') returns false; false - time() is
		// a large negative number, which is always < the window -- malformed
		// data fails toward "renew", not toward silently never renewing.
		$this->assertTrue( $this->store->renewal_due() );
	}

	public function test_renewal_window_is_configurable(): void {
		$GLOBALS['_wpdb_get_row'] = $this->fake_certificate_row( time() + ( 45 * DAY_IN_SECONDS ) );

		$this->assertFalse( $this->store->renewal_due( 30 ) );
		$this->assertTrue( $this->store->renewal_due( 60 ) );
	}

	// ── vault_health_warnings(): failure visibility, not silent data loss ────

	public function test_no_warnings_when_nothing_is_configured(): void {
		$this->assertSame( array(), $this->store->vault_health_warnings() );
	}

	public function test_no_warnings_when_secrets_are_healthy(): void {
		$this->store->save_config(
			array(
				'cpanel_token'    => 'a-real-token',
				'dns_credentials' => array( 'api_token' => 'a-real-cred' ),
			)
		);

		$this->assertSame( array(), $this->store->vault_health_warnings() );
	}

	public function test_flags_an_undecryptable_cpanel_token_without_exposing_it(): void {
		$stored                  = $GLOBALS['_wp_options'];
		$stored[ Certificate_Store::CONFIG_OPTION ] = array(
			'cpanel_token'    => Credential_Vault::seal( 'x' ) . 'corrupted',
			'dns_credentials' => array(),
			'custom_key_pem'  => '',
		);
		$GLOBALS['_wp_options'] = $stored;

		$warnings = $this->store->vault_health_warnings();

		$this->assertCount( 1, $warnings );
		$this->assertStringContainsString( 'cPanel', $warnings[0] );
		$this->assertStringNotContainsString( 'sam-v1:', implode( ' ', $warnings ), 'a warning must never contain raw ciphertext' );
	}

	public function test_flags_an_undecryptable_dns_credential_by_field_name_only(): void {
		$GLOBALS['_wp_options'][ Certificate_Store::CONFIG_OPTION ] = array(
			'cpanel_token'    => '',
			'custom_key_pem'  => '',
			'dns_credentials' => array( 'api_token' => Credential_Vault::seal( 'x' ) . 'corrupted' ),
		);

		$warnings = $this->store->vault_health_warnings();

		$this->assertCount( 1, $warnings );
		$this->assertStringContainsString( 'api_token', $warnings[0] );
	}

	public function test_flags_an_undecryptable_account_key(): void {
		$GLOBALS['_wp_options'][ Certificate_Store::ACCOUNT_KEY_OPTION ] = array(
			'staging' => array( 'key_pem' => Credential_Vault::seal( 'x' ) . 'corrupted', 'kid' => '' ),
		);

		$warnings = $this->store->vault_health_warnings();

		$this->assertCount( 1, $warnings );
		$this->assertStringContainsString( 'staging', $warnings[0] );
	}

	public function test_flags_an_undecryptable_issued_certificate_key(): void {
		$GLOBALS['_wpdb_get_results'] = array(
			array( 'environment' => 'production', 'key_pem' => Credential_Vault::seal( 'x' ) . 'corrupted' ),
		);

		$warnings = $this->store->vault_health_warnings();

		$this->assertCount( 1, $warnings );
		$this->assertStringContainsString( 'production', $warnings[0] );
	}

	public function test_a_field_that_was_never_configured_is_not_flagged(): void {
		// Empty string ('' -- open()'s own "never configured" return) must not
		// be conflated with sealed-but-undecryptable.
		$GLOBALS['_wp_options'][ Certificate_Store::CONFIG_OPTION ] = array(
			'cpanel_token'    => '',
			'custom_key_pem'  => '',
			'dns_credentials' => array( 'api_token' => '' ),
		);

		$this->assertSame( array(), $this->store->vault_health_warnings() );
	}

	public function test_vault_health_warnings_does_not_modify_stored_data(): void {
		$corrupted = Credential_Vault::seal( 'x' ) . 'corrupted';
		$GLOBALS['_wp_options'][ Certificate_Store::CONFIG_OPTION ] = array(
			'cpanel_token'    => $corrupted,
			'custom_key_pem'  => '',
			'dns_credentials' => array(),
		);

		$this->store->vault_health_warnings();

		$this->assertSame( $corrupted, $GLOBALS['_wp_options'][ Certificate_Store::CONFIG_OPTION ]['cpanel_token'], 'a read-only diagnostic must never re-seal, clear, or otherwise touch the stored value' );
	}

	private function fake_certificate_row( int $not_after_timestamp ): array {
		return array(
			'id'            => 1,
			'domains'       => (string) wp_json_encode( array( 'example.com' ) ),
			'environment'   => 'production',
			'key_pem'       => '',
			'fullchain_pem' => 'irrelevant-to-renewal_due',
			'not_before'    => gmdate( 'Y-m-d H:i:s', time() - DAY_IN_SECONDS ),
			'not_after'     => gmdate( 'Y-m-d H:i:s', $not_after_timestamp ),
		);
	}
}
