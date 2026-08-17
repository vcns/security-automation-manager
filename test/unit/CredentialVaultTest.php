<?php
/**
 * Unit tests for WP_SAM\Certificates\Credential_Vault.
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;
use WP_SAM\Certificates\Credential_Vault;

class CredentialVaultTest extends TestCase {

	public function test_seal_open_roundtrip(): void {
		$secret = 'cf_token_' . bin2hex( random_bytes( 8 ) );

		$sealed = Credential_Vault::seal( $secret );

		$this->assertNotSame( $secret, $sealed );
		$this->assertStringNotContainsString( $secret, $sealed );
		$this->assertSame( $secret, Credential_Vault::open( $sealed ) );
	}

	public function test_empty_string_round_trips_as_empty(): void {
		$this->assertSame( '', Credential_Vault::seal( '' ) );
		$this->assertSame( '', Credential_Vault::open( '' ) );
	}

	public function test_tampered_ciphertext_fails_closed(): void {
		$sealed = Credential_Vault::seal( 'secret-value' );

		// Flip one character inside the base64 body.
		$position            = strlen( $sealed ) - 2;
		$tampered            = $sealed;
		$tampered[ $position ] = 'A' === $tampered[ $position ] ? 'B' : 'A';

		$this->assertNull( Credential_Vault::open( $tampered ) );
	}

	public function test_plaintext_is_not_treated_as_sealed(): void {
		$this->assertNull( Credential_Vault::open( 'raw-plaintext-token' ) );
		$this->assertFalse( Credential_Vault::is_sealed( 'raw-plaintext-token' ) );
		$this->assertTrue( Credential_Vault::is_sealed( Credential_Vault::seal( 'x' ) ) );
	}

	public function test_two_seals_of_same_value_differ(): void {
		// Random nonce per seal: identical secrets must not produce identical
		// ciphertexts (no equality oracle in the database).
		$this->assertNotSame( Credential_Vault::seal( 'same' ), Credential_Vault::seal( 'same' ) );
	}
}
