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

	// ── is_sealed_but_undecryptable(): vault failure visibility ──────────────

	public function test_never_configured_is_not_flagged_as_undecryptable(): void {
		$this->assertFalse( Credential_Vault::is_sealed_but_undecryptable( '' ) );
	}

	public function test_plaintext_is_not_flagged_as_undecryptable(): void {
		// Not sealed at all -- a different condition (not-yet-migrated data, or
		// a settings-form bug), out of scope for "the vault key changed".
		$this->assertFalse( Credential_Vault::is_sealed_but_undecryptable( 'raw-plaintext-value' ) );
	}

	public function test_a_healthy_sealed_value_is_not_flagged(): void {
		$this->assertFalse( Credential_Vault::is_sealed_but_undecryptable( Credential_Vault::seal( 'secret' ) ) );
	}

	public function test_tampered_ciphertext_is_flagged_as_undecryptable(): void {
		$sealed   = Credential_Vault::seal( 'secret-value' );
		$position = strlen( $sealed ) - 2;
		$tampered = $sealed;
		$tampered[ $position ] = 'A' === $tampered[ $position ] ? 'B' : 'A';

		$this->assertTrue( Credential_Vault::is_sealed_but_undecryptable( $tampered ) );
	}

	public function test_wrong_key_is_flagged_as_undecryptable(): void {
		// A "wrong key" and "tampered ciphertext" fail authentication through
		// the exact same sodium_crypto_secretbox_open() code path -- see
		// docs/credential-vault-assessment.md, "Existing ciphertext
		// compatibility": there is no way to distinguish them from open()'s
		// perspective, so a value sealed under a key that's no longer
		// reproducible is faithfully simulated by tampering the ciphertext
		// sealed under the *current* key, without needing to actually rotate
		// WP_SAM_CERT_VAULT_KEY or wp_salt('auth') mid-test.
		$sealed_under_a_key_that_no_longer_exists = Credential_Vault::seal( 'secret' ) . 'x';

		$this->assertTrue( Credential_Vault::is_sealed_but_undecryptable( $sealed_under_a_key_that_no_longer_exists ) );
	}
}
