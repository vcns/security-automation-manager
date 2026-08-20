<?php
/**
 * Encryption at rest for certificate-module secrets.
 *
 * DNS API tokens are domain-takeover-grade credentials and private keys are
 * the certificate itself, so neither is ever stored as plaintext in the
 * database. Values are sealed with sodium's XSalsa20-Poly1305 secretbox.
 *
 * Key derivation: WP_SAM_CERT_VAULT_KEY (a wp-config.php constant) when
 * defined -- recommended, because it keeps the key out of the database and
 * out of DB dumps entirely -- otherwise a key derived from wp_salt('auth').
 * The derived fallback still defeats a database-only leak; the constant also
 * defeats a full-files+database leak of a *backup* taken before the constant
 * was rotated.
 */

declare( strict_types=1 );

namespace WP_SAM\Certificates;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Credential_Vault {

	private const PREFIX = 'sam-v1:';

	/**
	 * Encrypts a plaintext secret, returning an opaque printable string.
	 */
	public static function seal( string $plaintext ): string {
		if ( '' === $plaintext ) {
			return '';
		}

		$nonce  = random_bytes( SODIUM_CRYPTO_SECRETBOX_NONCEBYTES );
		$cipher = sodium_crypto_secretbox( $plaintext, $nonce, self::key() );

		return self::PREFIX . base64_encode( $nonce . $cipher );
	}

	/**
	 * Decrypts a sealed value. Returns null when the value is malformed or
	 * fails authentication (wrong key, tampered ciphertext).
	 */
	public static function open( string $sealed ): ?string {
		if ( '' === $sealed ) {
			return '';
		}
		if ( ! str_starts_with( $sealed, self::PREFIX ) ) {
			return null;
		}

		$raw = base64_decode( substr( $sealed, strlen( self::PREFIX ) ), true );
		if ( false === $raw || strlen( $raw ) <= SODIUM_CRYPTO_SECRETBOX_NONCEBYTES ) {
			return null;
		}

		$nonce  = substr( $raw, 0, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES );
		$cipher = substr( $raw, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES );

		$plain = sodium_crypto_secretbox_open( $cipher, $nonce, self::key() );

		return false === $plain ? null : $plain;
	}

	/**
	 * True when a value looks like output of seal() (used by settings forms to
	 * distinguish "unchanged, already-sealed" from "newly pasted plaintext").
	 */
	public static function is_sealed( string $value ): bool {
		return str_starts_with( $value, self::PREFIX );
	}

	/**
	 * True when a value is sealed ciphertext that fails to decrypt under the
	 * current vault key -- distinct from "never configured" (empty string)
	 * and from "plaintext, not sealed at all". Every existing call site
	 * coerces open()'s null return to '', which loses this distinction before
	 * it reaches the admin UI (see docs/credential-vault-assessment.md,
	 * "Recovery behaviour"); this lets a caller check for it explicitly
	 * without changing what open() itself returns or how it fails.
	 */
	public static function is_sealed_but_undecryptable( string $value ): bool {
		return self::is_sealed( $value ) && null === self::open( $value );
	}

	private static function key(): string {
		if ( defined( 'WP_SAM_CERT_VAULT_KEY' ) && is_string( WP_SAM_CERT_VAULT_KEY ) && '' !== WP_SAM_CERT_VAULT_KEY ) {
			return hash( 'sha256', 'wp-sam-cert-vault|' . WP_SAM_CERT_VAULT_KEY, true );
		}

		return hash( 'sha256', 'wp-sam-cert-vault|' . wp_salt( 'auth' ), true );
	}
}
