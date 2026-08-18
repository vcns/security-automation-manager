<?php
/**
 * Cryptographic primitives for the ACME v2 client.
 *
 * Pure-PHP (ext/openssl) implementations of everything RFC 8555 needs:
 *   - EC P-256 and RSA-2048 key generation (account and certificate keys).
 *   - JWK construction and RFC 7638 thumbprints for EC public keys.
 *   - ES256 / RS256 JWS signing, including the DER-to-raw (R||S) signature
 *     conversion ES256 requires (openssl emits DER; JOSE wants raw).
 *   - CSR generation with subjectAltName entries for every domain.
 *
 * No network access and no WordPress dependencies beyond ABSPATH -- kept
 * deliberately self-contained so it is unit-testable in isolation.
 */

declare( strict_types=1 );

namespace WP_SAM\Certificates;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Acme_Crypto {

	// ── Encoding ──────────────────────────────────────────────────────────────

	public static function base64url( string $data ): string {
		return rtrim( strtr( base64_encode( $data ), '+/', '-_' ), '=' );
	}

	// ── Key generation ────────────────────────────────────────────────────────

	/**
	 * Generates a private key and returns it as a PEM string.
	 *
	 * @param string $type 'ec-256' (default) or 'rsa-2048'.
	 */
	public static function generate_key( string $type = 'ec-256' ): string {
		$config = 'rsa-2048' === $type
			? array(
				'private_key_type' => OPENSSL_KEYTYPE_RSA,
				'private_key_bits' => 2048,
			)
			: array(
				'private_key_type' => OPENSSL_KEYTYPE_EC,
				'curve_name'       => 'prime256v1',
			);

		// Try the platform's default OpenSSL config first (correct on virtually
		// every Linux host); fall back to our own minimal config only when the
		// default is missing (Windows always, some minimal containers). Doing
		// it the other way round breaks hosts where loading ANY explicit
		// config triggers RANDFILE seed-file initialisation.
		$key = openssl_pkey_new( $config );
		if ( false === $key ) {
			$config['config'] = self::openssl_conf();
			$key              = openssl_pkey_new( $config );
		}
		if ( false === $key ) {
			throw new \RuntimeException( 'openssl_pkey_new failed: ' . (string) openssl_error_string() );
		}

		$pem = '';
		if ( ! openssl_pkey_export( $key, $pem )
			&& ! openssl_pkey_export( $key, $pem, null, array( 'config' => self::openssl_conf() ) ) ) {
			throw new \RuntimeException( 'openssl_pkey_export failed: ' . (string) openssl_error_string() );
		}

		return $pem;
	}

	/**
	 * Path to a minimal openssl.cnf, generated on first use. ext/openssl
	 * insists on loading a config file for key/CSR operations, and its
	 * compiled-in default path frequently does not exist (Windows always;
	 * some minimal Linux containers too) -- supplying our own makes every
	 * operation independent of host packaging.
	 */
	private static function openssl_conf(): string {
		static $path = null;

		if ( null === $path || ! is_readable( $path ) ) {
			$path = wp_tempnam( 'wp-sam-openssl-cnf' );
			// RANDFILE points at a writable location explicitly: on some
			// OpenSSL builds, loading a config initialises the RNG seed file,
			// and the default ($HOME/.rnd) may not be writable in web/cron
			// contexts.
			$rand = str_replace( '\\', '/', dirname( $path ) ) . '/wp-sam-openssl.rnd';
			file_put_contents( // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- local temp config for ext/openssl.
				$path,
				"RANDFILE = {$rand}\n[req]\ndistinguished_name = req_distinguished_name\n[req_distinguished_name]\n"
			);
		}

		return $path;
	}

	// ── JWK / thumbprint ──────────────────────────────────────────────────────

	/**
	 * Builds the public JWK for a private key PEM.
	 *
	 * @return array<string,string> JWK with keys in the RFC 7638 lexicographic
	 *                              order required for thumbprint computation.
	 */
	public static function jwk( string $private_key_pem ): array {
		$key = openssl_pkey_get_private( $private_key_pem );
		if ( false === $key ) {
			throw new \RuntimeException( 'Unable to load private key.' );
		}
		$details = openssl_pkey_get_details( $key );

		if ( isset( $details['ec'] ) ) {
			return array(
				'crv' => 'P-256',
				'kty' => 'EC',
				'x'   => self::base64url( str_pad( $details['ec']['x'], 32, "\0", STR_PAD_LEFT ) ),
				'y'   => self::base64url( str_pad( $details['ec']['y'], 32, "\0", STR_PAD_LEFT ) ),
			);
		}

		if ( isset( $details['rsa'] ) ) {
			return array(
				'e'   => self::base64url( $details['rsa']['e'] ),
				'kty' => 'RSA',
				'n'   => self::base64url( $details['rsa']['n'] ),
			);
		}

		throw new \RuntimeException( 'Unsupported key type for JWK.' );
	}

	/**
	 * RFC 7638 JWK thumbprint (used for challenge key authorizations).
	 */
	public static function thumbprint( array $jwk ): string {
		ksort( $jwk );
		return self::base64url( hash( 'sha256', (string) wp_json_encode( $jwk ), true ) );
	}

	// ── Signing ───────────────────────────────────────────────────────────────

	/**
	 * Signs data with the key, returning a JOSE-format signature.
	 * EC keys produce ES256 raw R||S (64 bytes); RSA keys produce RS256.
	 */
	public static function sign( string $data, string $private_key_pem ): string {
		$key = openssl_pkey_get_private( $private_key_pem );
		if ( false === $key ) {
			throw new \RuntimeException( 'Unable to load private key for signing.' );
		}

		$signature = '';
		if ( ! openssl_sign( $data, $signature, $key, OPENSSL_ALGO_SHA256 ) ) {
			throw new \RuntimeException( 'openssl_sign failed: ' . (string) openssl_error_string() );
		}

		$details = openssl_pkey_get_details( $key );
		if ( isset( $details['ec'] ) ) {
			return self::ec_der_to_raw( $signature );
		}

		return $signature;
	}

	/**
	 * Returns the JWS "alg" value for a private key PEM.
	 */
	public static function alg( string $private_key_pem ): string {
		$key     = openssl_pkey_get_private( $private_key_pem );
		$details = false !== $key ? openssl_pkey_get_details( $key ) : array();
		return isset( $details['ec'] ) ? 'ES256' : 'RS256';
	}

	/**
	 * Converts a DER-encoded ECDSA signature to the raw 64-byte R||S form
	 * JOSE requires. DER integers are variable length (leading zero bytes
	 * stripped, or one added when the high bit is set); each component must
	 * be normalised to exactly 32 bytes.
	 */
	public static function ec_der_to_raw( string $der ): string {
		$offset = 2; // Skip SEQUENCE header (assumes short-form length; P-256 sigs are < 128 bytes).
		$result = '';

		for ( $i = 0; $i < 2; $i++ ) {
			if ( "\x02" !== $der[ $offset ] ) {
				throw new \RuntimeException( 'Malformed DER signature.' );
			}
			$length  = ord( $der[ $offset + 1 ] );
			$integer = substr( $der, $offset + 2, $length );
			$offset += 2 + $length;

			$integer = ltrim( $integer, "\0" );
			$result .= str_pad( $integer, 32, "\0", STR_PAD_LEFT );
		}

		return $result;
	}

	// ── CSR ───────────────────────────────────────────────────────────────────

	/**
	 * Generates a CSR for the given domains, returning DER bytes ready for
	 * base64url-encoding into an ACME finalize request.
	 *
	 * @param array<int,string>    $domains At least one; first becomes the CN.
	 * @param string               $private_key_pem Certificate private key.
	 * @param array<string,string> $subject Optional distinguished-name parts:
	 *        organization, organizational_unit, country (ISO 3166-1 alpha-2),
	 *        state, locality. Included in the CSR when non-empty. Note that
	 *        domain-validated CAs (Let's Encrypt included) ignore everything
	 *        except the domain names in the issued certificate; these fields
	 *        matter for CAs and workflows that consume the CSR itself.
	 */
	public static function csr_der( array $domains, string $private_key_pem, array $subject = array() ): string {
		if ( empty( $domains ) ) {
			throw new \InvalidArgumentException( 'At least one domain is required.' );
		}

		$key = openssl_pkey_get_private( $private_key_pem );
		if ( false === $key ) {
			throw new \RuntimeException( 'Unable to load certificate private key.' );
		}

		$dn        = array( 'commonName' => $domains[0] );
		$dn_fields = array(
			'organization'        => 'organizationName',
			'organizational_unit' => 'organizationalUnitName',
			'country'             => 'countryName',
			'state'               => 'stateOrProvinceName',
			'locality'            => 'localityName',
		);
		foreach ( $dn_fields as $config_key => $openssl_key ) {
			$value = trim( (string) ( $subject[ $config_key ] ?? '' ) );
			if ( '' !== $value ) {
				$dn[ $openssl_key ] = $value;
			}
		}

		$san = implode(
			',',
			array_map(
				static fn( string $d ): string => 'DNS:' . $d,
				$domains
			)
		);

		// openssl_csr_new() only reads subjectAltName from an openssl.cnf, so a
		// temporary config file is unavoidable here.
		$config_path = wp_tempnam( 'wp-sam-csr' );
		file_put_contents( // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- local temp file for openssl config.
			$config_path,
			"[req]\ndistinguished_name = req_distinguished_name\nreq_extensions = v3_req\n[req_distinguished_name]\n[v3_req]\nsubjectAltName = {$san}\n"
		);

		try {
			$csr = openssl_csr_new(
				$dn,
				$key,
				array(
					'config'     => $config_path,
					'digest_alg' => 'sha256',
				)
			);
			if ( false === $csr ) {
				throw new \RuntimeException( 'openssl_csr_new failed: ' . (string) openssl_error_string() );
			}

			$pem = '';
			if ( ! openssl_csr_export( $csr, $pem ) ) {
				throw new \RuntimeException( 'openssl_csr_export failed: ' . (string) openssl_error_string() );
			}
		} finally {
			wp_delete_file( $config_path );
		}

		$body = preg_replace( '/-----[^-]+-----|\s/', '', $pem );

		return (string) base64_decode( (string) $body );
	}
}
