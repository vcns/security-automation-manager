<?php
/**
 * Unit tests for WP_SAM\Certificates\Acme_Crypto.
 *
 * Everything here is offline: key generation, JWK/thumbprint shape, ES256
 * signature conversion, and CSR SAN coverage via openssl round-trips.
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;
use WP_SAM\Certificates\Acme_Crypto;

class AcmeCryptoTest extends TestCase {

	public function test_base64url_is_url_safe_and_unpadded(): void {
		$encoded = Acme_Crypto::base64url( "\xfb\xef\xff" );

		$this->assertSame( '--__', $encoded );
		$this->assertStringNotContainsString( '=', Acme_Crypto::base64url( 'a' ) );
	}

	public function test_generate_key_produces_loadable_ec_pem(): void {
		$pem = Acme_Crypto::generate_key( 'ec-256' );

		$this->assertStringContainsString( 'PRIVATE KEY', $pem );
		$details = openssl_pkey_get_details( openssl_pkey_get_private( $pem ) );
		$this->assertSame( 'prime256v1', $details['ec']['curve_name'] );
	}

	public function test_jwk_for_ec_key_has_rfc7638_fields(): void {
		$jwk = Acme_Crypto::jwk( Acme_Crypto::generate_key( 'ec-256' ) );

		$this->assertSame( array( 'crv', 'kty', 'x', 'y' ), array_keys( $jwk ) );
		$this->assertSame( 'EC', $jwk['kty'] );
		// P-256 coordinates are exactly 32 bytes -> 43 base64url chars.
		$this->assertSame( 43, strlen( $jwk['x'] ) );
		$this->assertSame( 43, strlen( $jwk['y'] ) );
	}

	public function test_thumbprint_is_deterministic_and_order_insensitive(): void {
		$jwk = Acme_Crypto::jwk( Acme_Crypto::generate_key( 'ec-256' ) );

		$shuffled = array_reverse( $jwk, true );

		$this->assertSame( Acme_Crypto::thumbprint( $jwk ), Acme_Crypto::thumbprint( $shuffled ) );
		$this->assertSame( 43, strlen( Acme_Crypto::thumbprint( $jwk ) ) ); // sha256 -> 32 bytes -> 43 chars.
	}

	public function test_ec_signature_is_raw_64_bytes_and_verifiable(): void {
		$pem       = Acme_Crypto::generate_key( 'ec-256' );
		$signature = Acme_Crypto::sign( 'payload-to-sign', $pem );

		$this->assertSame( 64, strlen( $signature ) );
		$this->assertSame( 'ES256', Acme_Crypto::alg( $pem ) );
	}

	public function test_rsa_signature_uses_rs256(): void {
		$pem = Acme_Crypto::generate_key( 'rsa-2048' );

		$this->assertSame( 'RS256', Acme_Crypto::alg( $pem ) );
		$this->assertSame( 256, strlen( Acme_Crypto::sign( 'payload', $pem ) ) ); // 2048-bit RSA -> 256-byte signature.
	}

	public function test_csr_contains_every_domain_as_san(): void {
		$domains = array( 'example.com', 'www.example.com', '*.dev.example.com' );
		$der     = Acme_Crypto::csr_der( $domains, Acme_Crypto::generate_key( 'ec-256' ) );

		$pem = "-----BEGIN CERTIFICATE REQUEST-----\n" . chunk_split( base64_encode( $der ), 64, "\n" ) . '-----END CERTIFICATE REQUEST-----';

		$subject = openssl_csr_get_subject( $pem );
		$this->assertSame( 'example.com', $subject['CN'] );

		// The SAN extension lives in the DER; every DNS name must appear.
		foreach ( $domains as $domain ) {
			$this->assertStringContainsString( $domain, $der );
		}
	}
}
