<?php
/**
 * Unit tests for WP_SAM\CSP\Policy_Fingerprint.
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;
use WP_SAM\CSP\Policy_Fingerprint;

class PolicyFingerprintTest extends TestCase {

	public function test_canonicalise_drops_nonces_and_hashes_and_sorts_sources(): void {
		$policy = "Script-Src 'self' 'nonce-abc123' https://b.example.com 'sha256-AAAA' https://a.example.com; default-src 'self'; style-src-attr 'sha384-BBBB'";

		$this->assertSame(
			array(
				'default-src'    => array( "'self'" ),
				'script-src'     => array( "'self'", 'https://a.example.com', 'https://b.example.com' ),
				'style-src-attr' => array(),
			),
			Policy_Fingerprint::canonicalise( $policy )
		);
	}

	public function test_canonicalise_keeps_the_first_of_a_repeated_directive_as_browsers_do(): void {
		$canonical = Policy_Fingerprint::canonicalise( "img-src 'self'; img-src https://example.com" );

		$this->assertSame( array( 'img-src' => array( "'self'" ) ), $canonical );
	}

	public function test_digest_ignores_nonces_hashes_order_and_whitespace(): void {
		$a = "default-src 'self'; script-src 'self' 'nonce-one' https://a.example.com 'sha256-AAAA'";
		$b = "script-src  https://a.example.com 'nonce-two' 'self' 'sha256-CCCC' 'sha256-DDDD' ;default-src 'self'";

		$this->assertSame(
			Policy_Fingerprint::digest( 'report-only', 'content-security-policy-report-only', $a ),
			Policy_Fingerprint::digest( 'report-only', 'Content-Security-Policy-Report-Only', $b )
		);
	}

	public function test_digest_changes_with_a_source_the_mode_or_the_header(): void {
		$policy = "default-src 'self'; script-src 'self'";
		$base   = Policy_Fingerprint::digest( 'report-only', 'content-security-policy-report-only', $policy );

		$this->assertNotSame( $base, Policy_Fingerprint::digest( 'report-only', 'content-security-policy-report-only', $policy . ' https://example.com' ) );
		$this->assertNotSame( $base, Policy_Fingerprint::digest( 'enforce', 'content-security-policy-report-only', $policy ) );
		$this->assertNotSame( $base, Policy_Fingerprint::digest( 'report-only', 'x-origin-csp', $policy ) );
	}

	public function test_diff_names_missing_and_unexpected_entries(): void {
		$expected  = Policy_Fingerprint::canonicalise( "script-src 'self' https://www.example.com; font-src https://fonts.example.com" );
		$delivered = Policy_Fingerprint::canonicalise( "script-src 'self' https://old.example.com; img-src 'self'" );

		$this->assertSame(
			array(
				'missing'    => array( 'font-src', 'script-src https://www.example.com' ),
				'unexpected' => array( 'img-src', 'script-src https://old.example.com' ),
			),
			Policy_Fingerprint::diff( $expected, $delivered )
		);
	}
}
