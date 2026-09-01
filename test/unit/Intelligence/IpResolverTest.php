<?php
/**
 * Unit tests for WP_SAM\Intelligence\Ip_Resolver.
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;
use WP_SAM\Intelligence\Ip_Resolver;

class IpResolverTest extends TestCase {

	protected function setUp(): void {
		wp_test_reset_globals();
		unset( $_SERVER['REMOTE_ADDR'], $_SERVER['HTTP_X_FORWARDED_FOR'], $_SERVER['HTTP_X_REAL_IP'] );
	}

	public function test_resolve_returns_valid_ipv4_remote_addr(): void {
		$_SERVER['REMOTE_ADDR'] = '203.0.113.42';

		$this->assertSame( '203.0.113.42', Ip_Resolver::resolve() );
	}

	public function test_resolve_returns_valid_ipv6_remote_addr(): void {
		$_SERVER['REMOTE_ADDR'] = '2001:db8::1';

		$this->assertSame( '2001:db8::1', Ip_Resolver::resolve() );
	}

	public function test_resolve_returns_empty_string_when_remote_addr_missing(): void {
		$this->assertSame( '', Ip_Resolver::resolve() );
	}

	public function test_resolve_returns_empty_string_for_malformed_remote_addr(): void {
		$_SERVER['REMOTE_ADDR'] = 'not-an-ip';

		$this->assertSame( '', Ip_Resolver::resolve() );
	}

	/**
	 * Regression test for the deliberate design decision (see class docblock):
	 * X-Forwarded-For / X-Real-IP are trivially spoofable by the client and
	 * must never override a valid REMOTE_ADDR, since this codebase has no
	 * concept of a trusted, configured proxy.
	 */
	public function test_resolve_ignores_x_forwarded_for_and_x_real_ip(): void {
		$_SERVER['REMOTE_ADDR']         = '203.0.113.42';
		$_SERVER['HTTP_X_FORWARDED_FOR'] = '198.51.100.7';
		$_SERVER['HTTP_X_REAL_IP']       = '198.51.100.9';

		$this->assertSame( '203.0.113.42', Ip_Resolver::resolve() );
	}
}
