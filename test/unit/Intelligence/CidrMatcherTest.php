<?php
/**
 * Unit tests for WP_SAM\Intelligence\Cidr_Matcher.
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;
use WP_SAM\Intelligence\Cidr_Matcher;

class CidrMatcherTest extends TestCase {

	public function test_ipv4_address_inside_range_matches(): void {
		$this->assertTrue( Cidr_Matcher::ip_in_cidr( '64.39.96.5', '64.39.96.0/20' ) );
	}

	public function test_ipv4_address_outside_range_does_not_match(): void {
		$this->assertFalse( Cidr_Matcher::ip_in_cidr( '64.40.0.1', '64.39.96.0/20' ) );
	}

	public function test_ipv4_boundary_addresses(): void {
		$this->assertTrue( Cidr_Matcher::ip_in_cidr( '192.168.1.0', '192.168.1.0/24' ) );
		$this->assertTrue( Cidr_Matcher::ip_in_cidr( '192.168.1.255', '192.168.1.0/24' ) );
		$this->assertFalse( Cidr_Matcher::ip_in_cidr( '192.168.2.0', '192.168.1.0/24' ) );
	}

	public function test_slash_32_matches_only_the_exact_address(): void {
		$this->assertTrue( Cidr_Matcher::ip_in_cidr( '10.0.0.1', '10.0.0.1/32' ) );
		$this->assertFalse( Cidr_Matcher::ip_in_cidr( '10.0.0.2', '10.0.0.1/32' ) );
	}

	public function test_slash_zero_matches_everything_in_the_family(): void {
		$this->assertTrue( Cidr_Matcher::ip_in_cidr( '8.8.8.8', '0.0.0.0/0' ) );
		$this->assertTrue( Cidr_Matcher::ip_in_cidr( '203.0.113.42', '0.0.0.0/0' ) );
	}

	public function test_ipv6_address_inside_range_matches(): void {
		$this->assertTrue( Cidr_Matcher::ip_in_cidr( '2001:4860:4860::8888', '2001:4860::/32' ) );
	}

	public function test_ipv6_address_outside_range_does_not_match(): void {
		$this->assertFalse( Cidr_Matcher::ip_in_cidr( '2001:4861::1', '2001:4860::/32' ) );
	}

	public function test_mismatched_address_families_never_match(): void {
		$this->assertFalse( Cidr_Matcher::ip_in_cidr( '8.8.8.8', '::/0' ) );
		$this->assertFalse( Cidr_Matcher::ip_in_cidr( '::1', '0.0.0.0/0' ) );
	}

	public function test_malformed_cidr_is_rejected_not_fatal(): void {
		$this->assertFalse( Cidr_Matcher::ip_in_cidr( '10.0.0.1', 'not-a-cidr' ) );
		$this->assertFalse( Cidr_Matcher::ip_in_cidr( '10.0.0.1', '10.0.0.0/abc' ) );
		$this->assertFalse( Cidr_Matcher::ip_in_cidr( '10.0.0.1', '10.0.0.0/99' ) );
		$this->assertFalse( Cidr_Matcher::ip_in_cidr( 'not-an-ip', '10.0.0.0/24' ) );
	}

	public function test_ip_in_any_cidr_matches_any_entry(): void {
		$ranges = array( '203.0.113.0/24', '198.51.100.0/24' );

		$this->assertTrue( Cidr_Matcher::ip_in_any_cidr( '198.51.100.7', $ranges ) );
		$this->assertFalse( Cidr_Matcher::ip_in_any_cidr( '192.0.2.7', $ranges ) );
	}

	public function test_ip_in_any_cidr_with_empty_list_never_matches(): void {
		$this->assertFalse( Cidr_Matcher::ip_in_any_cidr( '203.0.113.1', array() ) );
	}

	/**
	 * @return array<string, array{0: string, 1: bool}>
	 */
	public static function local_addresses(): array {
		return array(
			'loopback v4'                   => array( '127.0.0.1', true ),
			'loopback v6'                   => array( '::1', true ),
			'RFC 1918 10/8 (staging self)'  => array( '10.16.17.55', true ),
			'RFC 1918 172.16/12 low'        => array( '172.16.0.1', true ),
			'RFC 1918 172.16/12 high'       => array( '172.31.255.255', true ),
			'just outside 172.16/12'        => array( '172.32.0.1', false ),
			'RFC 1918 192.168/16'           => array( '192.168.1.10', true ),
			'RFC 6598 shared space'         => array( '100.64.0.1', true ),
			'just outside 100.64/10'        => array( '100.128.0.1', false ),
			'link-local v4'                 => array( '169.254.10.20', true ),
			'unique local v6'               => array( 'fd12:3456::1', true ),
			'link-local v6'                 => array( 'fe80::1', true ),
			'public v4 (a server own address)' => array( '185.199.223.7', false ),
			'public v4'                     => array( '8.8.8.8', false ),
			'public v6'                     => array( '2a09:bac2:57ce:2478::3a2:2', false ),
			'not an address'                => array( 'not-an-ip', false ),
		);
	}

	/**
	 * @dataProvider local_addresses
	 */
	public function test_is_local_recognises_loopback_and_private_networks_only( string $ip, bool $expected ): void {
		$this->assertSame( $expected, Cidr_Matcher::is_local( $ip ) );
	}

}
