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
}
