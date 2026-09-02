<?php
/**
 * Unit tests for WP_SAM\Intelligence\Identity_Resolver.
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;
use WP_SAM\Intelligence\Identity_Resolver;
use WP_SAM\Intelligence\Scanner_Vendor_Store;

class IdentityResolverTest extends TestCase {

	protected function setUp(): void {
		wp_test_reset_globals();
	}

	private function resolver_with_vendors( array $vendors ): Identity_Resolver {
		$GLOBALS['_wpdb_get_results'] = $vendors;
		return new Identity_Resolver( new Scanner_Vendor_Store() );
	}

	private function googlebot_vendor_row( array $overrides = array() ): array {
		return array_merge(
			array(
				'vendor_key'           => 'googlebot',
				'vendor_name'          => 'Googlebot',
				'category'             => 'known_crawler',
				'ua_pattern'           => 'Googlebot',
				'rdns_suffixes'        => '["googlebot.com","google.com"]',
				'cidr_ranges'          => '[]',
				'source_url'           => 'https://example.test/verify',
				'verification_method'  => 'fcrdns',
				'notes'                => '',
				'is_builtin'           => 1,
			),
			$overrides
		);
	}

	public function test_resolve_returns_unknown_for_an_empty_user_agent(): void {
		$resolver = $this->resolver_with_vendors( array( $this->googlebot_vendor_row() ) );

		$result = $resolver->resolve( '203.0.113.42', '' );

		$this->assertSame( 'unknown', $result['verification_state'] );
		$this->assertSame( '', $result['claimed_identity'] );
	}

	public function test_resolve_returns_unknown_when_nothing_matches(): void {
		$resolver = $this->resolver_with_vendors( array( $this->googlebot_vendor_row() ) );

		$result = $resolver->resolve( '203.0.113.42', 'Mozilla/5.0 (an ordinary browser)' );

		$this->assertSame( 'unknown', $result['verification_state'] );
		$this->assertSame( '', $result['vendor_key'] );
	}

	public function test_resolve_recognises_a_ua_match_by_category(): void {
		$resolver = $this->resolver_with_vendors( array( $this->googlebot_vendor_row() ) );

		$result = $resolver->resolve( '203.0.113.42', 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)' );

		$this->assertSame( 'known_crawler', $result['verification_state'] );
		$this->assertSame( 'googlebot', $result['vendor_key'] );
		$this->assertSame( 'Googlebot', $result['claimed_identity'] );
	}

	public function test_resolve_ua_match_is_case_insensitive(): void {
		$resolver = $this->resolver_with_vendors( array( $this->googlebot_vendor_row( array( 'ua_pattern' => 'googlebot' ) ) ) );

		$result = $resolver->resolve( '203.0.113.42', 'GOOGLEBOT/2.1' );

		$this->assertSame( 'googlebot', $result['vendor_key'] );
	}

	public function test_resolve_maps_each_category_to_its_own_state(): void {
		$resolver = $this->resolver_with_vendors(
			array(
				array(
					'vendor_key'   => 'qualys',
					'vendor_name'  => 'Qualys',
					'category'     => 'known_commercial_scanner',
					'ua_pattern'   => 'QualysGuard',
					'rdns_suffixes' => '[]',
					'cidr_ranges'  => '[]',
					'source_url'   => '',
					'verification_method' => 'none',
					'notes'        => '',
					'is_builtin'   => 0,
				),
			)
		);

		$result = $resolver->resolve( '203.0.113.42', 'QualysGuard/1.0' );

		$this->assertSame( 'known_commercial_scanner', $result['verification_state'] );
	}

	public function test_resolve_reports_network_match_against_cidr_ranges(): void {
		$resolver = $this->resolver_with_vendors(
			array( $this->googlebot_vendor_row( array( 'cidr_ranges' => '["203.0.113.0/24"]' ) ) )
		);

		$in_range    = $resolver->resolve( '203.0.113.42', 'Googlebot/2.1' );
		$out_of_range = $resolver->resolve( '198.51.100.1', 'Googlebot/2.1' );

		$this->assertTrue( $in_range['network_match'] );
		$this->assertFalse( $out_of_range['network_match'] );
	}

	public function test_resolve_network_match_is_null_when_vendor_has_no_ranges(): void {
		$resolver = $this->resolver_with_vendors( array( $this->googlebot_vendor_row() ) ); // cidr_ranges: []

		$result = $resolver->resolve( '203.0.113.42', 'Googlebot/2.1' );

		$this->assertNull( $result['network_match'] );
	}

	// ── verify_fcrdns() -- no real DNS I/O, see reverse_lookup()/forward_lookup() overrides ──

	public function test_verify_fcrdns_returns_empty_for_an_unknown_vendor(): void {
		$resolver = $this->resolver_with_vendors( array() );

		$result = $resolver->verify_fcrdns( '203.0.113.42', 'ghost-vendor' );

		$this->assertSame( '', $result['hostname'] );
		$this->assertFalse( $result['suffix_match'] );
		$this->assertFalse( $result['forward_confirmed'] );
	}

	public function test_verify_fcrdns_confirms_a_matching_hostname_and_forward_lookup(): void {
		$GLOBALS['_wpdb_get_row'] = $this->googlebot_vendor_row();
		$resolver = new Identity_Resolver(
			new Scanner_Vendor_Store(),
			static fn ( string $ip ) => 'crawl-66-249-66-1.googlebot.com',
			static fn ( string $hostname ) => '66.249.66.1'
		);

		$result = $resolver->verify_fcrdns( '66.249.66.1', 'googlebot' );

		$this->assertSame( 'crawl-66-249-66-1.googlebot.com', $result['hostname'] );
		$this->assertTrue( $result['suffix_match'] );
		$this->assertTrue( $result['forward_confirmed'] );
	}

	public function test_verify_fcrdns_rejects_a_hostname_outside_the_published_suffix(): void {
		$GLOBALS['_wpdb_get_row'] = $this->googlebot_vendor_row();
		$resolver = new Identity_Resolver(
			new Scanner_Vendor_Store(),
			static fn ( string $ip ) => 'evil.example.net', // Spoofed UA, real host is unrelated.
			static fn ( string $hostname ) => '66.249.66.1'
		);

		$result = $resolver->verify_fcrdns( '66.249.66.1', 'googlebot' );

		$this->assertFalse( $result['suffix_match'] );
		$this->assertFalse( $result['forward_confirmed'] );
	}

	public function test_verify_fcrdns_rejects_a_suffix_match_that_fails_forward_confirmation(): void {
		$GLOBALS['_wpdb_get_row'] = $this->googlebot_vendor_row();
		$resolver = new Identity_Resolver(
			new Scanner_Vendor_Store(),
			static fn ( string $ip ) => 'crawl-66-249-66-1.googlebot.com',
			static fn ( string $hostname ) => '10.0.0.1' // Does not resolve back to the original IP.
		);

		$result = $resolver->verify_fcrdns( '66.249.66.1', 'googlebot' );

		$this->assertTrue( $result['suffix_match'] );
		$this->assertFalse( $result['forward_confirmed'] );
	}

	public function test_verify_fcrdns_handles_a_reverse_lookup_failure(): void {
		$GLOBALS['_wpdb_get_row'] = $this->googlebot_vendor_row();
		$resolver = new Identity_Resolver(
			new Scanner_Vendor_Store(),
			static fn ( string $ip ) => false
		);

		$result = $resolver->verify_fcrdns( '66.249.66.1', 'googlebot' );

		$this->assertSame( '', $result['hostname'] );
		$this->assertFalse( $result['suffix_match'] );
	}
}
