<?php
/**
 * Unit tests for WP_SAM\Intelligence\Own_Address_Store.
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;
use WP_SAM\Intelligence\Own_Address_Store;

class OwnAddressStoreTest extends TestCase {

	protected function setUp(): void {
		wp_test_reset_globals();
	}

	public function test_private_and_loopback_addresses_are_always_included(): void {
		$this->assertTrue( Own_Address_Store::includes( '127.0.0.1' ) );
		$this->assertTrue( Own_Address_Store::includes( '10.16.17.55' ) );
		$this->assertTrue( Own_Address_Store::includes( 'fd12:3456::1' ) );
	}

	public function test_a_public_address_is_not_included_until_declared(): void {
		$this->assertFalse( Own_Address_Store::includes( '185.199.223.7' ) );

		Own_Address_Store::save( '185.199.223.7' );

		$this->assertTrue( Own_Address_Store::includes( '185.199.223.7' ) );
		$this->assertFalse( Own_Address_Store::includes( '185.199.223.8' ) );
	}

	public function test_a_declared_range_covers_every_address_in_it(): void {
		Own_Address_Store::save( '203.0.113.32/28' );

		$this->assertTrue( Own_Address_Store::includes( '203.0.113.47' ) );
		$this->assertFalse( Own_Address_Store::includes( '203.0.113.48' ) );
	}

	public function test_an_empty_ip_is_never_included(): void {
		$this->assertFalse( Own_Address_Store::includes( '' ) );
	}

	public function test_save_accepts_lines_commas_and_spaces_and_drops_duplicates(): void {
		$result = Own_Address_Store::save( "203.0.113.10\n203.0.113.11, 203.0.113.10  2001:DB8::1" );

		$this->assertSame( array( '203.0.113.10', '203.0.113.11', '2001:db8::1' ), $result['saved'] );
		$this->assertSame( $result['saved'], Own_Address_Store::all() );
		$this->assertSame( array(), $result['rejected'] );
	}

	/**
	 * @dataProvider rejected_entries
	 */
	public function test_save_rejects_entries_that_should_not_be_exempted( string $entry ): void {
		$result = Own_Address_Store::save( $entry );

		$this->assertSame( array(), $result['saved'] );
		$this->assertCount( 1, $result['rejected'] );
		$this->assertSame( $entry, $result['rejected'][0]['entry'] );
		$this->assertNotSame( '', $result['rejected'][0]['reason'] );
	}

	/** @return array<string, array{string}> */
	public static function rejected_entries(): array {
		return array(
			'not an address'       => array( 'example.com' ),
			'bad prefix'           => array( '203.0.113.0/33' ),
			'non-numeric prefix'   => array( '203.0.113.0/abc' ),
			'everyone (IPv4)'      => array( '0.0.0.0/0' ),
			'too broad (IPv4)'     => array( '185.0.0.0/8' ),
			'too broad (IPv6)'     => array( '2001:db8::/32' ),
			'already private'      => array( '10.16.17.55' ),
		);
	}

	public function test_save_keeps_the_valid_entries_when_some_are_rejected(): void {
		$result = Own_Address_Store::save( "203.0.113.10\nnot-an-ip" );

		$this->assertSame( array( '203.0.113.10' ), $result['saved'] );
		$this->assertCount( 1, $result['rejected'] );
	}

	public function test_saving_an_empty_list_clears_it(): void {
		Own_Address_Store::save( '203.0.113.10' );
		Own_Address_Store::save( '' );

		$this->assertSame( array(), Own_Address_Store::all() );
		$this->assertFalse( Own_Address_Store::includes( '203.0.113.10' ) );
	}

	public function test_save_stops_at_the_maximum_number_of_entries(): void {
		$input  = implode( "\n", array_map( static fn( int $i ): string => "203.0.113.{$i}", range( 1, Own_Address_Store::MAX_ENTRIES + 2 ) ) );
		$result = Own_Address_Store::save( $input );

		$this->assertCount( Own_Address_Store::MAX_ENTRIES, $result['saved'] );
		$this->assertCount( 2, $result['rejected'] );
	}

	public function test_a_corrupt_option_is_treated_as_an_empty_list(): void {
		update_option( Own_Address_Store::OPTION, 'not-an-array' );

		$this->assertSame( array(), Own_Address_Store::all() );
		$this->assertFalse( Own_Address_Store::includes( '203.0.113.10' ) );
	}
}
