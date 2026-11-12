<?php
/**
 * Unit tests for WP_SAM\Intelligence\Site_Country -- the "Where does this
 * website operate?" choice on the Geo-IP sub-tab.
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;
use WP_SAM\Intelligence\Site_Country;

class SiteCountryTest extends TestCase {

	protected function setUp(): void {
		wp_test_reset_globals();
	}

	public function test_nothing_chosen_by_default(): void {
		$this->assertSame( '', Site_Country::get() );
	}

	public function test_a_known_code_is_saved_and_normalised(): void {
		$this->assertTrue( Site_Country::save( ' gb ' ) );
		$this->assertSame( 'GB', Site_Country::get() );
	}

	public function test_an_unknown_code_is_refused_and_the_saved_choice_kept(): void {
		Site_Country::save( 'FR' );

		$this->assertFalse( Site_Country::save( 'XX' ) );
		$this->assertSame( 'FR', Site_Country::get() );
	}

	public function test_an_empty_choice_clears_it(): void {
		Site_Country::save( 'FR' );

		$this->assertTrue( Site_Country::save( '' ) );
		$this->assertSame( '', Site_Country::get() );
	}

	public function test_a_corrupt_saved_value_reads_as_nothing_chosen(): void {
		update_option( Site_Country::OPTION, array( 'GB' ) );
		$this->assertSame( '', Site_Country::get() );

		update_option( Site_Country::OPTION, 'Narnia' );
		$this->assertSame( '', Site_Country::get() );
	}
}
