<?php
/**
 * Unit tests for WP_SAM\Intelligence\Country_Groups -- the bundled country
 * groupings behind the Country Block List's "Select by group" control.
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;
use WP_SAM\Intelligence\Country_Groups;
use WP_SAM\Intelligence\Iso_Countries;

class CountryGroupsTest extends TestCase {

	/** @return string[] */
	private function codes_of( string $key ): array {
		$groups = Country_Groups::all();
		$this->assertArrayHasKey( $key, $groups );
		return $groups[ $key ]['codes'];
	}

	/** @return array<string, array<string, mixed>> */
	private function groups_in( string $category ): array {
		return array_filter( Country_Groups::all(), static fn( $group ) => $category === $group['category'] );
	}

	public function test_every_code_in_every_group_is_a_known_iso_country(): void {
		$known = Iso_Countries::all();
		foreach ( Country_Groups::all() as $key => $group ) {
			foreach ( $group['codes'] as $code ) {
				$this->assertArrayHasKey( $code, $known, "Group {$key} contains unknown code {$code}." );
			}
		}
	}

	public function test_no_group_is_empty_or_has_duplicates(): void {
		foreach ( Country_Groups::all() as $key => $group ) {
			$this->assertNotEmpty( $group['codes'], "Group {$key} is empty." );
			$this->assertSame( count( $group['codes'] ), count( array_unique( $group['codes'] ) ), "Group {$key} has duplicate codes." );
		}
	}

	public function test_every_group_is_well_formed_with_a_source_and_as_of_date(): void {
		$categories = Country_Groups::categories();
		foreach ( Country_Groups::all() as $key => $group ) {
			$this->assertSame( $key, $group['key'] );
			$this->assertNotSame( '', $group['label'] );
			$this->assertArrayHasKey( $group['category'], $categories, "Group {$key} has an unknown category." );
			$this->assertNotSame( '', $group['source'], "Group {$key} has no source." );
			$this->assertStringStartsWith( 'https://', $group['source_url'], "Group {$key} has no https source URL." );
			$this->assertMatchesRegularExpression( '/^\d{4}-\d{2}-\d{2}$/', $group['as_of'], "Group {$key} has no as-of date." );
		}
	}

	public function test_eu_has_27_members_and_eea_is_eu_plus_iceland_liechtenstein_norway(): void {
		$eu  = $this->codes_of( 'eu' );
		$eea = $this->codes_of( 'eea' );

		$this->assertCount( 27, $eu );
		$this->assertCount( 30, $eea );
		$this->assertSame( array(), array_diff( $eu, $eea ) );
		$this->assertEqualsCanonicalizing( array( 'IS', 'LI', 'NO' ), array_values( array_diff( $eea, $eu ) ) );
		$this->assertNotContains( 'GB', $eu );
		$this->assertNotContains( 'CH', $eea );
	}

	public function test_m49_continents_partition_every_assigned_country(): void {
		$this->assert_partition( 'continents', 5 );
	}

	public function test_m49_sub_regions_partition_every_assigned_country(): void {
		$this->assert_partition( 'm49-sub-regions', 17 );
	}

	public function test_m49_sub_regions_nest_inside_one_continent_each(): void {
		$continents = $this->groups_in( 'continents' );
		foreach ( $this->groups_in( 'm49-sub-regions' ) as $key => $sub ) {
			$parents = array_filter(
				$continents,
				static fn( $continent ) => array() === array_diff( $sub['codes'], $continent['codes'] )
			);
			$this->assertCount( 1, $parents, "Sub-region {$key} is not wholly inside exactly one continent." );
		}
	}

	public function test_m49_intermediate_regions_do_not_overlap_and_nest_inside_a_sub_region(): void {
		$seen = array();
		$subs = $this->groups_in( 'm49-sub-regions' );
		foreach ( $this->groups_in( 'm49-intermediate-regions' ) as $key => $group ) {
			foreach ( $group['codes'] as $code ) {
				$this->assertArrayNotHasKey( $code, $seen, "{$code} is in both {$key} and " . ( $seen[ $code ] ?? '' ) . '.' );
				$seen[ $code ] = $key;
			}
			$parents = array_filter( $subs, static fn( $sub ) => array() === array_diff( $group['codes'], $sub['codes'] ) );
			$this->assertCount( 1, $parents, "Intermediate region {$key} is not wholly inside one sub-region." );
		}
	}

	public function test_sanctions_groups_never_include_ukraine_or_syria_on_the_ofac_list(): void {
		foreach ( $this->groups_in( 'sanctions' ) as $key => $group ) {
			$this->assertNotContains( 'UA', $group['codes'], "{$key} must not over-block Ukraine for Crimea/DNR/LNR." );
		}
		// Every authority with measures on Crimea and the other Russian-controlled
		// areas says why Ukraine itself isn't ticked.
		foreach ( array( 'eu-sanctions', 'uk-sanctions', 'us-ofac-comprehensive', 'us-ofac-programs', 'ch-sanctions', 'li-sanctions', 'no-sanctions', 'ca-sanctions', 'au-sanctions', 'jp-sanctions' ) as $key ) {
			$this->assertStringContainsString( 'Crimea', Country_Groups::all()[ $key ]['note'], $key );
		}
		$this->assertEqualsCanonicalizing( array( 'CU', 'IR', 'KP' ), $this->codes_of( 'us-ofac-comprehensive' ) );
	}

	public function test_every_sanctions_group_says_where_it_applies_and_no_other_group_does(): void {
		$known = array_keys( Iso_Countries::all() );
		foreach ( Country_Groups::all() as $key => $group ) {
			if ( 'sanctions' !== $group['category'] ) {
				$this->assertSame( array(), $group['applies_in'], "{$key} is not a sanctions list, so it is never narrowed." );
				continue;
			}
			$this->assertNotEmpty( $group['applies_in'], "{$key} has no applies_in, so it would never be offered." );
			$this->assertSame( array(), array_diff( $group['applies_in'], $known ), "{$key} applies_in has an unknown code." );
			$this->assertSame( count( $group['applies_in'] ), count( array_unique( $group['applies_in'] ) ), "{$key} applies_in has a duplicate." );
		}
		$this->assertEqualsCanonicalizing( $known, Country_Groups::all()['un-sanctions']['applies_in'] );
	}

	/**
	 * @dataProvider site_country_provider
	 */
	public function test_by_category_offers_only_the_sanctions_lists_that_bind_the_site_country( string $site_country, array $expected ): void {
		$categories = Country_Groups::by_category( $site_country );

		$this->assertEqualsCanonicalizing( $expected, array_keys( $categories['sanctions']['groups'] ) );
		// Non-sanctions groups are never narrowed.
		$this->assertSame( array_keys( Country_Groups::by_category()['blocs']['groups'] ), array_keys( $categories['blocs']['groups'] ) );
	}

	public static function site_country_provider(): array {
		return array(
			'France: UN and EU'                      => array( 'FR', array( 'un-sanctions', 'eu-sanctions' ) ),
			'French Guiana is in the EU'             => array( 'GF', array( 'un-sanctions', 'eu-sanctions' ) ),
			'United Kingdom: UN and UK'              => array( 'GB', array( 'un-sanctions', 'uk-sanctions' ) ),
			'Jersey applies UK sanctions'            => array( 'JE', array( 'un-sanctions', 'uk-sanctions' ) ),
			'Gibraltar applies UK and EU sanctions'  => array( 'GI', array( 'un-sanctions', 'uk-sanctions', 'eu-sanctions' ) ),
			'Puerto Rico: both OFAC lists'           => array( 'PR', array( 'un-sanctions', 'us-ofac-comprehensive', 'us-ofac-programs' ) ),
			'Liechtenstein: its own and the Swiss'   => array( 'LI', array( 'un-sanctions', 'li-sanctions', 'ch-sanctions' ) ),
			'Svalbard applies Norway\'s'             => array( 'SJ', array( 'un-sanctions', 'no-sanctions' ) ),
			'Norfolk Island applies Australia\'s'    => array( 'NF', array( 'un-sanctions', 'au-sanctions' ) ),
			'Brazil: the UN list only'               => array( 'BR', array( 'un-sanctions' ) ),
		);
	}

	public function test_no_site_country_offers_every_sanctions_list(): void {
		$this->assertSame( array_keys( $this->groups_in( 'sanctions' ) ), array_keys( Country_Groups::by_category()['sanctions']['groups'] ) );
	}

	public function test_by_category_returns_every_group_once_in_category_order(): void {
		$flattened = array();
		foreach ( Country_Groups::by_category() as $category => $entry ) {
			$this->assertArrayHasKey( $category, Country_Groups::categories() );
			foreach ( array_keys( $entry['groups'] ) as $key ) {
				$flattened[] = $key;
			}
		}
		$this->assertSame( array_keys( Country_Groups::all() ), $flattened );
	}

	/**
	 * Every country except M49_UNASSIGNED is in exactly one group of the category.
	 */
	private function assert_partition( string $category, int $expected_groups ): void {
		$groups = $this->groups_in( $category );
		$this->assertCount( $expected_groups, $groups );

		$owner = array();
		foreach ( $groups as $key => $group ) {
			foreach ( $group['codes'] as $code ) {
				$this->assertArrayNotHasKey( $code, $owner, "{$code} is in both {$key} and " . ( $owner[ $code ] ?? '' ) . '.' );
				$owner[ $code ] = $key;
			}
		}

		$expected = array_diff( array_keys( Iso_Countries::all() ), Country_Groups::M49_UNASSIGNED );
		$this->assertEqualsCanonicalizing( array_values( $expected ), array_keys( $owner ) );
	}
}
