<?php
/**
 * Static table of recognised country groupings, used by Control → Traffic
 * Controls → Network Intelligence → Geo-IP's Country Block List as a
 * selection aid: picking a group only ticks or unticks that group's
 * countries in the grid. Nothing here is ever saved or enforced on its own.
 *
 * Like Iso_Countries, a plain, bundled, never-fetched reference table. Only
 * defensible, citable groupings belong here:
 *
 * - UN M49 regions, sub-regions and intermediate regions, taken from the
 *   UN Statistics Division's M49 table (via the CSV mirror at
 *   github.com/lukes/ISO-3166-Countries-with-Regional-Codes, all/all.csv,
 *   retrieved 2026-10-27). M49 assigns no region to Antarctica (AQ) and does
 *   not list Taiwan (TW) separately, so both are deliberately left out of
 *   every M49 group rather than guessed. The mirror omits M49's Channel
 *   Islands intermediate region (830); it is added by hand from M49.
 * - The EU and EEA, as membership stood on the as_of date.
 * - Sanctions snapshots: the UN Security Council, and every authority found
 *   to have its own country-specific sanctions (EU, UK, US, Switzerland,
 *   Liechtenstein, Norway, Iceland, Canada, Australia, New Zealand, Japan,
 *   South Korea, Singapore, Taiwan and Ukraine), researched from official
 *   sources on 2026-10-28. Each lists every country that authority itself
 *   publishes a country regime for, whether the regime targets the state
 *   or named persons in it -- only Ukraine is left out, because its
 *   regimes protect it and the Russian-controlled areas have no code.
 *   Trade bans between two states, boycott laws and "unfriendly countries"
 *   counter-measure lists are deliberately not offered. These change: each
 *   carries an as_of date and source, and SAM never updates them
 *   automatically -- a plugin release is the only way they change.
 *   Sub-national regions (Crimea, the so-called DNR/LNR, Darfur,
 *   Transnistria) have no ISO 3166-1 code and are explained in the
 *   group's note rather than approximated by blocking a whole country.
 *
 *   Each sanctions group's applies_in lists where that authority's
 *   measures bind, including dependent territories, so by_category() can
 *   offer only the lists for the country the website operates in
 *   (Site_Country). Other groups have an empty applies_in and are always
 *   offered.
 *
 * Every code must be a key of Iso_Countries::all() (CountryGroupsTest).
 */

declare( strict_types=1 );

namespace WP_SAM\Intelligence;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Country_Groups {

	/**
	 * Countries M49 does not place in any region.
	 *
	 * @var string[]
	 */
	public const M49_UNASSIGNED = array( 'AQ', 'TW' );

	/**
	 * Where OFAC regulations apply: 31 CFR defines "United States" to
	 * include its territories and possessions (e.g. 31 CFR 560.307).
	 *
	 * @var string[]
	 */
	private const US_JURISDICTIONS = array( 'AS', 'GU', 'MP', 'PR', 'UM', 'US', 'VI' );

	/** @return array<string, string> Category key => English label, in display order. */
	public static function categories(): array {
		return array(
			'continents'               => 'Continents (UN M49 regions)',
			'm49-sub-regions'          => 'UN M49 sub-regions',
			'm49-intermediate-regions' => 'UN M49 intermediate regions',
			'blocs'                    => 'Political and economic blocs',
			'sanctions'                => 'Sanctions (snapshot)',
		);
	}

	/**
	 * Every group, in display order.
	 *
	 * @return array<string, array{key: string, label: string, category: string, codes: string[], applies_in: string[], source: string, source_url: string, as_of: string, note: string}> Group key => group.
	 */
	public static function all(): array {
		$groups = array(
			array(
				'key'        => 'm49-africa',
				'label'      => 'Africa',
				'category'   => 'continents',
				'codes'      => array( 'AO', 'BF', 'BI', 'BJ', 'BW', 'CD', 'CF', 'CG', 'CI', 'CM', 'CV', 'DJ', 'DZ', 'EG', 'EH', 'ER', 'ET', 'GA', 'GH', 'GM', 'GN', 'GQ', 'GW', 'IO', 'KE', 'KM', 'LR', 'LS', 'LY', 'MA', 'MG', 'ML', 'MR', 'MU', 'MW', 'MZ', 'NA', 'NE', 'NG', 'RE', 'RW', 'SC', 'SD', 'SH', 'SL', 'SN', 'SO', 'SS', 'ST', 'SZ', 'TD', 'TF', 'TG', 'TN', 'TZ', 'UG', 'YT', 'ZA', 'ZM', 'ZW' ),
				'source'     => 'United Nations Statistics Division, Standard country or area codes for statistical use (M49)',
				'source_url' => 'https://unstats.un.org/unsd/methodology/m49/overview/',
				'as_of'      => '2026-10-27',
				'note'       => 'Antarctica (AQ) has no M49 region, and Taiwan (TW) is not listed separately in M49, so neither is in any UN M49 group -- tick them individually if needed.',
			),
			array(
				'key'        => 'm49-americas',
				'label'      => 'Americas',
				'category'   => 'continents',
				'codes'      => array( 'AG', 'AI', 'AR', 'AW', 'BB', 'BL', 'BM', 'BO', 'BQ', 'BR', 'BS', 'BV', 'BZ', 'CA', 'CL', 'CO', 'CR', 'CU', 'CW', 'DM', 'DO', 'EC', 'FK', 'GD', 'GF', 'GL', 'GP', 'GS', 'GT', 'GY', 'HN', 'HT', 'JM', 'KN', 'KY', 'LC', 'MF', 'MQ', 'MS', 'MX', 'NI', 'PA', 'PE', 'PM', 'PR', 'PY', 'SR', 'SV', 'SX', 'TC', 'TT', 'US', 'UY', 'VC', 'VE', 'VG', 'VI' ),
				'source'     => 'United Nations Statistics Division, Standard country or area codes for statistical use (M49)',
				'source_url' => 'https://unstats.un.org/unsd/methodology/m49/overview/',
				'as_of'      => '2026-10-27',
				'note'       => 'Antarctica (AQ) has no M49 region, and Taiwan (TW) is not listed separately in M49, so neither is in any UN M49 group -- tick them individually if needed.',
			),
			array(
				'key'        => 'm49-asia',
				'label'      => 'Asia',
				'category'   => 'continents',
				'codes'      => array( 'AE', 'AF', 'AM', 'AZ', 'BD', 'BH', 'BN', 'BT', 'CN', 'CY', 'GE', 'HK', 'ID', 'IL', 'IN', 'IQ', 'IR', 'JO', 'JP', 'KG', 'KH', 'KP', 'KR', 'KW', 'KZ', 'LA', 'LB', 'LK', 'MM', 'MN', 'MO', 'MV', 'MY', 'NP', 'OM', 'PH', 'PK', 'PS', 'QA', 'SA', 'SG', 'SY', 'TH', 'TJ', 'TL', 'TM', 'TR', 'UZ', 'VN', 'YE' ),
				'source'     => 'United Nations Statistics Division, Standard country or area codes for statistical use (M49)',
				'source_url' => 'https://unstats.un.org/unsd/methodology/m49/overview/',
				'as_of'      => '2026-10-27',
				'note'       => 'Antarctica (AQ) has no M49 region, and Taiwan (TW) is not listed separately in M49, so neither is in any UN M49 group -- tick them individually if needed.',
			),
			array(
				'key'        => 'm49-europe',
				'label'      => 'Europe',
				'category'   => 'continents',
				'codes'      => array( 'AD', 'AL', 'AT', 'AX', 'BA', 'BE', 'BG', 'BY', 'CH', 'CZ', 'DE', 'DK', 'EE', 'ES', 'FI', 'FO', 'FR', 'GB', 'GG', 'GI', 'GR', 'HR', 'HU', 'IE', 'IM', 'IS', 'IT', 'JE', 'LI', 'LT', 'LU', 'LV', 'MC', 'MD', 'ME', 'MK', 'MT', 'NL', 'NO', 'PL', 'PT', 'RO', 'RS', 'RU', 'SE', 'SI', 'SJ', 'SK', 'SM', 'UA', 'VA' ),
				'source'     => 'United Nations Statistics Division, Standard country or area codes for statistical use (M49)',
				'source_url' => 'https://unstats.un.org/unsd/methodology/m49/overview/',
				'as_of'      => '2026-10-27',
				'note'       => 'Antarctica (AQ) has no M49 region, and Taiwan (TW) is not listed separately in M49, so neither is in any UN M49 group -- tick them individually if needed.',
			),
			array(
				'key'        => 'm49-oceania',
				'label'      => 'Oceania',
				'category'   => 'continents',
				'codes'      => array( 'AS', 'AU', 'CC', 'CK', 'CX', 'FJ', 'FM', 'GU', 'HM', 'KI', 'MH', 'MP', 'NC', 'NF', 'NR', 'NU', 'NZ', 'PF', 'PG', 'PN', 'PW', 'SB', 'TK', 'TO', 'TV', 'UM', 'VU', 'WF', 'WS' ),
				'source'     => 'United Nations Statistics Division, Standard country or area codes for statistical use (M49)',
				'source_url' => 'https://unstats.un.org/unsd/methodology/m49/overview/',
				'as_of'      => '2026-10-27',
				'note'       => 'Antarctica (AQ) has no M49 region, and Taiwan (TW) is not listed separately in M49, so neither is in any UN M49 group -- tick them individually if needed.',
			),
			array(
				'key'        => 'm49-northern-africa',
				'label'      => 'Northern Africa',
				'category'   => 'm49-sub-regions',
				'codes'      => array( 'DZ', 'EG', 'EH', 'LY', 'MA', 'SD', 'TN' ),
				'source'     => 'United Nations Statistics Division, Standard country or area codes for statistical use (M49)',
				'source_url' => 'https://unstats.un.org/unsd/methodology/m49/overview/',
				'as_of'      => '2026-10-27',
				'note'       => '',
			),
			array(
				'key'        => 'm49-sub-saharan-africa',
				'label'      => 'Sub-Saharan Africa',
				'category'   => 'm49-sub-regions',
				'codes'      => array( 'AO', 'BF', 'BI', 'BJ', 'BW', 'CD', 'CF', 'CG', 'CI', 'CM', 'CV', 'DJ', 'ER', 'ET', 'GA', 'GH', 'GM', 'GN', 'GQ', 'GW', 'IO', 'KE', 'KM', 'LR', 'LS', 'MG', 'ML', 'MR', 'MU', 'MW', 'MZ', 'NA', 'NE', 'NG', 'RE', 'RW', 'SC', 'SH', 'SL', 'SN', 'SO', 'SS', 'ST', 'SZ', 'TD', 'TF', 'TG', 'TZ', 'UG', 'YT', 'ZA', 'ZM', 'ZW' ),
				'source'     => 'United Nations Statistics Division, Standard country or area codes for statistical use (M49)',
				'source_url' => 'https://unstats.un.org/unsd/methodology/m49/overview/',
				'as_of'      => '2026-10-27',
				'note'       => '',
			),
			array(
				'key'        => 'm49-latin-america-and-the-caribbean',
				'label'      => 'Latin America and the Caribbean',
				'category'   => 'm49-sub-regions',
				'codes'      => array( 'AG', 'AI', 'AR', 'AW', 'BB', 'BL', 'BO', 'BQ', 'BR', 'BS', 'BV', 'BZ', 'CL', 'CO', 'CR', 'CU', 'CW', 'DM', 'DO', 'EC', 'FK', 'GD', 'GF', 'GP', 'GS', 'GT', 'GY', 'HN', 'HT', 'JM', 'KN', 'KY', 'LC', 'MF', 'MQ', 'MS', 'MX', 'NI', 'PA', 'PE', 'PR', 'PY', 'SR', 'SV', 'SX', 'TC', 'TT', 'UY', 'VC', 'VE', 'VG', 'VI' ),
				'source'     => 'United Nations Statistics Division, Standard country or area codes for statistical use (M49)',
				'source_url' => 'https://unstats.un.org/unsd/methodology/m49/overview/',
				'as_of'      => '2026-10-27',
				'note'       => '',
			),
			array(
				'key'        => 'm49-northern-america',
				'label'      => 'Northern America',
				'category'   => 'm49-sub-regions',
				'codes'      => array( 'BM', 'CA', 'GL', 'PM', 'US' ),
				'source'     => 'United Nations Statistics Division, Standard country or area codes for statistical use (M49)',
				'source_url' => 'https://unstats.un.org/unsd/methodology/m49/overview/',
				'as_of'      => '2026-10-27',
				'note'       => '',
			),
			array(
				'key'        => 'm49-central-asia',
				'label'      => 'Central Asia',
				'category'   => 'm49-sub-regions',
				'codes'      => array( 'KG', 'KZ', 'TJ', 'TM', 'UZ' ),
				'source'     => 'United Nations Statistics Division, Standard country or area codes for statistical use (M49)',
				'source_url' => 'https://unstats.un.org/unsd/methodology/m49/overview/',
				'as_of'      => '2026-10-27',
				'note'       => '',
			),
			array(
				'key'        => 'm49-eastern-asia',
				'label'      => 'Eastern Asia',
				'category'   => 'm49-sub-regions',
				'codes'      => array( 'CN', 'HK', 'JP', 'KP', 'KR', 'MN', 'MO' ),
				'source'     => 'United Nations Statistics Division, Standard country or area codes for statistical use (M49)',
				'source_url' => 'https://unstats.un.org/unsd/methodology/m49/overview/',
				'as_of'      => '2026-10-27',
				'note'       => '',
			),
			array(
				'key'        => 'm49-south-eastern-asia',
				'label'      => 'South-eastern Asia',
				'category'   => 'm49-sub-regions',
				'codes'      => array( 'BN', 'ID', 'KH', 'LA', 'MM', 'MY', 'PH', 'SG', 'TH', 'TL', 'VN' ),
				'source'     => 'United Nations Statistics Division, Standard country or area codes for statistical use (M49)',
				'source_url' => 'https://unstats.un.org/unsd/methodology/m49/overview/',
				'as_of'      => '2026-10-27',
				'note'       => '',
			),
			array(
				'key'        => 'm49-southern-asia',
				'label'      => 'Southern Asia',
				'category'   => 'm49-sub-regions',
				'codes'      => array( 'AF', 'BD', 'BT', 'IN', 'IR', 'LK', 'MV', 'NP', 'PK' ),
				'source'     => 'United Nations Statistics Division, Standard country or area codes for statistical use (M49)',
				'source_url' => 'https://unstats.un.org/unsd/methodology/m49/overview/',
				'as_of'      => '2026-10-27',
				'note'       => '',
			),
			array(
				'key'        => 'm49-western-asia',
				'label'      => 'Western Asia',
				'category'   => 'm49-sub-regions',
				'codes'      => array( 'AE', 'AM', 'AZ', 'BH', 'CY', 'GE', 'IL', 'IQ', 'JO', 'KW', 'LB', 'OM', 'PS', 'QA', 'SA', 'SY', 'TR', 'YE' ),
				'source'     => 'United Nations Statistics Division, Standard country or area codes for statistical use (M49)',
				'source_url' => 'https://unstats.un.org/unsd/methodology/m49/overview/',
				'as_of'      => '2026-10-27',
				'note'       => '',
			),
			array(
				'key'        => 'm49-eastern-europe',
				'label'      => 'Eastern Europe',
				'category'   => 'm49-sub-regions',
				'codes'      => array( 'BG', 'BY', 'CZ', 'HU', 'MD', 'PL', 'RO', 'RU', 'SK', 'UA' ),
				'source'     => 'United Nations Statistics Division, Standard country or area codes for statistical use (M49)',
				'source_url' => 'https://unstats.un.org/unsd/methodology/m49/overview/',
				'as_of'      => '2026-10-27',
				'note'       => '',
			),
			array(
				'key'        => 'm49-northern-europe',
				'label'      => 'Northern Europe',
				'category'   => 'm49-sub-regions',
				'codes'      => array( 'AX', 'DK', 'EE', 'FI', 'FO', 'GB', 'GG', 'IE', 'IM', 'IS', 'JE', 'LT', 'LV', 'NO', 'SE', 'SJ' ),
				'source'     => 'United Nations Statistics Division, Standard country or area codes for statistical use (M49)',
				'source_url' => 'https://unstats.un.org/unsd/methodology/m49/overview/',
				'as_of'      => '2026-10-27',
				'note'       => '',
			),
			array(
				'key'        => 'm49-southern-europe',
				'label'      => 'Southern Europe',
				'category'   => 'm49-sub-regions',
				'codes'      => array( 'AD', 'AL', 'BA', 'ES', 'GI', 'GR', 'HR', 'IT', 'ME', 'MK', 'MT', 'PT', 'RS', 'SI', 'SM', 'VA' ),
				'source'     => 'United Nations Statistics Division, Standard country or area codes for statistical use (M49)',
				'source_url' => 'https://unstats.un.org/unsd/methodology/m49/overview/',
				'as_of'      => '2026-10-27',
				'note'       => '',
			),
			array(
				'key'        => 'm49-western-europe',
				'label'      => 'Western Europe',
				'category'   => 'm49-sub-regions',
				'codes'      => array( 'AT', 'BE', 'CH', 'DE', 'FR', 'LI', 'LU', 'MC', 'NL' ),
				'source'     => 'United Nations Statistics Division, Standard country or area codes for statistical use (M49)',
				'source_url' => 'https://unstats.un.org/unsd/methodology/m49/overview/',
				'as_of'      => '2026-10-27',
				'note'       => '',
			),
			array(
				'key'        => 'm49-australia-and-new-zealand',
				'label'      => 'Australia and New Zealand',
				'category'   => 'm49-sub-regions',
				'codes'      => array( 'AU', 'CC', 'CX', 'HM', 'NF', 'NZ' ),
				'source'     => 'United Nations Statistics Division, Standard country or area codes for statistical use (M49)',
				'source_url' => 'https://unstats.un.org/unsd/methodology/m49/overview/',
				'as_of'      => '2026-10-27',
				'note'       => '',
			),
			array(
				'key'        => 'm49-melanesia',
				'label'      => 'Melanesia',
				'category'   => 'm49-sub-regions',
				'codes'      => array( 'FJ', 'NC', 'PG', 'SB', 'VU' ),
				'source'     => 'United Nations Statistics Division, Standard country or area codes for statistical use (M49)',
				'source_url' => 'https://unstats.un.org/unsd/methodology/m49/overview/',
				'as_of'      => '2026-10-27',
				'note'       => '',
			),
			array(
				'key'        => 'm49-micronesia',
				'label'      => 'Micronesia',
				'category'   => 'm49-sub-regions',
				'codes'      => array( 'FM', 'GU', 'KI', 'MH', 'MP', 'NR', 'PW', 'UM' ),
				'source'     => 'United Nations Statistics Division, Standard country or area codes for statistical use (M49)',
				'source_url' => 'https://unstats.un.org/unsd/methodology/m49/overview/',
				'as_of'      => '2026-10-27',
				'note'       => '',
			),
			array(
				'key'        => 'm49-polynesia',
				'label'      => 'Polynesia',
				'category'   => 'm49-sub-regions',
				'codes'      => array( 'AS', 'CK', 'NU', 'PF', 'PN', 'TK', 'TO', 'TV', 'WF', 'WS' ),
				'source'     => 'United Nations Statistics Division, Standard country or area codes for statistical use (M49)',
				'source_url' => 'https://unstats.un.org/unsd/methodology/m49/overview/',
				'as_of'      => '2026-10-27',
				'note'       => '',
			),
			array(
				'key'        => 'm49-eastern-africa',
				'label'      => 'Eastern Africa',
				'category'   => 'm49-intermediate-regions',
				'codes'      => array( 'BI', 'DJ', 'ER', 'ET', 'IO', 'KE', 'KM', 'MG', 'MU', 'MW', 'MZ', 'RE', 'RW', 'SC', 'SO', 'SS', 'TF', 'TZ', 'UG', 'YT', 'ZM', 'ZW' ),
				'source'     => 'United Nations Statistics Division, Standard country or area codes for statistical use (M49)',
				'source_url' => 'https://unstats.un.org/unsd/methodology/m49/overview/',
				'as_of'      => '2026-10-27',
				'note'       => '',
			),
			array(
				'key'        => 'm49-middle-africa',
				'label'      => 'Middle Africa',
				'category'   => 'm49-intermediate-regions',
				'codes'      => array( 'AO', 'CD', 'CF', 'CG', 'CM', 'GA', 'GQ', 'ST', 'TD' ),
				'source'     => 'United Nations Statistics Division, Standard country or area codes for statistical use (M49)',
				'source_url' => 'https://unstats.un.org/unsd/methodology/m49/overview/',
				'as_of'      => '2026-10-27',
				'note'       => '',
			),
			array(
				'key'        => 'm49-southern-africa',
				'label'      => 'Southern Africa',
				'category'   => 'm49-intermediate-regions',
				'codes'      => array( 'BW', 'LS', 'NA', 'SZ', 'ZA' ),
				'source'     => 'United Nations Statistics Division, Standard country or area codes for statistical use (M49)',
				'source_url' => 'https://unstats.un.org/unsd/methodology/m49/overview/',
				'as_of'      => '2026-10-27',
				'note'       => '',
			),
			array(
				'key'        => 'm49-western-africa',
				'label'      => 'Western Africa',
				'category'   => 'm49-intermediate-regions',
				'codes'      => array( 'BF', 'BJ', 'CI', 'CV', 'GH', 'GM', 'GN', 'GW', 'LR', 'ML', 'MR', 'NE', 'NG', 'SH', 'SL', 'SN', 'TG' ),
				'source'     => 'United Nations Statistics Division, Standard country or area codes for statistical use (M49)',
				'source_url' => 'https://unstats.un.org/unsd/methodology/m49/overview/',
				'as_of'      => '2026-10-27',
				'note'       => '',
			),
			array(
				'key'        => 'm49-caribbean',
				'label'      => 'Caribbean',
				'category'   => 'm49-intermediate-regions',
				'codes'      => array( 'AG', 'AI', 'AW', 'BB', 'BL', 'BQ', 'BS', 'CU', 'CW', 'DM', 'DO', 'GD', 'GP', 'HT', 'JM', 'KN', 'KY', 'LC', 'MF', 'MQ', 'MS', 'PR', 'SX', 'TC', 'TT', 'VC', 'VG', 'VI' ),
				'source'     => 'United Nations Statistics Division, Standard country or area codes for statistical use (M49)',
				'source_url' => 'https://unstats.un.org/unsd/methodology/m49/overview/',
				'as_of'      => '2026-10-27',
				'note'       => '',
			),
			array(
				'key'        => 'm49-central-america',
				'label'      => 'Central America',
				'category'   => 'm49-intermediate-regions',
				'codes'      => array( 'BZ', 'CR', 'GT', 'HN', 'MX', 'NI', 'PA', 'SV' ),
				'source'     => 'United Nations Statistics Division, Standard country or area codes for statistical use (M49)',
				'source_url' => 'https://unstats.un.org/unsd/methodology/m49/overview/',
				'as_of'      => '2026-10-27',
				'note'       => '',
			),
			array(
				'key'        => 'm49-south-america',
				'label'      => 'South America',
				'category'   => 'm49-intermediate-regions',
				'codes'      => array( 'AR', 'BO', 'BR', 'BV', 'CL', 'CO', 'EC', 'FK', 'GF', 'GS', 'GY', 'PE', 'PY', 'SR', 'UY', 'VE' ),
				'source'     => 'United Nations Statistics Division, Standard country or area codes for statistical use (M49)',
				'source_url' => 'https://unstats.un.org/unsd/methodology/m49/overview/',
				'as_of'      => '2026-10-27',
				'note'       => '',
			),
			array(
				'key'        => 'm49-channel-islands',
				'label'      => 'Channel Islands',
				'category'   => 'm49-intermediate-regions',
				'codes'      => array( 'GG', 'JE' ),
				'source'     => 'United Nations Statistics Division, Standard country or area codes for statistical use (M49)',
				'source_url' => 'https://unstats.un.org/unsd/methodology/m49/overview/',
				'as_of'      => '2026-10-27',
				'note'       => 'M49 also lists Sark within the Channel Islands; it has no ISO 3166-1 code of its own and is covered by Guernsey (GG).',
			),
			array(
				'key'        => 'eu',
				'label'      => 'European Union (EU)',
				'category'   => 'blocs',
				'codes'      => array( 'AT', 'BE', 'BG', 'CY', 'CZ', 'DE', 'DK', 'EE', 'ES', 'FI', 'FR', 'GR', 'HR', 'HU', 'IE', 'IT', 'LT', 'LU', 'LV', 'MT', 'NL', 'PL', 'PT', 'RO', 'SE', 'SI', 'SK' ),
				'source'     => 'European Union, EU countries',
				'source_url' => 'https://european-union.europa.eu/principles-countries-history/eu-countries_en',
				'as_of'      => '2026-10-27',
				'note'       => 'The 27 member states only. Outermost regions such as French Guiana (GF), Guadeloupe (GP), Martinique (MQ), Mayotte (YT), Reunion (RE) and Saint Martin (MF) have their own ISO codes and are not included -- tick them individually if needed.',
			),
			array(
				'key'        => 'eea',
				'label'      => 'European Economic Area (EEA)',
				'category'   => 'blocs',
				'codes'      => array( 'AT', 'BE', 'BG', 'CY', 'CZ', 'DE', 'DK', 'EE', 'ES', 'FI', 'FR', 'GR', 'HR', 'HU', 'IE', 'IS', 'IT', 'LI', 'LT', 'LU', 'LV', 'MT', 'NL', 'NO', 'PL', 'PT', 'RO', 'SE', 'SI', 'SK' ),
				'source'     => 'EFTA, EEA Agreement',
				'source_url' => 'https://www.efta.int/eea',
				'as_of'      => '2026-10-27',
				'note'       => 'The 27 EU member states plus Iceland, Liechtenstein and Norway. Switzerland is not in the EEA.',
			),
			array(
				'key'        => 'un-sanctions',
				'label'      => 'UN Security Council: countries with a country-specific sanctions regime',
				'category'   => 'sanctions',
				'codes'      => array( 'AF', 'CD', 'CF', 'GW', 'HT', 'IQ', 'IR', 'KP', 'LB', 'LY', 'SO', 'SS', 'YE' ),
				'applies_in' => array_keys( Iso_Countries::all() ),
				'source'     => 'United Nations Security Council, Sanctions',
				'source_url' => 'https://main.un.org/securitycouncil/en/sanctions/information',
				'as_of'      => '2026-10-28',
				'note'       => 'Security Council sanctions bind every UN member state, and dependent territories through the state that administers them, so this list is offered wherever the website operates. Regimes: Afghanistan (Taliban), Central African Republic, Democratic Republic of the Congo, Guinea-Bissau, Haiti, Iran, Iraq, Lebanon, Libya, North Korea, Somalia (now named for Al-Shabaab), South Sudan and Yemen. The UN Secretariat re-applied the Iran measures on 27 September 2025 under resolution 2231; Russia and China dispute that they are in force. The Yemen regime ends on 14 November 2026 unless it is renewed. The Darfur regime covers only Darfur, which has no ISO country code of its own, so Sudan (SD) is not included. The Mali regime ended on 31 August 2023. Regimes not tied to a country (ISIL and Al-Qaida) are not country lists and are not included. Most of these regimes target named persons, armed groups or arms sales; having a regime is not a requirement to block all traffic from a country.',
			),
			array(
				'key'        => 'eu-sanctions',
				'label'      => 'EU: countries with a country-specific sanctions regime',
				'category'   => 'sanctions',
				'codes'      => array( 'AF', 'BA', 'BI', 'BY', 'CD', 'CF', 'GN', 'GT', 'GW', 'HT', 'IQ', 'IR', 'KP', 'LB', 'LY', 'MD', 'ML', 'MM', 'NE', 'NI', 'RU', 'SD', 'SO', 'SS', 'SY', 'TN', 'TR', 'VE', 'YE', 'ZW' ),
				'applies_in' => array( 'AT', 'AX', 'BE', 'BG', 'CY', 'CZ', 'DE', 'DK', 'EE', 'ES', 'FI', 'FR', 'GF', 'GI', 'GP', 'GR', 'HR', 'HU', 'IE', 'IT', 'LT', 'LU', 'LV', 'MF', 'MQ', 'MT', 'NL', 'PL', 'PT', 'RE', 'RO', 'SE', 'SI', 'SK', 'YT' ),
				'source'     => 'EU Sanctions Map, with renewals confirmed in the Official Journal',
				'source_url' => 'https://www.sanctionsmap.eu/',
				'as_of'      => '2026-10-28',
				'note'       => 'EU restrictive measures bind the 27 member states, their outermost regions (French Guiana, Guadeloupe, Martinique, Mayotte, Reunion and Saint Martin) and the Aland Islands. Gibraltar applies them alongside UK sanctions under its Sanctions Act 2019. Several regimes target named persons rather than the state, among them those for Bosnia and Herzegovina, Guatemala, Moldova, Tunisia and Turkiye (unauthorised drilling). The Turkiye and Mali regimes are due for renewal by 30 November and 14 December 2026. China (CN) is not included: the EU\'s 1989 arms embargo is a political declaration, not a Council act. Ukraine (UA) is deliberately not included: the EU\'s Ukraine regimes protect Ukraine, and Crimea, Sevastopol and the other Russian-controlled areas have no ISO country code of their own. The Transnistrian region of Moldova is in the same position.',
			),
			array(
				'key'        => 'uk-sanctions',
				'label'      => 'UK: countries with a country-specific sanctions regime',
				'category'   => 'sanctions',
				'codes'      => array( 'AF', 'BA', 'BY', 'CD', 'CF', 'GN', 'GW', 'HT', 'IQ', 'IR', 'KP', 'LB', 'LY', 'ML', 'MM', 'NI', 'RU', 'SD', 'SO', 'SS', 'SY', 'VE', 'YE', 'ZW' ),
				'applies_in' => array( 'AI', 'BM', 'FK', 'GB', 'GG', 'GI', 'GS', 'IM', 'IO', 'JE', 'KY', 'MS', 'PN', 'SH', 'TC', 'VG' ),
				'source'     => 'GOV.UK, UK sanctions regimes under the Sanctions Act: regimes listed by country',
				'source_url' => 'https://www.gov.uk/government/collections/uk-sanctions-regimes-under-the-sanctions-act#regimes-listed-by-country',
				'as_of'      => '2026-10-28',
				'note'       => 'Countries with a country-specific UK sanctions regime: Afghanistan, Belarus, Bosnia and Herzegovina, Central African Republic, Democratic People\'s Republic of Korea, Democratic Republic of the Congo, Guinea, Republic of Guinea-Bissau, Haiti, Iran (two regimes: Iran, and Iran nuclear), Iraq, Lebanon (two regimes: Lebanon, and the assassination of Rafiq Hariri), Libya, Mali, Myanmar, Nicaragua, Russia, Somalia, South Sudan, Sudan, Syria (two regimes: Syria, and Syria cultural property), Venezuela, Yemen and Zimbabwe. UK sanctions also apply in the Crown Dependencies and the Overseas Territories, through Orders in Council or their own laws. These regimes mostly target named persons, entities or sectors; having a regime is not a requirement to block all traffic from a country. Thematic regimes (cyber, global human rights, anti-corruption and others) and the non-statutory arms embargo on mainland China and Hong Kong are not country lists and are not included. Crimea and the other Russian-controlled areas of Ukraine have no ISO country code of their own and cannot be selected by country -- Ukraine (UA) is deliberately not included.',
			),
			array(
				'key'        => 'us-ofac-comprehensive',
				'label'      => 'US OFAC: comprehensively sanctioned jurisdictions',
				'category'   => 'sanctions',
				'codes'      => array( 'CU', 'IR', 'KP' ),
				'applies_in' => self::US_JURISDICTIONS,
				'source'     => 'US Treasury, OFAC FAQ 10: What jurisdictions or countries are sanctioned by the United States?',
				'source_url' => 'https://ofac.treasury.gov/faqs/10',
				'as_of'      => '2026-10-28',
				'note'       => 'The jurisdictions OFAC lists as subject to broad, jurisdiction-based sanctions ("at times referred to as comprehensive sanctions"): Cuba, Iran and North Korea. OFAC itself says it keeps no list of countries U.S. persons may not do business with; its Sanctions Programs and Country Information page lists every program, most of them targeted. The Crimea region and the so-called Donetsk and Luhansk People\'s Republics are also comprehensively sanctioned, but have no ISO country code of their own and cannot be selected by country -- Ukraine (UA) is deliberately not included. Syria is no longer included: the Syria sanctions program was revoked by Executive Order 14312 (30 June 2025) and the Syrian Sanctions Regulations were removed on 26 August 2025; targeted Syria-related designations remain. Russia, Venezuela, Belarus and other programs are targeted or sectoral, not comprehensive, and are not included. OFAC blocks the Government of Venezuela, not the country as a whole.',
			),
			array(
				'key'        => 'us-ofac-programs',
				'label'      => 'US OFAC: countries with a sanctions program',
				'category'   => 'sanctions',
				'codes'      => array( 'AF', 'BY', 'CD', 'CF', 'CN', 'CU', 'HK', 'IQ', 'IR', 'KP', 'LB', 'LY', 'ML', 'MM', 'NI', 'RU', 'SD', 'SO', 'SS', 'SY', 'VE', 'YE' ),
				'applies_in' => self::US_JURISDICTIONS,
				'source'     => 'US Treasury, OFAC, Sanctions Programs and Country Information',
				'source_url' => 'https://ofac.treasury.gov/sanctions-programs-and-country-information',
				'as_of'      => '2026-10-28',
				'note'       => 'Countries named by an OFAC sanctions program: Afghanistan, Belarus, Burma (Myanmar), Central African Republic, China (Chinese Military Companies), Cuba, Democratic Republic of the Congo, Hong Kong, Iran, Iraq, Lebanon, Libya, Mali, Nicaragua, North Korea, Russia (also the Magnitsky and Ukraine-/Russia-related programs), Somalia, South Sudan, Sudan, Syria (Promoting Accountability for Assad and Regional Stabilization), Venezuela and Yemen. Most target named persons or sectors; only Cuba, Iran and North Korea are under broad, jurisdiction-wide sanctions, which the comprehensive group lists on its own. The Balkans-Related program covers the Western Balkans as a region and is not mapped to countries. Ukraine (UA) is deliberately not included: the Ukraine-/Russia-related program targets Russia and the Russian-controlled areas of Ukraine (Crimea and the so-called Donetsk and Luhansk People\'s Republics), which have no ISO country code of their own. Programs not tied to a country (counter-terrorism, narcotics, cyber, Global Magnitsky and others) are not country lists and are not included.',
			),
			array(
				'key'        => 'ch-sanctions',
				'label'      => 'Switzerland: countries with a sanctions ordinance',
				'category'   => 'sanctions',
				'codes'      => array( 'AF', 'BI', 'BY', 'CD', 'CF', 'GN', 'GT', 'GW', 'HT', 'IQ', 'IR', 'KP', 'LB', 'LY', 'MD', 'MM', 'NI', 'RU', 'SD', 'SO', 'SS', 'SY', 'VE', 'YE', 'ZW' ),
				'applies_in' => array( 'CH', 'LI' ),
				'source'     => 'SECO, Sanctions ordinances under the Embargo Act (SR 946.231)',
				'source_url' => 'https://www.seco.admin.ch/fr/ordonnances-sanctions',
				'as_of'      => '2026-10-28',
				'note'       => 'Federal Council ordinances under the Embargo Act, which implement UN sanctions and, case by case, EU ones. Swiss goods-related measures also apply in Liechtenstein under the 1923 customs treaty, so this list is offered there too. Mali is not included: its ordinance is recorded as no longer in force from 19 February 2025. Most ordinances target named persons, sectors or arms sales; having one is not a requirement to block all traffic from a country. Crimea, Sevastopol and the other designated areas of Ukraine have no ISO country code of their own.',
			),
			array(
				'key'        => 'li-sanctions',
				'label'      => 'Liechtenstein: countries with a sanctions ordinance',
				'category'   => 'sanctions',
				'codes'      => array( 'AF', 'BI', 'BY', 'CD', 'CF', 'GN', 'GT', 'GW', 'HT', 'IQ', 'IR', 'KP', 'LB', 'LY', 'MD', 'ML', 'MM', 'NE', 'NI', 'RU', 'SD', 'SO', 'SS', 'SY', 'TN', 'VE', 'YE', 'ZW' ),
				'applies_in' => array( 'LI' ),
				'source'     => 'Liechtenstein consolidated law register, international sanctions (LR 946.2)',
				'source_url' => 'https://www.gesetze.li/konso/gebietssystematik?lrstart=946.2',
				'as_of'      => '2026-10-28',
				'note'       => 'Government ordinances under the International Sanctions Act, which implement UN measures and incorporate EU Council decisions. Swiss goods-related measures also apply under the customs treaty, so the Switzerland list is offered here too. Most ordinances target named persons, sectors or arms sales; having one is not a requirement to block all traffic from a country. Ukraine (UA) is deliberately not included: Crimea, Sevastopol and the other Russian-controlled areas have no ISO country code of their own.',
			),
			array(
				'key'        => 'no-sanctions',
				'label'      => 'Norway: countries with a sanctions regulation',
				'category'   => 'sanctions',
				'codes'      => array( 'AF', 'BI', 'BY', 'CD', 'CF', 'GN', 'GW', 'HT', 'IQ', 'IR', 'KP', 'LB', 'LY', 'MD', 'ML', 'MM', 'NE', 'NI', 'RU', 'SD', 'SO', 'SS', 'SY', 'TN', 'VE', 'YE', 'ZW' ),
				'applies_in' => array( 'NO', 'SJ' ),
				'source'     => 'Lovdata, regulations under the Sanctions Act (LOV-2021-04-16-18)',
				'source_url' => 'https://lovdata.no/referanse/hjemmel?dokID=NL/lov/2021-04-16-18',
				'as_of'      => '2026-10-28',
				'note'       => 'Regulations under the Sanctions Act, which also applies in Svalbard and Jan Mayen. Norway implements UN sanctions and adopts most EU measures by its own regulations. Most regulations target named persons, sectors or arms sales; having one is not a requirement to block all traffic from a country. Ukraine (UA) is deliberately not included: Crimea, Sevastopol and the other Russian-controlled areas have no ISO country code of their own.',
			),
			array(
				'key'        => 'is-sanctions',
				'label'      => 'Iceland: countries with a sanctions regulation',
				'category'   => 'sanctions',
				'codes'      => array( 'AF', 'BA', 'BI', 'BY', 'CD', 'CF', 'GN', 'GT', 'GW', 'HT', 'IQ', 'IR', 'KP', 'LB', 'LY', 'MD', 'ML', 'MM', 'NE', 'NI', 'RU', 'SD', 'SO', 'SS', 'SY', 'TN', 'TR', 'VE', 'YE', 'ZW' ),
				'applies_in' => array( 'IS' ),
				'source'     => 'Government of Iceland, Restrictive measures',
				'source_url' => 'https://www.stjornarradid.is/verkefni/utanrikismal/lagamal/thvingunaradgerdir/',
				'as_of'      => '2026-10-28',
				'note'       => 'Regulations under the Act on the implementation of international sanctions (No. 68/2023), through which Iceland implements UN sanctions and adopts EU measures. Most target named persons, sectors or arms sales; having one is not a requirement to block all traffic from a country.',
			),
			array(
				'key'        => 'ca-sanctions',
				'label'      => 'Canada: countries with sanctions',
				'category'   => 'sanctions',
				'codes'      => array( 'BY', 'CD', 'CF', 'CN', 'GT', 'HT', 'IQ', 'IR', 'KP', 'LB', 'LK', 'LY', 'MD', 'MM', 'NI', 'RU', 'SD', 'SO', 'SS', 'SY', 'VE', 'YE', 'ZW' ),
				'applies_in' => array( 'CA' ),
				'source'     => 'Global Affairs Canada, Current sanctions imposed by Canada',
				'source_url' => 'https://www.international.gc.ca/world-monde/international_relations-relations_internationales/sanctions/current-actuelles.aspx?lang=eng',
				'as_of'      => '2026-10-28',
				'note'       => 'Measures under the Special Economic Measures Act and the United Nations Act; they bind anyone in Canada and Canadians abroad. North Korea is under bans on all exports, imports and new investment; most other regimes target named persons or sectors, and having one is not a requirement to block all traffic from a country. China (CN) is included for listings of individuals and entities, not measures against the country. Canada repealed its broad Syria trade bans on 13 February 2026; listings remain. Ukraine (UA) is deliberately not included: Canada\'s Ukraine measures target persons tied to the Russian occupation and trade with the occupied regions (Crimea and the Russian-occupied parts of the Donetsk, Luhansk, Kherson and Zaporizhzhia oblasts), which have no ISO country code of their own.',
			),
			array(
				'key'        => 'au-sanctions',
				'label'      => 'Australia: countries with sanctions',
				'category'   => 'sanctions',
				'codes'      => array( 'AF', 'CD', 'CF', 'HT', 'IQ', 'IR', 'KP', 'LB', 'LY', 'MM', 'RU', 'SD', 'SO', 'SS', 'SY', 'YE', 'ZW' ),
				'applies_in' => array( 'AU', 'CC', 'CX', 'HM', 'NF' ),
				'source'     => 'Federal Register of Legislation, Australian sanctions regulations',
				'source_url' => 'https://www.legislation.gov.au/F2011L02673/latest/text',
				'as_of'      => '2026-10-28',
				'note'       => 'UN sanctions under the Charter of the United Nations Act 1945, and Australian sanctions under the Autonomous Sanctions Act 2011. Both Acts extend to Australia\'s external territories (Christmas Island, the Cocos (Keeling) Islands, Norfolk Island, and Heard Island and McDonald Islands). Australia suspended its broad Syria measures in November 2025. Most regimes target named persons or sectors; having one is not a requirement to block all traffic from a country. Ukraine (UA) is deliberately not included: the measures apply to specified Russian-controlled regions (Crimea, Sevastopol, Donetsk and Luhansk), which have no ISO country code of their own.',
			),
			array(
				'key'        => 'nz-sanctions',
				'label'      => 'New Zealand: countries with sanctions',
				'category'   => 'sanctions',
				'codes'      => array( 'CD', 'CF', 'GW', 'HT', 'IQ', 'IR', 'KP', 'LB', 'LY', 'RU', 'SD', 'SO', 'SS', 'SY', 'YE' ),
				'applies_in' => array( 'NZ' ),
				'source'     => 'New Zealand Ministry of Foreign Affairs and Trade, UN sanctions',
				'source_url' => 'https://www.mfat.govt.nz/en/peace-rights-and-security/un-sanctions',
				'as_of'      => '2026-10-28',
				'note'       => 'UN sanctions under the United Nations Act 1946, and Russia under the Russia Sanctions Act 2022, New Zealand\'s only sanctions law of its own. Belarus (BY) is not included: the Russia Sanctions Act lists Belarusian persons and applies some measures to Belarus, but there is no Belarus regime. The Syria measures cover cultural property only. The Cook Islands has its own sanctions laws and is not included. Most regimes target named persons or sectors; having one is not a requirement to block all traffic from a country.',
			),
			array(
				'key'        => 'jp-sanctions',
				'label'      => 'Japan: countries under its own sanctions',
				'category'   => 'sanctions',
				'codes'      => array( 'BY', 'KP', 'RU', 'SY' ),
				'applies_in' => array( 'JP' ),
				'source'     => 'Ministry of Finance Japan, Economic sanctions under the Foreign Exchange and Foreign Trade Act',
				'source_url' => 'https://www.mof.go.jp/policy/international_policy/gaitame_kawase/gaitame/economic_sanctions/list.html',
				'as_of'      => '2026-10-28',
				'note'       => 'Japan\'s own measures under the Foreign Exchange and Foreign Trade Act. North Korea is under a comprehensive trade ban; the Russia, Belarus and Syria measures target named persons and sectors. Japan also implements every UN regime, which the UN list covers. Crimea, Sevastopol and the so-called Donetsk and Luhansk People\'s Republics have no ISO country code of their own.',
			),
			array(
				'key'        => 'kr-sanctions',
				'label'      => 'South Korea: countries under its own sanctions',
				'category'   => 'sanctions',
				'codes'      => array( 'BY', 'KP', 'RU' ),
				'applies_in' => array( 'KR' ),
				'source'     => 'Ministry of Foreign Affairs of the Republic of Korea, Independent sanctions',
				'source_url' => 'https://www.mofa.go.kr/www/brd/m_4080/view.do?seq=375752',
				'as_of'      => '2026-10-28',
				'note'       => 'South Korea\'s own designations and export controls against North Korea, Russia and Belarus. It implements UN sanctions separately, which the UN list covers.',
			),
			array(
				'key'        => 'sg-sanctions',
				'label'      => 'Singapore: countries under its own sanctions',
				'category'   => 'sanctions',
				'codes'      => array( 'KP', 'RU' ),
				'applies_in' => array( 'SG' ),
				'source'     => 'Monetary Authority of Singapore, Targeted financial sanctions',
				'source_url' => 'https://www.mas.gov.sg/regulation/anti-money-laundering/targeted-financial-sanctions',
				'as_of'      => '2026-10-28',
				'note'       => 'Singapore\'s own measures against Russia (2022), and its ban on commercial trade with North Korea, which goes beyond the UN measures. It also implements UN sanctions, which the UN list covers.',
			),
			array(
				'key'        => 'tw-sanctions',
				'label'      => 'Taiwan: countries under its own sanctions',
				'category'   => 'sanctions',
				'codes'      => array( 'BY', 'KP', 'RU' ),
				'applies_in' => array( 'TW' ),
				'source'     => 'Executive Yuan, sanctions against North Korea',
				'source_url' => 'https://www.ey.gov.tw/Page/9277F759E41CCD91/4fe44064-f941-4aba-bd13-cc5d24a630ab',
				'as_of'      => '2026-10-28',
				'note'       => 'Taiwan\'s own trade ban on North Korea and export controls on Russia and Belarus. Taiwan is not a UN member, but it applies UN-listed designations through its Counter-Terrorism Financing Act, so the UN list is offered here too.',
			),
			array(
				'key'        => 'ua-sanctions',
				'label'      => 'Ukraine: countries under its own sanctions',
				'category'   => 'sanctions',
				'codes'      => array( 'IR', 'RU' ),
				'applies_in' => array( 'UA' ),
				'source'     => 'Ministry of Economy of Ukraine',
				'source_url' => 'https://me.gov.ua/News/Detail/207ce520-7480-46f7-b96c-0f3d57e91fe7',
				'as_of'      => '2026-10-28',
				'note'       => 'Ukraine\'s own measures: a ban on trade with Russia, and sectoral sanctions on Iran. Ukraine also lists many individual Belarusian, Iranian, North Korean and other nationals; those are person listings, not country measures.',
			),
		);

		$keyed = array();
		foreach ( $groups as $group ) {
			$group['applies_in']  ??= array();
			$keyed[ $group['key'] ] = $group;
		}
		return $keyed;
	}

	/**
	 * Groups organised by category, in display order; empty categories are omitted.
	 *
	 * Given the country the website operates in (Site_Country), sanctions
	 * groups are narrowed to those whose applies_in includes it. Every other
	 * group is always offered, and '' (no country chosen) offers everything.
	 *
	 * @param string $site_country ISO 3166-1 alpha-2 code, or '' for every group.
	 * @return array<string, array{label: string, groups: array<string, array{key: string, label: string, category: string, codes: string[], applies_in: string[], source: string, source_url: string, as_of: string, note: string}>}>
	 */
	public static function by_category( string $site_country = '' ): array {
		$out = array();
		foreach ( self::categories() as $category => $label ) {
			$out[ $category ] = array(
				'label'  => $label,
				'groups' => array(),
			);
		}
		foreach ( self::all() as $key => $group ) {
			if ( '' !== $site_country && 'sanctions' === $group['category'] && ! in_array( $site_country, $group['applies_in'], true ) ) {
				continue;
			}
			$out[ $group['category'] ]['groups'][ $key ] = $group;
		}
		return array_filter( $out, static fn( $category ) => array() !== $category['groups'] );
	}
}
