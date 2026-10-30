<?php
/**
 * Unit tests for WP_SAM\Intelligence\Well_Known_File_Catalog.
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;
use WP_SAM\Intelligence\Well_Known_File_Catalog;

class WellKnownFileCatalogTest extends TestCase {

	protected function setUp(): void {
		wp_test_reset_globals();
	}

	public function test_every_file_has_a_label_a_root_path_a_purpose_and_a_template(): void {
		$files = Well_Known_File_Catalog::files();

		$this->assertSame( array( 'robots', 'agents', 'security', 'humans', 'ads', 'app-ads' ), array_keys( $files ) );
		foreach ( $files as $key => $file ) {
			$this->assertNotSame( '', $file['label'], $key );
			$this->assertNotSame( '', $file['purpose'], $key );
			$this->assertStringStartsWith( '/', $file['paths'][0], $key );
			$this->assertNotEmpty( Well_Known_File_Catalog::templates( $key ), $key );
		}
	}

	/**
	 * A template is only a starting point, but one that couldn't be saved
	 * as it stands would be a bad one -- except the Google ads.txt line,
	 * whose stand-in publisher ID must be replaced before it can be.
	 */
	public function test_every_template_passes_its_own_checks_except_the_publisher_id_placeholder(): void {
		foreach ( array_keys( Well_Known_File_Catalog::files() ) as $key ) {
			foreach ( Well_Known_File_Catalog::templates( $key ) as $template_id => $template ) {
				$problems = Well_Known_File_Catalog::problems( $key, Well_Known_File_Catalog::sanitize( $template['content'] ) );
				if ( str_contains( $template['content'], Well_Known_File_Catalog::PLACEHOLDER_PUBLISHER_ID ) ) {
					$this->assertCount( 1, $problems, "{$key}/{$template_id}" );
					$this->assertStringContainsString( 'replace ' . Well_Known_File_Catalog::PLACEHOLDER_PUBLISHER_ID, $problems[0] );
				} else {
					$this->assertSame( array(), $problems, "{$key}/{$template_id}" );
				}
			}
		}
	}

	public function test_the_ai_training_template_blocks_training_crawlers_but_not_search_engines(): void {
		$content = Well_Known_File_Catalog::templates( 'robots' )['block-ai-training']['content'];

		foreach ( array( 'GPTBot', 'ClaudeBot', 'CCBot', 'Google-Extended' ) as $token ) {
			$this->assertStringContainsString( "User-agent: {$token}\n", $content );
		}
		$this->assertStringNotContainsString( 'User-agent: Googlebot', $content );
		$this->assertStringNotContainsString( 'User-agent: Bingbot', $content );
		$this->assertStringContainsString( "User-agent: *\nDisallow: /wp-admin/\nAllow: /wp-admin/admin-ajax.php\n", $content );
	}

	public function test_the_security_txt_template_expires_within_a_year_and_names_its_own_address(): void {
		$content = Well_Known_File_Catalog::templates( 'security' )['rfc9116']['content'];

		$this->assertMatchesRegularExpression( '/^Expires: (\S+)$/m', $content );
		preg_match( '/^Expires: (\S+)$/m', $content, $matches );
		$expires = strtotime( $matches[1] );
		$this->assertGreaterThan( time(), $expires );
		$this->assertLessThan( time() + 365 * DAY_IN_SECONDS, $expires );
		$this->assertStringContainsString( 'Canonical: https://example.com/.well-known/security.txt', $content );
	}

	public function test_key_for_path_knows_both_security_txt_locations(): void {
		$this->assertSame( 'security', Well_Known_File_Catalog::key_for_path( '/.well-known/security.txt' ) );
		$this->assertSame( 'security', Well_Known_File_Catalog::key_for_path( '/security.txt' ) );
		$this->assertSame( 'app-ads', Well_Known_File_Catalog::key_for_path( '/app-ads.txt' ) );
		$this->assertNull( Well_Known_File_Catalog::key_for_path( '/blog/ads.txt' ) );
		$this->assertNull( Well_Known_File_Catalog::key_for_path( '/' ) );
	}

	public function test_url_is_this_sites_own_address_for_the_file(): void {
		$this->assertSame( 'https://example.com/.well-known/security.txt', Well_Known_File_Catalog::url( 'security' ) );
	}

	public function test_sanitize_normalises_line_endings_bom_control_characters_and_the_final_newline(): void {
		$this->assertSame( "User-agent: *\nDisallow: /x/\n", Well_Known_File_Catalog::sanitize( "\xEF\xBB\xBF\r\n\r\nUser-agent: *\r\nDis\x07allow: /x/\r\n\r\n   " ) );
		$this->assertSame( '', Well_Known_File_Catalog::sanitize( " \n\r\n\t" ) );
	}

	public function test_an_empty_oversized_or_non_utf8_file_is_refused(): void {
		$this->assertStringContainsString( 'empty', Well_Known_File_Catalog::problems( 'humans', '' )[0] );
		$this->assertStringContainsString( '64 KB', Well_Known_File_Catalog::problems( 'humans', str_repeat( 'a', Well_Known_File_Catalog::MAX_BYTES + 1 ) )[0] );
		$this->assertStringContainsString( 'UTF-8', Well_Known_File_Catalog::problems( 'humans', "caf\xC3\x28\n" )[0] );
	}

	public function test_robots_txt_lines_must_be_rules_inside_a_user_agent_group(): void {
		$problems = Well_Known_File_Catalog::problems( 'robots', "Disallow: /early/\nUser-agent: *\nthis is not a rule\n# a comment is fine\nDisallow: /x/ # so is a trailing one\n" );

		$this->assertCount( 2, $problems );
		$this->assertStringContainsString( 'Line 1', $problems[0] );
		$this->assertStringContainsString( 'after a User-agent', $problems[0] );
		$this->assertStringContainsString( 'Line 3', $problems[1] );
		$this->assertStringContainsString( 'this is not a rule', $problems[1] );
	}

	public function test_agents_txt_is_checked_like_robots_txt(): void {
		$this->assertNotEmpty( Well_Known_File_Catalog::problems( 'agents', "nonsense\n" ) );
	}

	public function test_security_txt_needs_a_contact_and_one_future_expires(): void {
		$missing = Well_Known_File_Catalog::problems( 'security', "Preferred-Languages: en\n" );
		$this->assertCount( 2, $missing );
		$this->assertStringContainsString( 'Contact', $missing[0] );
		$this->assertStringContainsString( 'Expires', $missing[1] );

		$expired = Well_Known_File_Catalog::problems( 'security', "Contact: mailto:a@example.com\nExpires: 2020-01-01T00:00:00Z\n" );
		$this->assertSame( array( 'Expires is in the past. Set a date less than a year ahead.' ), $expired );

		$future   = gmdate( 'Y-m-d\TH:i:s\Z', time() + 30 * DAY_IN_SECONDS );
		$bad_link = Well_Known_File_Catalog::problems( 'security', "Contact: http://example.com/report\nExpires: {$future}\n" );
		$this->assertCount( 1, $bad_link );
		$this->assertStringContainsString( 'mailto:, https:// or tel:', $bad_link[0] );

		$this->assertSame( array(), Well_Known_File_Catalog::problems( 'security', "Contact: https://example.com/report\nExpires: {$future}\n" ) );
	}

	public function test_ads_txt_lines_must_be_seller_records_or_variables(): void {
		$content  = "# comment\nCONTACT=ads@example.com\ngoogle.com, pub-1234567890123456, DIRECT, f08c47fec0942fa0\nexample.net, 42, RESELLER\nexample.org, 7, MAYBE\njust words\n";
		$problems = Well_Known_File_Catalog::problems( 'ads', $content );

		$this->assertCount( 2, $problems );
		$this->assertStringContainsString( 'Line 5', $problems[0] );
		$this->assertStringContainsString( 'Line 6', $problems[1] );
	}

	public function test_at_most_five_problems_are_listed(): void {
		$this->assertCount( 5, Well_Known_File_Catalog::problems( 'ads', str_repeat( "junk\n", 12 ) ) );
	}

	public function test_robots_txt_writer_is_null_unless_an_seo_plugin_is_active(): void {
		$this->assertNull( Well_Known_File_Catalog::robots_txt_writer() );

		add_filter( 'wp_sam_robots_txt_writer', static fn () => 'Yoast SEO' );

		$this->assertSame( 'Yoast SEO', Well_Known_File_Catalog::robots_txt_writer() );
	}

	public function test_a_site_at_its_domain_root_can_serve_well_known_files(): void {
		$this->assertTrue( Well_Known_File_Catalog::serves_from_root() );
	}
}
