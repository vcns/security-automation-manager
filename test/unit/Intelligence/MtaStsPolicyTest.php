<?php
/**
 * Unit tests for WP_SAM\Intelligence\Mta_Sts_Policy.
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;
use WP_SAM\Intelligence\Mta_Sts_Policy;

class MtaStsPolicyTest extends TestCase {

	private const ENFORCE = "version: STSv1\nmode: enforce\nmx: mx1.example.com\nmx: *.mail.example.net\nmax_age: 604800\n";

	protected function setUp(): void {
		wp_test_reset_globals();
	}

	public function test_the_policy_lives_on_the_mta_sts_host_of_this_sites_own_domain(): void {
		$this->assertSame( 'example.com', Mta_Sts_Policy::domain() );
		$this->assertSame( 'mta-sts.example.com', Mta_Sts_Policy::host() );
		$this->assertSame( 'https://mta-sts.example.com/.well-known/mta-sts.txt', Mta_Sts_Policy::url() );
	}

	public function test_fetch_follows_no_redirect_and_verifies_the_certificate(): void {
		Mta_Sts_Policy::fetch( 'https://mta-sts.example.com/.well-known/mta-sts.txt' );

		$request = $GLOBALS['_wp_remote_get_requests'][0];
		$this->assertSame( 'https://mta-sts.example.com/.well-known/mta-sts.txt', $request['url'] );
		$this->assertSame( 0, $request['args']['redirection'] );
		$this->assertTrue( $request['args']['sslverify'] );
	}

	public function test_a_response_is_usable_only_as_a_plain_text_200(): void {
		$ok = array(
			'response' => array( 'code' => 200 ),
			'headers'  => array( 'content-type' => 'text/plain; charset=utf-8' ),
			'body'     => self::ENFORCE,
		);
		$this->assertNull( Mta_Sts_Policy::unusable_reason( $ok ) );

		$html                            = $ok;
		$html['headers']['content-type'] = 'text/html';
		$this->assertStringContainsString( 'text/plain', (string) Mta_Sts_Policy::unusable_reason( $html ) );

		$redirect = array(
			'response' => array( 'code' => 301 ),
			'headers'  => array( 'location' => 'https://example.org/elsewhere' ),
		);
		$reason   = (string) Mta_Sts_Policy::unusable_reason( $redirect );
		$this->assertStringContainsString( 'redirect', $reason );
		$this->assertStringNotContainsString( 'example.org', $reason, 'Never says where a redirect pointed.' );

		$this->assertStringContainsString( 'HTTP 404', (string) Mta_Sts_Policy::unusable_reason( array( 'response' => array( 'code' => 404 ) ) ) );
		$this->assertStringContainsString( 'fetched', (string) Mta_Sts_Policy::unusable_reason( new WP_Error( 'http', 'Could not resolve host' ) ) );
	}

	public function test_parse_reads_the_first_of_each_field_and_every_mx_line(): void {
		$fields = Mta_Sts_Policy::parse( "version: STSv1\nmode: testing\nmode: enforce\nmx: a.example.com\nextension: ignored\nmx: b.example.com\nmax_age:86400\n" );

		$this->assertSame( 'STSv1', $fields['version'] );
		$this->assertSame( 'testing', $fields['mode'] );
		$this->assertSame( '86400', $fields['max_age'] );
		$this->assertSame( array( 'a.example.com', 'b.example.com' ), $fields['mx'] );
	}

	public function test_a_complete_policy_has_no_problems(): void {
		$this->assertSame( array(), Mta_Sts_Policy::problems( self::ENFORCE, array( 'mx1.example.com', 'smtp.mail.example.net' ) ) );
		$this->assertSame( array(), Mta_Sts_Policy::problems( "version: STSv1\nmode: none\nmax_age: 86400\n", null ), 'mode: none needs no mx line.' );
	}

	/** @return array<string, array{string, string}> */
	public static function broken_policies(): array {
		return array(
			'no version'             => array( "mode: testing\nmx: mx1.example.com\nmax_age: 86400\n", 'version: STSv1' ),
			'wrong version'          => array( "version: STSv2\nmode: testing\nmx: mx1.example.com\nmax_age: 86400\n", 'version: STSv1' ),
			'unknown mode'           => array( "version: STSv1\nmode: strict\nmx: mx1.example.com\nmax_age: 86400\n", 'mode line' ),
			'no max_age'             => array( "version: STSv1\nmode: testing\nmx: mx1.example.com\n", 'max_age' ),
			'max_age over a year'    => array( "version: STSv1\nmode: testing\nmx: mx1.example.com\nmax_age: 31557601\n", 'max_age' ),
			'max_age not a number'   => array( "version: STSv1\nmode: testing\nmx: mx1.example.com\nmax_age: 1 week\n", 'max_age' ),
			'no mx in testing'       => array( "version: STSv1\nmode: testing\nmax_age: 86400\n", 'at least one "mx:"' ),
			'trailing dot'           => array( "version: STSv1\nmode: testing\nmx: mx1.example.com.\nmax_age: 86400\n", 'isn\'t a mail server name' ),
			'wildcard in the middle' => array( "version: STSv1\nmode: testing\nmx: mx.*.example.com\nmax_age: 86400\n", 'isn\'t a mail server name' ),
			'placeholder'            => array( "version: STSv1\nmode: testing\nmx: mail.example.invalid\nmax_age: 86400\n", 'Replace mail.example.invalid' ),
			'capitalised field'      => array( "version: STSv1\nMode: testing\nmx: mx1.example.com\nmax_age: 86400\n", 'lower case' ),
			'blank line'             => array( "version: STSv1\nmode: testing\n\nmx: mx1.example.com\nmax_age: 86400\n", 'blank' ),
			'comment line'           => array( "# MTA-STS\nversion: STSv1\nmode: testing\nmx: mx1.example.com\nmax_age: 86400\n", 'isn\'t a "field: value" line' ),
		);
	}

	/** @dataProvider broken_policies */
	public function test_a_broken_policy_is_refused( string $content, string $expected ): void {
		$problems = Mta_Sts_Policy::problems( $content, null );

		$this->assertNotEmpty( $problems );
		$this->assertStringContainsString( $expected, implode( "\n", $problems ) );
	}

	public function test_enforce_mode_refuses_a_policy_that_leaves_out_one_of_the_domains_mail_servers(): void {
		$problems = Mta_Sts_Policy::problems( self::ENFORCE, array( 'mx1.example.com', 'backup.example.org' ) );

		$this->assertCount( 1, $problems );
		$this->assertStringContainsString( 'backup.example.org', $problems[0] );
	}

	public function test_testing_mode_and_unknown_mail_servers_are_not_checked_against_mx_records(): void {
		$testing = str_replace( 'mode: enforce', 'mode: testing', self::ENFORCE );

		$this->assertSame( array(), Mta_Sts_Policy::problems( $testing, array( 'backup.example.org' ) ) );
		$this->assertSame( array(), Mta_Sts_Policy::problems( self::ENFORCE, null ) );
		$this->assertSame( array(), Mta_Sts_Policy::problems( self::ENFORCE, array() ) );
	}

	public function test_a_wildcard_matches_exactly_one_left_most_label(): void {
		$this->assertTrue( Mta_Sts_Policy::matches( 'mail.example.com', '*.example.com' ) );
		$this->assertTrue( Mta_Sts_Policy::matches( 'MAIL.Example.com.', '*.example.com' ) );
		$this->assertFalse( Mta_Sts_Policy::matches( 'example.com', '*.example.com' ) );
		$this->assertFalse( Mta_Sts_Policy::matches( 'a.b.example.com', '*.example.com' ) );
		$this->assertTrue( Mta_Sts_Policy::matches( 'mx1.example.com', 'mx1.example.com' ) );
		$this->assertFalse( Mta_Sts_Policy::matches( 'mx10.example.com', 'mx1.example.com' ) );
	}

	public function test_templates_list_the_domains_mail_servers_and_start_with_testing(): void {
		$templates = Mta_Sts_Policy::templates( array( 'mx1.example.com', 'mx2.example.com' ) );

		$this->assertSame( array( 'testing', 'enforce', 'none' ), array_keys( $templates ) );
		$this->assertSame( "version: STSv1\nmode: testing\nmx: mx1.example.com\nmx: mx2.example.com\nmax_age: 86400\n", $templates['testing']['content'] );
		$this->assertStringContainsString( "mode: enforce\nmx: mx1.example.com\nmx: mx2.example.com\nmax_age: 604800\n", $templates['enforce']['content'] );
		$this->assertSame( "version: STSv1\nmode: none\nmax_age: 86400\n", $templates['none']['content'] );
		foreach ( $templates as $id => $template ) {
			$this->assertSame( array(), Mta_Sts_Policy::problems( $template['content'], array( 'mx1.example.com', 'mx2.example.com' ) ), $id );
		}
	}

	public function test_without_mx_records_the_templates_use_a_placeholder_that_cannot_be_saved(): void {
		$templates = Mta_Sts_Policy::templates( array() );

		$this->assertStringContainsString( 'mx: mail.example.invalid', $templates['testing']['content'] );
		$this->assertStringContainsString( 'found no MX records', $templates['testing']['description'] );
		$this->assertNotEmpty( Mta_Sts_Policy::problems( $templates['testing']['content'], array() ) );
	}

	public function test_the_dns_id_changes_exactly_when_the_policy_does(): void {
		$id = Mta_Sts_Policy::id( self::ENFORCE );

		$this->assertMatchesRegularExpression( '/^[a-z0-9]{1,32}$/', $id );
		$this->assertSame( $id, Mta_Sts_Policy::id( self::ENFORCE ) );
		$this->assertNotSame( $id, Mta_Sts_Policy::id( str_replace( '604800', '1209600', self::ENFORCE ) ) );
		$this->assertSame( 'v=STSv1; id=' . $id, Mta_Sts_Policy::dns_record( self::ENFORCE ) );
	}

	public function test_tls_reports_go_to_the_admin_email(): void {
		update_option( 'admin_email', 'postmaster@example.com' );

		$this->assertSame( 'v=TLSRPTv1; rua=mailto:postmaster@example.com', Mta_Sts_Policy::tls_rpt_suggestion() );
	}
}
