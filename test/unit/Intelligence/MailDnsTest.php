<?php
/**
 * Unit tests for WP_SAM\Intelligence\Mail_Dns. DNS is answered from
 * $GLOBALS['_wp_dns_records'] (see wp_test_dns_lookup() in the bootstrap).
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;
use WP_SAM\Intelligence\Mail_Dns;

class MailDnsTest extends TestCase {

	protected function setUp(): void {
		wp_test_reset_globals();
	}

	private function txt( string $name, array $texts ): void {
		$GLOBALS['_wp_dns_records'][ DNS_TXT . ':' . $name ] = array_map(
			static fn ( $text ) => is_array( $text ) ? array( 'entries' => $text ) : array( 'txt' => $text ),
			$texts
		);
	}

	public function test_mx_hosts_are_ordered_by_preference_without_trailing_dots_or_a_null_mx(): void {
		$GLOBALS['_wp_dns_records'][ DNS_MX . ':example.com' ] = array(
			array(
				'target' => 'Backup.Example.com.',
				'pri'    => 20,
			),
			array(
				'target' => 'mx1.example.com',
				'pri'    => 10,
			),
			array(
				'target' => '',
				'pri'    => 0,
			),
		);

		$this->assertSame( array( 'mx1.example.com', 'backup.example.com' ), Mail_Dns::mx_hosts( 'example.com' ) );
	}

	public function test_a_failed_lookup_is_unknown_not_missing(): void {
		$GLOBALS['_wp_dns_records'][ DNS_MX . ':example.com' ]           = false;
		$GLOBALS['_wp_dns_records'][ DNS_TXT . ':_mta-sts.example.com' ] = false;

		$this->assertNull( Mail_Dns::mx_hosts( 'example.com' ) );
		$this->assertSame( Mail_Dns::UNKNOWN, Mail_Dns::sts_record( 'example.com' )['status'] );
		$this->assertSame( array(), Mail_Dns::mx_hosts( 'example.org' ), 'No records is an answer.' );
	}

	public function test_sts_record_reads_the_id_of_the_one_v_stsv1_record(): void {
		$this->txt( '_mta-sts.example.com', array( 'google-site-verification=abc', array( 'v=STSv1; ', 'id=20261118T1200;' ) ) );

		$this->assertSame(
			array(
				'status' => Mail_Dns::FOUND,
				'id'     => '20261118T1200',
			),
			Mail_Dns::sts_record( 'example.com' )
		);
	}

	public function test_sts_record_reports_missing_multiple_and_invalid_records(): void {
		$this->assertSame( Mail_Dns::MISSING, Mail_Dns::sts_record( 'example.com' )['status'] );

		$this->txt( '_mta-sts.example.com', array( 'v=STSv1; id=one', 'v=STSv1; id=two' ) );
		$this->assertSame( Mail_Dns::MULTIPLE, Mail_Dns::sts_record( 'example.com' )['status'] );

		$this->txt( '_mta-sts.example.com', array( 'v=STSv1; id=not-alphanumeric' ) );
		$this->assertSame( Mail_Dns::INVALID, Mail_Dns::sts_record( 'example.com' )['status'] );
	}

	public function test_tls_rpt_record_is_the_one_v_tlsrptv1_record(): void {
		$this->assertSame( Mail_Dns::MISSING, Mail_Dns::tls_rpt_record( 'example.com' )['status'] );

		$this->txt( '_smtp._tls.example.com', array( 'v=TLSRPTv1; rua=mailto:tls@example.com' ) );

		$this->assertSame(
			array(
				'status' => Mail_Dns::FOUND,
				'record' => 'v=TLSRPTv1; rua=mailto:tls@example.com',
			),
			Mail_Dns::tls_rpt_record( 'example.com' )
		);
	}
}
