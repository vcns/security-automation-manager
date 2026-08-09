<?php
/**
 * Unit tests for WP_SAM\CSP\Conflict_Detector.
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;
use WP_SAM\CSP\Conflict_Detector;
use WP_SAM\Modules\Audit_Log;

class ConflictDetectorTest extends TestCase {

	private Audit_Log         $audit;
	private Conflict_Detector $detector;

	protected function setUp(): void {
		wp_test_reset_globals();
		$this->audit    = new Audit_Log();
		$this->detector = new Conflict_Detector( $this->audit );
	}

	public function test_scan_htaccess_detects_csp_header_directives(): void {
		$path = tempnam( sys_get_temp_dir(), 'wp-sam-htaccess-' );
		$this->assertIsString( $path );

		try {
			file_put_contents(
				$path,
				implode(
					PHP_EOL,
					array(
						'# comment',
						'Header always set Content-Security-Policy "default-src \'self\'"',
						'Header set X-Frame-Options "DENY"',
						'Header append Content-Security-Policy-Report-Only "script-src \'self\'"',
					)
				)
			);

			$found = $this->detector->scan_htaccess( $path );
		} finally {
			@unlink( $path );
		}

		$this->assertCount( 2, $found );
		$this->assertSame( 'Content-Security-Policy', $found[0]['header'] );
		$this->assertSame( 'Content-Security-Policy-Report-Only', $found[1]['header'] );
		$this->assertAuditDetailContains( 'via htaccess' );
		$this->assertAuditDetailContains( 'Review Apache or LiteSpeed .htaccess Header directives' );
	}

	public function test_headers_filter_detects_case_insensitive_array_values(): void {
		$headers = array(
			'content-security-policy-report-only' => array(
				"default-src 'self'",
				"script-src 'self'",
			),
		);

		$this->assertSame( $headers, $this->detector->check_headers_filter( $headers ) );
		$this->assertAuditDetailContains( 'content-security-policy-report-only' );
		$this->assertAuditDetailContains( 'via header_filter' );
	}

	public function test_probe_records_single_existing_csp_header(): void {
		$GLOBALS['_wp_remote_head_response'] = array(
			'response' => array( 'code' => 200 ),
			'headers'  => array(
				'Content-Security-Policy' => "default-src 'self'",
			),
		);

		$found = $this->detector->run_probe( 'https://example.com/' );

		$this->assertSame( array( 'content-security-policy' ), $found );
		$this->assertAuditDetailContains( 'via probe_existing' );
		$this->assertAuditDetailContains( 'likely from web-server configuration or another security headers plugin' );
	}

	public function test_probe_records_duplicate_csp_headers(): void {
		$GLOBALS['_wp_remote_head_response'] = array(
			'response' => array( 'code' => 200 ),
			'headers'  => array(
				'content-security-policy' => array(
					"default-src 'self'",
					"script-src 'self'",
				),
			),
		);

		$found = $this->detector->run_probe( 'https://example.com/' );

		$this->assertSame( array( 'content-security-policy' ), $found );
		$this->assertAuditDetailContains( 'via probe_duplicate' );
		$this->assertAuditDetailContains( 'Multiple live CSP headers are present' );
	}

	public function test_maybe_run_probe_sends_internal_probe_header_once_per_day(): void {
		$GLOBALS['_wp_remote_head_response'] = array(
			'response' => array( 'code' => 200 ),
			'headers'  => array(),
		);

		$this->detector->maybe_run_probe();
		$this->detector->maybe_run_probe();

		$this->assertCount( 1, $GLOBALS['_wp_remote_head_requests'] );
		$this->assertSame( 'https://example.com', $GLOBALS['_wp_remote_head_requests'][0]['url'] );
		$this->assertSame( '1', $GLOBALS['_wp_remote_head_requests'][0]['args']['headers']['X-WP-CSP-Probe'] );
		$this->assertSame( 1, $GLOBALS['_wp_transients']['wp_sam_conflict_probe_ran'] );
	}

	private function assertAuditDetailContains( string $needle ): void {
		$details = array_map(
			static fn( array $entry ): string => $entry['detail'],
			$this->audit->get_buffer()
		);

		$this->assertStringContainsString( $needle, implode( "\n", $details ) );
	}
}
