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

	public function test_probe_ignores_own_cached_header_served_by_a_front_end_cache(): void {
		// A full-page cache/CDN in front of the site can serve a previously
		// rendered response -- including this plugin's own CSP header from an
		// earlier real visitor request -- for the probe's HEAD request without
		// WordPress ever re-running, so the outgoing X-WP-SAM-Probe header
		// never reaches PHP and the usual self-suppression never fires. This
		// must not be misreported as a competing header from another plugin.
		$GLOBALS['_wp_remote_head_response'] = array(
			'response' => array( 'code' => 200 ),
			'headers'  => array(
				'content-security-policy-report-only' => "default-src 'none'; script-src 'nonce-abc123'; report-uri https://example.com/wp-json/security-manager/v1/report",
			),
		);

		$found = $this->detector->run_probe( 'https://example.com/' );

		$this->assertSame( array(), $found );
		$this->assertSame( array(), $this->audit->get_buffer() );
	}

	public function test_probe_still_flags_a_genuine_third_party_csp_header(): void {
		$GLOBALS['_wp_remote_head_response'] = array(
			'response' => array( 'code' => 200 ),
			'headers'  => array(
				'content-security-policy-report-only' => "default-src 'self'; report-uri https://example.com/wp-json/some-other-plugin/v1/report",
			),
		);

		$found = $this->detector->run_probe( 'https://example.com/' );

		$this->assertSame( array( 'content-security-policy-report-only' ), $found );
		$this->assertAuditDetailContains( 'via probe_existing' );
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
		$this->assertSame( '1', $GLOBALS['_wp_remote_head_requests'][0]['args']['headers']['X-WP-SAM-Probe'] );
		$this->assertSame( 1, $GLOBALS['_wp_transients']['wp_sam_conflict_probe_ran'] );
	}

	public function test_probe_header_name_matches_request_surface_suppression_constant(): void {
		// Regression test: the outgoing probe header name and the incoming
		// suppression check (Request_Surface::is_conflict_probe_request())
		// must always agree, or every probe silently stops suppressing this
		// plugin's own CSP output and misreports it as a "competing" header
		// from another plugin or the web server. This diverged once already
		// during the WP_CSP -> WP_SAM rename -- the outgoing header name was
		// never updated while the incoming check was, so the suppression
		// never actually fired on any live site running that release.
		$GLOBALS['_wp_remote_head_response'] = array(
			'response' => array( 'code' => 200 ),
			'headers'  => array(),
		);

		$this->detector->run_probe( 'https://example.com/' );

		$sent_header_name = array_key_first( $GLOBALS['_wp_remote_head_requests'][0]['args']['headers'] );
		$this->assertSame( \WP_SAM\Security\Request_Surface::CONFLICT_PROBE_HEADER, $sent_header_name );
	}

	public function test_conflict_probe_request_is_recognised_via_the_shared_header_name(): void {
		$stub = new class extends \WP_SAM\Security\Request_Surface {
			public function is_probe(): bool {
				return $this->is_conflict_probe_request();
			}
		};

		$server_key                 = 'HTTP_' . strtoupper( str_replace( '-', '_', \WP_SAM\Security\Request_Surface::CONFLICT_PROBE_HEADER ) );
		$_SERVER[ $server_key ]     = '1';

		$this->assertTrue( $stub->is_probe() );

		unset( $_SERVER[ $server_key ] );
	}

	private function assertAuditDetailContains( string $needle ): void {
		$details = array_map(
			static fn( array $entry ): string => $entry['detail'],
			$this->audit->get_buffer()
		);

		$this->assertStringContainsString( $needle, implode( "\n", $details ) );
	}
}
