<?php
/**
 * Unit tests for WP_SAM\Security\Information_Masking_Diagnostic.
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;
use WP_SAM\Security\Information_Masking_Diagnostic;

class InformationMaskingDiagnosticTest extends TestCase {

	protected function setUp(): void {
		wp_test_reset_globals();
	}

	private function head_response( array $headers, int $code = 200 ): array {
		return array(
			'response' => array( 'code' => $code ),
			'headers'  => $headers,
		);
	}

	public function test_results_is_empty_before_any_check(): void {
		$this->assertSame( array(), ( new Information_Masking_Diagnostic() )->results() );
	}

	public function test_checked_at_is_null_before_any_check(): void {
		$this->assertNull( ( new Information_Masking_Diagnostic() )->checked_at() );
	}

	public function test_check_reports_masked_when_every_header_is_absent(): void {
		$diagnostic = new Information_Masking_Diagnostic( fn ( string $url ) => $this->head_response( array() ) );

		$result = $diagnostic->check();

		$this->assertSame( 'checked', $result['status'] );
		$this->assertSame(
			array(
				'x-powered-by' => 'masked',
				'server'       => 'masked',
				'x-pingback'   => 'masked',
			),
			$result['results']
		);
		$this->assertSame( $result['results'], $diagnostic->results() );
		$this->assertNotNull( $diagnostic->checked_at() );
		$this->assertSame( 'success', $diagnostic->last_status() );
	}

	public function test_check_reports_present_when_a_header_is_still_sent(): void {
		$diagnostic = new Information_Masking_Diagnostic(
			fn ( string $url ) => $this->head_response(
				array(
					'server' => 'Apache/2.4.62 (Debian)',
				)
			)
		);

		$result = $diagnostic->check();

		$this->assertSame( 'present', $result['results']['server'] );
		$this->assertSame( 'masked', $result['results']['x-powered-by'] );
		$this->assertSame( 'masked', $result['results']['x-pingback'] );
	}

	public function test_check_is_case_insensitive_about_header_names(): void {
		$diagnostic = new Information_Masking_Diagnostic(
			fn ( string $url ) => $this->head_response(
				array(
					'X-Powered-By' => 'PHP/8.1.32',
				)
			)
		);

		$result = $diagnostic->check();

		$this->assertSame( 'present', $result['results']['x-powered-by'] );
	}

	public function test_check_returns_failed_on_a_wp_error_response_and_keeps_previous_results(): void {
		$diagnostic = new Information_Masking_Diagnostic( fn ( string $url ) => $this->head_response( array() ) );
		$diagnostic->check();
		$previous_results = $diagnostic->results();

		$failing = new Information_Masking_Diagnostic( static fn ( string $url ) => new WP_Error( 'http_request_failed', 'timeout' ) );
		$result  = $failing->check();

		$this->assertSame( 'failed', $result['status'] );
		$this->assertSame( $previous_results, $result['results'] );
		$this->assertSame( $previous_results, $failing->results() );
		$this->assertSame( 'failed', $failing->last_status() );
	}

	public function test_check_returns_failed_on_a_non_2xx_response_and_keeps_previous_results(): void {
		$diagnostic = new Information_Masking_Diagnostic( fn ( string $url ) => $this->head_response( array() ) );
		$diagnostic->check();
		$previous_results = $diagnostic->results();

		$failing = new Information_Masking_Diagnostic( fn ( string $url ) => $this->head_response( array(), 500 ) );
		$result  = $failing->check();

		$this->assertSame( 'failed', $result['status'] );
		$this->assertSame( $previous_results, $result['results'] );
	}
}
