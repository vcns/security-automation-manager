<?php
/**
 * Unit tests for WP_SAM\Intelligence\Detectors\Protocol_Injection_Detector.
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;
use WP_SAM\Intelligence\Detectors\Protocol_Injection_Detector;

class ProtocolInjectionDetectorTest extends TestCase {

	private Protocol_Injection_Detector $detector;

	protected function setUp(): void {
		wp_test_reset_globals();
		$this->detector = new Protocol_Injection_Detector();
	}

	private function context( string $path, string $query = '' ): array {
		return array(
			'surface'      => 'frontend',
			'path'         => $path,
			'query_string' => $query,
		);
	}

	public function test_positive_match_php_filter_wrapper(): void {
		$finding = $this->detector->evaluate( $this->context( '/', 'page=php://filter/convert.base64-encode/resource=index' ) );

		$this->assertNotNull( $finding );
		$this->assertSame( 'PROTO-001', $finding['detail']['rule_id'] );
		$this->assertSame( 'critical', $finding['severity'] );
	}

	public function test_negative_match_ordinary_https_url_parameter(): void {
		$this->assertNull( $this->detector->evaluate( $this->context( '/', 'redirect=https://example.com/thanks' ) ) );
	}

	public function test_encoded_variant_of_file_scheme(): void {
		// %3A%2F%2F = ://
		$finding = $this->detector->evaluate( $this->context( '/', 'src=file%3A%2F%2F%2Fetc%2Fpasswd' ) );

		$this->assertNotNull( $finding );
		$this->assertSame( 'PROTO-003', $finding['detail']['rule_id'] );
	}

	public function test_benign_lookalike_data_uri_is_not_matched(): void {
		// data: URIs never take a "//" form -- a legitimate inline data: URI
		// parameter must not be misclassified as a scheme-injection attempt.
		$this->assertNull( $this->detector->evaluate( $this->context( '/', 'img=data:image/png;base64,iVBORw0KGgo' ) ) );
	}

	public function test_surface_applicability_is_every_surface(): void {
		$this->assertSame( array(), $this->detector->applicable_surfaces() );
	}

	public function test_action_eligibility_finding_carries_no_control_field(): void {
		$finding = $this->detector->evaluate( $this->context( '/', 'page=php://filter/resource=index' ) );

		$this->assertArrayNotHasKey( 'action', $finding );
		$this->assertArrayNotHasKey( 'control', $finding );
	}

	public function test_confidence_outcome(): void {
		$finding = $this->detector->evaluate( $this->context( '/', 'page=php://filter/resource=index' ) );

		$this->assertSame( 0.9, $finding['confidence'] );
	}

	public function test_false_positive_regression_scheme_must_be_a_parameter_value(): void {
		// A scheme name appearing as ordinary descriptive text (not
		// immediately after "=") must not match.
		$this->assertNull( $this->detector->evaluate( $this->context( '/', 's=how+does+file+sharing+work' ) ) );
	}
}
