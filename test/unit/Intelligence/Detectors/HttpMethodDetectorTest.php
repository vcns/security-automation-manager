<?php
/**
 * Unit tests for WP_SAM\Intelligence\Detectors\Http_Method_Detector.
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;
use WP_SAM\Intelligence\Detectors\Http_Method_Detector;

class HttpMethodDetectorTest extends TestCase {

	private Http_Method_Detector $detector;

	protected function setUp(): void {
		wp_test_reset_globals();
		$this->detector = new Http_Method_Detector();
	}

	/** @return array<string, mixed> */
	private function context( string $method, string $origin = '', string $acrm = '' ): array {
		return array(
			'surface'                        => 'frontend',
			'method'                         => $method,
			'origin'                         => $origin,
			'access_control_request_method'  => $acrm,
		);
	}

	public function test_get_never_produces_a_finding(): void {
		$this->assertNull( $this->detector->evaluate( $this->context( 'GET' ) ) );
	}

	public function test_post_never_produces_a_finding(): void {
		$this->assertNull( $this->detector->evaluate( $this->context( 'POST' ) ) );
	}

	public function test_head_never_produces_a_finding(): void {
		$this->assertNull( $this->detector->evaluate( $this->context( 'HEAD' ) ) );
	}

	public function test_options_with_origin_and_access_control_request_method_classifies_as_cors_preflight(): void {
		$finding = $this->detector->evaluate( $this->context( 'OPTIONS', 'https://example.com', 'POST' ) );

		$this->assertNotNull( $finding );
		$this->assertSame( 'cors_preflight', $finding['detail']['method_classification'] );
		$this->assertSame( 'low', $finding['severity'] );
		$this->assertSame( 'https://example.com', $finding['detail']['origin'] );
		$this->assertSame( 'POST', $finding['detail']['requested_method'] );
	}

	public function test_options_without_origin_classifies_as_unclassified(): void {
		$finding = $this->detector->evaluate( $this->context( 'OPTIONS' ) );

		$this->assertNotNull( $finding );
		$this->assertSame( 'unclassified_options', $finding['detail']['method_classification'] );
		$this->assertSame( 'medium', $finding['severity'] );
	}

	public function test_options_with_origin_but_no_access_control_request_method_classifies_as_unclassified(): void {
		// Origin alone isn't sufficient -- a genuine preflight always
		// carries the paired Access-Control-Request-Method header too.
		$finding = $this->detector->evaluate( $this->context( 'OPTIONS', 'https://example.com', '' ) );

		$this->assertNotNull( $finding );
		$this->assertSame( 'unclassified_options', $finding['detail']['method_classification'] );
	}

	public function test_method_matching_is_case_insensitive(): void {
		$finding = $this->detector->evaluate( $this->context( 'options', 'https://example.com', 'POST' ) );

		$this->assertNotNull( $finding );
		$this->assertSame( 'cors_preflight', $finding['detail']['method_classification'] );
	}

	public function test_surface_applicability_is_every_surface(): void {
		$this->assertSame( array(), $this->detector->applicable_surfaces() );
	}

	public function test_control_action_framework_allows_enforce_but_defaults_to_observe(): void {
		$this->assertSame( array( 'observe', 'enforce' ), $this->detector->allowed_control_actions() );
		$this->assertSame( 'observe', $this->detector->default_control_action() );
	}
}
