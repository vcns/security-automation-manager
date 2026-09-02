<?php
/**
 * Unit tests for WP_SAM\Intelligence\Detectors\Html_Injection_Detector.
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;
use WP_SAM\Intelligence\Detectors\Html_Injection_Detector;

class HtmlInjectionDetectorTest extends TestCase {

	private Html_Injection_Detector $detector;

	protected function setUp(): void {
		wp_test_reset_globals();
		$this->detector = new Html_Injection_Detector();
	}

	private function context( string $path, string $query = '' ): array {
		return array(
			'surface'      => 'frontend',
			'path'         => $path,
			'query_string' => $query,
		);
	}

	public function test_positive_match_script_tag(): void {
		$finding = $this->detector->evaluate( $this->context( '/', 'q=%3Cscript%3Ealert(1)%3C/script%3E' ) );

		$this->assertNotNull( $finding );
		$this->assertSame( 'HTMLI-001', $finding['detail']['rule_id'] );
		$this->assertSame( 'critical', $finding['severity'] );
	}

	public function test_positive_match_svg_onload(): void {
		$finding = $this->detector->evaluate( $this->context( '/', 'q=<svg onload=alert(1)>' ) );

		$this->assertNotNull( $finding );
		$this->assertSame( 'HTMLI-002', $finding['detail']['rule_id'] );
	}

	public function test_positive_match_img_onerror(): void {
		$finding = $this->detector->evaluate( $this->context( '/', 'q=<img src=x onerror=alert(1)>' ) );

		$this->assertNotNull( $finding );
		$this->assertSame( 'HTMLI-003', $finding['detail']['rule_id'] );
	}

	public function test_positive_match_iframe(): void {
		$finding = $this->detector->evaluate( $this->context( '/', 'q=<iframe src=//evil.example></iframe>' ) );

		$this->assertNotNull( $finding );
		$this->assertSame( 'HTMLI-004', $finding['detail']['rule_id'] );
	}

	public function test_positive_match_javascript_uri_scheme(): void {
		$finding = $this->detector->evaluate( $this->context( '/', 'redirect=javascript:alert(1)' ) );

		$this->assertNotNull( $finding );
		$this->assertSame( 'HTMLI-006', $finding['detail']['rule_id'] );
	}

	public function test_positive_match_generic_event_handler_on_an_uncovered_tag(): void {
		$finding = $this->detector->evaluate( $this->context( '/', 'q=<a href=# onclick=alert(1)>x</a>' ) );

		$this->assertNotNull( $finding );
		$this->assertSame( 'HTMLI-008', $finding['detail']['rule_id'] );
	}

	public function test_encoded_variant_of_script_tag_is_decoded_before_matching(): void {
		// %3C = '<', %3E = '>' -- Pattern_Detector urldecode()s the subject
		// before matching, so an encoded payload hits the same rule as the
		// literal form.
		$finding = $this->detector->evaluate( $this->context( '/', 'q=%3Cscript%3E' ) );

		$this->assertNotNull( $finding );
		$this->assertSame( 'HTMLI-001', $finding['detail']['rule_id'] );
	}

	public function test_negative_match_a_lone_less_than_sign_in_ordinary_text(): void {
		$this->assertNull( $this->detector->evaluate( $this->context( '/', 'q=price<100' ) ) );
	}

	public function test_negative_match_ordinary_word_containing_on(): void {
		$this->assertNull( $this->detector->evaluate( $this->context( '/', 'q=onboarding+information' ) ) );
	}

	public function test_negative_match_plain_text_without_markup(): void {
		$this->assertNull( $this->detector->evaluate( $this->context( '/', 's=learn+more+about+security' ) ) );
	}

	public function test_surface_applicability_is_every_surface(): void {
		$this->assertSame( array(), $this->detector->applicable_surfaces() );
	}

	public function test_control_action_framework_allows_enforce_but_defaults_to_observe(): void {
		$this->assertSame( array( 'observe', 'enforce' ), $this->detector->allowed_control_actions() );
		$this->assertSame( 'observe', $this->detector->default_control_action() );
	}

	public function test_higher_severity_rule_wins_when_multiple_rules_match(): void {
		// <svg onload=...> matches both the specific HTMLI-002 rule
		// (critical) and the generic event-handler catch-all HTMLI-008
		// (high) -- the more specific/severe rule must win.
		$finding = $this->detector->evaluate( $this->context( '/', 'q=<svg onload=alert(1)>' ) );

		$this->assertSame( 'HTMLI-002', $finding['detail']['rule_id'] );
		$this->assertSame( 'critical', $finding['severity'] );
	}
}
