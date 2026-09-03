<?php
/**
 * Unit tests for WP_SAM\Intelligence\Detectors\Login_Cookie_Consistency_Detector.
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;
use WP_SAM\Intelligence\Detectors\Login_Cookie_Consistency_Detector;

class LoginCookieConsistencyDetectorTest extends TestCase {

	private Login_Cookie_Consistency_Detector $detector;

	protected function setUp(): void {
		wp_test_reset_globals();
		$this->detector = new Login_Cookie_Consistency_Detector();
	}

	/** @return array<string, mixed> */
	private function context( string $method, bool $has_cookie ): array {
		return array(
			'surface'                => 'login',
			'method'                 => $method,
			'has_login_test_cookie'  => $has_cookie,
		);
	}

	public function test_post_without_test_cookie_produces_a_finding(): void {
		$finding = $this->detector->evaluate( $this->context( 'POST', false ) );

		$this->assertNotNull( $finding );
		$this->assertSame( 'missing_login_test_cookie', $finding['detail']['session_signal'] );
		$this->assertSame( 'medium', $finding['severity'] );
	}

	public function test_post_with_test_cookie_produces_no_finding(): void {
		$this->assertNull( $this->detector->evaluate( $this->context( 'POST', true ) ) );
	}

	public function test_get_never_produces_a_finding_even_without_the_cookie(): void {
		// Loading the login form itself -- the cookie isn't set yet by
		// definition, and this isn't a credential-submission attempt.
		$this->assertNull( $this->detector->evaluate( $this->context( 'GET', false ) ) );
	}

	public function test_method_matching_is_case_insensitive(): void {
		$finding = $this->detector->evaluate( $this->context( 'post', false ) );

		$this->assertNotNull( $finding );
	}

	public function test_applicable_surfaces_is_login_only(): void {
		$this->assertSame( array( 'login' ), $this->detector->applicable_surfaces() );
	}

	public function test_control_action_defaults_to_observe_only(): void {
		$this->assertSame( array( 'observe' ), $this->detector->allowed_control_actions() );
		$this->assertSame( 'observe', $this->detector->default_control_action() );
	}
}
