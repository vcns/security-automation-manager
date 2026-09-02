<?php
/**
 * Unit tests for WP_SAM\Intelligence\Detectors\Php_Probe_Detector.
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;
use WP_SAM\Intelligence\Detectors\Php_Probe_Detector;

class PhpProbeDetectorTest extends TestCase {

	private Php_Probe_Detector $detector;

	protected function setUp(): void {
		wp_test_reset_globals();
		$this->detector = new Php_Probe_Detector();
	}

	private function context( string $path, string $query = '' ): array {
		return array(
			'surface'      => 'frontend',
			'path'         => $path,
			'query_string' => $query,
		);
	}

	public function test_positive_match_phpunit_eval_stdin_rce_path(): void {
		$finding = $this->detector->evaluate( $this->context( '/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php' ) );

		$this->assertNotNull( $finding );
		$this->assertSame( 'PHPPROBE-001', $finding['detail']['rule_id'] );
		$this->assertSame( 'critical', $finding['severity'] );
	}

	public function test_positive_match_legacy_eval_stdin_path_shape(): void {
		// Pre-refactor PHPUnit vendor layout (no src/ segment).
		$finding = $this->detector->evaluate( $this->context( '/vendor/phpunit/phpunit/Util/PHP/eval-stdin.php' ) );

		$this->assertNotNull( $finding );
		$this->assertSame( 'PHPPROBE-001', $finding['detail']['rule_id'] );
	}

	public function test_positive_match_generic_phpunit_vendor_path(): void {
		$finding = $this->detector->evaluate( $this->context( '/vendor/phpunit/phpunit/phpunit.xml' ) );

		$this->assertNotNull( $finding );
		$this->assertSame( 'PHPPROBE-002', $finding['detail']['rule_id'] );
		$this->assertSame( 'medium', $finding['severity'] );
	}

	public function test_positive_match_exposed_phpinfo_script(): void {
		$finding = $this->detector->evaluate( $this->context( '/phpinfo.php' ) );

		$this->assertNotNull( $finding );
		$this->assertSame( 'PHPPROBE-003', $finding['detail']['rule_id'] );
	}

	public function test_positive_match_laravel_ignition_rce(): void {
		$finding = $this->detector->evaluate( $this->context( '/_ignition/execute-solution' ) );

		$this->assertNotNull( $finding );
		$this->assertSame( 'PHPPROBE-004', $finding['detail']['rule_id'] );
		$this->assertSame( 'critical', $finding['severity'] );
	}

	public function test_positive_match_php_cgi_argument_injection(): void {
		$finding = $this->detector->evaluate( $this->context( '/index.php', '-d+allow_url_include=1+-d+auto_prepend_file=php://input' ) );

		$this->assertNotNull( $finding );
		$this->assertSame( 'PHPPROBE-005', $finding['detail']['rule_id'] );
	}

	public function test_positive_match_symfony_profiler_path(): void {
		$finding = $this->detector->evaluate( $this->context( '/_profiler/latest' ) );

		$this->assertNotNull( $finding );
		$this->assertSame( 'PHPPROBE-006', $finding['detail']['rule_id'] );
		$this->assertSame( 'low', $finding['severity'] );
	}

	public function test_negative_match_ordinary_wordpress_php_paths(): void {
		$this->assertNull( $this->detector->evaluate( $this->context( '/wp-login.php' ) ) );
		$this->assertNull( $this->detector->evaluate( $this->context( '/wp-admin/admin-ajax.php' ) ) );
	}

	public function test_negative_match_plain_query_string_without_the_injection_shape(): void {
		// "info" and "test" appear in ordinary query values without the
		// specific ".php filename" shape the rule requires.
		$this->assertNull( $this->detector->evaluate( $this->context( '/', 's=more+info+about+this+test' ) ) );
	}

	public function test_higher_severity_specific_rule_wins_over_the_generic_phpunit_rule(): void {
		$finding = $this->detector->evaluate( $this->context( '/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php' ) );

		// Both PHPPROBE-001 (critical) and PHPPROBE-002 (medium, "a phpunit
		// vendor path") match this string -- the more specific/severe one
		// must win.
		$this->assertSame( 'PHPPROBE-001', $finding['detail']['rule_id'] );
		$this->assertSame( 2, $finding['detail']['matched_rule_count'] );
	}

	public function test_surface_applicability_is_every_surface(): void {
		$this->assertSame( array(), $this->detector->applicable_surfaces() );
	}

	public function test_control_action_defaults_to_observe_only(): void {
		$this->assertSame( array( 'observe' ), $this->detector->allowed_control_actions() );
		$this->assertSame( 'observe', $this->detector->default_control_action() );
	}
}
