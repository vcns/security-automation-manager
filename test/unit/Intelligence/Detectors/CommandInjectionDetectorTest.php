<?php
/**
 * Unit tests for WP_SAM\Intelligence\Detectors\Command_Injection_Detector.
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;
use WP_SAM\Intelligence\Detectors\Command_Injection_Detector;

class CommandInjectionDetectorTest extends TestCase {

	private Command_Injection_Detector $detector;

	protected function setUp(): void {
		wp_test_reset_globals();
		$this->detector = new Command_Injection_Detector();
	}

	private function context( string $path, string $query = '' ): array {
		return array(
			'surface'      => 'frontend',
			'path'         => $path,
			'query_string' => $query,
		);
	}

	public function test_positive_match_semicolon_chained_command(): void {
		$finding = $this->detector->evaluate( $this->context( '/page', 'q=1;cat /etc/passwd' ) );

		$this->assertNotNull( $finding );
		$this->assertSame( 'CMDI-001', $finding['detail']['rule_id'] );
	}

	public function test_negative_match_ordinary_search_query(): void {
		$this->assertNull( $this->detector->evaluate( $this->context( '/', 's=hello+world' ) ) );
	}

	public function test_encoded_variant_of_backtick_substitution(): void {
		// %60 = backtick.
		$finding = $this->detector->evaluate( $this->context( '/page', 'q=%60whoami%60' ) );

		$this->assertNotNull( $finding );
		$this->assertSame( 'CMDI-002', $finding['detail']['rule_id'] );
	}

	public function test_benign_lookalike_cat_and_id_query_vars(): void {
		// cat= and id= are ordinary WordPress query-var names (category ID,
		// object ID) -- must never be treated as shell command words.
		$this->assertNull( $this->detector->evaluate( $this->context( '/', 'cat=5' ) ) );
		$this->assertNull( $this->detector->evaluate( $this->context( '/', 'id=5' ) ) );
	}

	public function test_surface_applicability_is_every_surface(): void {
		$this->assertSame( array(), $this->detector->applicable_surfaces() );
	}

	public function test_action_eligibility_finding_carries_no_control_field(): void {
		$finding = $this->detector->evaluate( $this->context( '/page', 'q=1;cat /etc/passwd' ) );

		$this->assertArrayNotHasKey( 'action', $finding );
		$this->assertArrayNotHasKey( 'control', $finding );
	}

	public function test_confidence_outcome(): void {
		$finding = $this->detector->evaluate( $this->context( '/page', 'q=1;cat /etc/passwd' ) );

		$this->assertSame( 0.75, $finding['confidence'] );
	}

	public function test_false_positive_regression_command_word_followed_by_equals(): void {
		// ';cat=5' -- 'cat' immediately followed by '=' must not match, even
		// though it's preceded by a semicolon (the exact collision the
		// negative lookahead exists to prevent).
		$this->assertNull( $this->detector->evaluate( $this->context( '/', 'p=1;cat=5' ) ) );
	}
}
