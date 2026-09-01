<?php
/**
 * Unit tests for WP_SAM\Intelligence\Detectors\Sql_Injection_Detector.
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;
use WP_SAM\Intelligence\Detectors\Sql_Injection_Detector;

class SqlInjectionDetectorTest extends TestCase {

	private Sql_Injection_Detector $detector;

	protected function setUp(): void {
		wp_test_reset_globals();
		$this->detector = new Sql_Injection_Detector();
	}

	private function context( string $path, string $query = '' ): array {
		return array(
			'surface'      => 'frontend',
			'path'         => $path,
			'query_string' => $query,
		);
	}

	public function test_positive_match_classic_tautology(): void {
		$finding = $this->detector->evaluate( $this->context( '/', "id=1' OR '1'='1" ) );

		$this->assertNotNull( $finding );
		$this->assertSame( 'SQLI-002', $finding['detail']['rule_id'] );
		$this->assertSame( 'critical', $finding['severity'] );
	}

	public function test_negative_match_ordinary_apostrophe_in_text(): void {
		$this->assertNull( $this->detector->evaluate( $this->context( '/', "s=O%27Brien" ) ) );
	}

	public function test_encoded_variant_of_tautology(): void {
		// %27 = single quote.
		$finding = $this->detector->evaluate( $this->context( '/', 'id=1%27 OR %271%27=%271' ) );

		$this->assertNotNull( $finding );
		$this->assertSame( 'SQLI-002', $finding['detail']['rule_id'] );
	}

	public function test_benign_lookalike_union_select_in_free_text_search(): void {
		// A legitimate site search for "union select committee" must not be
		// treated the same as a structural injection attempt.
		$finding = $this->detector->evaluate( $this->context( '/', 's=union+select+committee' ) );

		$this->assertNotNull( $finding );
		$this->assertSame( 'medium', $finding['severity'] );
		$this->assertSame( 0.5, $finding['confidence'] );
	}

	public function test_surface_applicability_is_every_surface(): void {
		$this->assertSame( array(), $this->detector->applicable_surfaces() );
	}

	public function test_action_eligibility_finding_carries_no_control_field(): void {
		$finding = $this->detector->evaluate( $this->context( '/', "id=1' OR '1'='1" ) );

		$this->assertArrayNotHasKey( 'action', $finding );
		$this->assertArrayNotHasKey( 'control', $finding );
	}

	public function test_confidence_outcome_distinguishes_structural_from_keyword_match(): void {
		$tautology = $this->detector->evaluate( $this->context( '/', "id=1' OR '1'='1" ) );
		$union     = $this->detector->evaluate( $this->context( '/', 's=union+select+committee' ) );

		$this->assertGreaterThan( $union['confidence'], $tautology['confidence'] );
	}

	public function test_false_positive_regression_stacked_query_requires_semicolon(): void {
		// "update" alone (e.g. a plausible free-text word) must not match --
		// only a stacked-query shape (semicolon + destructive verb) should.
		$this->assertNull( $this->detector->evaluate( $this->context( '/', 's=please+update+my+order' ) ) );

		$finding = $this->detector->evaluate( $this->context( '/', 'id=1;DROP TABLE users' ) );
		$this->assertNotNull( $finding );
		$this->assertSame( 'SQLI-005', $finding['detail']['rule_id'] );
	}
}
