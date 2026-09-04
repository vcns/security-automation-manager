<?php
/**
 * Unit tests for WP_SAM\Intelligence\Detectors\Custom_Rule_Detector.
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;
use WP_SAM\Intelligence\Detectors\Custom_Rule_Detector;

class CustomRuleDetectorTest extends TestCase {

	protected function setUp(): void {
		wp_test_reset_globals();
	}

	/** @param array<string,mixed> $overrides */
	private function detector( array $overrides = array() ): Custom_Rule_Detector {
		return new Custom_Rule_Detector(
			array_merge(
				array(
					'id'            => 3,
					'name'          => 'Old backup file probe',
					'pattern'       => '/\.bak$/i',
					'subject_field' => 'request_uri',
					'severity'      => 'high',
					'surfaces'      => '[]',
				),
				$overrides
			)
		);
	}

	public function test_id_is_stable_and_derived_from_the_row_id(): void {
		$this->assertSame( 'custom_3', $this->detector()->id() );
	}

	public function test_family_is_custom(): void {
		$this->assertSame( 'custom', $this->detector()->family() );
	}

	public function test_applicable_surfaces_is_empty_for_every_surface(): void {
		$this->assertSame( array(), $this->detector( array( 'surfaces' => '[]' ) )->applicable_surfaces() );
	}

	public function test_applicable_surfaces_decodes_a_stored_subset(): void {
		$this->assertSame(
			array( 'frontend', 'api' ),
			$this->detector( array( 'surfaces' => '["frontend","api"]' ) )->applicable_surfaces()
		);
	}

	public function test_applicable_surfaces_is_empty_for_malformed_json(): void {
		$this->assertSame( array(), $this->detector( array( 'surfaces' => 'not json' ) )->applicable_surfaces() );
	}

	public function test_allows_both_observe_and_enforce(): void {
		$this->assertSame( array( 'observe', 'enforce' ), $this->detector()->allowed_control_actions() );
	}

	public function test_default_control_action_is_observe(): void {
		$this->assertSame( 'observe', $this->detector()->default_control_action() );
	}

	public function test_evaluate_matches_the_request_uri_by_default(): void {
		$context = array( 'path' => '/old-backups/wp-config.bak', 'query_string' => '' );

		$finding = $this->detector()->evaluate( $context );

		$this->assertNotNull( $finding );
		$this->assertSame( 'high', $finding['severity'] );
		$this->assertSame( 'custom_3', $finding['detail']['rule_id'] );
		$this->assertSame( 'Old backup file probe', $finding['detail']['description'] );
	}

	public function test_evaluate_includes_query_string_in_the_request_uri_subject(): void {
		$detector = $this->detector( array( 'pattern' => '/token=leaked/' ) );

		$this->assertNotNull( $detector->evaluate( array( 'path' => '/search', 'query_string' => 'token=leaked' ) ) );
	}

	public function test_evaluate_returns_null_when_the_pattern_does_not_match(): void {
		$this->assertNull( $this->detector()->evaluate( array( 'path' => '/hello-world', 'query_string' => '' ) ) );
	}

	public function test_subject_field_path_only_ignores_the_query_string(): void {
		$detector = $this->detector(
			array( 'subject_field' => 'path', 'pattern' => '/secret/' )
		);

		$this->assertNull( $detector->evaluate( array( 'path' => '/ok', 'query_string' => 'secret=1' ) ) );
		$this->assertNotNull( $detector->evaluate( array( 'path' => '/secret', 'query_string' => '' ) ) );
	}

	public function test_subject_field_query_string_only_ignores_the_path(): void {
		$detector = $this->detector(
			array( 'subject_field' => 'query_string', 'pattern' => '/union\+select/i' )
		);

		// Pattern_Detector::evaluate() urldecode()s the subject before
		// matching (see its own docblock: a raw '+' means a literal space,
		// the same convention $_GET itself follows) -- %2B is how a real
		// browser encodes a query-string value containing a literal plus.
		$this->assertNull( $detector->evaluate( array( 'path' => '/union%2Bselect', 'query_string' => '' ) ) );
		$this->assertNotNull( $detector->evaluate( array( 'path' => '/search', 'query_string' => 'q=union%2Bselect' ) ) );
	}

	public function test_subject_field_user_agent_matches_the_user_agent_context_value(): void {
		$detector = $this->detector(
			array( 'subject_field' => 'user_agent', 'pattern' => '/curl/i' )
		);

		$this->assertNotNull( $detector->evaluate( array( 'path' => '/', 'query_string' => '', 'user_agent' => 'curl/8.0' ) ) );
		$this->assertNull( $detector->evaluate( array( 'path' => '/', 'query_string' => '', 'user_agent' => 'Mozilla/5.0' ) ) );
	}

	public function test_an_invalid_stored_severity_falls_back_to_medium(): void {
		$finding = $this->detector( array( 'severity' => 'not-a-real-severity' ) )
			->evaluate( array( 'path' => '/x.bak', 'query_string' => '' ) );

		$this->assertSame( 'medium', $finding['severity'] );
	}

	public function test_an_invalid_stored_subject_field_falls_back_to_request_uri(): void {
		$detector = $this->detector( array( 'subject_field' => 'not-a-real-field' ) );

		$this->assertNotNull( $detector->evaluate( array( 'path' => '/x.bak', 'query_string' => '' ) ) );
	}
}
