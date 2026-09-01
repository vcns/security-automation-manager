<?php
/**
 * Unit tests for WP_SAM\Intelligence\Detectors\Pattern_Detector.
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;

class PatternDetectorTest extends TestCase {

	protected function setUp(): void {
		wp_test_reset_globals();
	}

	public function test_no_match_returns_null(): void {
		$detector = new Fixture_Pattern_Detector();

		$this->assertNull( $detector->evaluate( array( 'subject' => 'nothing interesting here' ) ) );
	}

	public function test_highest_severity_match_wins_over_declaration_order(): void {
		$detector = new Fixture_Pattern_Detector();

		// 'low-word' (declared first, low severity) and 'high-word' (declared
		// second, high severity) both appear -- the low-severity rule must
		// not win just because it comes first in rules().
		$finding = $detector->evaluate( array( 'subject' => 'low-word and high-word both present' ) );

		$this->assertSame( 'high', $finding['severity'] );
		$this->assertSame( 'FIX-002', $finding['detail']['rule_id'] );
	}

	public function test_matched_rule_count_reflects_all_matches_not_just_the_winner(): void {
		$detector = new Fixture_Pattern_Detector();

		$finding = $detector->evaluate( array( 'subject' => 'low-word and high-word both present' ) );

		$this->assertSame( 2, $finding['detail']['matched_rule_count'] );
	}

	public function test_confidence_defaults_when_a_rule_omits_it(): void {
		$detector = new Fixture_Pattern_Detector();

		$finding = $detector->evaluate( array( 'subject' => 'low-word only' ) );

		$this->assertSame( 0.75, $finding['confidence'] );
	}

	public function test_confidence_is_honoured_when_a_rule_provides_it(): void {
		$detector = new Fixture_Pattern_Detector();

		$finding = $detector->evaluate( array( 'subject' => 'high-word only' ) );

		$this->assertSame( 0.9, $finding['confidence'] );
	}

	public function test_empty_subject_short_circuits_to_null(): void {
		$detector = new Fixture_Pattern_Detector();

		$this->assertNull( $detector->evaluate( array( 'subject' => '' ) ) );
	}

	public function test_subject_is_decoded_before_matching(): void {
		$detector = new Fixture_Pattern_Detector();

		// 'high-word' percent-encoded.
		$finding = $detector->evaluate( array( 'subject' => 'high%2Dword' ) );

		$this->assertNotNull( $finding );
		$this->assertSame( 'FIX-002', $finding['detail']['rule_id'] );
	}

	public function test_oversized_subject_is_truncated_before_matching(): void {
		$detector = new Fixture_Pattern_Detector();

		// Padding pushes 'high-word' past the 4096-byte cap -- must not match.
		$subject = str_repeat( 'x', 4100 ) . 'high-word';
		$this->assertNull( $detector->evaluate( array( 'subject' => $subject ) ) );
	}

	public function test_detail_carries_ruleset_version(): void {
		$detector = new Fixture_Pattern_Detector();

		$finding = $detector->evaluate( array( 'subject' => 'high-word only' ) );

		$this->assertSame( '1', $finding['detail']['ruleset_version'] );
	}
}

final class Fixture_Pattern_Detector extends \WP_SAM\Intelligence\Detectors\Pattern_Detector {

	public function id(): string {
		return 'fixture-pattern';
	}

	public function family(): string {
		return 'fixture-pattern';
	}

	public function applicable_surfaces(): array {
		return array();
	}

	protected function subject( array $context ): string {
		return (string) ( $context['subject'] ?? '' );
	}

	protected function rules(): array {
		return array(
			array(
				'id'          => 'FIX-001',
				'pattern'     => '#low-word#',
				'severity'    => 'low',
				'description' => 'Fixture low-severity rule.',
			),
			array(
				'id'          => 'FIX-002',
				'pattern'     => '#high-word#',
				'severity'    => 'high',
				'confidence'  => 0.9,
				'description' => 'Fixture high-severity rule.',
			),
		);
	}
}
