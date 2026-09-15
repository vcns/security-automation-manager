<?php
/**
 * Unit tests for WP_SAM\Intelligence\Recommendation_Rule_Detector_Disabled_But_Firing.
 *
 * Reuses Fixture_Detector from DetectorRegistryTest.php (PHPUnit loads every
 * *Test.php file before running any test -- see Fixture_Recommendation_
 * Rule's own docblock for the same established cross-file-reuse pattern).
 *
 * Per candidate detector: Detector_Policy_Store::is_enabled() does one
 * get_row() internally; if that returns "disabled", Event_Store::
 * occurrences_since() does one get_var(); if that's > 0, this rule makes
 * its own second, separate get_row() call (via Detector_Policy_Store::get())
 * to read updated_at for evidence_changed_at -- so a firing detector
 * consumes two identical get_row() queue entries, not one.
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;
use WP_SAM\Intelligence\Detector_Registry;
use WP_SAM\Intelligence\Recommendation_Rule_Detector_Disabled_But_Firing;

class RecommendationRuleDetectorDisabledButFiringTest extends TestCase {

	private Recommendation_Rule_Detector_Disabled_But_Firing $rule;

	protected function setUp(): void {
		wp_test_reset_globals();
		Detector_Registry::reset();
		$this->rule = new Recommendation_Rule_Detector_Disabled_But_Firing();
	}

	/** @param array<string, mixed> $overrides */
	private function disabled_policy_row( array $overrides = array() ): array {
		return array_merge(
			array(
				'detector_id'    => 'fixture',
				'is_enabled'     => 0,
				'control_action' => 'observe',
				'updated_at'     => '2026-01-01 00:00:00',
			),
			$overrides
		);
	}

	public function test_no_registered_detectors_produces_no_recommendations(): void {
		$this->assertSame( array(), $this->rule->evaluate() );
	}

	public function test_an_enabled_detector_is_never_a_candidate(): void {
		Detector_Registry::register( new Fixture_Detector() );
		$GLOBALS['_wpdb_get_row'] = null; // No policy row at all -- missing row means enabled.

		$this->assertSame( array(), $this->rule->evaluate() );
	}

	public function test_a_disabled_detector_with_zero_recent_occurrences_does_not_fire(): void {
		Detector_Registry::register( new Fixture_Detector() );
		$GLOBALS['_wpdb_get_row'] = $this->disabled_policy_row();
		$GLOBALS['_wpdb_get_var'] = 0;

		$this->assertSame( array(), $this->rule->evaluate() );
	}

	public function test_a_disabled_detector_with_recent_occurrences_fires(): void {
		Detector_Registry::register( new Fixture_Detector() );
		$row                             = $this->disabled_policy_row( array( 'updated_at' => '2026-03-05 00:00:00' ) );
		$GLOBALS['_wpdb_get_row_queue']  = array( $row, $row );
		$GLOBALS['_wpdb_get_var']        = 7;

		$results = $this->rule->evaluate();

		$this->assertCount( 1, $results );
		$this->assertSame( 'detector_disabled_but_firing_fixture', $results[0]['key'] );
		$this->assertSame( 'high', $results[0]['risk'] );
		$this->assertSame( 'high', $results[0]['confidence'] );
		$this->assertTrue( $results[0]['dismissible'] );
		$this->assertSame( '2026-03-05 00:00:00', $results[0]['evidence_changed_at'] );
		$this->assertSame( 7, $results[0]['evidence']['occurrences'] );
		$this->assertStringContainsString( 'matched 7 times', $results[0]['observed'] );
	}

	public function test_why_it_matters_stays_grammatical_when_the_detector_has_no_description(): void {
		// Fixture_Detector never overrides description() -- exercises the
		// abstract base class's own '' default, which the rule must handle
		// without producing a broken sentence.
		Detector_Registry::register( new Fixture_Detector() );
		$row                            = $this->disabled_policy_row();
		$GLOBALS['_wpdb_get_row_queue'] = array( $row, $row );
		$GLOBALS['_wpdb_get_var']       = 1;

		$results = $this->rule->evaluate();

		$this->assertStringContainsString( 'A disabled detector is never evaluated at all', $results[0]['why_it_matters'] );
		$this->assertStringNotContainsString( '--  ', $results[0]['why_it_matters'] );
	}

	public function test_multiple_disabled_and_firing_detectors_each_produce_their_own_recommendation(): void {
		Detector_Registry::register( new Fixture_Detector( 'fixture-one' ) );
		Detector_Registry::register( new Fixture_Detector( 'fixture-two' ) );

		$row_one = $this->disabled_policy_row( array( 'detector_id' => 'fixture-one' ) );
		$row_two = $this->disabled_policy_row( array( 'detector_id' => 'fixture-two' ) );

		$GLOBALS['_wpdb_get_row_queue'] = array( $row_one, $row_one, $row_two, $row_two );
		$GLOBALS['_wpdb_get_var_queue'] = array( 3, 4 );

		$results = $this->rule->evaluate();

		$this->assertSame(
			array( 'detector_disabled_but_firing_fixture-one', 'detector_disabled_but_firing_fixture-two' ),
			array_column( $results, 'key' )
		);
	}
}
