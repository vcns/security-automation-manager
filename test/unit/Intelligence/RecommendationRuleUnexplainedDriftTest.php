<?php
/**
 * Unit tests for WP_SAM\Intelligence\Recommendation_Rule_Unexplained_Drift.
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;
use WP_SAM\Intelligence\Recommendation_Rule_Unexplained_Drift;

class RecommendationRuleUnexplainedDriftTest extends TestCase {

	private Recommendation_Rule_Unexplained_Drift $rule;

	protected function setUp(): void {
		wp_test_reset_globals();
		$this->rule = new Recommendation_Rule_Unexplained_Drift();
	}

	/** @param array<string, mixed> $overrides */
	private function drift_row( array $overrides = array() ): array {
		return array_merge(
			array(
				'category'      => 'pillar',
				'surface'       => 'frontend',
				'item_key'      => 'x-frame-options.enabled',
				'risk_level'    => 'high',
				'last_seen_at'  => '2026-01-01 00:00:00',
				'disposition'   => 'unexplained',
			),
			$overrides
		);
	}

	public function test_does_not_fire_when_there_is_no_drift(): void {
		$GLOBALS['_wpdb_get_results'] = array();

		$this->assertSame( array(), $this->rule->evaluate() );
	}

	public function test_does_not_fire_for_low_or_medium_risk_drift_only(): void {
		$GLOBALS['_wpdb_get_results'] = array(
			$this->drift_row( array( 'risk_level' => 'low' ) ),
			$this->drift_row( array( 'risk_level' => 'medium' ) ),
		);

		$this->assertSame( array(), $this->rule->evaluate() );
	}

	public function test_fires_as_high_risk_when_a_high_risk_item_is_open(): void {
		$GLOBALS['_wpdb_get_results'] = array( $this->drift_row( array( 'risk_level' => 'high' ) ) );

		$results = $this->rule->evaluate();

		$this->assertCount( 1, $results );
		$this->assertSame( 'unexplained_high_risk_drift', $results[0]['key'] );
		$this->assertSame( 'high', $results[0]['risk'] );
		$this->assertFalse( $results[0]['dismissible'] );
	}

	public function test_fires_as_critical_risk_when_any_item_is_critical(): void {
		$GLOBALS['_wpdb_get_results'] = array(
			$this->drift_row( array( 'risk_level' => 'high' ) ),
			$this->drift_row( array( 'risk_level' => 'critical' ) ),
		);

		$results = $this->rule->evaluate();

		$this->assertSame( 'critical', $results[0]['risk'] );
	}

	public function test_evidence_changed_at_is_the_most_recent_last_seen_at(): void {
		$GLOBALS['_wpdb_get_results'] = array(
			$this->drift_row( array( 'last_seen_at' => '2026-01-01 00:00:00' ) ),
			$this->drift_row( array( 'last_seen_at' => '2026-06-01 00:00:00' ) ),
		);

		$results = $this->rule->evaluate();

		$this->assertSame( '2026-06-01 00:00:00', $results[0]['evidence_changed_at'] );
	}
}
