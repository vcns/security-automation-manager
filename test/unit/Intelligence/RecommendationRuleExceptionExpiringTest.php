<?php
/**
 * Unit tests for WP_SAM\Intelligence\Recommendation_Rule_Exception_Expiring.
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;
use WP_SAM\Intelligence\Recommendation_Rule_Exception_Expiring;

class RecommendationRuleExceptionExpiringTest extends TestCase {

	private Recommendation_Rule_Exception_Expiring $rule;

	protected function setUp(): void {
		wp_test_reset_globals();
		$this->rule = new Recommendation_Rule_Exception_Expiring();
	}

	/** @param array<string, mixed> $overrides */
	private function exception_row( array $overrides = array() ): array {
		return array_merge(
			array(
				'control'             => 'csp_enforce',
				'surface'             => 'frontend',
				'risk_classification' => 'medium',
				'expiry_date'         => '2026-01-10 00:00:00',
			),
			$overrides
		);
	}

	public function test_does_not_fire_when_nothing_is_due_for_notice(): void {
		$GLOBALS['_wpdb_get_results'] = array();

		$this->assertSame( array(), $this->rule->evaluate() );
	}

	public function test_fires_with_the_single_exceptions_own_risk_classification(): void {
		$GLOBALS['_wpdb_get_results'] = array( $this->exception_row( array( 'risk_classification' => 'low' ) ) );

		$results = $this->rule->evaluate();

		$this->assertCount( 1, $results );
		$this->assertSame( 'exception_expiring_soon', $results[0]['key'] );
		$this->assertSame( 'low', $results[0]['risk'] );
		$this->assertFalse( $results[0]['dismissible'] );
	}

	public function test_risk_is_the_highest_among_multiple_expiring_exceptions(): void {
		$GLOBALS['_wpdb_get_results'] = array(
			$this->exception_row( array( 'risk_classification' => 'low' ) ),
			$this->exception_row( array( 'risk_classification' => 'high' ) ),
		);

		$results = $this->rule->evaluate();

		$this->assertSame( 'high', $results[0]['risk'] );
	}

	public function test_evidence_changed_at_is_the_latest_expiry_date(): void {
		$GLOBALS['_wpdb_get_results'] = array(
			$this->exception_row( array( 'expiry_date' => '2026-01-10 00:00:00' ) ),
			$this->exception_row( array( 'expiry_date' => '2026-02-20 00:00:00' ) ),
		);

		$results = $this->rule->evaluate();

		$this->assertSame( '2026-02-20 00:00:00', $results[0]['evidence_changed_at'] );
	}

	public function test_observed_text_reflects_the_count(): void {
		$GLOBALS['_wpdb_get_results'] = array(
			$this->exception_row(),
			$this->exception_row(),
		);

		$results = $this->rule->evaluate();

		$this->assertStringContainsString( '2 active exceptions expire within', $results[0]['observed'] );
	}
}
