<?php
/**
 * Unit tests for WP_SAM\Intelligence\Recommendation_Engine.
 *
 * Reuses Fixture_Recommendation_Rule from RecommendationRegistryTest.php
 * (PHPUnit loads every *Test.php file before running any test, so this is
 * available without a separate require -- see Fixture_Detector's own
 * cross-file reuse for the established precedent).
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;
use WP_SAM\Intelligence\Recommendation_Engine;
use WP_SAM\Intelligence\Recommendation_Registry;

class RecommendationEngineTest extends TestCase {

	protected function setUp(): void {
		wp_test_reset_globals();
		Recommendation_Registry::reset();
	}

	/** @param array<string, mixed> $overrides */
	private function recommendation( array $overrides = array() ): array {
		return array_merge(
			array(
				'key'                  => 'fixture_recommendation',
				'layer'                => 'Layer 4: Browser Security Policies',
				'pillar'               => 'Content Security Policy',
				'surface'              => 'frontend',
				'observed'             => 'Observed something.',
				'why_it_matters'       => 'It matters because.',
				'confidence'           => 'high',
				'risk'                 => 'medium',
				'evidence'             => array(),
				'recommended_action'   => 'Do the thing.',
				'alternative_action'   => null,
				'automation_eligible'  => false,
				'rollback_position'    => 'Can be reverted at any time.',
				'evidence_changed_at'  => '2026-01-01 00:00:00',
				'cta_url'              => 'https://example.test/manage',
				'dismissible'          => false,
			),
			$overrides
		);
	}

	public function test_no_registered_rules_returns_no_recommendations(): void {
		$this->assertSame( array(), ( new Recommendation_Engine() )->get_recommendations() );
	}

	public function test_a_non_dismissible_recommendation_is_always_included(): void {
		Recommendation_Registry::register( new Fixture_Recommendation_Rule( array( $this->recommendation() ) ) );

		$results = ( new Recommendation_Engine() )->get_recommendations();

		$this->assertCount( 1, $results );
		$this->assertSame( 'fixture_recommendation', $results[0]['key'] );
	}

	public function test_a_dismissible_recommendation_with_no_stored_dismissal_is_included(): void {
		$GLOBALS['_wpdb_get_row'] = null; // Recommendation_Dismissal_Store::get() -- nothing stored.
		Recommendation_Registry::register(
			new Fixture_Recommendation_Rule( array( $this->recommendation( array( 'dismissible' => true ) ) ) )
		);

		$results = ( new Recommendation_Engine() )->get_recommendations();

		$this->assertCount( 1, $results );
	}

	public function test_a_dismissible_recommendation_is_dropped_while_the_dismissal_is_still_current(): void {
		$GLOBALS['_wpdb_get_row'] = array( 'dismissed_at' => '2026-06-01 00:00:00' ); // After evidence_changed_at.
		Recommendation_Registry::register(
			new Fixture_Recommendation_Rule(
				array( $this->recommendation( array( 'dismissible' => true, 'evidence_changed_at' => '2026-01-01 00:00:00' ) ) )
			)
		);

		$results = ( new Recommendation_Engine() )->get_recommendations();

		$this->assertSame( array(), $results );
	}

	public function test_a_dismissible_recommendation_reopens_once_evidence_is_newer_than_the_dismissal(): void {
		$GLOBALS['_wpdb_get_row'] = array( 'dismissed_at' => '2026-01-01 00:00:00' );
		Recommendation_Registry::register(
			new Fixture_Recommendation_Rule(
				array( $this->recommendation( array( 'dismissible' => true, 'evidence_changed_at' => '2026-06-01 00:00:00' ) ) )
			)
		);

		$results = ( new Recommendation_Engine() )->get_recommendations();

		$this->assertCount( 1, $results );
	}

	public function test_results_are_sorted_by_risk_descending(): void {
		Recommendation_Registry::register(
			new Fixture_Recommendation_Rule(
				array(
					$this->recommendation( array( 'key' => 'low', 'risk' => 'low' ) ),
					$this->recommendation( array( 'key' => 'critical', 'risk' => 'critical' ) ),
					$this->recommendation( array( 'key' => 'medium', 'risk' => 'medium' ) ),
					$this->recommendation( array( 'key' => 'high', 'risk' => 'high' ) ),
				)
			)
		);

		$results = ( new Recommendation_Engine() )->get_recommendations();

		$this->assertSame( array( 'critical', 'high', 'medium', 'low' ), array_column( $results, 'key' ) );
	}
}
