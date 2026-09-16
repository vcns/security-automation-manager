<?php
/**
 * Unit tests for WP_SAM\Admin\Action_Centre.
 *
 * Reuses Fixture_Recommendation_Rule from
 * test/unit/Intelligence/RecommendationRegistryTest.php (PHPUnit loads every
 * *Test.php file before running any test, so it's available here without a
 * separate require -- see RecommendationEngineTest.php's own docblock for
 * the established precedent).
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;
use WP_SAM\Admin\Action_Centre;
use WP_SAM\Intelligence\Recommendation_Registry;

class ActionCentreTest extends TestCase {

	protected function setUp(): void {
		wp_test_reset_globals();
		Recommendation_Registry::reset();
		// No pending CSP sources / unclassified dependencies unless a test overrides it.
		$GLOBALS['_wpdb_get_var_queue'] = array( 0, 0 );
	}

	/** @param array<string, mixed> $overrides */
	private function recommendation( array $overrides = array() ): array {
		return array_merge(
			array(
				'key'                 => 'fixture_recommendation',
				'layer'               => 'Layer 4: Browser Security Policies',
				'pillar'              => 'Content Security Policy',
				'surface'             => 'frontend',
				'observed'            => 'Observed something.',
				'why_it_matters'      => 'It matters because.',
				'confidence'          => 'high',
				'risk'                => 'medium',
				'evidence'            => array(),
				'recommended_action'  => 'Do the thing.',
				'alternative_action'  => null,
				'automation_eligible' => false,
				'rollback_position'   => 'Can be reverted at any time.',
				'evidence_changed_at' => '2026-01-01 00:00:00',
				'cta_url'             => 'https://example.test/manage',
				'dismissible'         => false,
			),
			$overrides
		);
	}

	public function test_empty_state_returns_no_items(): void {
		$this->assertSame( array(), ( new Action_Centre() )->items() );
		$this->assertSame( 0, ( new Action_Centre() )->count_open() );
	}

	public function test_recommendation_normalises_to_the_action_centre_shape_with_consequence_copy(): void {
		Recommendation_Registry::register(
			new Fixture_Recommendation_Rule( array( $this->recommendation( array( 'key' => 'csp_enforce_ready_frontend' ) ) ) )
		);

		$items = ( new Action_Centre() )->items();

		$this->assertCount( 1, $items );
		$this->assertSame( 'Observed something.', $items[0]['what_found'] );
		$this->assertSame( 'It matters because.', $items[0]['why_it_matters'] );
		$this->assertSame( 'Do the thing.', $items[0]['recommended_action'] );
		$this->assertSame( 'https://example.test/manage', $items[0]['evidence_url'] );
		$this->assertSame( 'medium', $items[0]['risk'] );
		$this->assertNotSame( '', $items[0]['what_will_happen'] );
		$this->assertStringContainsString( 'enforcement', $items[0]['what_will_happen'] );
	}

	public function test_recommendation_evidence_becomes_the_technical_detail_line(): void {
		Recommendation_Registry::register(
			new Fixture_Recommendation_Rule(
				array( $this->recommendation( array( 'evidence' => array( 'violations_last_30_days' => 0, 'surface' => 'frontend' ) ) ) )
			)
		);

		$items = ( new Action_Centre() )->items();

		$this->assertStringContainsString( 'violations_last_30_days: 0', $items[0]['technical_detail'] );
		$this->assertStringContainsString( 'surface: frontend', $items[0]['technical_detail'] );
	}

	public function test_unknown_recommendation_key_gets_no_consequence_copy_rather_than_a_guess(): void {
		Recommendation_Registry::register(
			new Fixture_Recommendation_Rule( array( $this->recommendation( array( 'key' => 'something_not_in_the_lookup' ) ) ) )
		);

		$items = ( new Action_Centre() )->items();

		$this->assertSame( '', $items[0]['what_will_happen'] );
	}

	public function test_dismissed_recommendation_does_not_appear(): void {
		$GLOBALS['_wpdb_get_row'] = array( 'dismissed_at' => '2026-06-01 00:00:00' );
		Recommendation_Registry::register(
			new Fixture_Recommendation_Rule(
				array( $this->recommendation( array( 'dismissible' => true, 'evidence_changed_at' => '2026-01-01 00:00:00' ) ) )
			)
		);

		$this->assertSame( array(), ( new Action_Centre() )->items() );
	}

	public function test_pending_csp_sources_appear_as_one_aggregate_item(): void {
		$GLOBALS['_wpdb_get_var_queue'] = array( 3, 0 );

		$items = ( new Action_Centre() )->items();

		$this->assertCount( 1, $items );
		$this->assertStringContainsString( '3', $items[0]['what_found'] );
		$this->assertStringContainsString( 'tab=sources', $items[0]['evidence_url'] );
	}

	public function test_unclassified_dependencies_appear_as_one_aggregate_item(): void {
		$GLOBALS['_wpdb_get_var_queue'] = array( 0, 5 );

		$items = ( new Action_Centre() )->items();

		$this->assertCount( 1, $items );
		$this->assertStringContainsString( '5', $items[0]['what_found'] );
		$this->assertStringContainsString( 'page=security-automation-manager-scripts', $items[0]['evidence_url'] );
	}

	public function test_count_open_matches_item_count(): void {
		$GLOBALS['_wpdb_get_var_queue'] = array( 2, 1 );
		Recommendation_Registry::register(
			new Fixture_Recommendation_Rule( array( $this->recommendation() ) )
		);

		$centre = new Action_Centre();
		// count_open() re-runs items() internally with its own get_var calls,
		// so the queue needs enough entries for both invocations below.
		$GLOBALS['_wpdb_get_var_queue'] = array( 2, 1, 2, 1 );

		$this->assertSame( count( $centre->items() ), $centre->count_open() );
	}
}
