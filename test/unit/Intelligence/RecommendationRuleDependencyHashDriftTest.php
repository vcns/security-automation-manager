<?php
/**
 * Unit tests for WP_SAM\Intelligence\Recommendation_Rule_Dependency_Hash_Drift.
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;
use WP_SAM\Admin\Action_Centre;
use WP_SAM\Intelligence\Recommendation_Registry;
use WP_SAM\Intelligence\Recommendation_Rule_Dependency_Hash_Drift;

class RecommendationRuleDependencyHashDriftTest extends TestCase {

	private Recommendation_Rule_Dependency_Hash_Drift $rule;

	protected function setUp(): void {
		wp_test_reset_globals();
		Recommendation_Registry::reset();
		$this->rule = new Recommendation_Rule_Dependency_Hash_Drift();
	}

	protected function tearDown(): void {
		Recommendation_Registry::reset();
	}

	/** @param array<string, mixed> $overrides */
	private function drifted_row( array $overrides = array() ): array {
		return array_merge(
			array(
				'id'                   => 12,
				'surface'              => 'frontend',
				'resource_type'        => 'script',
				'origin'               => 'https://cdn.example.net',
				'expected_sri'         => 'sha384-old',
				'pinned_url'           => 'https://cdn.example.net/lib.js',
				'last_seen_url'        => 'https://cdn.example.net/lib.js',
				'drift_detected_at'    => '2026-10-20 02:00:00',
				'drift_observed_sri'   => 'sha384-new',
				'integrity_checked_at' => '2026-10-26 02:00:00',
			),
			$overrides
		);
	}

	public function test_does_not_fire_without_drift(): void {
		$GLOBALS['_wpdb_get_results'] = array();

		$this->assertSame( array(), $this->rule->evaluate() );
	}

	public function test_only_queries_drifted_pinned_rows(): void {
		$this->rule->evaluate();

		$query = (string) $GLOBALS['_wpdb_last_get_results_query'];
		$this->assertStringContainsString( "classification = 'immutable_pinned'", $query );
		$this->assertStringContainsString( 'drift_detected_at IS NOT NULL', $query );
	}

	public function test_fires_once_per_drifted_row_as_high_risk_with_the_route_and_url(): void {
		$GLOBALS['_wpdb_get_results'] = array( $this->drifted_row(), $this->drifted_row( array( 'id' => 13, 'surface' => 'login' ) ) );

		$results = $this->rule->evaluate();

		$this->assertCount( 2, $results );
		$this->assertSame( 'dependency_sri_drift_12', $results[0]['key'] );
		$this->assertSame( 'dependency_sri_drift_13', $results[1]['key'] );
		$this->assertSame( 'high', $results[0]['risk'] );
		$this->assertFalse( $results[0]['dismissible'] );
		$this->assertFalse( $results[0]['automation_eligible'] );
		$this->assertStringContainsString( 'Pinned script hash has drifted', $results[0]['observed'] );
		$this->assertStringContainsString( 'Decide → Dependency Classification', $results[0]['recommended_action'] );
		$this->assertStringContainsString( 'integrity attribute', $results[0]['recommended_action'] );
		$this->assertSame( 'https://example.com/wp-admin/admin.php?page=security-automation-manager-scripts&tab=external', $results[0]['cta_url'] );
		$this->assertSame( 'sha384-new', $results[0]['evidence']['observed_sri'] );
		$this->assertSame( 'sha384-old', $results[0]['evidence']['pinned_sri'] );
	}

	public function test_known_vendor_drift_recommends_host_based_allowance(): void {
		$GLOBALS['_wpdb_get_results'] = array(
			$this->drifted_row(
				array(
					'origin'        => 'https://www.googletagmanager.com',
					'pinned_url'    => 'https://www.googletagmanager.com/gtm.js?id=GTM-1',
					'last_seen_url' => 'https://www.googletagmanager.com/gtm.js?id=GTM-1',
				)
			),
		);

		$result = $this->rule->evaluate()[0];

		$this->assertStringContainsString( 'Google Tag Manager', $result['recommended_action'] );
		$this->assertStringContainsString( 'Allow by host instead', $result['recommended_action'] );
		$this->assertStringContainsString( 'Decide → Dependency Classification', $result['recommended_action'] );
		$this->assertSame( 'Google Tag Manager', $result['evidence']['known_vendor'] );
	}

	public function test_surfaces_in_the_action_centre_with_consequence_copy(): void {
		$GLOBALS['_wpdb_get_results'] = array( $this->drifted_row() );
		$GLOBALS['_wpdb_get_var']     = 0;

		// Only this rule: every other default rule would read the same stub rows.
		Recommendation_Registry::register( $this->rule );
		$flag = new ReflectionProperty( Recommendation_Registry::class, 'defaults_registered' );
		$flag->setValue( null, true );

		$items = array_values(
			array_filter(
				( new Action_Centre() )->items(),
				static fn( array $item ): bool => 'dependency_sri_drift_12' === $item['key']
			)
		);

		$this->assertCount( 1, $items );
		$this->assertSame( 'high', $items[0]['risk'] );
		$this->assertStringContainsString( 'integrity attribute', $items[0]['what_will_happen'] );
	}
}
