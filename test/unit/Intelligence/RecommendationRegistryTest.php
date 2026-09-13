<?php
/**
 * Unit tests for WP_SAM\Intelligence\Recommendation_Registry.
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;
use WP_SAM\Intelligence\Recommendation_Registry;
use WP_SAM\Intelligence\Recommendation_Rule;

class Fixture_Recommendation_Rule implements Recommendation_Rule {

	/** @var array<int, array<string, mixed>> */
	private array $results;

	public function __construct( array $results = array() ) {
		$this->results = $results;
	}

	public function id(): string {
		return 'fixture_rule';
	}

	public function evaluate(): array {
		return $this->results;
	}
}

class RecommendationRegistryTest extends TestCase {

	protected function setUp(): void {
		wp_test_reset_globals();
		Recommendation_Registry::reset();
	}

	public function test_starts_empty(): void {
		$this->assertSame( array(), Recommendation_Registry::all() );
	}

	public function test_register_makes_a_rule_available_via_all(): void {
		$rule = new Fixture_Recommendation_Rule();

		Recommendation_Registry::register( $rule );

		$this->assertSame( array( $rule ), Recommendation_Registry::all() );
	}

	public function test_register_defaults_registers_the_core_rule_catalogue(): void {
		Recommendation_Registry::register_defaults();

		$ids = array_map( static fn( Recommendation_Rule $rule ): string => $rule->id(), Recommendation_Registry::all() );

		$this->assertContains( 'certificate_renewal_due', $ids );
		$this->assertContains( 'unexplained_high_risk_drift', $ids );
		$this->assertContains( 'exception_expiring_soon', $ids );
	}

	public function test_register_defaults_is_idempotent(): void {
		Recommendation_Registry::register_defaults();
		$count_after_first_call = count( Recommendation_Registry::all() );

		Recommendation_Registry::register( new Fixture_Recommendation_Rule() );
		Recommendation_Registry::register_defaults(); // Second call must not wipe the manually-registered rule above, nor duplicate the defaults.

		$this->assertCount( $count_after_first_call + 1, Recommendation_Registry::all() );
	}

	public function test_register_defaults_fires_the_extension_point(): void {
		$fired = false;
		add_action(
			'wp_sam_register_recommendation_rules',
			static function () use ( &$fired ): void {
				$fired = true;
			}
		);

		Recommendation_Registry::register_defaults();

		$this->assertTrue( $fired );
	}
}
