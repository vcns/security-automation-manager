<?php
/**
 * Unit tests for WP_SAM\Intelligence\Detector_Engine.
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;
use WP_SAM\Intelligence\Detector_Engine;
use WP_SAM\Intelligence\Detector_Registry;

class DetectorEngineTest extends TestCase {

	private Detector_Engine $engine;

	protected function setUp(): void {
		wp_test_reset_globals();
		Detector_Registry::reset();
		$this->engine = new Detector_Engine();
	}

	public function test_evaluate_returns_empty_array_on_an_empty_registry(): void {
		$this->assertSame( array(), $this->engine->evaluate( array( 'surface' => 'frontend' ) ) );
	}

	public function test_evaluate_returns_one_finding_with_correct_defaults_for_a_matching_detector(): void {
		Detector_Registry::register( new Engine_Always_Match_Detector() );

		$findings = $this->engine->evaluate( array( 'surface' => 'frontend' ) );

		$this->assertCount( 1, $findings );
		$this->assertSame( 'always-match', $findings[0]['detector_id'] );
		$this->assertSame( 'fixture-family', $findings[0]['detector_family'] );
		$this->assertSame( 'frontend', $findings[0]['surface'] );
		$this->assertSame( 'high', $findings[0]['severity'] );
		$this->assertSame( 0.9, $findings[0]['confidence'] );
		$this->assertSame( array( 'matched' => true ), $findings[0]['detail'] );
	}

	public function test_evaluate_defaults_severity_confidence_and_detail_when_a_detector_omits_them(): void {
		Detector_Registry::register( new Engine_Bare_Match_Detector() );

		$findings = $this->engine->evaluate( array( 'surface' => 'frontend' ) );

		$this->assertCount( 1, $findings );
		$this->assertSame( 'unknown', $findings[0]['severity'] );
		$this->assertNull( $findings[0]['confidence'] );
		$this->assertSame( array(), $findings[0]['detail'] );
	}

	public function test_evaluate_skips_a_detector_not_applicable_to_the_current_surface(): void {
		Detector_Registry::register( new Engine_Frontend_Only_Detector() );

		$findings = $this->engine->evaluate( array( 'surface' => 'admin' ) );

		$this->assertSame( array(), $findings );
	}

	public function test_evaluate_runs_a_detector_applicable_to_every_surface_regardless_of_current_surface(): void {
		Detector_Registry::register( new Engine_Frontend_Only_Detector() );

		$findings = $this->engine->evaluate( array( 'surface' => 'frontend' ) );

		$this->assertCount( 1, $findings );
	}

	public function test_evaluate_skips_an_unavailable_detector(): void {
		Detector_Registry::register( new Engine_Unavailable_Detector() );

		$findings = $this->engine->evaluate( array( 'surface' => 'frontend' ) );

		$this->assertSame( array(), $findings );
	}

	public function test_evaluate_skips_a_detector_that_returns_null(): void {
		Detector_Registry::register( new Engine_No_Match_Detector() );

		$findings = $this->engine->evaluate( array( 'surface' => 'frontend' ) );

		$this->assertSame( array(), $findings );
	}

	/**
	 * Fail-open regression: a throwing detector must not prevent a
	 * well-behaved detector registered alongside it from producing its
	 * Finding.
	 */
	public function test_evaluate_fails_open_when_a_detector_throws(): void {
		Detector_Registry::register( new Engine_Throwing_Detector() );
		Detector_Registry::register( new Engine_Always_Match_Detector() );

		$findings = $this->engine->evaluate( array( 'surface' => 'frontend' ) );

		$this->assertCount( 1, $findings );
		$this->assertSame( 'always-match', $findings[0]['detector_id'] );
	}
}

final class Engine_Always_Match_Detector extends \WP_SAM\Intelligence\Detector {
	public function id(): string {
		return 'always-match';
	}
	public function family(): string {
		return 'fixture-family';
	}
	public function applicable_surfaces(): array {
		return array();
	}
	public function evaluate( array $context ): ?array {
		return array(
			'severity'   => 'high',
			'confidence' => 0.9,
			'detail'     => array( 'matched' => true ),
		);
	}
}

final class Engine_Bare_Match_Detector extends \WP_SAM\Intelligence\Detector {
	public function id(): string {
		return 'bare-match';
	}
	public function family(): string {
		return 'fixture-family';
	}
	public function applicable_surfaces(): array {
		return array();
	}
	public function evaluate( array $context ): ?array {
		return array();
	}
}

final class Engine_Frontend_Only_Detector extends \WP_SAM\Intelligence\Detector {
	public function id(): string {
		return 'frontend-only';
	}
	public function family(): string {
		return 'fixture-family';
	}
	public function applicable_surfaces(): array {
		return array( 'frontend' );
	}
	public function evaluate( array $context ): ?array {
		return array();
	}
}

final class Engine_Unavailable_Detector extends \WP_SAM\Intelligence\Detector {
	public function id(): string {
		return 'unavailable';
	}
	public function family(): string {
		return 'fixture-family';
	}
	public function applicable_surfaces(): array {
		return array();
	}
	public function is_available(): bool {
		return false;
	}
	public function evaluate( array $context ): ?array {
		return array();
	}
}

final class Engine_No_Match_Detector extends \WP_SAM\Intelligence\Detector {
	public function id(): string {
		return 'no-match';
	}
	public function family(): string {
		return 'fixture-family';
	}
	public function applicable_surfaces(): array {
		return array();
	}
	public function evaluate( array $context ): ?array {
		return null;
	}
}

final class Engine_Throwing_Detector extends \WP_SAM\Intelligence\Detector {
	public function id(): string {
		return 'throwing';
	}
	public function family(): string {
		return 'fixture-family';
	}
	public function applicable_surfaces(): array {
		return array();
	}
	public function evaluate( array $context ): ?array {
		throw new \RuntimeException( 'Fixture: evaluate() failed (simulated).' );
	}
}
