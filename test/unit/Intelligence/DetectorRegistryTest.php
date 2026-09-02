<?php
/**
 * Unit tests for WP_SAM\Intelligence\Detector_Registry.
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;
use WP_SAM\Intelligence\Detector_Registry;

class DetectorRegistryTest extends TestCase {

	protected function setUp(): void {
		wp_test_reset_globals();
		Detector_Registry::reset();
	}

	public function test_starts_empty(): void {
		$this->assertSame( array(), Detector_Registry::keys() );
		$this->assertSame( array(), Detector_Registry::all() );
	}

	public function test_register_makes_a_detector_findable_by_id(): void {
		$detector = new Fixture_Detector();

		Detector_Registry::register( $detector );

		$this->assertTrue( Detector_Registry::is_registered( 'fixture' ) );
		$this->assertSame( array( 'fixture' ), Detector_Registry::keys() );
		$this->assertSame( $detector, Detector_Registry::get( 'fixture' ) );
		$this->assertSame( array( $detector ), Detector_Registry::all() );
	}

	public function test_is_registered_is_false_for_an_unknown_id(): void {
		$this->assertFalse( Detector_Registry::is_registered( 'does-not-exist' ) );
	}

	public function test_get_returns_null_for_an_unknown_id(): void {
		$this->assertNull( Detector_Registry::get( 'does-not-exist' ) );
	}

	public function test_is_available_reflects_the_detectors_own_availability(): void {
		$available   = new Fixture_Detector();
		$unavailable = new Fixture_Detector( 'unavailable-fixture', false );

		Detector_Registry::register( $available );
		Detector_Registry::register( $unavailable );

		$this->assertTrue( Detector_Registry::is_available( 'fixture' ) );
		$this->assertFalse( Detector_Registry::is_available( 'unavailable-fixture' ) );
	}

	public function test_is_available_is_false_for_an_unregistered_id(): void {
		$this->assertFalse( Detector_Registry::is_available( 'does-not-exist' ) );
	}

	public function test_reset_clears_all_registered_state(): void {
		Detector_Registry::register( new Fixture_Detector() );
		Detector_Registry::reset();

		$this->assertSame( array(), Detector_Registry::keys() );
		$this->assertFalse( Detector_Registry::is_registered( 'fixture' ) );
	}

	public function test_register_defaults_registers_the_core_detectors(): void {
		Detector_Registry::register_defaults();

		$this->assertSame(
			array(
				'technology-mismatch',
				'command-injection',
				'sql-injection',
				'sensitive-directories',
				'sensitive-files',
				'setup-install-probes',
				'script-webshell-probes',
				'protocol-injection',
				'version-control-artefacts',
				'vulnerability-probes',
				'html-injection',
				'php-probes',
			),
			Detector_Registry::keys()
		);
	}

	public function test_register_defaults_is_idempotent(): void {
		Detector_Registry::register_defaults();
		Detector_Registry::register_defaults();

		$this->assertCount( 12, Detector_Registry::keys() );
	}

	public function test_reset_allows_register_defaults_to_repopulate(): void {
		Detector_Registry::register_defaults();
		Detector_Registry::reset();

		$this->assertSame( array(), Detector_Registry::keys() );

		Detector_Registry::register_defaults();

		$this->assertCount( 12, Detector_Registry::keys() );
	}
}

/**
 * Proves a real class -- not just a closure -- can register against
 * Detector_Registry. Never registered outside of this test file: the
 * production Detector_Registry ships empty (see its own docblock).
 */
final class Fixture_Detector extends \WP_SAM\Intelligence\Detector {

	private string $fixture_id;
	private bool $available;

	public function __construct( string $id = 'fixture', bool $available = true ) {
		$this->fixture_id = $id;
		$this->available  = $available;
	}

	public function id(): string {
		return $this->fixture_id;
	}

	public function family(): string {
		return 'fixture-family';
	}

	public function applicable_surfaces(): array {
		return array();
	}

	public function is_available(): bool {
		return $this->available;
	}

	public function evaluate( array $context ): ?array {
		return array(
			'severity' => 'low',
			'detail'   => array( 'matched' => true ),
		);
	}
}
