<?php
/**
 * Unit tests for WP_SAM\Security\Pillar_Header_Builder, exercised through the
 * simplest concrete subclass (X_Content_Type_Options_Builder) since the
 * storage logic under test lives entirely in the shared abstract base.
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;
use WP_SAM\Security\X_Content_Type_Options_Builder;

class PillarHeaderBuilderTest extends TestCase {

	protected function setUp(): void {
		wp_test_reset_globals();
	}

	public function test_load_profile_returns_row_from_wpdb(): void {
		$GLOBALS['_wpdb_get_row'] = array(
			'pillar'  => 'x-content-type-options',
			'surface' => 'frontend',
			'enabled' => 1,
			'payload' => '{}',
		);

		$this->assertSame( $GLOBALS['_wpdb_get_row'], $this->load_profile( 'frontend' ) );
	}

	public function test_load_profile_returns_null_when_no_row_found(): void {
		$GLOBALS['_wpdb_get_row'] = null;

		$this->assertNull( $this->load_profile( 'frontend' ) );
	}

	public function test_is_profile_active_returns_true_for_enabled_row(): void {
		$this->assertTrue( $this->is_profile_active( array( 'enabled' => 1 ) ) );
	}

	public function test_is_profile_active_false_when_disabled(): void {
		$this->assertFalse( $this->is_profile_active( array( 'enabled' => 0 ) ) );
	}

	public function test_is_profile_active_false_when_missing(): void {
		$this->assertFalse( $this->is_profile_active( array() ) );
	}

	private function load_profile( string $surface ): ?array {
		$method = new ReflectionMethod( X_Content_Type_Options_Builder::class, 'load_profile' );
		$method->setAccessible( true );
		return $method->invoke( new X_Content_Type_Options_Builder(), $surface );
	}

	private function is_profile_active( array $profile ): bool {
		$method = new ReflectionMethod( X_Content_Type_Options_Builder::class, 'is_profile_active' );
		$method->setAccessible( true );
		return $method->invoke( new X_Content_Type_Options_Builder(), $profile );
	}
}
