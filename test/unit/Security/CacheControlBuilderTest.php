<?php
/**
 * Unit tests for WP_SAM\Security\Cache_Control_Builder.
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;
use WP_SAM\Security\Cache_Control_Builder;
use WP_SAM\Security\Cache_Control_Conflict_Detector;

class CacheControlBuilderTest extends TestCase {

	protected function setUp(): void {
		wp_test_reset_globals();
	}

	public function test_sanitize_value_accepts_a_known_preset(): void {
		$this->assertSame( 'no-store', Cache_Control_Builder::sanitize_value( 'no-store' ) );
	}

	public function test_sanitize_value_is_case_insensitive(): void {
		$this->assertSame( 'public-short', Cache_Control_Builder::sanitize_value( 'PUBLIC-SHORT' ) );
	}

	public function test_sanitize_value_rejects_an_unknown_preset(): void {
		$this->assertSame( '', Cache_Control_Builder::sanitize_value( 'garbage' ) );
	}

	public function test_sanitize_value_rejects_a_raw_directive_string_not_in_the_preset_list(): void {
		// The whole point of the preset model: an admin (or a tampered
		// request) cannot inject an arbitrary Cache-Control value.
		$this->assertSame( '', Cache_Control_Builder::sanitize_value( 'public, max-age=99999999' ) );
	}

	public function test_sanitize_value_rejects_blank_input(): void {
		$this->assertSame( '', Cache_Control_Builder::sanitize_value( '' ) );
	}

	public function test_extract_value_reads_payload_json(): void {
		$profile = array( 'payload' => wp_json_encode( array( 'value' => 'public-long' ) ) );
		$this->assertSame( 'public-long', Cache_Control_Builder::extract_value( $profile ) );
	}

	public function test_extract_value_returns_empty_for_missing_value_key(): void {
		$profile = array( 'payload' => wp_json_encode( array() ) );
		$this->assertSame( '', Cache_Control_Builder::extract_value( $profile ) );
	}

	public function test_extract_value_returns_empty_for_invalid_json(): void {
		$profile = array( 'payload' => 'not json' );
		$this->assertSame( '', Cache_Control_Builder::extract_value( $profile ) );
	}

	public function test_every_preset_value_is_a_non_empty_string(): void {
		foreach ( Cache_Control_Builder::PRESET_VALUES as $preset => $value ) {
			$this->assertIsString( $value, $preset );
			$this->assertNotSame( '', $value, $preset );
		}
	}

	public function test_default_value_is_itself_a_valid_preset(): void {
		$this->assertArrayHasKey( Cache_Control_Builder::DEFAULT_VALUE, Cache_Control_Builder::PRESET_VALUES );
	}

	public function test_is_profile_active_is_true_when_enabled_and_no_conflict(): void {
		$this->assertTrue( $this->is_profile_active( array( 'enabled' => 1 ) ) );
	}

	public function test_is_profile_active_is_false_when_disabled(): void {
		$this->assertFalse( $this->is_profile_active( array( 'enabled' => 0 ) ) );
	}

	/**
	 * The core of issue #221's safety requirement: a stored enabled=1 row
	 * is never sufficient on its own -- a detected conflict always wins,
	 * so this pillar can never emit a header competing with a known
	 * caching plugin or an acknowledged CDN.
	 */
	public function test_is_profile_active_is_false_when_enabled_but_a_conflict_is_detected(): void {
		update_option( Cache_Control_Conflict_Detector::CDN_ACKNOWLEDGED_OPTION, true );

		$this->assertFalse( $this->is_profile_active( array( 'enabled' => 1 ) ) );
	}

	private function is_profile_active( array $profile ): bool {
		$method = new ReflectionMethod( Cache_Control_Builder::class, 'is_profile_active' );
		$method->setAccessible( true );
		return $method->invoke( new Cache_Control_Builder(), $profile );
	}
}
