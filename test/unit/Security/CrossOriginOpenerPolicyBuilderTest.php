<?php
/**
 * Unit tests for WP_SAM\Security\Cross_Origin_Opener_Policy_Builder.
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;
use WP_SAM\Security\Cross_Origin_Opener_Policy_Builder;

class CrossOriginOpenerPolicyBuilderTest extends TestCase {

	protected function setUp(): void {
		wp_test_reset_globals();
	}

	/**
	 * @dataProvider valid_value_provider
	 */
	public function test_sanitize_value_accepts_each_standard_token( string $value ): void {
		$this->assertSame( $value, Cross_Origin_Opener_Policy_Builder::sanitize_value( $value ) );
	}

	public static function valid_value_provider(): array {
		return array_map(
			static fn ( string $value ): array => array( $value ),
			Cross_Origin_Opener_Policy_Builder::VALID_VALUES
		);
	}

	public function test_sanitize_value_is_case_insensitive(): void {
		$this->assertSame( 'same-origin', Cross_Origin_Opener_Policy_Builder::sanitize_value( 'Same-Origin' ) );
	}

	public function test_sanitize_value_rejects_arbitrary_input(): void {
		$this->assertSame( '', Cross_Origin_Opener_Policy_Builder::sanitize_value( 'garbage' ) );
	}

	public function test_sanitize_value_rejects_blank_input(): void {
		$this->assertSame( '', Cross_Origin_Opener_Policy_Builder::sanitize_value( '' ) );
	}

	public function test_extract_value_reads_payload_json(): void {
		$profile = array( 'payload' => wp_json_encode( array( 'value' => 'same-origin-allow-popups' ) ) );
		$this->assertSame( 'same-origin-allow-popups', Cross_Origin_Opener_Policy_Builder::extract_value( $profile ) );
	}

	public function test_extract_value_returns_empty_for_missing_value_key(): void {
		$profile = array( 'payload' => wp_json_encode( array() ) );
		$this->assertSame( '', Cross_Origin_Opener_Policy_Builder::extract_value( $profile ) );
	}

	public function test_extract_value_returns_empty_for_invalid_json(): void {
		$profile = array( 'payload' => 'not json' );
		$this->assertSame( '', Cross_Origin_Opener_Policy_Builder::extract_value( $profile ) );
	}

	// ── mode ──────────────────────────────────────────────────────────────────

	/**
	 * @dataProvider valid_mode_provider
	 */
	public function test_sanitize_mode_accepts_each_valid_mode( string $mode ): void {
		$this->assertSame( $mode, Cross_Origin_Opener_Policy_Builder::sanitize_mode( $mode ) );
	}

	public static function valid_mode_provider(): array {
		return array_map(
			static fn ( string $mode ): array => array( $mode ),
			Cross_Origin_Opener_Policy_Builder::VALID_MODES
		);
	}

	public function test_sanitize_mode_is_case_insensitive(): void {
		$this->assertSame( 'report-only', Cross_Origin_Opener_Policy_Builder::sanitize_mode( 'Report-Only' ) );
	}

	public function test_sanitize_mode_rejects_arbitrary_input(): void {
		$this->assertSame( '', Cross_Origin_Opener_Policy_Builder::sanitize_mode( 'garbage' ) );
	}

	public function test_extract_mode_reads_payload_json(): void {
		$profile = array( 'payload' => wp_json_encode( array( 'mode' => 'report-only' ) ) );
		$this->assertSame( 'report-only', Cross_Origin_Opener_Policy_Builder::extract_mode( $profile ) );
	}

	public function test_extract_mode_defaults_to_enforce_when_key_missing(): void {
		// Every profile that predates the mode field was, by definition,
		// unconditionally enforcing whenever enabled -- an upgrade must not
		// silently switch it to report-only or stop emitting the header.
		$profile = array( 'payload' => wp_json_encode( array( 'value' => 'same-origin' ) ) );
		$this->assertSame( 'enforce', Cross_Origin_Opener_Policy_Builder::extract_mode( $profile ) );
	}

	public function test_extract_mode_defaults_to_enforce_for_invalid_value(): void {
		$profile = array( 'payload' => wp_json_encode( array( 'mode' => 'garbage' ) ) );
		$this->assertSame( 'enforce', Cross_Origin_Opener_Policy_Builder::extract_mode( $profile ) );
	}

	public function test_extract_mode_defaults_to_enforce_for_invalid_json(): void {
		$profile = array( 'payload' => 'not json' );
		$this->assertSame( 'enforce', Cross_Origin_Opener_Policy_Builder::extract_mode( $profile ) );
	}

	public function test_extract_mode_returns_disabled_when_explicitly_set(): void {
		$profile = array( 'payload' => wp_json_encode( array( 'mode' => 'disabled' ) ) );
		$this->assertSame( 'disabled', Cross_Origin_Opener_Policy_Builder::extract_mode( $profile ) );
	}
}
