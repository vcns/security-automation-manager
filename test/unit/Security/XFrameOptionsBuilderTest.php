<?php
/**
 * Unit tests for WP_SAM\Security\X_Frame_Options_Builder.
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;
use WP_SAM\Security\X_Frame_Options_Builder;

class XFrameOptionsBuilderTest extends TestCase {

	protected function setUp(): void {
		wp_test_reset_globals();
	}

	public function test_sanitize_value_accepts_deny(): void {
		$this->assertSame( 'DENY', X_Frame_Options_Builder::sanitize_value( 'DENY' ) );
	}

	public function test_sanitize_value_accepts_sameorigin_case_insensitively(): void {
		$this->assertSame( 'SAMEORIGIN', X_Frame_Options_Builder::sanitize_value( 'sameorigin' ) );
	}

	public function test_sanitize_value_rejects_allow_from(): void {
		$this->assertSame( '', X_Frame_Options_Builder::sanitize_value( 'ALLOW-FROM https://example.com' ) );
	}

	public function test_sanitize_value_rejects_arbitrary_input(): void {
		$this->assertSame( '', X_Frame_Options_Builder::sanitize_value( 'garbage' ) );
	}

	public function test_sanitize_value_rejects_empty_string(): void {
		$this->assertSame( '', X_Frame_Options_Builder::sanitize_value( '' ) );
	}

	public function test_extract_value_reads_payload_json(): void {
		$profile = array( 'payload' => wp_json_encode( array( 'value' => 'DENY' ) ) );
		$this->assertSame( 'DENY', X_Frame_Options_Builder::extract_value( $profile ) );
	}

	public function test_extract_value_returns_empty_for_missing_value_key(): void {
		$profile = array( 'payload' => wp_json_encode( array() ) );
		$this->assertSame( '', X_Frame_Options_Builder::extract_value( $profile ) );
	}

	public function test_extract_value_returns_empty_for_invalid_json(): void {
		$profile = array( 'payload' => 'not json' );
		$this->assertSame( '', X_Frame_Options_Builder::extract_value( $profile ) );
	}

	public function test_extract_value_rejects_unrecognized_stored_value(): void {
		$profile = array( 'payload' => wp_json_encode( array( 'value' => 'ALLOW-FROM https://example.com' ) ) );
		$this->assertSame( '', X_Frame_Options_Builder::extract_value( $profile ) );
	}
}
