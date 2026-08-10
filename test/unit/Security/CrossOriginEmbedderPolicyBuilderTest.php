<?php
/**
 * Unit tests for WP_SAM\Security\Cross_Origin_Embedder_Policy_Builder.
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;
use WP_SAM\Security\Cross_Origin_Embedder_Policy_Builder;

class CrossOriginEmbedderPolicyBuilderTest extends TestCase {

	protected function setUp(): void {
		wp_test_reset_globals();
	}

	/**
	 * @dataProvider valid_value_provider
	 */
	public function test_sanitize_value_accepts_each_standard_token( string $value ): void {
		$this->assertSame( $value, Cross_Origin_Embedder_Policy_Builder::sanitize_value( $value ) );
	}

	public static function valid_value_provider(): array {
		return array_map(
			static fn ( string $value ): array => array( $value ),
			Cross_Origin_Embedder_Policy_Builder::VALID_VALUES
		);
	}

	public function test_sanitize_value_is_case_insensitive(): void {
		$this->assertSame( 'require-corp', Cross_Origin_Embedder_Policy_Builder::sanitize_value( 'Require-Corp' ) );
	}

	public function test_sanitize_value_rejects_arbitrary_input(): void {
		$this->assertSame( '', Cross_Origin_Embedder_Policy_Builder::sanitize_value( 'garbage' ) );
	}

	public function test_sanitize_value_rejects_blank_input(): void {
		$this->assertSame( '', Cross_Origin_Embedder_Policy_Builder::sanitize_value( '' ) );
	}

	public function test_extract_value_reads_payload_json(): void {
		$profile = array( 'payload' => wp_json_encode( array( 'value' => 'credentialless' ) ) );
		$this->assertSame( 'credentialless', Cross_Origin_Embedder_Policy_Builder::extract_value( $profile ) );
	}

	public function test_extract_value_returns_empty_for_missing_value_key(): void {
		$profile = array( 'payload' => wp_json_encode( array() ) );
		$this->assertSame( '', Cross_Origin_Embedder_Policy_Builder::extract_value( $profile ) );
	}

	public function test_extract_value_returns_empty_for_invalid_json(): void {
		$profile = array( 'payload' => 'not json' );
		$this->assertSame( '', Cross_Origin_Embedder_Policy_Builder::extract_value( $profile ) );
	}
}
