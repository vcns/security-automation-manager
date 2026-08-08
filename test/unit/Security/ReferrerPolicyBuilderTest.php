<?php
/**
 * Unit tests for WP_SAM\Security\Referrer_Policy_Builder.
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;
use WP_SAM\Security\Referrer_Policy_Builder;

class ReferrerPolicyBuilderTest extends TestCase {

	protected function setUp(): void {
		wp_test_reset_globals();
	}

	public function test_default_value_is_strict_origin_when_cross_origin(): void {
		$this->assertSame( 'strict-origin-when-cross-origin', Referrer_Policy_Builder::DEFAULT_VALUE );
	}

	public function test_default_value_is_among_valid_values(): void {
		$this->assertContains( Referrer_Policy_Builder::DEFAULT_VALUE, Referrer_Policy_Builder::VALID_VALUES );
	}

	public function test_valid_values_has_all_eight_standard_tokens(): void {
		$this->assertCount( 8, Referrer_Policy_Builder::VALID_VALUES );
	}

	/**
	 * @dataProvider valid_value_provider
	 */
	public function test_sanitize_value_accepts_each_standard_token( string $value ): void {
		$this->assertSame( $value, Referrer_Policy_Builder::sanitize_value( $value ) );
	}

	public static function valid_value_provider(): array {
		return array_map(
			static fn ( string $value ): array => array( $value ),
			Referrer_Policy_Builder::VALID_VALUES
		);
	}

	public function test_sanitize_value_is_case_insensitive(): void {
		$this->assertSame( 'no-referrer', Referrer_Policy_Builder::sanitize_value( 'No-Referrer' ) );
	}

	public function test_sanitize_value_rejects_arbitrary_input(): void {
		$this->assertSame( '', Referrer_Policy_Builder::sanitize_value( 'garbage' ) );
	}

	public function test_extract_value_reads_payload_json(): void {
		$profile = array( 'payload' => wp_json_encode( array( 'value' => 'same-origin' ) ) );
		$this->assertSame( 'same-origin', Referrer_Policy_Builder::extract_value( $profile ) );
	}

	public function test_extract_value_returns_empty_for_invalid_json(): void {
		$profile = array( 'payload' => 'not json' );
		$this->assertSame( '', Referrer_Policy_Builder::extract_value( $profile ) );
	}
}
