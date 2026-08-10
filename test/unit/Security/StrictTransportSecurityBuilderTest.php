<?php
/**
 * Unit tests for WP_SAM\Security\Strict_Transport_Security_Builder.
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;
use WP_SAM\Security\Strict_Transport_Security_Builder;

class StrictTransportSecurityBuilderTest extends TestCase {

	protected function setUp(): void {
		wp_test_reset_globals();
	}

	// ── sanitize_max_age() ────────────────────────────────────────────────────

	public function test_sanitize_max_age_accepts_value_in_range(): void {
		$this->assertSame( 86400, Strict_Transport_Security_Builder::sanitize_max_age( 86400 ) );
	}

	public function test_sanitize_max_age_clamps_negative_to_zero(): void {
		$this->assertSame( 0, Strict_Transport_Security_Builder::sanitize_max_age( -100 ) );
	}

	public function test_sanitize_max_age_clamps_to_two_year_ceiling(): void {
		$this->assertSame( 63072000, Strict_Transport_Security_Builder::sanitize_max_age( 999999999 ) );
	}

	public function test_sanitize_max_age_casts_non_numeric_input_to_zero(): void {
		$this->assertSame( 0, Strict_Transport_Security_Builder::sanitize_max_age( 'garbage' ) );
	}

	// ── preload_eligible() ────────────────────────────────────────────────────

	public function test_preload_eligible_requires_one_year_and_include_subdomains(): void {
		$this->assertTrue( Strict_Transport_Security_Builder::preload_eligible( 31536000, true ) );
	}

	public function test_preload_eligible_false_when_max_age_too_short(): void {
		$this->assertFalse( Strict_Transport_Security_Builder::preload_eligible( 31535999, true ) );
	}

	public function test_preload_eligible_false_when_include_subdomains_off(): void {
		$this->assertFalse( Strict_Transport_Security_Builder::preload_eligible( 63072000, false ) );
	}

	// ── build_header_value() ──────────────────────────────────────────────────

	public function test_build_header_value_emits_max_age_only_by_default(): void {
		$profile = array( 'payload' => wp_json_encode( array( 'max_age' => 86400 ) ) );
		$this->assertSame( 'max-age=86400', Strict_Transport_Security_Builder::build_header_value( $profile ) );
	}

	public function test_build_header_value_includes_subdomains_token(): void {
		$profile = array(
			'payload' => wp_json_encode(
				array(
					'max_age'            => 86400,
					'include_subdomains' => true,
				)
			),
		);
		$this->assertSame( 'max-age=86400; includeSubDomains', Strict_Transport_Security_Builder::build_header_value( $profile ) );
	}

	public function test_build_header_value_includes_preload_when_eligible(): void {
		$profile = array(
			'payload' => wp_json_encode(
				array(
					'max_age'            => 63072000,
					'include_subdomains' => true,
					'preload'            => true,
				)
			),
		);
		$this->assertSame( 'max-age=63072000; includeSubDomains; preload', Strict_Transport_Security_Builder::build_header_value( $profile ) );
	}

	public function test_build_header_value_drops_preload_when_max_age_too_short(): void {
		$profile = array(
			'payload' => wp_json_encode(
				array(
					'max_age'            => 86400,
					'include_subdomains' => true,
					'preload'            => true,
				)
			),
		);
		$this->assertSame( 'max-age=86400; includeSubDomains', Strict_Transport_Security_Builder::build_header_value( $profile ) );
	}

	public function test_build_header_value_drops_preload_when_include_subdomains_off(): void {
		$profile = array(
			'payload' => wp_json_encode(
				array(
					'max_age' => 63072000,
					'preload' => true,
				)
			),
		);
		$this->assertSame( 'max-age=63072000', Strict_Transport_Security_Builder::build_header_value( $profile ) );
	}

	public function test_build_header_value_defaults_max_age_when_payload_missing(): void {
		$profile = array( 'payload' => wp_json_encode( array() ) );
		$this->assertSame(
			'max-age=' . Strict_Transport_Security_Builder::DEFAULT_MAX_AGE,
			Strict_Transport_Security_Builder::build_header_value( $profile )
		);
	}

	public function test_build_header_value_returns_default_for_invalid_json(): void {
		$profile = array( 'payload' => 'not json' );
		$this->assertSame(
			'max-age=' . Strict_Transport_Security_Builder::DEFAULT_MAX_AGE,
			Strict_Transport_Security_Builder::build_header_value( $profile )
		);
	}

	// ── extract_settings() ────────────────────────────────────────────────────

	public function test_extract_settings_reads_stored_payload(): void {
		$profile = array(
			'payload' => wp_json_encode(
				array(
					'max_age'            => 604800,
					'include_subdomains' => true,
					'preload'            => false,
				)
			),
		);

		$this->assertSame(
			array(
				'max_age'            => 604800,
				'include_subdomains' => true,
				'preload'            => false,
			),
			Strict_Transport_Security_Builder::extract_settings( $profile )
		);
	}

	public function test_extract_settings_drops_preload_when_ineligible(): void {
		$profile = array(
			'payload' => wp_json_encode(
				array(
					'max_age'            => 86400,
					'include_subdomains' => false,
					'preload'            => true,
				)
			),
		);

		$settings = Strict_Transport_Security_Builder::extract_settings( $profile );
		$this->assertFalse( $settings['preload'] );
	}
}
