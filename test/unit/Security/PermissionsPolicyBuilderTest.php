<?php
/**
 * Unit tests for WP_SAM\Security\Permissions_Policy_Builder.
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;
use WP_SAM\Security\Permissions_Policy_Builder;

class PermissionsPolicyBuilderTest extends TestCase {

	protected function setUp(): void {
		wp_test_reset_globals();
	}

	public function test_sanitize_token_accepts_the_three_known_tokens(): void {
		$this->assertSame( 'none', Permissions_Policy_Builder::sanitize_token( 'none' ) );
		$this->assertSame( 'self', Permissions_Policy_Builder::sanitize_token( 'self' ) );
		$this->assertSame( 'all', Permissions_Policy_Builder::sanitize_token( 'all' ) );
	}

	public function test_sanitize_token_is_case_insensitive(): void {
		$this->assertSame( 'self', Permissions_Policy_Builder::sanitize_token( 'SELF' ) );
	}

	public function test_sanitize_token_rejects_arbitrary_input(): void {
		$this->assertSame( '', Permissions_Policy_Builder::sanitize_token( 'https://evil.example' ) );
		$this->assertSame( '', Permissions_Policy_Builder::sanitize_token( '' ) );
	}

	public function test_token_to_allowlist_maps_each_token(): void {
		$this->assertSame( '()', Permissions_Policy_Builder::token_to_allowlist( 'none' ) );
		$this->assertSame( '(self)', Permissions_Policy_Builder::token_to_allowlist( 'self' ) );
		$this->assertSame( '(*)', Permissions_Policy_Builder::token_to_allowlist( 'all' ) );
		$this->assertSame( '', Permissions_Policy_Builder::token_to_allowlist( 'garbage' ) );
	}

	public function test_extract_directives_reads_known_directives(): void {
		$profile = array(
			'payload' => wp_json_encode(
				array(
					'directives' => array(
						'geolocation' => 'none',
						'camera'      => 'self',
					),
				)
			),
		);

		$this->assertSame(
			array(
				'geolocation' => 'none',
				'camera'      => 'self',
			),
			Permissions_Policy_Builder::extract_directives( $profile )
		);
	}

	public function test_extract_directives_drops_unknown_directive_names(): void {
		$profile = array(
			'payload' => wp_json_encode(
				array(
					'directives' => array(
						'geolocation'        => 'self',
						'not-a-real-feature' => 'all',
					),
				)
			),
		);

		$this->assertSame( array( 'geolocation' => 'self' ), Permissions_Policy_Builder::extract_directives( $profile ) );
	}

	public function test_extract_directives_drops_invalid_tokens(): void {
		$profile = array(
			'payload' => wp_json_encode(
				array(
					'directives' => array(
						'geolocation' => 'https://evil.example',
					),
				)
			),
		);

		$this->assertSame( array(), Permissions_Policy_Builder::extract_directives( $profile ) );
	}

	public function test_extract_directives_returns_empty_for_invalid_json(): void {
		$this->assertSame( array(), Permissions_Policy_Builder::extract_directives( array( 'payload' => 'not json' ) ) );
	}

	public function test_extract_directives_returns_empty_when_directives_key_missing(): void {
		$profile = array( 'payload' => wp_json_encode( array() ) );

		$this->assertSame( array(), Permissions_Policy_Builder::extract_directives( $profile ) );
	}
}
