<?php
/**
 * Unit tests for WP_SAM\Admin\Known_Source_Badge.
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;
use WP_SAM\Admin\Known_Source_Badge;

class KnownSourceBadgeTest extends TestCase {

	protected function setUp(): void {
		wp_test_reset_globals();
	}

	public function test_known_host_renders_a_labelled_badge(): void {
		$html = Known_Source_Badge::render( 'googletagmanager.com' );

		$this->assertStringContainsString( 'wp-sam-known-source-badge', $html );
		$this->assertStringContainsString( 'tabindex="0"', $html );
		$this->assertStringContainsString( 'role="tooltip"', $html );
		$this->assertStringContainsString( 'Google Tag Manager', $html );
	}

	public function test_unknown_host_renders_nothing(): void {
		$html = Known_Source_Badge::render( 'some-random-vendor-cdn.example.com' );

		$this->assertSame( '', $html );
	}

	public function test_lookup_is_case_insensitive(): void {
		$html = Known_Source_Badge::render( 'FONTS.GOOGLEAPIS.COM' );

		$this->assertStringContainsString( 'Google Fonts', $html );
	}

	public function test_lookup_trims_whitespace(): void {
		$html = Known_Source_Badge::render( '  fonts.gstatic.com  ' );

		$this->assertStringContainsString( 'Google Fonts', $html );
	}

	public function test_label_content_is_escaped(): void {
		add_filter(
			'wp_sam_known_source_labels',
			static function ( array $labels ): array {
				$labels['evil.example.com'] = '<script>alert(1)</script>';
				return $labels;
			}
		);

		$html = Known_Source_Badge::render( 'evil.example.com' );

		$this->assertStringNotContainsString( '<script>', $html );
		$this->assertStringContainsString( '&lt;script&gt;', $html );
	}

	public function test_filter_can_add_a_new_known_host(): void {
		add_filter(
			'wp_sam_known_source_labels',
			static function ( array $labels ): array {
				$labels['internal-cdn.example.com'] = 'Internal CDN';
				return $labels;
			}
		);

		$html = Known_Source_Badge::render( 'internal-cdn.example.com' );

		$this->assertStringContainsString( 'Internal CDN', $html );
	}

	public function test_filter_can_remove_a_default_entry(): void {
		add_filter(
			'wp_sam_known_source_labels',
			static function ( array $labels ): array {
				unset( $labels['googletagmanager.com'] );
				return $labels;
			}
		);

		$this->assertSame( '', Known_Source_Badge::render( 'googletagmanager.com' ) );
	}
}
