<?php
/**
 * Unit tests for WP_SAM\Admin\Risk_Badge.
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;
use WP_SAM\Admin\Risk_Badge;

class RiskBadgeTest extends TestCase {

	public function test_plain_badge_has_no_tooltip_markup(): void {
		$html = Risk_Badge::render( 'low' );

		$this->assertStringContainsString( 'wp-sam-risk-badge risk-low', $html );
		$this->assertStringContainsString( 'Low', $html );
		$this->assertStringNotContainsString( 'wp-sam-risk-badge--has-note', $html );
		$this->assertStringNotContainsString( 'tabindex', $html );
		$this->assertStringNotContainsString( 'wp-sam-meta-popover', $html );
	}

	public function test_badge_with_note_is_a_focusable_tooltip_trigger(): void {
		$html = Risk_Badge::render( 'medium', 'Only takes effect with an approved hash.' );

		$this->assertStringContainsString( 'wp-sam-risk-badge risk-medium wp-sam-risk-badge--has-note', $html );
		$this->assertStringContainsString( 'tabindex="0"', $html );
		$this->assertStringContainsString( 'role="tooltip"', $html );
		$this->assertStringContainsString( 'Only takes effect with an approved hash.', $html );
	}

	public function test_whitespace_only_note_is_treated_as_no_note(): void {
		$html = Risk_Badge::render( 'high', "   \n  " );

		$this->assertStringNotContainsString( 'wp-sam-risk-badge--has-note', $html );
	}

	public function test_empty_level_falls_back_to_unknown(): void {
		$html = Risk_Badge::render( '' );

		$this->assertStringContainsString( 'risk-unknown', $html );
		$this->assertStringContainsString( 'Unknown', $html );
	}

	public function test_note_content_is_escaped(): void {
		$html = Risk_Badge::render( 'high', '<script>alert(1)</script>' );

		$this->assertStringNotContainsString( '<script>', $html );
		$this->assertStringContainsString( '&lt;script&gt;', $html );
	}
}
