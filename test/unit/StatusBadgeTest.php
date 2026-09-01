<?php
/**
 * Unit tests for WP_SAM\Admin\Status_Badge.
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;
use WP_SAM\Admin\Status_Badge;

class StatusBadgeTest extends TestCase {

	public function test_plain_badge_has_no_tooltip_markup(): void {
		$html = Status_Badge::render( Status_Badge::STATE_ACTIVE, 'Frontend: Active' );

		$this->assertStringContainsString( 'wp-sam-status-badge status-active', $html );
		$this->assertStringContainsString( 'Frontend: Active', $html );
		$this->assertStringNotContainsString( 'wp-sam-status-badge--has-note', $html );
		$this->assertStringNotContainsString( 'tabindex', $html );
		$this->assertStringNotContainsString( 'wp-sam-meta-popover', $html );
	}

	public function test_badge_with_note_is_a_focusable_tooltip_trigger(): void {
		$html = Status_Badge::render( Status_Badge::STATE_NOT_CONFIGURED, 'Admin: Not configured', 'No sam_pillar_profiles row exists for this surface yet.' );

		$this->assertStringContainsString( 'wp-sam-status-badge status-not-configured wp-sam-status-badge--has-note', $html );
		$this->assertStringContainsString( 'tabindex="0"', $html );
		$this->assertStringContainsString( 'role="tooltip"', $html );
		$this->assertStringContainsString( 'No sam_pillar_profiles row exists for this surface yet.', $html );
	}

	public function test_whitespace_only_note_is_treated_as_no_note(): void {
		$html = Status_Badge::render( Status_Badge::STATE_DISABLED, 'Login: Disabled', "   \n  " );

		$this->assertStringNotContainsString( 'wp-sam-status-badge--has-note', $html );
	}

	public function test_empty_state_falls_back_to_not_configured(): void {
		$html = Status_Badge::render( '', 'Api: Unknown' );

		$this->assertStringContainsString( 'status-not-configured', $html );
	}

	public function test_unrecognised_state_still_renders(): void {
		$html = Status_Badge::render( 'some-future-state', 'Frontend: Something new' );

		$this->assertStringContainsString( 'status-some-future-state', $html );
		$this->assertStringContainsString( 'Something new', $html );
	}

	public function test_note_content_is_escaped(): void {
		$html = Status_Badge::render( Status_Badge::STATE_ACTIVE, 'Frontend: Active', '<script>alert(1)</script>' );

		$this->assertStringNotContainsString( '<script>', $html );
		$this->assertStringContainsString( '&lt;script&gt;', $html );
	}

	public function test_render_automation_emits_verbatim_label_with_automation_modifier(): void {
		$html = Status_Badge::render_automation( 'Frontend: Automatic (with high approvals only)' );

		$this->assertStringContainsString( 'wp-sam-status-badge wp-sam-status-badge--automation', $html );
		$this->assertStringContainsString( 'Frontend: Automatic (with high approvals only)', $html );
		$this->assertStringNotContainsString( 'status-active', $html );
	}
}
