<?php
/**
 * Renders the small coloured status badge used by the Settings/Overview
 * table's Layer 4/Layer 5 pillar rows -- modeled directly on Risk_Badge
 * (same forgiving-unrecognised-input contract, same .wp-sam-meta-popover
 * hover/focus tooltip mechanism).
 *
 * This is a display-layer vocabulary for the cross-pillar Settings table
 * only. It does not rename or replace CSP's own mode terminology
 * (csp_policy_profiles.mode, its 'enforce' CSS class, or its dedicated
 * Profiles-tab UI) -- those stay exactly as they are, since "Enforce" is
 * precise, pillar-specific terminology technical users still need there.
 */

declare( strict_types=1 );

namespace WP_SAM\Admin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Status_Badge {

	public const STATE_NOT_CONFIGURED = 'not-configured';
	public const STATE_DISABLED       = 'disabled';
	public const STATE_REPORT_ONLY    = 'report-only';
	public const STATE_ACTIVE         = 'active';

	/**
	 * @param string $state One of the STATE_* constants (an unrecognised
	 *                      state still renders, with a neutral style,
	 *                      rather than being rejected).
	 * @param string $label Visible text, e.g. "Frontend: Active".
	 * @param string $note  Optional hover/focus popover explanation. Empty
	 *                      renders a plain, non-interactive badge.
	 * @return string Pre-escaped HTML.
	 */
	public static function render( string $state, string $label, string $note = '' ): string {
		$state = '' !== $state ? $state : self::STATE_NOT_CONFIGURED;
		$note  = trim( $note );
		$class = 'wp-sam-status-badge status-' . $state;

		if ( '' === $note ) {
			return '<span class="' . esc_attr( $class ) . '">' . esc_html( $label ) . '</span>';
		}

		return '<span class="' . esc_attr( $class . ' wp-sam-status-badge--has-note' ) . '" tabindex="0">'
			. esc_html( $label )
			. '<span class="wp-sam-meta-popover" role="tooltip">' . esc_html( $note ) . '</span>'
			. '</span>';
	}

	/**
	 * CSP-only: renders a per-surface automation-mode badge. $label comes
	 * verbatim from Automation_Config::mode_label() / Automation_Mode_Registry
	 * -- no mode identifier or label text is redefined here.
	 */
	public static function render_automation( string $label ): string {
		return '<span class="wp-sam-status-badge wp-sam-status-badge--automation">' . esc_html( $label ) . '</span>';
	}
}
