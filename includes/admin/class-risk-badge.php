<?php
/**
 * Renders the small coloured "risk" badge (Low/Medium/High/Critical/Unknown)
 * used across the CSP dashboard -- Profiles tab's Bypass Best Practices
 * toggles, the Sources table, and the Policy Changes/Events table.
 *
 * Was previously hand-rolled independently at each of those three call
 * sites, with the explanation shown two different ways: a permanently
 * visible paragraph on the Profiles tab, and a bare HTML title="" attribute
 * (unstyled native browser tooltip, not keyboard-reachable) on the other
 * two. Centralised here so all three render identically: the explanation is
 * always a hover/focus popover on the badge itself, reusing the same
 * .wp-sam-meta-popover accessible-tooltip mechanism already used elsewhere
 * in the admin UI (assets/css/admin.css).
 */

declare( strict_types=1 );

namespace WP_SAM\Admin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Risk_Badge {

	/**
	 * @param string $level 'low' | 'medium' | 'high' | 'critical' | 'unknown'
	 *                      (or any value -- unrecognised levels still render
	 *                      with a neutral style rather than being rejected).
	 * @param string $note  Plain-text explanation shown as a hover/focus
	 *                      tooltip. Empty string renders a plain, non-
	 *                      interactive badge with no tooltip at all.
	 * @return string Pre-escaped HTML.
	 */
	public static function render( string $level, string $note = '' ): string {
		$level = '' !== $level ? $level : 'unknown';
		$note  = trim( $note );
		$class = 'wp-sam-risk-badge risk-' . $level;

		if ( '' === $note ) {
			return '<span class="' . esc_attr( $class ) . '">' . esc_html( ucfirst( $level ) ) . '</span>';
		}

		return '<span class="' . esc_attr( $class . ' wp-sam-risk-badge--has-note' ) . '" tabindex="0">'
			. esc_html( ucfirst( $level ) )
			. '<span class="wp-sam-meta-popover" role="tooltip">' . esc_html( $note ) . '</span>'
			. '</span>';
	}
}
