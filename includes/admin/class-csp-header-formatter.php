<?php
/**
 * Formats a serialised CSP header string for admin-UI display: bolds each
 * directive name, leaving its source list in normal weight, so a long
 * header (often a dozen-plus directives on one line, as shown on the CSP
 * dashboard's Policy Audit tab) reads as scannable segments instead of one
 * dense run of text.
 */

declare( strict_types=1 );

namespace WP_SAM\Admin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Csp_Header_Formatter {

	/**
	 * @param string $header A serialised CSP header value, e.g.
	 *                       "default-src 'none'; script-src 'self'".
	 * @return string Pre-escaped HTML -- every fragment is escaped
	 *                individually with esc_html() before the literal
	 *                <strong> markup is added.
	 */
	public static function render( string $header ): string {
		$clauses = array_filter( array_map( 'trim', explode( ';', $header ) ) );
		$parts   = array();

		foreach ( $clauses as $clause ) {
			$space_pos = strpos( $clause, ' ' );
			if ( false === $space_pos ) {
				// Boolean directive with no source list (e.g. upgrade-insecure-requests).
				$parts[] = '<strong>' . esc_html( $clause ) . '</strong>';
				continue;
			}
			$directive = substr( $clause, 0, $space_pos );
			$sources   = substr( $clause, $space_pos + 1 );
			$parts[]   = '<strong>' . esc_html( $directive ) . '</strong> ' . esc_html( $sources );
		}

		return implode( '; ', $parts );
	}
}
