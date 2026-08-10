<?php
/**
 * Adds rel="noopener" to front-end links that open in a new browsing
 * context, mitigating reverse tabnabbing (a target="_blank" page gaining
 * window.opener access back to this site and redirecting it to a phishing
 * page while the original tab looks untouched).
 *
 * A content rewrite, not a header -- the only pillar in this plugin that
 * modifies the HTML body rather than an HTTP header. Stored the same way
 * as the simplest header pillars (sam_pillar_profiles, enabled-only, no
 * configurable value) purely for admin-UI and storage consistency; it has
 * nothing else in common with Header_Builder, so it extends Content_Rewriter
 * instead.
 */

declare( strict_types=1 );

namespace WP_SAM\Security;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Reverse_Tabnabbing_Builder extends Content_Rewriter {

	public const PILLAR_KEY = 'reverse-tabnabbing';

	protected function is_active( string $surface ): bool {
		global $wpdb;
		$table = $wpdb->prefix . 'sam_pillar_profiles';
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$enabled = $wpdb->get_var( $wpdb->prepare( "SELECT enabled FROM {$table} WHERE pillar = %s AND surface = %s LIMIT 1", self::PILLAR_KEY, $surface ) );
		return ! empty( $enabled );
	}

	protected function rewrite( string $html, string $surface ): string {
		unset( $surface );

		// Cheap pre-check before parsing: nothing to do if there's no anchor
		// with a target attribute at all.
		if ( false === stripos( $html, '<a' ) || false === stripos( $html, 'target' ) ) {
			return $html;
		}

		return self::add_noopener( $html );
	}

	/**
	 * Adds rel="noopener" to anchors that open a new browsing context.
	 *
	 * Uses WP_HTML_Tag_Processor so surrounding markup, attribute order and
	 * attribute encoding are preserved byte-for-byte. Anchors already
	 * carrying noopener or noreferrer are left unchanged; noreferrer alone
	 * already severs window.opener access.
	 *
	 * @param string $html Completed HTML response.
	 * @return string HTML with noopener applied, or the original on any failure.
	 */
	public static function add_noopener( string $html ): string {
		if ( ! class_exists( 'WP_HTML_Tag_Processor' ) ) {
			return $html;
		}

		try {
			$processor = new \WP_HTML_Tag_Processor( $html );
			$modified  = false;

			while ( $processor->next_tag( 'a' ) ) {
				$target = $processor->get_attribute( 'target' );

				if ( ! is_string( $target ) || '_blank' !== strtolower( trim( $target ) ) ) {
					continue;
				}

				$rel = $processor->get_attribute( 'rel' );
				if ( ! is_string( $rel ) ) {
					// null (absent) or true (value-less attribute) both mean no tokens.
					$rel = '';
				}

				$tokens = preg_split( '/\s+/', strtolower( $rel ), -1, PREG_SPLIT_NO_EMPTY );
				if ( ! is_array( $tokens ) ) {
					$tokens = array();
				}

				if ( in_array( 'noopener', $tokens, true ) || in_array( 'noreferrer', $tokens, true ) ) {
					continue;
				}

				$existing = trim( $rel );
				$processor->set_attribute( 'rel', '' === $existing ? 'noopener' : $existing . ' noopener' );
				$modified = true;
			}

			if ( ! $modified ) {
				return $html;
			}

			$updated = $processor->get_updated_html();

			return '' !== $updated ? $updated : $html;
		} catch ( \Throwable $unused ) {
			return $html;
		}
	}
}
