<?php
/**
 * Renders a small "commonly recognised" label next to a discovered source
 * host on the Sources table -- display-only context for the admin doing
 * manual review, never a change to that source's computed risk_level or
 * approval_state. A well-known domain isn't inherently safe to approve
 * (a tag-manager container in particular can push arbitrary new script
 * logic after approval, entirely outside this plugin's visibility), so
 * this deliberately never feeds into Decision_Engine or auto-approval --
 * it only helps a human reviewer recognise what they're looking at faster.
 *
 * The curated list is intentionally short, not an exhaustive or
 * auto-generated directory -- extend it via the wp_sam_known_source_labels
 * filter (host => label) rather than growing this list unboundedly.
 */

declare( strict_types=1 );

namespace WP_SAM\Admin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Known_Source_Badge {

	private const LABELS = array(
		'googletagmanager.com'     => 'Google Tag Manager',
		'www.googletagmanager.com' => 'Google Tag Manager',
		'www.google-analytics.com' => 'Google Analytics',
		'analytics.google.com'     => 'Google Analytics',
		'fonts.googleapis.com'     => 'Google Fonts (stylesheet)',
		'fonts.gstatic.com'        => 'Google Fonts (font files)',
		'www.google.com'           => 'Google (e.g. reCAPTCHA)',
		'www.gstatic.com'          => 'Google static assets',
		'maps.googleapis.com'      => 'Google Maps',
		'secure.gravatar.com'      => 'Gravatar (WordPress avatars)',
		'www.gravatar.com'         => 'Gravatar (WordPress avatars)',
		'www.youtube.com'          => 'YouTube embed',
		'www.youtube-nocookie.com' => 'YouTube embed (privacy-enhanced)',
		'i.ytimg.com'              => 'YouTube thumbnails',
		'player.vimeo.com'         => 'Vimeo embed',
		'connect.facebook.net'     => 'Facebook Pixel/SDK',
		'code.jquery.com'          => 'jQuery CDN',
		'cdn.jsdelivr.net'         => 'jsDelivr CDN',
		'cdnjs.cloudflare.com'     => 'cdnjs (Cloudflare)',
	);

	/**
	 * @param string $host Lowercase hostname (as stored in
	 *                      csp_source_inventory.source_host).
	 * @return string Pre-escaped HTML, or '' when the host isn't in the
	 *                curated list -- callers can echo the result directly
	 *                with no extra markup when there's nothing to show.
	 */
	public static function render( string $host ): string {
		$labels = apply_filters( 'wp_sam_known_source_labels', self::LABELS );
		$host   = strtolower( trim( $host ) );

		if ( ! isset( $labels[ $host ] ) || '' === trim( (string) $labels[ $host ] ) ) {
			return '';
		}

		return '<span class="wp-sam-known-source-badge" tabindex="0">'
			. esc_html__( 'Known', 'vcns-security-automation-manager' )
			. '<span class="wp-sam-meta-popover" role="tooltip">' . esc_html( (string) $labels[ $host ] ) . '</span>'
			. '</span>';
	}
}
