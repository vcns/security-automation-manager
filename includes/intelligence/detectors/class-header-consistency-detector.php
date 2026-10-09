<?php
/**
 * Header-consistency signal (Phase 4C, .roadmap/phase3_early_plan.md §10's
 * "header consistency" signal).
 *
 * A real browser always sends an Accept-Language header alongside its
 * User-Agent -- every mainstream browser does this unconditionally, even
 * with default settings. A request claiming to be a specific, versioned
 * desktop/mobile browser (Chrome, Firefox, Edge, or Safari -- matched on
 * each browser's own version token, e.g. "Chrome/91", not the generic
 * "Safari/537.36" substring that appears in countless non-Safari WebKit
 * user agents including several legitimate crawlers) but sending no
 * Accept-Language at all is far more consistent with a script setting a
 * copy-pasted User-Agent string than an actual browser -- most HTTP
 * client libraries (curl, requests, scrapy, ...) send no Accept-Language
 * unless a caller explicitly adds one.
 *
 * Deliberately narrow: this is one reliable signal, not the full battery
 * of modern browser fingerprinting (Client Hints, Sec-Fetch-*, and
 * similar are not checked here) -- carried forward, see .roadmap/
 * phase4_plan.md's Phase 4C status.
 */

declare( strict_types=1 );

namespace WP_SAM\Intelligence\Detectors;

use WP_SAM\Intelligence\Detector;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Header_Consistency_Detector extends Detector {

	private const BROWSER_TOKEN_PATTERN = '#Chrome/\d|Firefox/\d|Edg/\d|Edge/\d|Version/\d[\d.]*\s+Safari/\d#';

	/**
	 * Returns the stable id of the header consistency detector.
	 *
	 * @return string Detector id.
	 */
	public function id(): string {
		return 'header-consistency';
	}

	/**
	 * Returns the family the header consistency detector belongs to.
	 *
	 * @return string Family label.
	 */
	public function family(): string {
		return 'header-consistency';
	}

	/**
	 * Returns the plain-language description of the header consistency detector shown in the Detectors tab.
	 *
	 * @return string Translated description.
	 */
	public function description(): string {
		return __( 'Flags a request claiming to be a specific browser but missing a header every real browser sends unconditionally.', 'vcns-security-automation-manager' );
	}

	/**
	 * Returns the surfaces the header consistency detector runs on.
	 *
	 * @return array Surface slugs, or an empty array for every surface.
	 */
	public function applicable_surfaces(): array {
		return array();
	}

	/**
	 * Flags a browser user agent that sends no Accept-Language header.
	 *
	 * @param array $context Request context built by Request_Observer.
	 * @return array|null Finding data, or null when nothing was found.
	 */
	public function evaluate( array $context ): ?array {
		$user_agent = (string) ( $context['user_agent'] ?? '' );
		if ( '' === $user_agent || 1 !== preg_match( self::BROWSER_TOKEN_PATTERN, $user_agent ) ) {
			return null;
		}

		if ( '' !== trim( (string) ( $context['accept_language'] ?? '' ) ) ) {
			return null;
		}

		return array(
			'severity'   => 'medium',
			'confidence' => 0.6,
			'detail'     => array(
				'header_signal' => 'browser_ua_missing_accept_language',
				'description'   => 'User-Agent claims a specific versioned browser, but no Accept-Language header was sent -- every mainstream browser sends one unconditionally, so this is more consistent with a script using a copy-pasted browser User-Agent than an actual browser.',
			),
		);
	}
}
