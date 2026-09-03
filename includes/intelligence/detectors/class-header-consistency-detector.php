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

	public function id(): string {
		return 'header-consistency';
	}

	public function family(): string {
		return 'header-consistency';
	}

	public function applicable_surfaces(): array {
		return array();
	}

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
