<?php
/**
 * HTTP Method Intelligence (.roadmap/phase3_early_plan.md §12) -- classifies
 * OPTIONS requests rather than treating every one as reconnaissance.
 *
 * Not a Pattern_Detector: there's no string to regex-match against, just a
 * header-presence check. GET/POST/HEAD/PUT/DELETE/PATCH are always expected
 * and never produce a Finding -- this only ever has something to say about
 * OPTIONS.
 *
 * A genuine browser CORS preflight always carries BOTH an Origin header and
 * an Access-Control-Request-Method header naming the method the real
 * request will use -- that's the Fetch/CORS spec's own mechanism, not a
 * heuristic, so its presence is a reliable, low-severity "this is expected"
 * signal (§12: "OPTIONS must not be considered malicious merely because it
 * is OPTIONS"). An OPTIONS request missing that pair could still be
 * legitimate (API/method-discovery tooling explicitly checking the `Allow`
 * header) or reconnaissance -- §12 lists both as real possibilities this
 * detector can't tell apart from headers alone, so that case is recorded at
 * medium severity/moderate confidence, not asserted as malicious.
 *
 * Enforce-capable (unlike most detectors) since an admin who has actually
 * seen abusive OPTIONS-probing traffic on their own site is better placed
 * to judge that than a fixed default -- still observation-only until they
 * opt in, matching every other detector's default-safety posture.
 */

declare( strict_types=1 );

namespace WP_SAM\Intelligence\Detectors;

use WP_SAM\Intelligence\Detector;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Http_Method_Detector extends Detector {

	public function id(): string {
		return 'http-method-intelligence';
	}

	public function family(): string {
		return 'http-method-intelligence';
	}

	public function applicable_surfaces(): array {
		return array();
	}

	public function allowed_control_actions(): array {
		return array( 'observe', 'enforce' );
	}

	public function evaluate( array $context ): ?array {
		if ( 'OPTIONS' !== strtoupper( (string) ( $context['method'] ?? '' ) ) ) {
			return null;
		}

		$origin = (string) ( $context['origin'] ?? '' );
		$acrm   = (string) ( $context['access_control_request_method'] ?? '' );

		if ( '' !== $origin && '' !== $acrm ) {
			return array(
				'severity'   => 'low',
				'confidence' => 0.9,
				'detail'     => array(
					'method_classification' => 'cors_preflight',
					'origin'                => $origin,
					'requested_method'      => $acrm,
					'description'           => 'OPTIONS carrying both Origin and Access-Control-Request-Method -- a genuine CORS preflight, not reconnaissance.',
				),
			);
		}

		return array(
			'severity'   => 'medium',
			'confidence' => 0.5,
			'detail'     => array(
				'method_classification' => 'unclassified_options',
				'origin'                => $origin,
				'description'           => 'OPTIONS without the Origin + Access-Control-Request-Method pair a genuine browser preflight always carries -- may be legitimate API/method-discovery tooling or reconnaissance; not confidently either.',
			),
		);
	}
}
