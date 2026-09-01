<?php
/**
 * Resolves the requesting client's IP address for request-observation
 * purposes.
 *
 * Deliberately trusts REMOTE_ADDR only. Headers like X-Forwarded-For and
 * X-Real-IP are trivially spoofable by the client unless the web server is
 * known to sit behind a specific, configured, trusted proxy -- a
 * configuration concept that doesn't exist anywhere else in this codebase.
 * Honouring those headers without that trust boundary would let a hostile
 * request simply claim to be any IP it likes, defeating the point of
 * recording it. A trusted-proxy allowlist is a plausible future extension,
 * not something to half-build speculatively here.
 */

declare( strict_types=1 );

namespace WP_SAM\Intelligence;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Ip_Resolver {

	public static function resolve(): string {
		$candidate = isset( $_SERVER['REMOTE_ADDR'] ) ? (string) $_SERVER['REMOTE_ADDR'] : '';
		if ( '' === $candidate ) {
			return '';
		}

		$filtered = filter_var( $candidate, FILTER_VALIDATE_IP );
		return false !== $filtered ? $filtered : '';
	}
}
