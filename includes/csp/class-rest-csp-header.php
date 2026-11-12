<?php
/**
 * Sends a fixed, lock-down Content-Security-Policy on REST API responses.
 *
 * Replaces the learned "api" CSP surface, which could never work: WordPress
 * serves REST requests inside parse_request (rest_api_loaded exits there),
 * before send_headers, so Policy_Builder never sent that surface's policy;
 * and a JSON response loads no scripts, styles or images, so it could never
 * produce a violation to learn from. A JSON API needs no allowlist at all --
 * `default-src 'none'` stops anything rendering from a response someone
 * opens directly in a browser, and `frame-ancestors 'none'` stops it being
 * framed. This is the standard hardening for API responses, with nothing
 * to learn or review.
 *
 * Left alone: a response whose endpoint already set its own CSP, and one
 * whose endpoint set a non-JSON Content-Type (a file download or rendered
 * HTML, which a lock-down policy could break). Filterable
 * (`wp_sam_rest_csp_header`); return '' to send nothing.
 */

declare( strict_types=1 );

namespace WP_SAM\CSP;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Rest_Csp_Header {

	public const DEFAULT_POLICY = "default-src 'none'; frame-ancestors 'none'";

	public function register(): void {
		add_filter( 'rest_post_dispatch', array( $this, 'add_header' ), 10, 1 );
	}

	/**
	 * @param mixed $response WP_HTTP_Response (normally WP_REST_Response) from rest_post_dispatch.
	 * @return mixed The same response.
	 */
	public function add_header( mixed $response ): mixed {
		if ( ! is_object( $response ) || ! method_exists( $response, 'header' ) || ! method_exists( $response, 'get_headers' ) ) {
			return $response;
		}

		$policy = trim( (string) apply_filters( 'wp_sam_rest_csp_header', self::DEFAULT_POLICY ) );
		if ( '' === $policy ) {
			return $response;
		}

		foreach ( (array) $response->get_headers() as $name => $value ) {
			$name = strtolower( (string) $name );
			if ( 'content-security-policy' === $name ) {
				return $response;
			}
			if ( 'content-type' === $name && ! str_contains( strtolower( (string) $value ), 'json' ) ) {
				return $response;
			}
		}

		$response->header( 'Content-Security-Policy', $policy );
		return $response;
	}
}
