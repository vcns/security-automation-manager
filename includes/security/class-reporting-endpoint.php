<?php
/**
 * Resolves and emits this plugin's single shared Reporting API endpoint.
 *
 * `wp_sam_report_endpoint_url` is one site-wide override (for proxy/CDN/load
 * -balanced deployments) shared by every header this plugin can deliver
 * Reporting API violations for -- CSP's own `report-to` directive, and the
 * Cross-Origin-Opener-Policy-Report-Only / Cross-Origin-Embedder-Policy-Report-Only
 * headers. All of them register the SAME group name (GROUP_NAME) pointing at
 * the SAME URL, so whichever pillar builder emits the Reporting-Endpoints
 * header first on a given request, the value is byte-identical to what any
 * other pillar builder would have sent -- no coordination between builders
 * is needed even though each is hooked independently on `send_headers`.
 */

declare( strict_types=1 );

namespace WP_SAM\Security;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Reporting_Endpoint {

	/**
	 * Shared Reporting API group name. Referenced both by the
	 * Reporting-Endpoints header this class emits and by any directive/header
	 * attribute that names which group to report to (e.g. CSP's
	 * `report-to csp-endpoint` directive, or a future
	 * `Cross-Origin-Opener-Policy-Report-Only: ...; report-to="csp-endpoint"`).
	 * Kept as "csp-endpoint" rather than renamed for every consumer -- it is
	 * an opaque identifier, not a claim about which header it belongs to.
	 */
	public const GROUP_NAME = 'csp-endpoint';

	public static function url(): string {
		$override = trim( (string) get_option( 'wp_sam_report_endpoint_url', '' ) );
		if ( '' !== $override && self::is_allowed_url( $override ) ) {
			return esc_url_raw( $override );
		}

		if ( function_exists( 'did_action' ) && did_action( 'init' ) > 0 ) {
			return esc_url_raw( rest_url( 'sam/v1/report' ) );
		}

		return esc_url_raw( home_url( '/wp-json/sam/v1/report' ) );
	}

	public static function is_allowed_url( string $url ): bool {
		if ( preg_match( '/[\r\n"\\\\]/', $url ) ) {
			return false;
		}

		$parts = wp_parse_url( $url );
		if ( ! is_array( $parts ) ) {
			return false;
		}

		$scheme = strtolower( (string) ( $parts['scheme'] ?? '' ) );
		$host   = (string) ( $parts['host'] ?? '' );

		return '' !== $host && in_array( $scheme, array( 'http', 'https' ), true );
	}

	/**
	 * Emits the Reporting-Endpoints header and, for legacy Reporting API v0
	 * clients, the deprecated Report-To header carrying the same group/URL.
	 * Safe to call from more than one pillar builder on the same request --
	 * every call produces the same header value.
	 */
	public static function emit_headers(): void {
		$url = self::url();

		header( 'Reporting-Endpoints: ' . self::GROUP_NAME . '="' . $url . '"' );

		$report_to = wp_json_encode(
			array(
				'group'     => self::GROUP_NAME,
				'max_age'   => 86400,
				'endpoints' => array(
					array( 'url' => $url ),
				),
			)
		);
		if ( false !== $report_to ) {
			header( 'Report-To: ' . $report_to );
		}
	}
}
