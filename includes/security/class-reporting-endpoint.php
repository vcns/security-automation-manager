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

	/** Query parameter url_for_surface() adds; read back by Violation_Reporter. */
	public const SURFACE_PARAM = 'surface';

	/** Surfaces whose report URL carries a surface hint. */
	private const HINTED_SURFACES = array( 'admin', 'login' );

	/**
	 * Delegates entirely to rest_url() -- no independent opinion of its own
	 * about permalink structure, multisite subsite paths, or the REST URL
	 * prefix. get_rest_url() (which rest_url() calls) resolves those from
	 * WordPress's own URL/permalink/rewrite functions and does not require
	 * `init` to have fired; an earlier version of this method special-cased
	 * a not-yet-`init`-fired state with a hardcoded `/wp-json/...` fallback,
	 * which both hardcoded a path WordPress.org's review flagged and could
	 * silently diverge from rest_url()'s real output (a non-default REST
	 * prefix, a multisite subsite path, or plain-permalink `?rest_route=`
	 * form would all have been wrong under that fallback).
	 */
	public static function url(): string {
		if ( self::has_override() ) {
			return esc_url_raw( trim( (string) get_option( 'wp_sam_report_endpoint_url', '' ) ) );
		}

		return esc_url_raw( rest_url( 'sam/v1/report' ) );
	}

	/**
	 * The report URL a CSP header for $surface should point at: url() plus
	 * a `surface` hint on the admin and login surfaces, so
	 * Violation_Reporter::check_not_flooding() can give each surface its
	 * own per-IP budget before the body is even decoded. Without it, staff
	 * browsing wp-admin from one office IP shared a single 40-per-10s
	 * budget with their own frontend browsing, and an unlearned admin page
	 * (dozens of violations per load) exhausted it on every visit -- so
	 * admin reports were the ones answered with a 429.
	 *
	 * The frontend keeps the bare url(), byte-identical to what the
	 * COOP/COEP builders declare for the same group on the same response.
	 * An administrator-configured override URL is left untouched too: it
	 * usually fronts a proxy whose handling of an extra query parameter
	 * this plugin can't know. The hint only ever selects a throttle
	 * bucket; the stored surface still comes from the report's own
	 * document URI.
	 */
	public static function url_for_surface( string $surface ): string {
		$url = self::url();
		if ( ! in_array( $surface, self::HINTED_SURFACES, true ) || self::has_override() ) {
			return $url;
		}

		return esc_url_raw( add_query_arg( self::SURFACE_PARAM, $surface, $url ) );
	}

	/**
	 * The surface a report request claims via url_for_surface()'s hint,
	 * or 'frontend' when it carries none (or an unrecognised one). Client
	 * supplied, so only ever used to pick a throttle bucket.
	 */
	public static function surface_hint( mixed $value ): string {
		$value = is_string( $value ) ? strtolower( trim( $value ) ) : '';
		return in_array( $value, self::HINTED_SURFACES, true ) ? $value : 'frontend';
	}

	private static function has_override(): bool {
		$override = trim( (string) get_option( 'wp_sam_report_endpoint_url', '' ) );
		return '' !== $override && self::is_allowed_url( $override );
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
	 * every call for the same surface produces the same header value.
	 */
	public static function emit_headers( string $surface = 'frontend' ): void {
		foreach ( self::header_lines( $surface ) as $line ) {
			header( $line );
		}
	}

	/**
	 * The header lines emit_headers() sends, as "Name: value" strings.
	 *
	 * @return string[]
	 */
	public static function header_lines( string $surface = 'frontend' ): array {
		$url   = self::url_for_surface( $surface );
		$lines = array( 'Reporting-Endpoints: ' . self::GROUP_NAME . '="' . $url . '"' );

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
			$lines[] = 'Report-To: ' . $report_to;
		}

		return $lines;
	}
}
