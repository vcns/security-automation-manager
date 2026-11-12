<?php
/**
 * The site surfaces Content-Security-Policy applies to.
 */

declare( strict_types=1 );

namespace WP_SAM\CSP;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Single source of truth for which surfaces CSP manages, learns from, and
 * shows in its admin UI. The REST API ('api') is deliberately not one of
 * them, although other pillars (HSTS, Permissions-Policy, Traffic Controls
 * and so on) still treat it as a surface: WordPress serves a REST request
 * from inside `parse_request` (core's rest_api_loaded() answers it there
 * and exits) before `send_headers` ever fires, so a policy built for 'api'
 * is never actually sent -- and a JSON response loads no subresources, so
 * it could never produce a violation to learn from either. Existing 'api'
 * rows in CSP's tables are left in place; CSP simply no longer reads,
 * proposes into, or displays them.
 */
final class Csp_Surfaces {

	public const ALL = array( 'frontend', 'admin', 'login' );

	/**
	 * ALL as a quoted SQL list -- `'frontend', 'admin', 'login'` -- for a
	 * literal `surface IN (...)` clause. Safe to interpolate into a query:
	 * every value is the hard-coded constant above, never request input.
	 */
	public static function sql_list(): string {
		return "'" . implode( "', '", self::ALL ) . "'";
	}
}
