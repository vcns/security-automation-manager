<?php
/**
 * Same-origin script and worker files as reviewable CSP sources.
 *
 * The default script-src, script-src-elem and worker-src carry no 'self'.
 * Scripts WordPress prints through its script functions are allowed by
 * nonce, and other inline blocks by hash. A file on this site that reaches
 * the page some other way is blocked. Examples are the first-party
 * /gtm/gtm.js that Google tag gateway serves, a script a theme template
 * hard-codes, or a service worker. Before this class nothing could ever
 * allow such a file, because both learning paths dropped every source on
 * the site's own host on the assumption that 'self' covered it.
 *
 * A blocked same-origin file in one of DIRECTIVES now becomes a For Review
 * proposal for that exact path. It is stored with source_scheme SCHEME and
 * the path in source_host. Policy_Builder turns it into this site's current
 * origin plus the path (https://example.com/gtm/gtm.js), never 'self'.
 * 'self' in script-src would let injected markup load any script-shaped
 * response from the site, including a REST API JSONP callback
 * (/wp-json/...?_jsonp=). Storing the path rather than the host keeps a
 * configuration export free of this site's hostname, so an import elsewhere
 * allows the same path on that site and names no other.
 *
 * proposable_path() refuses paths that would reopen that hole: anything
 * under the REST prefix or the uploads directory, any PHP endpoint, a
 * directory (which a CSP source would match as a prefix), the site root, a
 * request carrying a JSONP-style or rest_route query, and any character a
 * CSP path can't carry literally. That includes '%', because browsers
 * percent-decode source paths before matching, so /wp%2Djson/ would match
 * /wp-json/.
 */

declare( strict_types=1 );

namespace WP_SAM\CSP;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Same_Origin_Source {

	/** source_scheme value marking a row as a path on this site. */
	public const SCHEME = 'self';

	/** Directives whose default has no 'self', where a same-origin file is otherwise unreachable. */
	public const DIRECTIVES = array( 'script-src', 'script-src-elem', 'worker-src' );

	/** Query keys that turn a same-origin URL into a callback or REST endpoint. */
	private const REFUSED_QUERY_KEYS = array( 'rest_route', '_jsonp', 'jsonp', 'callback' );

	private const MAX_PATH_LENGTH = 255;

	/**
	 * Builds a proposal for a blocked same-origin file, or null when it can't be proposed.
	 *
	 * @param string $directive   Normalised effective directive.
	 * @param string $blocked_uri Blocked URL, already known to be on this site's host.
	 * @return array{directive:string,uri:string,scheme:string,host:string}|null
	 */
	public static function candidate( string $directive, string $blocked_uri ): ?array {
		if ( ! in_array( $directive, self::DIRECTIVES, true ) ) {
			return null;
		}

		$parsed = wp_parse_url( $blocked_uri );
		if ( ! is_array( $parsed ) ) {
			return null;
		}

		$path = self::proposable_path( (string) ( $parsed['path'] ?? '' ), (string) ( $parsed['query'] ?? '' ) );
		if ( null === $path ) {
			return null;
		}

		return array(
			'directive' => $directive,
			'uri'       => esc_url_raw( $blocked_uri ),
			'scheme'    => self::SCHEME,
			'host'      => $path,
		);
	}

	/**
	 * Returns the path when it is safe to offer as an exact-file source, otherwise null.
	 *
	 * @param string $path  URL path, starting with '/'.
	 * @param string $query URL query string, without '?'.
	 * @return string|null
	 */
	public static function proposable_path( string $path, string $query = '' ): ?string {
		if ( '' === $path || strlen( $path ) > self::MAX_PATH_LENGTH || ! str_starts_with( $path, '/' ) || str_ends_with( $path, '/' ) ) {
			return null;
		}

		if ( 1 !== preg_match( '#^[A-Za-z0-9._~/-]+$#', $path ) || str_contains( $path, '//' ) ) {
			return null;
		}

		$segments = explode( '/', strtolower( substr( $path, 1 ) ) );
		if ( in_array( '.', $segments, true ) || in_array( '..', $segments, true ) || in_array( self::rest_prefix(), $segments, true ) ) {
			return null;
		}

		$lower = strtolower( $path );
		if ( str_ends_with( $lower, '.php' ) || str_starts_with( $lower . '/', self::uploads_path() . '/' ) || str_contains( $lower, '/wp-content/uploads/' ) ) {
			return null;
		}

		if ( '' !== $query ) {
			parse_str( $query, $params );
			foreach ( self::REFUSED_QUERY_KEYS as $key ) {
				if ( array_key_exists( $key, $params ) ) {
					return null;
				}
			}
		}

		return $path;
	}

	/**
	 * The CSP source expression for a stored path: this site's origin plus the path.
	 *
	 * Re-checks the path, so a row that is no longer proposable (or was
	 * altered in the database) is left out of the header rather than emitted.
	 *
	 * @param string $path Stored source_host of a SCHEME row.
	 * @return string Source expression, or an empty string when it can't be emitted.
	 */
	public static function expression( string $path ): string {
		if ( null === self::proposable_path( $path ) ) {
			return '';
		}

		$origin = self::origin();
		return '' === $origin ? '' : $origin . $path;
	}

	/**
	 * Text for the source column, e.g. "This site: /gtm/gtm.js".
	 *
	 * @param string $path Stored source_host of a SCHEME row.
	 * @return string
	 */
	public static function label( string $path ): string {
		/* translators: %s: path of a file on this site, e.g. /gtm/gtm.js */
		return sprintf( __( 'This site: %s', 'vcns-security-automation-manager' ), $path );
	}

	/**
	 * This site's origin (scheme, host and any port) from home_url().
	 *
	 * @return string e.g. "https://example.com", or an empty string if home_url() has no host.
	 */
	private static function origin(): string {
		$parts = wp_parse_url( home_url( '/' ) );
		if ( ! is_array( $parts ) || empty( $parts['host'] ) ) {
			return '';
		}

		$scheme = strtolower( (string) ( $parts['scheme'] ?? 'https' ) );
		$origin = $scheme . '://' . strtolower( (string) $parts['host'] );
		if ( ! empty( $parts['port'] ) ) {
			$origin .= ':' . (int) $parts['port'];
		}

		return $origin;
	}

	/**
	 * The REST API's URL prefix (a path segment), "wp-json" by default.
	 *
	 * @return string
	 */
	private static function rest_prefix(): string {
		$prefix = function_exists( 'rest_get_url_prefix' ) ? (string) rest_get_url_prefix() : 'wp-json';
		$prefix = strtolower( trim( $prefix, '/' ) );
		return '' === $prefix ? 'wp-json' : $prefix;
	}

	/**
	 * Path of the uploads directory's URL, without a trailing slash.
	 *
	 * @return string e.g. "/wp-content/uploads"
	 */
	private static function uploads_path(): string {
		$path = '';
		if ( function_exists( 'wp_upload_dir' ) ) {
			$uploads = wp_upload_dir( null, false );
			$path    = (string) wp_parse_url( (string) ( $uploads['baseurl'] ?? '' ), PHP_URL_PATH );
		}

		$path = strtolower( rtrim( $path, '/' ) );
		return '' === $path ? '/wp-content/uploads' : $path;
	}
}
