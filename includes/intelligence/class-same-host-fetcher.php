<?php
/**
 * GET request for this site's own URLs that only follows a redirect when
 * it stays on the same host.
 *
 * wp_remote_get() follows up to five redirects by default, wherever they
 * point, and never tells the caller where it finally ended up. That is
 * wrong for a self-fetch: a site whose .htaccess sends non-approved IPs to
 * another domain would silently hand back that other site's robots.txt (or
 * front page) as if it were its own. This disables WordPress's own
 * redirect handling ('redirection' => 0) and follows each hop itself, but
 * only while the Location stays on the originally requested host --
 * compared case-insensitively and ignoring a leading "www.", so an
 * apex/www canonicalisation or an http->https upgrade still works. A
 * redirect anywhere else returns a wp_sam_offsite_redirect WP_Error
 * instead of being followed.
 *
 * That error deliberately carries only the status code, never the
 * Location. SAM knows this site's own address and nothing else: where a
 * redirect pointed is often another copy of the same site (staging and
 * production), and nothing in SAM may record, show or reason about one.
 */

declare( strict_types=1 );

namespace WP_SAM\Intelligence;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Same_Host_Fetcher {

	private const MAX_REDIRECTS = 5;

	private const REDIRECT_CODES = array( 301, 302, 303, 307, 308 );

	/** @var callable(string, array):(array|\WP_Error) Real wp_remote_get() by default; injectable so tests never make a real HTTP call. */
	private $transport;

	public function __construct( ?callable $transport = null ) {
		$this->transport = $transport ?? static fn ( string $url, array $args ) => wp_remote_get( $url, $args );
	}

	/**
	 * @param array<string, mixed> $args wp_remote_get() arguments; 'redirection' is always forced to 0.
	 * @return array|\WP_Error The final (non-redirect) response, or a WP_Error for an off-site redirect or too many redirects.
	 */
	public function get( string $url, array $args = array() ): array|\WP_Error {
		$args['redirection'] = 0;
		$origin_host         = self::normalise_host( $url );
		$current             = $url;

		for ( $redirects = 0; ; ++$redirects ) {
			$response = ( $this->transport )( $current, $args );
			if ( is_wp_error( $response ) ) {
				return $response;
			}

			$code     = (int) wp_remote_retrieve_response_code( $response );
			$location = wp_remote_retrieve_header( $response, 'location' );
			$location = trim( (string) ( is_array( $location ) ? reset( $location ) : $location ) );
			if ( ! in_array( $code, self::REDIRECT_CODES, true ) || '' === $location ) {
				return $response;
			}

			$next = self::resolve( $location, $current );
			if ( '' === $origin_host || self::normalise_host( $next ) !== $origin_host ) {
				return new \WP_Error(
					'wp_sam_offsite_redirect',
					sprintf( "Redirected away from this site (HTTP %d), so this site's own copy could not be read.", $code ),
					array( 'code' => $code )
				);
			}

			if ( $redirects >= self::MAX_REDIRECTS ) {
				return new \WP_Error(
					'wp_sam_too_many_redirects',
					sprintf( "Stopped after %d redirects on this site's own host without reaching a final page.", self::MAX_REDIRECTS )
				);
			}

			$current = $next;
		}
	}

	private static function normalise_host( string $url ): string {
		$host = strtolower( (string) wp_parse_url( $url, PHP_URL_HOST ) );
		return str_starts_with( $host, 'www.' ) ? substr( $host, 4 ) : $host;
	}

	/** Resolves a (possibly relative) Location header against the URL that returned it. */
	private static function resolve( string $location, string $base ): string {
		if ( 1 === preg_match( '#^[a-z][a-z0-9+.-]*://#i', $location ) ) {
			return $location;
		}

		$parts  = wp_parse_url( $base );
		$scheme = is_array( $parts ) && isset( $parts['scheme'] ) ? $parts['scheme'] : 'https';
		if ( str_starts_with( $location, '//' ) ) {
			return $scheme . ':' . $location;
		}

		$origin = $scheme . '://' . ( $parts['host'] ?? '' ) . ( isset( $parts['port'] ) ? ':' . $parts['port'] : '' );
		if ( str_starts_with( $location, '/' ) ) {
			return $origin . $location;
		}

		$path = $parts['path'] ?? '/';
		if ( str_starts_with( $location, '?' ) ) {
			return $origin . $path . $location;
		}
		return $origin . substr( $path, 0, (int) strrpos( $path, '/' ) + 1 ) . $location;
	}
}
