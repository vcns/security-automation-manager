<?php
/**
 * Caches this site's own security.txt (RFC 9116) fields (Phase 4C
 * extension, user-requested, alongside Robots_Rules_Store/Agents_Rules_
 * Store -- see Robots_Rules_Store's own docblock for the shared "ask the
 * site what it actually serves" fetch/cache reasoning).
 *
 * RFC 9116 names /.well-known/security.txt as the canonical location and a
 * bare /security.txt at the root as a deprecated fallback for older
 * crawlers (§3) -- this fetches the canonical location first and only
 * falls back to the root path when that request doesn't return a usable
 * file, the same preference order the RFC itself recommends.
 *
 * Unlike robots.txt/agents.txt, security.txt has no Disallow-style
 * directive a visitor's request can violate -- it is vulnerability-
 * disclosure contact metadata, not a crawler-behaviour rule, so there is
 * no compliance detector alongside Security_Txt_Detector's plain "was this
 * examined" visit signal. What IS a genuine, checkable security fact here
 * is staleness: an Expires field in the past means the file's own contents
 * say they can no longer be trusted, exactly the kind of drift an
 * administrator would otherwise have no way to notice.
 */

declare( strict_types=1 );

namespace WP_SAM\Intelligence;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Security_Txt_Store {

	private const WELL_KNOWN_PATH = '/.well-known/security.txt';
	private const LEGACY_PATH     = '/security.txt';

	/** @var callable(string):(array|\WP_Error) Real wp_remote_get() by default; injectable so tests never make a real HTTP call. */
	private $http_get;

	/**
	 * Per-request cache: is_present()/is_expired() are typically rendered
	 * on the same admin view alongside a direct fields() call, and options
	 * don't change mid-request -- avoids re-querying the same option 3
	 * times to render one status table. Populated by fields() and kept in
	 * sync by refresh() so an instance never returns stale data after
	 * writing new fields.
	 *
	 * @var array<string, array<int, string>>|null
	 */
	private ?array $fields_cache = null;

	public function __construct( ?callable $http_get = null ) {
		$this->http_get = $http_get ?? static fn ( string $url ) => wp_remote_get(
			$url,
			array(
				'timeout'    => 10,
				'sslverify'  => true,
				'user-agent' => 'WordPress/' . get_bloginfo( 'version' ) . '; VCNS-Security-Automation-Manager/' . WP_SAM_VERSION . '; ' . get_bloginfo( 'url' ),
			)
		);
	}

	/**
	 * True once a fetch has ever succeeded -- deliberately NOT "is fields()
	 * non-empty": a security.txt that returns 200 but is comment-only, or
	 * whose lines don't match the field regex, is still a successfully-
	 * fetched file, and reporting it as "not present" would be
	 * indistinguishable from the file never having been fetched at all.
	 */
	public function is_present(): bool {
		return 'success' === $this->last_fetch_status();
	}

	/** @return array<string, array<int, string>> Field name => one or more values, in file order. */
	public function fields(): array {
		if ( null === $this->fields_cache ) {
			$stored             = get_option( 'wp_sam_security_txt_fields', array() );
			$this->fields_cache = is_array( $stored ) ? $stored : array();
		}
		return $this->fields_cache;
	}

	/** False both when there is no Expires field and when it hasn't passed yet -- only a genuinely past date counts. */
	public function is_expired(): bool {
		$expires = $this->fields()['Expires'][0] ?? null;
		if ( null === $expires ) {
			return false;
		}
		$timestamp = strtotime( $expires );
		return false !== $timestamp && $timestamp < time();
	}

	public function last_refreshed_at(): ?string {
		$value = get_option( 'wp_sam_security_txt_refreshed_at', '' );
		return '' !== $value ? (string) $value : null;
	}

	public function last_fetch_status(): string {
		return (string) get_option( 'wp_sam_security_txt_last_fetch_status', '' );
	}

	/**
	 * Fetches this site's own security.txt (canonical location first, then
	 * the legacy root fallback) and replaces the cached fields on success.
	 * Never touches cached fields on failure.
	 *
	 * @return array{status:string, count:int, message:string}
	 */
	public function refresh(): array {
		$response = ( $this->http_get )( home_url( self::WELL_KNOWN_PATH ) );

		if ( is_wp_error( $response ) || 200 !== (int) wp_remote_retrieve_response_code( $response ) ) {
			$response = ( $this->http_get )( home_url( self::LEGACY_PATH ) );
		}

		if ( is_wp_error( $response ) ) {
			return $this->record_failure( 'Fetch failed: ' . $response->get_error_message() );
		}

		$code = (int) wp_remote_retrieve_response_code( $response );
		if ( 200 !== $code ) {
			return $this->record_failure( "Fetch returned HTTP {$code}." );
		}

		$fields = $this->parse( (string) wp_remote_retrieve_body( $response ) );

		update_option( 'wp_sam_security_txt_fields', $fields );
		update_option( 'wp_sam_security_txt_refreshed_at', current_time( 'mysql', true ) );
		update_option( 'wp_sam_security_txt_last_fetch_status', 'success' );
		$this->fields_cache = $fields;

		return array(
			'status'  => 'refreshed',
			'count'   => count( $fields ),
			'message' => sprintf( 'Refreshed %d field(s).', count( $fields ) ),
		);
	}

	/** @return array<string, array<int, string>> */
	private function parse( string $body ): array {
		$lines = preg_split( '/\r\n|\r|\n/', $body );
		if ( false === $lines ) {
			return array();
		}

		$fields = array();
		foreach ( $lines as $line ) {
			$line = trim( $line );
			if ( '' === $line || str_starts_with( $line, '#' ) ) {
				continue;
			}
			if ( 1 !== preg_match( '/^([A-Za-z-]+):\s*(.+)$/', $line, $matches ) ) {
				continue;
			}
			$name              = ucfirst( strtolower( $matches[1] ) );
			$fields[ $name ][] = trim( $matches[2] );
		}

		return $fields;
	}

	/** @return array{status:string, count:int, message:string} */
	private function record_failure( string $message ): array {
		update_option( 'wp_sam_security_txt_last_fetch_status', 'failed' );

		return array(
			'status'  => 'failed',
			'count'   => count( $this->fields() ),
			'message' => $message,
		);
	}
}
