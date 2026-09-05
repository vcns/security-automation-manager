<?php
/**
 * Caches this site's own /ads.txt seller records (Phase 4C extension,
 * user-requested -- see Robots_Rules_Store's own docblock for the shared
 * fetch/cache reasoning). Parses the IAB Tech Lab ads.txt v1.1 record
 * format (domain, publisher account ID, relationship, optional
 * certification authority ID) -- variable assignments (CONTACT=,
 * SUBDOMAIN=, OWNERDOMAIN=, etc.) are recognised and skipped, not parsed
 * into structured data, since nothing in this plugin currently consumes
 * them.
 *
 * Like security.txt, ads.txt has no Disallow-style directive a visitor's
 * request can violate -- it is an authorised-sellers list ad networks
 * check against, not a crawler-behaviour rule, so there is no compliance
 * detector alongside Ads_Txt_Detector's plain "was this examined" visit
 * signal. The genuine security-relevant fact here is simply the record
 * count and last-fetch outcome -- an unexpected drop to zero records, or a
 * sudden fetch failure, is the kind of unauthorised-change signal worth an
 * administrator noticing (ads.txt tampering is a known ad-fraud vector).
 */

declare( strict_types=1 );

namespace WP_SAM\Intelligence;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Ads_Txt_Store {

	private const MAX_RECORDS = 2000;

	/** @var callable(string):(array|\WP_Error) Real wp_remote_get() by default; injectable so tests never make a real HTTP call. */
	private $http_get;

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

	/** @return array<int, array{domain:string, publisher_id:string, relationship:string, certification_id:?string}> */
	public function records(): array {
		$stored = get_option( 'wp_sam_ads_txt_records', array() );
		return is_array( $stored ) ? $stored : array();
	}

	/**
	 * True once a fetch has ever succeeded -- deliberately NOT "is records()
	 * non-empty": a successful fetch that finds zero seller records (e.g.
	 * an ads.txt that is comment/variable-only) is a real, checkable state
	 * this class's own docblock treats as a tampering signal worth
	 * surfacing, which "not present" would make indistinguishable from the
	 * file never having been fetched at all.
	 */
	public function is_present(): bool {
		return 'success' === $this->last_fetch_status();
	}

	public function last_refreshed_at(): ?string {
		$value = get_option( 'wp_sam_ads_txt_refreshed_at', '' );
		return '' !== $value ? (string) $value : null;
	}

	public function last_fetch_status(): string {
		return (string) get_option( 'wp_sam_ads_txt_last_fetch_status', '' );
	}

	/**
	 * Fetches this site's own /ads.txt and replaces the cached record set
	 * on success. Never touches cached records on failure.
	 *
	 * @return array{status:string, count:int, message:string}
	 */
	public function refresh(): array {
		$response = ( $this->http_get )( home_url( '/ads.txt' ) );

		if ( is_wp_error( $response ) ) {
			return $this->record_failure( 'Fetch failed: ' . $response->get_error_message() );
		}

		$code = (int) wp_remote_retrieve_response_code( $response );
		if ( 200 !== $code ) {
			return $this->record_failure( "Fetch returned HTTP {$code}." );
		}

		$records = $this->parse( (string) wp_remote_retrieve_body( $response ) );

		update_option( 'wp_sam_ads_txt_records', $records );
		update_option( 'wp_sam_ads_txt_refreshed_at', current_time( 'mysql', true ) );
		update_option( 'wp_sam_ads_txt_last_fetch_status', 'success' );

		return array(
			'status'  => 'refreshed',
			'count'   => count( $records ),
			'message' => sprintf( 'Refreshed %d record(s).', count( $records ) ),
		);
	}

	/** @return array<int, array{domain:string, publisher_id:string, relationship:string, certification_id:?string}> */
	private function parse( string $body ): array {
		$lines = preg_split( '/\r\n|\r|\n/', $body );
		if ( false === $lines ) {
			return array();
		}

		$records = array();
		foreach ( $lines as $line ) {
			$line = trim( (string) preg_replace( '/#.*$/', '', $line ) );
			if ( '' === $line || ! str_contains( $line, ',' ) ) {
				continue; // Blank line, comment, or a variable assignment (CONTACT=, SUBDOMAIN=, etc.), not a seller record.
			}

			$fields = array_map( 'trim', explode( ',', $line ) );
			if ( count( $fields ) < 3 || '' === $fields[0] || '' === $fields[1] || '' === $fields[2] ) {
				continue;
			}

			$records[] = array(
				'domain'           => $fields[0],
				'publisher_id'     => $fields[1],
				'relationship'     => strtoupper( $fields[2] ),
				'certification_id' => '' !== ( $fields[3] ?? '' ) ? $fields[3] : null,
			);

			if ( count( $records ) >= self::MAX_RECORDS ) {
				break;
			}
		}

		return $records;
	}

	/** @return array{status:string, count:int, message:string} */
	private function record_failure( string $message ): array {
		update_option( 'wp_sam_ads_txt_last_fetch_status', 'failed' );

		return array(
			'status'  => 'failed',
			'count'   => count( $this->records() ),
			'message' => $message,
		);
	}
}
