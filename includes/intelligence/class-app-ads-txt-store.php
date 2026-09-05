<?php
/**
 * Caches this site's own /app-ads.txt seller records (Phase 4C extension,
 * user-requested). Identical IAB Tech Lab record format and reasoning to
 * Ads_Txt_Store -- see that class's own docblock -- kept as its own class
 * (rather than a parameterised path) for the same reason every other
 * well-known-file store in this codebase is single-purpose: app-ads.txt is
 * a distinct file this site serves for mobile-app inventory, with its own
 * cache, refresh cadence, and admin-facing status independent of the
 * desktop/web ads.txt.
 */

declare( strict_types=1 );

namespace WP_SAM\Intelligence;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class App_Ads_Txt_Store {

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
		$stored = get_option( 'wp_sam_app_ads_txt_records', array() );
		return is_array( $stored ) ? $stored : array();
	}

	/**
	 * True once a fetch has ever succeeded -- deliberately NOT "is records()
	 * non-empty"; see Ads_Txt_Store::is_present()'s own docblock for why.
	 */
	public function is_present(): bool {
		return 'success' === $this->last_fetch_status();
	}

	public function last_refreshed_at(): ?string {
		$value = get_option( 'wp_sam_app_ads_txt_refreshed_at', '' );
		return '' !== $value ? (string) $value : null;
	}

	public function last_fetch_status(): string {
		return (string) get_option( 'wp_sam_app_ads_txt_last_fetch_status', '' );
	}

	/**
	 * Fetches this site's own /app-ads.txt and replaces the cached record
	 * set on success. Never touches cached records on failure.
	 *
	 * @return array{status:string, count:int, message:string}
	 */
	public function refresh(): array {
		$response = ( $this->http_get )( home_url( '/app-ads.txt' ) );

		if ( is_wp_error( $response ) ) {
			return $this->record_failure( 'Fetch failed: ' . $response->get_error_message() );
		}

		$code = (int) wp_remote_retrieve_response_code( $response );
		if ( 200 !== $code ) {
			return $this->record_failure( "Fetch returned HTTP {$code}." );
		}

		$records = $this->parse( (string) wp_remote_retrieve_body( $response ) );

		update_option( 'wp_sam_app_ads_txt_records', $records );
		update_option( 'wp_sam_app_ads_txt_refreshed_at', current_time( 'mysql', true ) );
		update_option( 'wp_sam_app_ads_txt_last_fetch_status', 'success' );

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
				continue; // Blank line, comment, or a variable assignment, not a seller record.
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
		update_option( 'wp_sam_app_ads_txt_last_fetch_status', 'failed' );

		return array(
			'status'  => 'failed',
			'count'   => count( $this->records() ),
			'message' => $message,
		);
	}
}
