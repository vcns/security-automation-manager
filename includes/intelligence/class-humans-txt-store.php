<?php
/**
 * Caches this site's own /humans.txt content (Phase 4C extension, user-
 * requested -- see Robots_Rules_Store's own docblock for the shared fetch/
 * cache reasoning).
 *
 * humans.txt is an informal credits/colophon convention with no directive
 * syntax at all -- there is nothing here to parse into a rule, so there is
 * no compliance detector alongside Humans_Txt_Detector's plain "was this
 * examined" visit signal. This store exists only to give an administrator
 * the same presence/last-fetch visibility Robots.txt Rules already gives,
 * for consistency across every well-known file this plugin tracks.
 */

declare( strict_types=1 );

namespace WP_SAM\Intelligence;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Humans_Txt_Store {

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

	/**
	 * True once a fetch has ever succeeded -- deliberately NOT "is content()
	 * non-empty": a 0-byte or whitespace-only humans.txt is a legitimate,
	 * successfully-fetched file, and reporting it as "not present" would be
	 * indistinguishable from the file never having been fetched at all.
	 */
	public function is_present(): bool {
		return 'success' === $this->last_fetch_status();
	}

	public function content(): string {
		return (string) get_option( 'wp_sam_humans_txt_content', '' );
	}

	public function last_refreshed_at(): ?string {
		$value = get_option( 'wp_sam_humans_txt_refreshed_at', '' );
		return '' !== $value ? (string) $value : null;
	}

	public function last_fetch_status(): string {
		return (string) get_option( 'wp_sam_humans_txt_last_fetch_status', '' );
	}

	/**
	 * Fetches this site's own /humans.txt and replaces the cached content
	 * on success. Never touches cached content on failure.
	 *
	 * @return array{status:string, count:int, message:string}
	 */
	public function refresh(): array {
		$response = ( $this->http_get )( home_url( '/humans.txt' ) );

		if ( is_wp_error( $response ) ) {
			return $this->record_failure( 'Fetch failed: ' . $response->get_error_message() );
		}

		$code = (int) wp_remote_retrieve_response_code( $response );
		if ( 200 !== $code ) {
			return $this->record_failure( "Fetch returned HTTP {$code}." );
		}

		$content = (string) wp_remote_retrieve_body( $response );

		update_option( 'wp_sam_humans_txt_content', $content );
		update_option( 'wp_sam_humans_txt_refreshed_at', current_time( 'mysql', true ) );
		update_option( 'wp_sam_humans_txt_last_fetch_status', 'success' );

		return array(
			'status'  => 'refreshed',
			'count'   => strlen( $content ),
			'message' => 'Refreshed humans.txt.',
		);
	}

	/** @return array{status:string, count:int, message:string} */
	private function record_failure( string $message ): array {
		update_option( 'wp_sam_humans_txt_last_fetch_status', 'failed' );

		return array(
			'status'  => 'failed',
			'count'   => strlen( $this->content() ),
			'message' => $message,
		);
	}
}
