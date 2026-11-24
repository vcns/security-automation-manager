<?php
/**
 * What this site serves at /.well-known/traffic-advice, fetched daily and
 * after every save on the Well-Known Files editor, for that page's table.
 * The same presence and last-fetch record as Humans_Txt_Store, plus whether
 * the response carried the media type prefetch proxies require: a file
 * served as anything else is ignored by them (see Traffic_Advice).
 */

declare( strict_types=1 );

namespace WP_SAM\Intelligence;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Traffic_Advice_Store {

	public const CONTENT_OPTION = 'wp_sam_traffic_advice_content';

	public const REFRESHED_OPTION = 'wp_sam_traffic_advice_refreshed_at';

	public const STATUS_OPTION = 'wp_sam_traffic_advice_last_fetch_status';

	public const MEDIA_TYPE_OPTION = 'wp_sam_traffic_advice_media_type_ok';

	/** @var callable(string):(array|\WP_Error) Same_Host_Fetcher by default; injectable so tests make no HTTP call. */
	private $http_get;

	/**
	 * @param callable|null $http_get HTTP GET function.
	 */
	public function __construct( ?callable $http_get = null ) {
		$this->http_get = $http_get ?? static fn ( string $url ) => ( new Same_Host_Fetcher() )->get(
			$url,
			array(
				'timeout'    => 10,
				'sslverify'  => true,
				'user-agent' => 'WordPress/' . get_bloginfo( 'version' ) . '; VCNS-Security-Automation-Manager/' . WP_SAM_VERSION . '; ' . get_bloginfo( 'url' ),
			)
		);
	}

	/** True once a fetch has found the file. */
	public function is_present(): bool {
		return 'success' === $this->last_fetch_status();
	}

	/** The file as last fetched, or '' when it isn't there. */
	public function content(): string {
		return (string) get_option( self::CONTENT_OPTION, '' );
	}

	/** Whether the last fetch came back as application/trafficadvice+json. */
	public function has_media_type(): bool {
		return (bool) get_option( self::MEDIA_TYPE_OPTION, false );
	}

	/**
	 * What prefetch proxies, Chrome's included, take from the file.
	 *
	 * @return array{user_agent:string, disallow:bool, fraction:float}|null
	 */
	public function advice(): ?array {
		return $this->is_present() ? Traffic_Advice::advice_for_prefetch_proxies( $this->content() ) : null;
	}

	/** Time of the last fetch that got an answer, or null. */
	public function last_refreshed_at(): ?string {
		$value = get_option( self::REFRESHED_OPTION, '' );
		return '' !== $value ? (string) $value : null;
	}

	/** 'success', 'absent', 'failed', or '' before the first fetch. */
	public function last_fetch_status(): string {
		return (string) get_option( self::STATUS_OPTION, '' );
	}

	/**
	 * Fetches this site's traffic advice and records what came back. A
	 * 404 or 410 is an answer (the site has none), not a failure; a
	 * failure leaves the previous record in place.
	 *
	 * @return array{status:string, count:int, message:string}
	 */
	public function refresh(): array {
		$response = ( $this->http_get )( home_url( Traffic_Advice::PATH ) );
		if ( is_wp_error( $response ) ) {
			return $this->record_failure(
				sprintf(
					/* translators: %s: error message returned by the HTTP request */
					__( 'Fetch failed: %s', 'vcns-security-automation-manager' ),
					$response->get_error_message()
				)
			);
		}

		$code = (int) wp_remote_retrieve_response_code( $response );
		if ( 404 === $code || 410 === $code ) {
			delete_option( self::CONTENT_OPTION );
			delete_option( self::MEDIA_TYPE_OPTION );
			update_option( self::REFRESHED_OPTION, current_time( 'mysql', true ) );
			update_option( self::STATUS_OPTION, 'absent' );
			return array(
				'status'  => 'absent',
				'count'   => 0,
				'message' => "No traffic advice on this site (HTTP {$code}).",
			);
		}
		if ( 200 !== $code ) {
			return $this->record_failure(
				sprintf(
					/* translators: %d: HTTP status code */
					__( 'Fetch returned HTTP %d.', 'vcns-security-automation-manager' ),
					$code
				)
			);
		}

		$content = (string) wp_remote_retrieve_body( $response );
		update_option( self::CONTENT_OPTION, $content, false );
		update_option( self::MEDIA_TYPE_OPTION, Traffic_Advice::has_media_type( $response ), false );
		update_option( self::REFRESHED_OPTION, current_time( 'mysql', true ) );
		update_option( self::STATUS_OPTION, 'success' );

		return array(
			'status'  => 'refreshed',
			'count'   => strlen( $content ),
			'message' => __( 'Refreshed traffic advice.', 'vcns-security-automation-manager' ),
		);
	}

	/** @return array{status:string, count:int, message:string} */
	private function record_failure( string $message ): array {
		update_option( self::STATUS_OPTION, 'failed' );
		return array(
			'status'  => 'failed',
			'count'   => strlen( $this->content() ),
			'message' => $message,
		);
	}
}
