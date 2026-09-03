<?php
/**
 * Self-probe that reports whether Information_Masking_Builder's header
 * removals are actually taking effect on this specific install (GitHub
 * issue #220's own acceptance criterion).
 *
 * X-Powered-By and X-Pingback are removed entirely from PHP via
 * header_remove(), so a "masked" result for either is a reliable
 * confirmation. Server is a different story -- see Information_Masking_
 * Builder's own docblock -- many hosts set it at the web-server layer
 * before PHP ever runs, a layer header_remove() cannot reach or override.
 * A "present" result for Server on such a host is not a bug in this
 * plugin; it's the documented technical ceiling from issue #220, and the
 * reason this diagnostic exists at all rather than just promising the
 * toggle "works".
 *
 * Probes the site's own front page over real HTTP (home_url('/')), the
 * same "observe real behaviour rather than infer it" approach already
 * used by Robots_Rules_Store and Tor_Exit_List_Store -- the only way to
 * know what a real visitor's browser actually receives.
 */

declare( strict_types=1 );

namespace WP_SAM\Security;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Information_Masking_Diagnostic {

	public const ITEMS = array( 'x-powered-by', 'server', 'x-pingback' );

	/** @var callable(string):(array|\WP_Error) Real wp_remote_head() by default; injectable so tests never make a real HTTP call. */
	private $http_head;

	public function __construct( ?callable $http_head = null ) {
		$this->http_head = $http_head ?? static fn ( string $url ) => wp_remote_head(
			$url,
			array(
				'timeout'    => 10,
				'sslverify'  => true,
				'user-agent' => 'WordPress/' . get_bloginfo( 'version' ) . '; VCNS-Security-Automation-Manager/' . WP_SAM_VERSION . '; ' . get_bloginfo( 'url' ),
			)
		);
	}

	/**
	 * Runs the probe against the site's own front page and persists the
	 * result. A transient failure never overwrites a previous good result
	 * -- same "never revoke known-good data on a refresh failure" pattern
	 * used throughout this plugin (see Robots_Rules_Store, Tor_Exit_List_
	 * Store).
	 *
	 * @return array{status:string, results:array<string,string>, message:string}
	 */
	public function check(): array {
		$response = ( $this->http_head )( home_url( '/' ) );

		if ( is_wp_error( $response ) ) {
			return $this->record_failure( 'Probe failed: ' . $response->get_error_message() );
		}

		$code = (int) wp_remote_retrieve_response_code( $response );
		if ( $code < 200 || $code >= 300 ) {
			return $this->record_failure( "Probe returned HTTP {$code}." );
		}

		$results = array();
		foreach ( self::ITEMS as $item ) {
			$value            = wp_remote_retrieve_header( $response, $item );
			$results[ $item ] = ( is_string( $value ) && '' !== $value ) ? 'present' : 'masked';
		}

		update_option( 'wp_sam_information_masking_diagnostic', $results );
		update_option( 'wp_sam_information_masking_checked_at', current_time( 'mysql', true ) );
		update_option( 'wp_sam_information_masking_last_status', 'success' );

		return array(
			'status'  => 'checked',
			'results' => $results,
			'message' => __( 'Diagnostic check complete.', 'vcns-security-automation-manager' ),
		);
	}

	/** @return array<string,string> item => 'masked'|'present'; empty before the first check. */
	public function results(): array {
		$stored = get_option( 'wp_sam_information_masking_diagnostic', array() );
		return is_array( $stored ) ? $stored : array();
	}

	public function checked_at(): ?string {
		$value = get_option( 'wp_sam_information_masking_checked_at', '' );
		return '' !== $value ? (string) $value : null;
	}

	public function last_status(): string {
		return (string) get_option( 'wp_sam_information_masking_last_status', '' );
	}

	/** @return array{status:string, results:array<string,string>, message:string} */
	private function record_failure( string $message ): array {
		update_option( 'wp_sam_information_masking_last_status', 'failed' );

		return array(
			'status'  => 'failed',
			'results' => $this->results(),
			'message' => $message,
		);
	}
}
