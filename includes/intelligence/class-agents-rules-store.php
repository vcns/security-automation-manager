<?php
/**
 * Caches this site's own effective agents.txt Disallow rules (Phase 4C
 * extension, user-requested, alongside the existing robots.txt behaviour
 * signal). agents.txt is an emerging, not-yet-standardised convention some
 * AI-crawler operators support for scoping what an AI agent/crawler may
 * access, using the same `User-agent:` / `Disallow:` block syntax as the
 * Robots Exclusion Protocol -- see Robots_Rules_Store's own docblock for
 * why this fetches the site's own file over real HTTP rather than trying
 * to reimplement any generator logic.
 *
 * Only the generic `User-agent: *` block's Disallow directives are parsed,
 * the same deliberately-simple scope Robots_Rules_Store uses.
 */

declare( strict_types=1 );

namespace WP_SAM\Intelligence;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Agents_Rules_Store {

	private const MAX_RULES = 200;

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

	public function is_disallowed( string $path ): bool {
		if ( '' === $path ) {
			return false;
		}
		foreach ( $this->rules() as $rule ) {
			if ( '' !== $rule && str_starts_with( $path, $rule ) ) {
				return true;
			}
		}
		return false;
	}

	/** @return array<int, string> */
	public function rules(): array {
		$stored = get_option( 'wp_sam_agents_disallow_rules', array() );
		return is_array( $stored ) ? $stored : array();
	}

	public function last_refreshed_at(): ?string {
		$value = get_option( 'wp_sam_agents_rules_refreshed_at', '' );
		return '' !== $value ? (string) $value : null;
	}

	public function last_fetch_status(): string {
		return (string) get_option( 'wp_sam_agents_rules_last_fetch_status', '' );
	}

	/**
	 * Fetches this site's own /agents.txt and replaces the cached rule set
	 * on success. Never touches cached rules on failure.
	 *
	 * @return array{status:string, count:int, message:string}
	 */
	public function refresh(): array {
		$response = ( $this->http_get )( home_url( '/agents.txt' ) );

		if ( is_wp_error( $response ) ) {
			return $this->record_failure( 'Fetch failed: ' . $response->get_error_message() );
		}

		$code = (int) wp_remote_retrieve_response_code( $response );
		if ( 200 !== $code ) {
			return $this->record_failure( "Fetch returned HTTP {$code}." );
		}

		$rules = $this->parse( (string) wp_remote_retrieve_body( $response ) );

		update_option( 'wp_sam_agents_disallow_rules', $rules );
		update_option( 'wp_sam_agents_rules_refreshed_at', current_time( 'mysql', true ) );
		update_option( 'wp_sam_agents_rules_last_fetch_status', 'success' );

		return array(
			'status'  => 'refreshed',
			'count'   => count( $rules ),
			'message' => sprintf( 'Refreshed %d disallow rule(s).', count( $rules ) ),
		);
	}

	/** @return array<int, string> */
	private function parse( string $body ): array {
		$lines = preg_split( '/\r\n|\r|\n/', $body );
		if ( false === $lines ) {
			return array();
		}

		$rules             = array();
		$in_wildcard_block = false;

		foreach ( $lines as $line ) {
			$line = trim( $line );
			if ( '' === $line || str_starts_with( $line, '#' ) ) {
				continue;
			}

			if ( 1 === preg_match( '/^user-agent:\s*(.+)$/i', $line, $matches ) ) {
				$in_wildcard_block = ( '*' === trim( $matches[1] ) );
				continue;
			}

			if ( $in_wildcard_block && 1 === preg_match( '/^disallow:\s*(.*)$/i', $line, $matches ) ) {
				$rule = trim( $matches[1] );
				if ( '' !== $rule ) {
					$rules[] = $rule;
				}
			}
		}

		return array_slice( array_values( array_unique( $rules ) ), 0, self::MAX_RULES );
	}

	/** @return array{status:string, count:int, message:string} */
	private function record_failure( string $message ): array {
		update_option( 'wp_sam_agents_rules_last_fetch_status', 'failed' );

		return array(
			'status'  => 'failed',
			'count'   => count( $this->rules() ),
			'message' => $message,
		);
	}
}
