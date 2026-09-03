<?php
/**
 * Caches this site's own effective robots.txt Disallow rules (Phase 4C,
 * .roadmap/phase4_plan.md, .roadmap/phase3_early_plan.md §10's "robots.txt
 * behaviour" signal, second half -- Robots_Txt_Detector, shipped earlier,
 * only recognised the *fetch*; this is the actual compliance check).
 *
 * Fetches /robots.txt over real HTTP (home_url()) the same way any real
 * crawler would, rather than trying to replicate WordPress core's own
 * do_robots()/robots_txt-filter resolution logic (a physical robots.txt
 * file on disk takes priority over the dynamic generator, plugins can
 * filter the output, and so on) -- asking the site what it actually
 * serves is the only way to be sure this reflects reality, matching this
 * plugin's established preference for observing real behaviour over
 * reimplementing it (see Tor_Exit_List_Store's own docblock for the same
 * reasoning applied to the Tor Project's exit list).
 *
 * Refreshed daily (Scheduler::refresh_robots_rules(), mirroring Tor_Exit_
 * List_Store's own cadence) rather than on the request path -- robots.txt
 * changes rarely, and a fetch failure never clears already-cached rules
 * (same "never revoke known-good data on a refresh failure" pattern used
 * throughout this plugin).
 *
 * Only the generic `User-agent: *` block's Disallow directives are parsed
 * -- a deliberately simple, best-effort reading of the file (it does not
 * implement the full Robots Exclusion Protocol: no per-bot-name blocks,
 * no wildcard/$ path matching, no Allow-overrides-Disallow precedence).
 * is_disallowed() is a plain string-prefix match against those rules,
 * which is what WordPress's own default robots.txt output (and the
 * overwhelming majority of real-world ones) actually needs.
 */

declare( strict_types=1 );

namespace WP_SAM\Intelligence;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Robots_Rules_Store {

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
		$stored = get_option( 'wp_sam_robots_disallow_rules', array() );
		return is_array( $stored ) ? $stored : array();
	}

	public function last_refreshed_at(): ?string {
		$value = get_option( 'wp_sam_robots_rules_refreshed_at', '' );
		return '' !== $value ? (string) $value : null;
	}

	public function last_fetch_status(): string {
		return (string) get_option( 'wp_sam_robots_rules_last_fetch_status', '' );
	}

	/**
	 * Fetches this site's own /robots.txt and replaces the cached rule set
	 * on success. Never touches cached rules on failure.
	 *
	 * @return array{status:string, count:int, message:string}
	 */
	public function refresh(): array {
		$response = ( $this->http_get )( home_url( '/robots.txt' ) );

		if ( is_wp_error( $response ) ) {
			return $this->record_failure( 'Fetch failed: ' . $response->get_error_message() );
		}

		$code = (int) wp_remote_retrieve_response_code( $response );
		if ( 200 !== $code ) {
			return $this->record_failure( "Fetch returned HTTP {$code}." );
		}

		$rules = $this->parse( (string) wp_remote_retrieve_body( $response ) );

		update_option( 'wp_sam_robots_disallow_rules', $rules );
		update_option( 'wp_sam_robots_rules_refreshed_at', current_time( 'mysql', true ) );
		update_option( 'wp_sam_robots_rules_last_fetch_status', 'success' );

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
		update_option( 'wp_sam_robots_rules_last_fetch_status', 'failed' );

		return array(
			'status'  => 'failed',
			'count'   => count( $this->rules() ),
			'message' => $message,
		);
	}
}
