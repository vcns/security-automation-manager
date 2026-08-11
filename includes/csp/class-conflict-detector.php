<?php
/**
 * Detects competing Content-Security-Policy headers.
 *
 * Implements §4.9 of the directive:
 *   - Detects if any other plugin or server config is emitting a CSP header
 *     that would conflict with or override this plugin's output.
 *   - Checks wp_headers filter for pre-existing CSP values.
 *   - Probes the site home URL and checks the response headers.
 *   - Logs conflicts via Audit_Log and surfaces them as admin notices.
 *
 * Multi-surface conflict detection.
 */

declare( strict_types=1 );

namespace WP_SAM\CSP;

use WP_SAM\Modules\Audit_Log;
use WP_SAM\Security\Request_Surface;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Conflict_Detector {

	private const CSP_HEADERS = array(
		'content-security-policy',
		'content-security-policy-report-only',
		'x-content-security-policy',
	);

	private Audit_Log $audit;

	public function __construct( Audit_Log $audit ) {
		$this->audit = $audit;
	}

	// ── Bootstrap ─────────────────────────────────────────────────────────────

	public function register(): void {
		// Hook late into wp_headers to detect competing CSP values already queued.
		add_filter( 'wp_headers', array( $this, 'check_headers_filter' ), PHP_INT_MAX );

		// Run a background probe once per day via a transient gate.
		add_action( 'admin_init', array( $this, 'maybe_run_probe' ) );
	}

	// ── Header filter hook ────────────────────────────────────────────────────

	/**
	 * Fired on the wp_headers filter. If a CSP header is already in the array
	 * (set by another plugin), record the conflict.
	 *
	 * @param array $headers  Associative array of header name → value.
	 * @return array          Unchanged – we only detect, never remove.
	 */
	public function check_headers_filter( array $headers ): array {
		foreach ( self::CSP_HEADERS as $key ) {
			$values = $this->get_response_header_values( $headers, $key );
			if ( ! empty( $values ) ) {
				$this->record_conflict(
					'header_filter',
					$key,
					substr( implode( ' | ', $values ), 0, 256 )
				);
			}
		}

		return $headers;
	}

	// ── Active probe ──────────────────────────────────────────────────────────

	/**
	 * Performs an HTTP HEAD probe to check response headers on the live site.
	 * Throttled via a 24-hour transient to avoid hammering.
	 */
	public function maybe_run_probe(): void {
		$transient_key = 'wp_sam_conflict_probe_ran';
		if ( get_transient( $transient_key ) ) {
			return;
		}
		set_transient( $transient_key, 1, DAY_IN_SECONDS );

		$this->scan_htaccess();
		$this->run_probe( get_home_url() );
	}

	/**
	 * Checks the site's Apache .htaccess file for CSP Header directives.
	 *
	 * @param string|null $path Explicit file path for tests; defaults to ABSPATH/.htaccess.
	 * @return array<int,array{line:int,header:string,value:string}> Detected directives.
	 */
	public function scan_htaccess( ?string $path = null ): array {
		$path ??= rtrim( ABSPATH, '/\\' ) . DIRECTORY_SEPARATOR . '.htaccess';
		if ( ! is_readable( $path ) ) {
			return array();
		}

		$size = filesize( $path );
		if ( false === $size || $size > 262144 ) {
			return array();
		}

		$lines = file( $path, FILE_IGNORE_NEW_LINES );
		if ( false === $lines ) {
			return array();
		}

		$found = array();
		foreach ( $lines as $index => $line ) {
			$trimmed = trim( (string) $line );
			if ( '' === $trimmed || str_starts_with( $trimmed, '#' ) ) {
				continue;
			}

			if ( ! preg_match( '/^\s*Header\s+(?:always\s+)?(?:set|add|append|merge|edit)\s+["\']?(Content-Security-Policy(?:-Report-Only)?|X-Content-Security-Policy)["\']?\b(.*)$/i', $trimmed, $matches ) ) {
				continue;
			}

			$header      = $matches[1];
			$value       = trim( $matches[2] ?? '' );
			$line_number = $index + 1;

			$this->record_conflict(
				'htaccess',
				$header,
				'line ' . $line_number . ': ' . substr( $value, 0, 220 )
			);

			$found[] = array(
				'line'   => $line_number,
				'header' => $header,
				'value'  => $value,
			);
		}

		return $found;
	}

	/**
	 * Probes a URL and checks for duplicate CSP headers.
	 *
	 * @param string $url  URL to probe.
	 * @return array       List of conflicting header names found.
	 */
	public function run_probe( string $url ): array {
		$response = wp_remote_head(
			$url,
			array(
				'timeout'   => 10,
				'sslverify' => true,
				'headers'   => array( Request_Surface::CONFLICT_PROBE_HEADER => '1' ),
			)
		);

		if ( is_wp_error( $response ) ) {
			return array();
		}

		$headers = wp_remote_retrieve_headers( $response );
		$found   = array();

		foreach ( self::CSP_HEADERS as $hdr ) {
			$values = $this->get_response_header_values( $headers, $hdr );
			if ( empty( $values ) ) {
				continue;
			}

			$source = count( $values ) > 1 ? 'probe_duplicate' : 'probe_existing';
			$this->record_conflict( $source, $hdr, implode( ' | ', array_slice( $values, 0, 2 ) ) );
			$found[] = $hdr;
		}

		return $found;
	}

	// ── Helpers ───────────────────────────────────────────────────────────────

	private function record_conflict( string $source, string $header, string $value ): void {
		$guidance = $this->get_source_guidance( $source );
		$this->audit->log(
			'conflict_detector',
			'csp_conflict',
			"Competing '{$header}' detected via {$source}. {$guidance} Value prefix: {$value}",
			'warning'
		);
	}

	/**
	 * @return array<int,string>
	 */
	private function get_response_header_values( mixed $headers, string $header ): array {
		$value = null;

		if ( is_object( $headers ) && method_exists( $headers, 'offsetGet' ) ) {
			$value = $headers->offsetGet( $header );
		} elseif ( is_array( $headers ) ) {
			foreach ( $headers as $key => $candidate ) {
				if ( strtolower( (string) $key ) === $header ) {
					$value = $candidate;
					break;
				}
			}
		}

		if ( null === $value || '' === $value ) {
			return array();
		}

		$values = is_array( $value ) ? $value : array( $value );

		return array_values(
			array_filter(
				array_map( 'strval', $values ),
				static fn( string $candidate ): bool => '' !== trim( $candidate )
			)
		);
	}

	private function get_source_guidance( string $source ): string {
		return match ( $source ) {
			'htaccess'        => 'Review Apache or LiteSpeed .htaccess Header directives before enabling enforcement here.',
			'probe_existing'  => 'The internal probe suppresses this plugin\'s own CSP header, so this is likely from web-server configuration or another security headers plugin.',
			'probe_duplicate' => 'Multiple live CSP headers are present; browsers apply all policies, which can make breakage difficult to predict.',
			'header_filter'   => 'Another WordPress plugin appears to be adding this header through wp_headers.',
			default           => 'Review other CSP emitters before enabling enforcement here.',
		};
	}
}
