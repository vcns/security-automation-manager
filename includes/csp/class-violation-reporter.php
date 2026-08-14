<?php
/**
 * CSP violation report ingestion endpoint.
 *
 * Implements §4.13 of the directive:
 *   - Handles both CSP Level 3 (application/csp-report) and legacy formats.
 *   - Deduplicates by a stable fingerprint: hash(surface + blocked_uri + violated_directive).
 *   - Stores one row per unique fingerprint, with first/last reported timestamps.
 *   - Increments occurrence_count on duplicate reports using a single database upsert.
 *   - Rate-limits storage: drops reports after 500 per hour per (surface, directive) (soft cap).
 *   - Returns 204 No Content for valid reports (browser expects no body).
 *   - Stores rollup data for administrator review and future export surfaces.
 *   - Flags a likely competing CSP header when a report's disposition doesn't
 *     match this surface's own configured mode.
 */

declare( strict_types=1 );

namespace WP_SAM\CSP;

use WP_SAM\Modules\Audit_Log;
use WP_SAM\Modules\Feature_Gate;
use WP_SAM\Security\Pillar_Violation_Store;
use WP_REST_Request;
use WP_REST_Response;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Violation_Reporter {

	private const MAX_PER_HOUR_PER_SURFACE_DIRECTIVE = 500;
	private const RATE_LIMIT_WINDOW                  = HOUR_IN_SECONDS;
	private const DISPOSITION_MISMATCH_COOLDOWN      = HOUR_IN_SECONDS;
	private const LEARNABLE_DIRECTIVES               = array(
		'script-src',
		'script-src-elem',
		'style-src',
		'style-src-elem',
		'img-src',
		'font-src',
		'connect-src',
		'frame-src',
		'media-src',
		'manifest-src',
		'worker-src',
		'child-src',
		'form-action',
	);

	/** Reporting API report `type` -> this plugin's internal pillar key. */
	private const PILLAR_REPORT_TYPES = array(
		'coop' => 'cross-origin-opener-policy',
		'coep' => 'cross-origin-embedder-policy',
	);

	private Audit_Log $audit;
	private ?Learning_Window $learning_window;
	private Policy_Change_Manager $policy_changes;
	private Pillar_Violation_Store $pillar_violations;

	/**
	 * Per-request cache of surface => expected disposition ('enforce'|'report'|null),
	 * derived from csp_policy_profiles.mode. Avoids one query per report when a
	 * single batch contains many reports for the same surface.
	 *
	 * @var array<string,string|null>
	 */
	private array $profile_mode_cache = array();

	public function __construct( Audit_Log $audit, ?Learning_Window $learning_window = null, ?Policy_Change_Manager $policy_changes = null, ?Feature_Gate $gate = null, ?Pillar_Violation_Store $pillar_violations = null ) {
		$this->audit             = $audit;
		$this->learning_window   = $learning_window;
		$this->policy_changes    = null !== $policy_changes ? $policy_changes : new Policy_Change_Manager( $audit, gate: $gate );
		$this->pillar_violations = null !== $pillar_violations ? $pillar_violations : new Pillar_Violation_Store();
	}

	// ── REST handler ──────────────────────────────────────────────────────────

	/**
	 * Handles POST /sam/v1/report (and the legacy /security-manager/v1/report alias)
	 * Accepts application/csp-report (legacy) and application/reports+json (Reporting API).
	 * Rejects any other Content-Type — browsers must send one of these two (R10).
	 */
	public function handle( WP_REST_Request $request ): WP_REST_Response {
		// Validate Content-Type to reduce spoofing surface. application/json is accepted
		// as a legacy fallback — some older Chromium versions used it before the spec settled.
		$ct      = $request->get_content_type();
		$ct_val  = is_array( $ct ) ? ( $ct['value'] ?? '' ) : '';
		$allowed = array( 'application/csp-report', 'application/reports+json', 'application/json' );
		if ( '' !== $ct_val && ! in_array( $ct_val, $allowed, true ) ) {
			return new WP_REST_Response( null, 400 );
		}

		$raw = $request->get_body();
		if ( empty( $raw ) ) {
			return new WP_REST_Response( null, 204 );
		}

		$body = json_decode( $raw, true );
		if ( ! is_array( $body ) ) {
			return new WP_REST_Response( null, 204 );
		}

		$reports = $this->normalise_body( $body );

		foreach ( $reports as $report ) {
			$this->store_report( $report );
		}

		$this->store_pillar_reports( $body );

		return new WP_REST_Response( null, 204 );
	}

	/**
	 * Routes Reporting API report items whose `type` is coop/coep to the
	 * generic Pillar_Violation_Store, separately from the CSP-shaped path
	 * above. A single POST body can legitimately contain a batch mixing CSP
	 * and COOP/COEP reports -- the browser groups everything queued for
	 * delivery to the same endpoint into one request.
	 */
	private function store_pillar_reports( array $body ): void {
		if ( ! isset( $body[0]['type'] ) ) {
			return;
		}

		foreach ( $body as $item ) {
			$type = isset( $item['type'] ) ? (string) $item['type'] : '';
			if ( ! isset( self::PILLAR_REPORT_TYPES[ $type ] ) || ! is_array( $item['body'] ?? null ) ) {
				continue;
			}

			// The report envelope's own `url` (not a field inside `body`) is the
			// page the report was generated for, per the Reporting API spec.
			$page_url = isset( $item['url'] ) ? (string) $item['url'] : '';
			if ( '' !== $page_url ) {
				$page_host = wp_parse_url( $page_url, PHP_URL_HOST );
				if ( ! empty( $page_host ) && ! in_array( strtolower( (string) $page_host ), $this->get_allowed_document_hosts(), true ) ) {
					continue; // silently discard a spoofed cross-origin report, same as the CSP path
				}
			}

			$disposition = isset( $item['body']['disposition'] ) ? (string) $item['body']['disposition'] : 'reporting';

			$this->pillar_violations->store(
				self::PILLAR_REPORT_TYPES[ $type ],
				$this->surface_from_document_uri( $page_url ),
				$type,
				$disposition,
				$item['body']
			);
		}
	}

	// ── Normalisation ─────────────────────────────────────────────────────────

	/**
	 * Normalises both CSP Level 3 and legacy report formats into a flat array.
	 */
	private function normalise_body( array $body ): array {
		// CSP Level 3: { "csp-report": { … } }
		if ( isset( $body['csp-report'] ) && is_array( $body['csp-report'] ) ) {
			return array( $this->map_csp_report( $body['csp-report'] ) );
		}

		// Reporting API (array of report objects): [ { "type": "csp-violation", "body": { … } } ]
		if ( isset( $body[0]['type'] ) ) {
			$out = array();
			foreach ( $body as $item ) {
				if ( in_array( isset( $item['type'] ) ? $item['type'] : '', array( 'csp-violation', 'content-security-policy' ), true )
					&& is_array( isset( $item['body'] ) ? $item['body'] : null )
				) {
					$out[] = $this->map_reporting_api( $item['body'] );
				}
			}
			return $out;
		}

		return array();
	}

	private function map_csp_report( array $r ): array {
		// Legacy field names use hyphens (application/csp-report format).
		// script-sample is only present when 'report-sample' is in the policy (R7).
		return array(
			'blocked_uri'         => isset( $r['blocked-uri'] ) ? $r['blocked-uri'] : '',
			'document_uri'        => isset( $r['document-uri'] ) ? $r['document-uri'] : '',
			'violated_directive'  => isset( $r['violated-directive'] ) ? $r['violated-directive'] : '',
			'effective_directive' => isset( $r['effective-directive'] ) ? $r['effective-directive'] : ( isset( $r['violated-directive'] ) ? $r['violated-directive'] : '' ),
			'original_policy'     => isset( $r['original-policy'] ) ? $r['original-policy'] : '',
			'source_file'         => isset( $r['source-file'] ) ? $r['source-file'] : '',
			'line_number'         => isset( $r['line-number'] ) ? (int) $r['line-number'] : null,
			'column_number'       => isset( $r['column-number'] ) ? (int) $r['column-number'] : null,
			'status_code'         => isset( $r['status-code'] ) ? (int) $r['status-code'] : null,
			'disposition'         => isset( $r['disposition'] ) ? $r['disposition'] : 'report',
			'referrer'            => isset( $r['referrer'] ) ? $r['referrer'] : '',
			'sample'              => isset( $r['script-sample'] ) ? $r['script-sample'] : '',
		);
	}

	private function map_reporting_api( array $b ): array {
		// Reporting API field names use camelCase (application/reports+json format).
		// sample is only present when 'report-sample' is in the policy (R7).
		return array(
			'blocked_uri'         => isset( $b['blockedURL'] ) ? $b['blockedURL'] : '',
			'document_uri'        => isset( $b['documentURL'] ) ? $b['documentURL'] : '',
			'violated_directive'  => isset( $b['violatedDirective'] ) ? $b['violatedDirective'] : '',
			'effective_directive' => isset( $b['effectiveDirective'] ) ? $b['effectiveDirective'] : ( isset( $b['violatedDirective'] ) ? $b['violatedDirective'] : '' ),
			'original_policy'     => isset( $b['originalPolicy'] ) ? $b['originalPolicy'] : '',
			'source_file'         => isset( $b['sourceFile'] ) ? $b['sourceFile'] : '',
			'line_number'         => isset( $b['lineNumber'] ) ? (int) $b['lineNumber'] : null,
			'column_number'       => isset( $b['columnNumber'] ) ? (int) $b['columnNumber'] : null,
			'status_code'         => isset( $b['statusCode'] ) ? (int) $b['statusCode'] : null,
			'disposition'         => isset( $b['disposition'] ) ? $b['disposition'] : 'report',
			'referrer'            => isset( $b['referrer'] ) ? $b['referrer'] : '',
			'sample'              => isset( $b['sample'] ) ? $b['sample'] : '',
		);
	}

	// ── Storage ───────────────────────────────────────────────────────────────

	private function store_report( array $r ): void {
		global $wpdb;
		$table = $wpdb->prefix . 'csp_violation_reports';

		$blocked_uri        = sanitize_text_field( substr( $r['blocked_uri'], 0, 2048 ) );
		$violated_directive = sanitize_text_field( substr( $r['violated_directive'], 0, 128 ) );
		$document_uri       = isset( $r['document_uri'] ) ? $r['document_uri'] : '';
		$surface            = $this->surface_from_document_uri( $document_uri );

		if ( empty( $violated_directive ) ) {
			return;
		}

		// Reject spoofed cross-origin reports: document-uri must be on this site's host.
		// CSP violation reports are client-generated and therefore spoofable (research.md).
		if ( ! empty( $document_uri ) ) {
			$doc_host = wp_parse_url( $document_uri, PHP_URL_HOST );
			if ( ! empty( $doc_host ) && ! in_array( strtolower( (string) $doc_host ), $this->get_allowed_document_hosts(), true ) ) {
				return; // silently discard; do not reveal rejection to the sender
			}
		}

		// Checked ahead of the rate limit below (and regardless of it) so this
		// diagnostic signal survives even on a surface that's already saturating
		// its rate cap -- a competing header is exactly the kind of problem that
		// tends to show up as unusually high report volume in the first place.
		$this->check_disposition_mismatch( $surface, $violated_directive, isset( $r['disposition'] ) ? (string) $r['disposition'] : 'report' );

		// Rate-limit check. Keyed per (surface, directive) rather than per surface
		// alone -- a single noisy directive (e.g. hundreds of inline style
		// violations on one page-builder-heavy page) would otherwise exhaust the
		// shared surface budget and silently drop reports for every OTHER
		// directive on that surface too, including a brand-new violation type
		// that had never been seen before.
		$rate_key = 'wp_sam_viol_rate_' . $surface . '_' . $violated_directive;
		$count    = (int) get_transient( $rate_key );
		if ( $count >= self::MAX_PER_HOUR_PER_SURFACE_DIRECTIVE ) {
			return;
		}
		set_transient( $rate_key, $count + 1, self::RATE_LIMIT_WINDOW );

		// FIX: fingerprint on the host, not the exact blocked_uri, wherever a host is
		// extractable. Font providers (and many other CDNs) serve each request from a
		// distinct, content-hashed filename under the same host -- fingerprinting on
		// the exact URL meant every file variant got its own permanent row instead of
		// being recognised as "the same source, seen again." Keyword-like values
		// (inline/eval/data:/blob:/about:) have no host and keep their exact-value
		// fingerprint, matching how source-approval already groups at host granularity.
		$blocked_host        = self::extract_blocked_host( $blocked_uri );
		$fingerprint_subject = $blocked_host ?? $blocked_uri;
		$fingerprint         = hash( 'sha256', $surface . '|' . $fingerprint_subject . '|' . $violated_directive );

		$now = current_time( 'mysql', true );

		$document_uri_sanitized        = sanitize_text_field( substr( $document_uri, 0, 2048 ) );
		$effective_directive_sanitized = sanitize_text_field( substr( isset( $r['effective_directive'] ) ? $r['effective_directive'] : '', 0, 128 ) );
		$original_policy_sanitized     = sanitize_textarea_field( isset( $r['original_policy'] ) ? $r['original_policy'] : '' );
		$source_file_sanitized         = sanitize_text_field( substr( isset( $r['source_file'] ) ? $r['source_file'] : '', 0, 512 ) );
		$line_number_value             = null === $r['line_number'] ? -1 : (int) $r['line_number'];
		$column_number_value           = null === $r['column_number'] ? -1 : (int) $r['column_number'];
		$status_code_value             = null === $r['status_code'] ? -1 : (int) $r['status_code'];
		$disposition_sanitized         = in_array( isset( $r['disposition'] ) ? $r['disposition'] : '', array( 'enforce', 'report' ), true ) ? $r['disposition'] : 'report';
		$referrer_sanitized            = sanitize_text_field( substr( isset( $r['referrer'] ) ? $r['referrer'] : '', 0, 2048 ) );
		$user_agent_raw                = isset( $_SERVER['HTTP_USER_AGENT'] ) ? wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) : '';
		$user_agent_sanitized          = sanitize_text_field( substr( (string) $user_agent_raw, 0, 512 ) );
		$sample_sanitized              = sanitize_text_field( substr( isset( $r['sample'] ) ? $r['sample'] : '', 0, 256 ) );

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.PreparedSQL.NotPrepared
		$wpdb->query(
			$wpdb->prepare(
				// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				"INSERT INTO {$table} (
					profile_surface, blocked_uri, blocked_host, document_uri, violated_directive, effective_directive,
					original_policy, source_file, line_number, column_number, status_code, disposition,
					referrer, user_agent, sample, reported_at, first_reported_at, last_reported_at,
					fingerprint, occurrence_count
				) VALUES (
					%s, %s, NULLIF(%s, ''), %s, %s, %s,
					%s, %s, NULLIF(%d, -1), NULLIF(%d, -1), NULLIF(%d, -1), %s,
					%s, %s, %s, %s, %s, %s,
					%s, %d
				) ON DUPLICATE KEY UPDATE
					occurrence_count = occurrence_count + 1,
					reported_at = VALUES(last_reported_at),
					last_reported_at = VALUES(last_reported_at),
					blocked_uri = VALUES(blocked_uri),
					effective_directive = VALUES(effective_directive),
					original_policy = VALUES(original_policy),
					status_code = VALUES(status_code),
					disposition = VALUES(disposition),
					source_file = VALUES(source_file),
					line_number = VALUES(line_number),
					column_number = VALUES(column_number),
					referrer = VALUES(referrer),
					user_agent = VALUES(user_agent),
					sample = CASE WHEN VALUES(sample) <> '' THEN VALUES(sample) ELSE sample END",
				$surface,
				$blocked_uri,
				$blocked_host,
				$document_uri_sanitized,
				$violated_directive,
				$effective_directive_sanitized,
				$original_policy_sanitized,
				$source_file_sanitized,
				$line_number_value,
				$column_number_value,
				$status_code_value,
				$disposition_sanitized,
				$referrer_sanitized,
				$user_agent_sanitized,
				$sample_sanitized,
				$now,
				$now,
				$now,
				$fingerprint,
				1
			)
		);

		// Only the first occurrence needs to create/refresh a source proposal; duplicate
		// violation counts are now represented on the violation row itself.
		if ( 1 === (int) $wpdb->rows_affected ) {
			$this->learn_source_from_report( $r, $surface, $blocked_uri, $now );
		}
	}

	// ── Competing-header detection ───────────────────────────────────────────

	/**
	 * A browser-reported disposition that doesn't match this surface's own
	 * configured CSP mode is strong evidence that another source (server
	 * config, another plugin, a stale cached response) is also emitting a
	 * Content-Security-Policy header for this surface -- this plugin only ever
	 * emits one policy, fully enforcing or fully report-only, per surface, so a
	 * genuine per-directive split can't originate here. Reuses the same
	 * 'conflict_detector' audit component as Conflict_Detector's own
	 * header-probe checks, so both land in one place for an administrator to
	 * review.
	 */
	private function check_disposition_mismatch( string $surface, string $directive, string $disposition ): void {
		if ( ! in_array( $disposition, array( 'enforce', 'report' ), true ) ) {
			return;
		}

		$expected = $this->expected_disposition_for_surface( $surface );
		if ( null === $expected || $expected === $disposition ) {
			return;
		}

		// Throttled per (surface, directive): a single busy page can generate
		// hundreds of mismatched reports within minutes, and the underlying
		// cause doesn't change from one report to the next.
		$cooldown_key = 'wp_sam_disposition_mismatch_' . $surface . '_' . $directive;
		if ( false !== get_transient( $cooldown_key ) ) {
			return;
		}
		set_transient( $cooldown_key, 1, self::DISPOSITION_MISMATCH_COOLDOWN );

		$this->audit->log(
			'conflict_detector',
			'csp_disposition_mismatch',
			sprintf(
				"Browser reported '%s' disposition for '%s' on the '%s' surface, but this surface's own CSP profile is configured for '%s'. This usually means another source (server configuration or a different plugin) is also emitting a Content-Security-Policy header for this surface.",
				$disposition,
				$directive,
				$surface,
				$expected
			),
			'warning'
		);
	}

	/**
	 * Returns 'enforce' | 'report' | null (disabled, or profile not found) for
	 * a surface's currently configured CSP mode. Cached per request -- a single
	 * report batch can contain many reports for the same surface.
	 */
	private function expected_disposition_for_surface( string $surface ): ?string {
		if ( array_key_exists( $surface, $this->profile_mode_cache ) ) {
			return $this->profile_mode_cache[ $surface ];
		}

		global $wpdb;
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.PreparedSQL.NotPrepared
		$mode = $wpdb->get_var(
			$wpdb->prepare(
				"SELECT mode FROM {$wpdb->prefix}csp_policy_profiles WHERE surface = %s LIMIT 1",
				$surface
			)
		);

		$expected = null;
		if ( 'enforce' === $mode ) {
			$expected = 'enforce';
		} elseif ( 'report-only' === $mode ) {
			$expected = 'report';
		}

		$this->profile_mode_cache[ $surface ] = $expected;
		return $expected;
	}

	private function learn_source_from_report( array $r, string $surface, string $blocked_uri, string $now ): void {
		if ( null === $this->learning_window || ! $this->learning_window->is_open() ) {
			return;
		}

		$candidate = $this->source_candidate_from_report( $r, $blocked_uri );
		if ( null === $candidate ) {
			return;
		}

		$document_uri = sanitize_text_field( substr( isset( $r['document_uri'] ) ? $r['document_uri'] : '', 0, 512 ) );
		$notes        = sprintf( 'Learned from CSP report endpoint. Document: %s', $document_uri );

		$this->policy_changes->propose_source(
			$surface,
			$candidate,
			'report-endpoint',
			'runtime-report',
			$notes
		);
	}

	private function source_candidate_from_report( array $r, string $blocked_uri ): ?array {
		$directive = $this->normalise_directive(
			isset( $r['effective_directive'] ) && '' !== $r['effective_directive']
				? $r['effective_directive']
				: ( $r['violated_directive'] ?? '' )
		);

		if ( ! in_array( $directive, self::LEARNABLE_DIRECTIVES, true ) ) {
			return null;
		}

		$blocked_uri = trim( $blocked_uri );
		if ( '' === $blocked_uri || self::is_non_host_blocked_uri( $blocked_uri ) ) {
			return null;
		}

		if ( str_starts_with( $blocked_uri, '//' ) ) {
			$blocked_uri = 'https:' . $blocked_uri;
		}

		$parsed = wp_parse_url( $blocked_uri );
		if ( empty( $parsed['host'] ) ) {
			return null;
		}

		$scheme = strtolower( isset( $parsed['scheme'] ) ? $parsed['scheme'] : 'https' );
		if ( ! in_array( $scheme, array( 'http', 'https', 'ws', 'wss' ), true ) ) {
			return null;
		}

		$host      = strtolower( $parsed['host'] );
		$site_host = wp_parse_url( home_url(), PHP_URL_HOST );
		if ( ! empty( $site_host ) && strtolower( (string) $site_host ) === $host ) {
			return null;
		}

		return array(
			'directive' => $directive,
			'uri'       => esc_url_raw( $blocked_uri ),
			'scheme'    => $scheme,
			'host'      => sanitize_text_field( substr( $host, 0, 255 ) ),
		);
	}

	private function normalise_directive( string $directive ): string {
		$directive = strtolower( trim( $directive ) );
		if ( str_contains( $directive, ' ' ) ) {
			$directive = strtok( $directive, ' ' );
		}

		$normalised = preg_replace( '/[^a-z0-9-]/', '', (string) $directive );
		return is_string( $normalised ) ? $normalised : '';
	}

	private static function is_non_host_blocked_uri( string $blocked_uri ): bool {
		$value = strtolower( $blocked_uri );
		if ( in_array( $value, array( 'inline', 'eval', 'wasm-eval', 'data', 'blob', 'about' ), true ) ) {
			return true;
		}

		return str_starts_with( $value, 'data:' )
			|| str_starts_with( $value, 'blob:' )
			|| str_starts_with( $value, 'about:' );
	}

	/**
	 * Extracts the host from a blocked_uri for host-level violation dedup
	 * (e.g. every fonts.gstatic.com/.../<hash>.woff2 file collapses to one
	 * "fonts.gstatic.com" row instead of a permanent row per file). Returns
	 * null for keyword-like values (inline/eval/data:/blob:/about:) that
	 * have no host to group by -- those keep their exact-value fingerprint.
	 * Public + static so Activator's one-time dedup migration can reuse the
	 * exact same logic store_report() uses, rather than a second copy that
	 * could silently drift out of sync (as already happened once this
	 * session with the conflict-probe header name).
	 */
	public static function extract_blocked_host( string $blocked_uri ): ?string {
		$blocked_uri = trim( $blocked_uri );
		if ( '' === $blocked_uri || self::is_non_host_blocked_uri( $blocked_uri ) ) {
			return null;
		}

		if ( str_starts_with( $blocked_uri, '//' ) ) {
			$blocked_uri = 'https:' . $blocked_uri;
		}

		$host = wp_parse_url( $blocked_uri, PHP_URL_HOST );

		return ! empty( $host ) ? strtolower( sanitize_text_field( substr( (string) $host, 0, 255 ) ) ) : null;
	}

	private function get_allowed_document_hosts(): array {
		$urls = array(
			home_url(),
			get_site_url(),
			(string) get_option( 'wp_sam_report_endpoint_url', '' ),
		);

		$hosts = array();
		foreach ( $urls as $url ) {
			$host = wp_parse_url( $url, PHP_URL_HOST );
			if ( ! empty( $host ) ) {
				$hosts[] = strtolower( (string) $host );
			}
		}

		foreach ( array( 'HTTP_HOST', 'HTTP_X_FORWARDED_HOST' ) as $server_key ) {
			if ( empty( $_SERVER[ $server_key ] ) ) {
				continue;
			}

			$host = strtok( (string) wp_unslash( $_SERVER[ $server_key ] ), ',' );
			$host = strtolower( trim( false === $host ? '' : $host ) );
			$host = preg_replace( '/:\d+$/', '', $host );
			if ( is_string( $host ) && preg_match( '/^[a-z0-9.-]+$/', $host ) ) {
				$hosts[] = $host;
			}
		}

		return array_values( array_unique( $hosts ) );
	}

	private function surface_from_document_uri( string $uri ): string {
		if ( empty( $uri ) ) {
			return 'frontend';
		}
		$path = wp_parse_url( $uri, PHP_URL_PATH );
		$path = ! empty( $path ) ? $path : '';
		if ( str_contains( $path, '/wp-admin' ) ) {
			return 'admin';
		}
		if ( str_contains( $path, '/wp-login.php' ) ) {
			return 'login';
		}
		if ( str_contains( $path, '/wp-json' ) || str_contains( $path, '?rest_route' ) ) {
			return 'api';
		}
		return 'frontend';
	}
}
