<?php
/**
 * Generic storage for Reporting API violation reports from pillars other
 * than CSP -- currently Cross-Origin-Opener-Policy and Cross-Origin-Embedder-Policy,
 * the only two pillars this plugin manages with a browser-native
 * report-only + Reporting API delivery mechanism (Chromium only).
 *
 * Deliberately generic rather than CSP-shaped: COOP and COEP report bodies
 * carry meaningfully different fields from each other and from a CSP
 * violation report, and (unlike CSP's report format) their exact field
 * names are less stable across browser versions. Rather than guess at named
 * columns, the pillar-specific fields are kept as an opaque `detail` JSON
 * blob; only the fields every report type shares (pillar, surface,
 * disposition) are real columns, for the same sort/filter UI pattern CSP's
 * Violations tab already uses.
 *
 * Fingerprinting is intentionally coarser than CSP's (pillar+surface+
 * report_type+disposition only, not any field inside `detail`): CSP can
 * fingerprint on a stable blocked_uri because that field name and meaning
 * are well established; this plugin does not yet have enough confidence in
 * which COOP/COEP body fields are stable per-occurrence identifiers versus
 * incidental (e.g. a line/column number) to fingerprint on them safely.
 * Revisit once real report payloads are verified.
 */

declare( strict_types=1 );

namespace WP_SAM\Security;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Pillar_Violation_Store {

	private const MAX_PER_HOUR_PER_PILLAR_SURFACE = 500;
	private const RATE_LIMIT_WINDOW               = HOUR_IN_SECONDS;
	private const MAX_DETAIL_BYTES                = 8192;

	/**
	 * @param array<string,mixed> $detail Raw report body fields, stored as-is (size-capped) in the detail JSON column.
	 */
	public function store( string $pillar, string $surface, string $report_type, string $disposition, array $detail ): void {
		global $wpdb;
		$table = $wpdb->prefix . 'sam_pillar_violation_reports';

		$pillar      = sanitize_text_field( substr( $pillar, 0, 32 ) );
		$surface     = in_array( $surface, array( 'frontend', 'admin', 'login', 'api' ), true ) ? $surface : 'frontend';
		$report_type = sanitize_text_field( substr( $report_type, 0, 64 ) );
		$disposition = in_array( $disposition, array( 'enforce', 'reporting', 'report' ), true ) ? $disposition : 'reporting';

		if ( '' === $pillar || '' === $report_type ) {
			return;
		}

		$rate_key = 'wp_sam_pillar_viol_rate_' . $pillar . '_' . $surface;
		$count    = (int) get_transient( $rate_key );
		if ( $count >= self::MAX_PER_HOUR_PER_PILLAR_SURFACE ) {
			return;
		}
		set_transient( $rate_key, $count + 1, self::RATE_LIMIT_WINDOW );

		$detail_json = wp_json_encode( $detail );
		if ( false === $detail_json ) {
			$detail_json = '{}';
		}
		if ( strlen( $detail_json ) > self::MAX_DETAIL_BYTES ) {
			$detail_json = substr( $detail_json, 0, self::MAX_DETAIL_BYTES );
		}

		$fingerprint = hash( 'sha256', $pillar . '|' . $surface . '|' . $report_type . '|' . $disposition );
		$now         = current_time( 'mysql', true );

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.NotPrepared,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$wpdb->query(
			$wpdb->prepare(
				// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				"INSERT INTO {$table} (
					pillar, surface, disposition, report_type, detail,
					fingerprint, occurrence_count, first_seen_at, last_seen_at
				) VALUES (
					%s, %s, %s, %s, %s,
					%s, %d, %s, %s
				) ON DUPLICATE KEY UPDATE
					occurrence_count = occurrence_count + 1,
					last_seen_at = VALUES(last_seen_at),
					detail = VALUES(detail)",
				$pillar,
				$surface,
				$disposition,
				$report_type,
				$detail_json,
				$fingerprint,
				1,
				$now,
				$now
			)
		);
	}
}
