<?php
/**
 * Records, per CSP surface, when a policy header was actually sent and when
 * its learned hashes last had to be trimmed to fit the byte budget.
 *
 * Exists so "no violations reported" can be told apart from "no policy was
 * ever delivered": until the admin surface was hooked on admin_init, its
 * report-only policy was never sent at all (WordPress only fires
 * send_headers from WP::main(), the frontend pipeline), and
 * Recommendation_Rule_Csp_Enforce_Ready read that silence as a clean
 * 30-day run and recommended enforcing it. The rule now requires this log
 * to show continuous delivery for the whole quiet window.
 *
 * One small autoloaded option per surface (not one shared array) so two
 * concurrent requests on different surfaces can't overwrite each other's
 * entry. Writes are throttled to once per field per hour, so the per-request
 * cost on an ordinary page load is a read of an already-autoloaded option.
 */

declare( strict_types=1 );

namespace WP_SAM\CSP;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Csp_Delivery_Log {

	public const OPTION_PREFIX = 'wp_sam_csp_delivery_';

	/**
	 * A gap in delivery longer than this restarts the continuous-delivery
	 * clock (first_sent): a surface that was disabled, or simply not
	 * visited, for over a week hasn't been "running quietly" through it.
	 */
	public const MAX_GAP_SECONDS = 7 * DAY_IN_SECONDS;

	private const WRITE_INTERVAL_SECONDS = HOUR_IN_SECONDS;

	/** Finer than the hourly fields, so "last throttled" stays meaningful. */
	private const THROTTLE_WRITE_INTERVAL_SECONDS = 5 * MINUTE_IN_SECONDS;

	public static function record_sent( string $surface, ?int $now = null ): void {
		$now   = $now ?? time();
		$entry = self::get( $surface );

		$last_sent = isset( $entry['last_sent'] ) ? (int) $entry['last_sent'] : 0;
		if ( $last_sent > 0 && $now - $last_sent < self::WRITE_INTERVAL_SECONDS ) {
			return;
		}

		if ( 0 === $last_sent || $now - $last_sent > self::MAX_GAP_SECONDS || empty( $entry['first_sent'] ) ) {
			$entry['first_sent'] = $now;
		}
		$entry['last_sent'] = $now;

		update_option( self::OPTION_PREFIX . $surface, $entry, true );
	}

	public static function record_trimmed( string $surface, ?int $now = null ): void {
		$now   = $now ?? time();
		$entry = self::get( $surface );

		$last_trimmed = isset( $entry['last_trimmed'] ) ? (int) $entry['last_trimmed'] : 0;
		if ( $last_trimmed > 0 && $now - $last_trimmed < self::WRITE_INTERVAL_SECONDS ) {
			return;
		}

		$entry['last_trimmed'] = $now;

		update_option( self::OPTION_PREFIX . $surface, $entry, true );
	}

	/**
	 * Violation_Reporter::check_not_flooding() answered a report for this
	 * surface with a 429, so some of its violations were never stored.
	 * Recorded so that loss is visible (the Violations tab's per-surface
	 * strip, the Readiness tab) and so a surface whose reports were being
	 * dropped is never read as having run quietly. Throttled to one write
	 * per interval like the other fields: during a real storm this is
	 * called once per throttled IP per window.
	 */
	public static function record_throttled( string $surface, ?int $now = null ): void {
		$now   = $now ?? time();
		$entry = self::get( $surface );

		$last_throttled = isset( $entry['last_throttled'] ) ? (int) $entry['last_throttled'] : 0;
		if ( $last_throttled > 0 && $now - $last_throttled < self::THROTTLE_WRITE_INTERVAL_SECONDS ) {
			return;
		}

		$entry['last_throttled'] = $now;

		update_option( self::OPTION_PREFIX . $surface, $entry, true );
	}

	/** @return array{first_sent?: int, last_sent?: int, last_trimmed?: int, last_throttled?: int} */
	public static function get( string $surface ): array {
		$entry = get_option( self::OPTION_PREFIX . $surface, array() );
		return is_array( $entry ) ? $entry : array();
	}
}
