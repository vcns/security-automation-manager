<?php
/**
 * Fixed-window request counter for Traffic_Guard (Phase 3E,
 * .roadmap/phase3_early_plan.md §13.1 Rate Limiting).
 *
 * Uses a WordPress transient per (ip, surface), the same fixed-window
 * counter pattern Event_Store and Hash_Manager already use for their own
 * per-hour rate limits -- not a true sliding window, but simple, and
 * consistent with the rest of this codebase.
 *
 * The window is anchored to its first hit and stored alongside the count.
 * Previously only the count was stored, and set_transient() pushed the
 * expiry out again on every hit, so the counter only reset after a full
 * window with no requests at all. A slow, steady source -- WordPress's own
 * wp-cron loopback calls, a monitoring check, an office of staff behind one
 * address -- therefore kept counting up for hours and eventually "exceeded"
 * a per-minute limit it had never come close to in any single minute.
 */

declare( strict_types=1 );

namespace WP_SAM\Intelligence;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Rate_Limiter {

	/** @var callable():int Real time() by default; injectable so tests can move between windows. */
	private $clock;

	public function __construct( ?callable $clock = null ) {
		$this->clock = $clock ?? 'time';
	}

	/**
	 * Records one hit for this key and returns the count so far in the
	 * current window. The window starts at the first hit and lasts
	 * $window_seconds; the first hit after it ends starts a new window at 1.
	 * A sustained flood still exceeds the limit in every window it spans.
	 */
	public function hit( string $ip, string $surface, int $window_seconds ): int {
		if ( '' === $ip ) {
			return 0;
		}

		$window = max( 1, $window_seconds );
		$key    = $this->transient_key( $ip, $surface );
		$now    = (int) ( $this->clock )();
		$state  = get_transient( $key );

		// A non-array value is a bare count from the old format, with no start time:
		// treat it as expired rather than guess where its window began.
		if ( ! is_array( $state ) || ! isset( $state['start'], $state['count'] ) || $now - (int) $state['start'] >= $window ) {
			$state = array(
				'start' => $now,
				'count' => 0,
			);
		}

		++$state['count'];

		// Expires when this window ends, not $window seconds after the latest hit.
		set_transient( $key, $state, max( 1, (int) $state['start'] + $window - $now ) );

		return (int) $state['count'];
	}

	public function exceeded( string $ip, string $surface, int $max_requests, int $window_seconds ): bool {
		return $this->hit( $ip, $surface, $window_seconds ) > max( 1, $max_requests );
	}

	private function transient_key( string $ip, string $surface ): string {
		return 'wp_sam_rate_' . $surface . '_' . md5( $ip );
	}
}
