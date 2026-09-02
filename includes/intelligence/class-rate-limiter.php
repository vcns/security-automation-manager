<?php
/**
 * Fixed-window request counter for Traffic_Guard (Phase 3E,
 * .roadmap/phase3_early_plan.md §13.1 Rate Limiting).
 *
 * Uses a WordPress transient per (ip, surface), the same fixed-window
 * counter pattern Event_Store and Hash_Manager already use for their own
 * per-hour rate limits -- not a true sliding window, but simple, and
 * consistent with the rest of this codebase.
 */

declare( strict_types=1 );

namespace WP_SAM\Intelligence;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Rate_Limiter {

	/**
	 * Records one hit for this key and returns the count so far in the
	 * current window. set_transient() resets the expiry to $window_seconds
	 * from now on every call, so a source sending a continuous stream of
	 * requests never lets the counter lapse -- it keeps climbing for as
	 * long as traffic keeps arriving, and only resets after a genuine gap
	 * longer than $window_seconds. That's the intended behaviour here: a
	 * sustained flood should escalate quickly rather than getting a fresh
	 * allowance every time the window nominally "rolls over" while still
	 * under active abuse.
	 */
	public function hit( string $ip, string $surface, int $window_seconds ): int {
		if ( '' === $ip ) {
			return 0;
		}

		$key   = $this->transient_key( $ip, $surface );
		$count = (int) get_transient( $key );

		if ( 0 === $count ) {
			set_transient( $key, 1, max( 1, $window_seconds ) );
			return 1;
		}

		// set_transient() with the same key refreshes the value without
		// resetting the expiry it was first set with in most transient
		// backends (object cache or options table), so the window's end
		// stays anchored to the first hit.
		set_transient( $key, $count + 1, max( 1, $window_seconds ) );
		return $count + 1;
	}

	public function exceeded( string $ip, string $surface, int $max_requests, int $window_seconds ): bool {
		return $this->hit( $ip, $surface, $window_seconds ) > max( 1, $max_requests );
	}

	private function transient_key( string $ip, string $surface ): string {
		return 'wp_sam_rate_' . $surface . '_' . md5( $ip );
	}
}
