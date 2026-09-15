<?php
/**
 * Timing signal (Phase 4C carried-forward item, .roadmap/phase3_early_
 * plan.md §10), built on Scanner_Identity_Store's bounded recent_seen_at
 * history.
 *
 * Recognises suspiciously uniform inter-request intervals: a run of
 * consecutive requests spaced almost exactly the same number of seconds
 * apart, the classic signature of a script sleeping a fixed duration
 * between requests rather than a person browsing, whose timing is
 * naturally irregular. Only flags a sustained, tight pattern -- a couple
 * of coincidentally close requests proves nothing, and a long-average
 * interval (e.g. a source that merely visits once every few hours) is
 * never flagged even if each individual gap happens to be similar,
 * because that cadence is indistinguishable from ordinary infrequent
 * traffic and flagging it would just be noise.
 *
 * Pure and read-only, same as Uri_Pattern_Analyzer: takes already-recorded
 * timestamp history, returns a bool, touches nothing.
 */

declare( strict_types=1 );

namespace WP_SAM\Intelligence;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Request_Timing_Analyzer {

	/** A run shorter than this proves nothing -- three intervals could easily be coincidence. */
	private const MIN_INTERVAL_COUNT = 4;

	/**
	 * Longest average interval still worth treating as "active" traffic --
	 * beyond this, infrequent visits are normal and not a timing signal.
	 */
	private const MAX_MEAN_INTERVAL_SECONDS = 300;

	/**
	 * How tightly clustered consecutive intervals must be, expressed as a
	 * fraction of the mean interval (coefficient of variation). Real
	 * browsing varies far more than this; a fixed-sleep script does not.
	 */
	private const MAX_COEFFICIENT_OF_VARIATION = 0.15;

	/**
	 * @param array<int, string> $recent_seen_at Oldest first, as stored in Scanner_Identity_Store's recent_seen_at column (MySQL datetime strings).
	 */
	public function is_scripted_timing( array $recent_seen_at ): bool {
		$timestamps = array();
		foreach ( $recent_seen_at as $value ) {
			$time = strtotime( (string) $value );
			if ( false === $time ) {
				return false; // Malformed data -- never guess.
			}
			$timestamps[] = $time;
		}

		if ( count( $timestamps ) < self::MIN_INTERVAL_COUNT + 1 ) {
			return false;
		}

		$intervals = array();
		for ( $i = 1, $count = count( $timestamps ); $i < $count; $i++ ) {
			$intervals[] = $timestamps[ $i ] - $timestamps[ $i - 1 ];
		}

		$mean = array_sum( $intervals ) / count( $intervals );

		// A mean of 0 (multiple requests in the same second, every time)
		// is maximally uniform but not a *timed* pattern in any meaningful
		// sense -- treat as inconclusive rather than flag.
		if ( $mean <= 0.0 || $mean > self::MAX_MEAN_INTERVAL_SECONDS ) {
			return false;
		}

		$variance = 0.0;
		foreach ( $intervals as $interval ) {
			$variance += ( $interval - $mean ) ** 2;
		}
		$variance          /= count( $intervals );
		$standard_deviation = sqrt( $variance );

		return ( $standard_deviation / $mean ) <= self::MAX_COEFFICIENT_OF_VARIATION;
	}
}
