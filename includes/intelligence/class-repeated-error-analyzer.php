<?php
/**
 * Repeated-errors signal (Phase 4C carried-forward item, .roadmap/
 * phase3_early_plan.md §10), built on Scanner_Identity_Store's bounded
 * recent_errors history.
 *
 * Recognises a source whose recent requests were disproportionately
 * errors (an HTTP response of 400 or above -- most often 404, but also
 * covers a REST route that doesn't exist, an admin action refused, and
 * similar) -- the classic signature of a scanner or scraper probing for
 * paths that don't exist or aren't allowed, as distinct from
 * Uri_Pattern_Analyzer's enumeration signal, which is about a *pattern* in
 * what's requested rather than whether any of it actually existed. A
 * source can trip either signal without the other: enumerating a real,
 * existing ID sequence produces no errors at all, and undirected 404
 * probing (trying random/well-known sensitive paths) produces no
 * sequential pattern.
 *
 * Pure and read-only, same as the other analyzers: takes already-recorded
 * history, returns a bool, touches nothing.
 */

declare( strict_types=1 );

namespace WP_SAM\Intelligence;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Repeated_Error_Analyzer {

	/** A run shorter than this proves nothing -- a couple of stray 404s could easily be coincidence. */
	private const MIN_SAMPLE_SIZE = 4;

	/** Share of recent requests that must have been errors to flag as probing. */
	private const MIN_ERROR_RATIO = 0.7;

	/**
	 * @param array<int, int|bool> $recent_errors Oldest first, as stored in Scanner_Identity_Store's recent_errors column (0/1 ints).
	 */
	public function is_error_probing( array $recent_errors ): bool {
		if ( count( $recent_errors ) < self::MIN_SAMPLE_SIZE ) {
			return false;
		}

		$errors = 0;
		foreach ( $recent_errors as $entry ) {
			if ( $entry ) {
				++$errors;
			}
		}

		return ( $errors / count( $recent_errors ) ) >= self::MIN_ERROR_RATIO;
	}
}
