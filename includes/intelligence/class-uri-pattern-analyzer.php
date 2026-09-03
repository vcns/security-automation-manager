<?php
/**
 * URI-pattern signal (Phase 4C, .roadmap/phase3_early_plan.md §10),
 * built on Scanner_Identity_Store's bounded recent_paths history.
 *
 * Recognises sequential/enumerating access: a run of consecutive request
 * paths whose trailing number changes by the same fixed step every time
 * (e.g. /product/101, /product/102, /product/103, /product/104 -- step
 * +1), the classic signature of a script walking IDs rather than a person
 * browsing or a search engine following actual links. A single path
 * without a trailing number anywhere in the run breaks the sequence --
 * this only ever flags a genuinely consistent, sustained pattern, not an
 * isolated coincidence.
 *
 * Pure and read-only, same as Bot_Classifier: takes already-recorded path
 * history, returns a bool, touches nothing.
 */

declare( strict_types=1 );

namespace WP_SAM\Intelligence;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Uri_Pattern_Analyzer {

	/** A run shorter than this proves nothing -- three hits could easily be coincidence. */
	private const MIN_SEQUENCE_LENGTH = 4;

	/**
	 * @param array<int, string> $recent_paths Oldest first, as stored in Scanner_Identity_Store's recent_paths column.
	 */
	public function is_enumerating( array $recent_paths ): bool {
		$numbers = array();

		foreach ( $recent_paths as $path ) {
			if ( 1 === preg_match( '/(\d+)(?!.*\d)/', (string) $path, $matches ) ) {
				$numbers[] = (int) $matches[1];
			} else {
				$numbers = array();
			}
		}

		if ( count( $numbers ) < self::MIN_SEQUENCE_LENGTH ) {
			return false;
		}

		$step = $numbers[1] - $numbers[0];
		if ( 0 === $step ) {
			return false;
		}

		for ( $i = 2, $count = count( $numbers ); $i < $count; $i++ ) {
			if ( ( $numbers[ $i ] - $numbers[ $i - 1 ] ) !== $step ) {
				return false;
			}
		}

		return true;
	}
}
