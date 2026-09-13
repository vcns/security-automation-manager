<?php
/**
 * Registry of available Recommendations Engine rules (Phase 4F, .roadmap/
 * phase3_early_plan.md §22).
 *
 * register_defaults() (called lazily, once, from Recommendation_Engine::
 * get_recommendations() -- this feature is admin-view-only, so there is no
 * reason to hook it into the per-request `init` bootstrap the way Detector_
 * Registry is) registers this build's own free rule catalogue, filled in
 * incrementally across rule batches (see .roadmap/phase4_plan.md's Phase 4F
 * entry for what's shipped and what's still to come).
 *
 * Mirrors Detector_Registry's own shape for the same reason: extensions
 * (see includes/extensions/, physically absent from the WordPress.org-
 * channel build) can add their own rule via the wp_sam_register_recommendation_rules
 * action without this class, or anything else in core, knowing they exist.
 */

declare( strict_types=1 );

namespace WP_SAM\Intelligence;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Recommendation_Registry {

	/** @var array<string, Recommendation_Rule> */
	private static array $rules = array();

	private static bool $defaults_registered = false;

	public static function register( Recommendation_Rule $rule ): void {
		self::$rules[ $rule->id() ] = $rule;
	}

	/**
	 * Registers the core rule catalogue. Idempotent -- safe to call more
	 * than once (e.g. once per test).
	 */
	public static function register_defaults(): void {
		if ( self::$defaults_registered ) {
			return;
		}
		self::$defaults_registered = true;

		// Rule batch 1: no new store methods needed -- each reuses evidence
		// already exposed by an existing store.
		self::register( new Recommendation_Rule_Certificate_Renewal() );
		self::register( new Recommendation_Rule_Unexplained_Drift() );
		self::register( new Recommendation_Rule_Exception_Expiring() );

		// Rule batch 2: CSP enforce-readiness -- the one new read method it
		// needed (Violation_Reporter::count_since()) is now in place.
		self::register( new Recommendation_Rule_Csp_Enforce_Ready() );

		do_action( 'wp_sam_register_recommendation_rules' );
	}

	/** @return array<Recommendation_Rule> every registered rule, for Recommendation_Engine to evaluate. */
	public static function all(): array {
		return array_values( self::$rules );
	}

	/** Test-only: clears all registered state so each test starts from a clean registry. */
	public static function reset(): void {
		self::$rules               = array();
		self::$defaults_registered = false;
	}
}
