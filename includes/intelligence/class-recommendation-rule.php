<?php
/**
 * Contract for one Recommendations Engine rule (Phase 4F, .roadmap/
 * phase3_early_plan.md §22).
 *
 * A rule is a deterministic, read-only evaluator over already-existing
 * evidence (Pillar_Registry, Traffic_Policy_Store, Certificate_Store,
 * Drift_Store, Exception_Store, and similar) -- it never mutates anything,
 * and it never itself decides to enforce, approve, or bypass a control. Per
 * §22: "Deterministic rules remain authoritative for: risk classification;
 * source validation; approval requirements; enforcement decisions; hard
 * exclusions; automation limits." A rule class is that deterministic
 * authority; Recommendation_Engine only aggregates, filters dismissals, and
 * sorts what rules produce.
 */

declare( strict_types=1 );

namespace WP_SAM\Intelligence;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

interface Recommendation_Rule {

	/** Stable identifier for this rule, e.g. 'certificate_renewal_due'. */
	public function id(): string;

	/**
	 * Evaluates current, live evidence and returns zero or more
	 * recommendations (a rule may fire once, once per surface, or not at
	 * all). See Recommendation_Engine's docblock for the exact shape each
	 * returned array must have.
	 *
	 * @return array<int, array<string, mixed>>
	 */
	public function evaluate(): array;
}
