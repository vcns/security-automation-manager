<?php
/**
 * Recommendations Engine (Phase 4F, .roadmap/phase3_early_plan.md §22).
 *
 * Aggregates every registered Recommendation_Rule's output, drops anything
 * still validly dismissed (Recommendation_Dismissal_Store), and sorts what
 * remains by risk. This is the only class the admin view calls -- rule
 * selection, evidence-reading, and risk classification are each rule's own
 * responsibility (see Recommendation_Rule's docblock for why that split
 * matters for §22's deterministic-authority requirement).
 *
 * Each recommendation array carries (per §22's own required field list):
 * key (string, stable id used for dismissal lookups -- lowercase, ASCII,
 * underscore-separated only, since it round-trips through sanitize_key() on
 * the dismiss handler, e.g. 'csp_enforce_ready_frontend'), layer (string),
 * pillar (?string), surface (?string), observed (string), why_it_matters
 * (string), confidence
 * ('high'|'medium'|'low'), risk ('low'|'medium'|'high'|'critical', the same
 * vocabulary Drift_Store::RISK_LEVELS uses), evidence (array<string,mixed>,
 * the concrete numbers/dates behind the observation), recommended_action
 * (string), alternative_action (?string), automation_eligible (bool --
 * always false in this build; nothing here is authorised to act
 * automatically), rollback_position (string), evidence_changed_at (string,
 * mysql datetime -- the freshest timestamp behind this recommendation, what
 * a dismissal's currency is checked against), cta_url (string), and
 * dismissible (bool -- see Recommendation_Dismissal_Store's docblock for
 * why only some rules need this).
 */

declare( strict_types=1 );

namespace WP_SAM\Intelligence;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Recommendation_Engine {

	private const RISK_RANK = array(
		'critical' => 3,
		'high'     => 2,
		'medium'   => 1,
		'low'      => 0,
	);

	/** @return array<int, array<string, mixed>> */
	public function get_recommendations(): array {
		Recommendation_Registry::register_defaults();

		$dismissals      = new Recommendation_Dismissal_Store();
		$recommendations = array();

		foreach ( Recommendation_Registry::all() as $rule ) {
			foreach ( $rule->evaluate() as $recommendation ) {
				if ( ! empty( $recommendation['dismissible'] )
					&& $dismissals->is_dismissed( (string) $recommendation['key'], (string) $recommendation['evidence_changed_at'] )
				) {
					continue;
				}
				$recommendations[] = $recommendation;
			}
		}

		usort(
			$recommendations,
			static function ( array $a, array $b ): int {
				$rank_a = self::RISK_RANK[ $a['risk'] ] ?? 0;
				$rank_b = self::RISK_RANK[ $b['risk'] ] ?? 0;
				return $rank_b <=> $rank_a;
			}
		);

		return $recommendations;
	}
}
