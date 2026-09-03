<?php
/**
 * Combines identity, network-verification, and request-rate signals into a
 * multi-state bot/crawler classification (Phase 4C, .roadmap/phase4_plan.md,
 * .roadmap/phase3_early_plan.md §10) -- the roadmap is explicit that a
 * binary "bot/not bot" model must be avoided, so this never collapses down
 * to one.
 *
 * Pure and read-only: takes an already-recorded Scanner_Identity_Store row
 * and the matching Traffic_Block_Store row (if any) for the same (ip,
 * surface), and returns a classification -- no new data is captured or
 * written here, and no new network/DB calls happen inside this class
 * itself. Deliberately does NOT touch the request-observation hot path;
 * callers (currently the Identities admin view) look this up on demand.
 *
 * An administrator's own decision (customer_authorised / explicitly_denied
 * / previously_authorised_expired) always wins over the automatic signals
 * below it -- a human decision is more authoritative than any inference
 * this class could draw, mirroring the same "decision beats automatic
 * detection" rule already enforced throughout this product (e.g. Traffic_
 * Guard never auto-blocking a privileged admin session).
 *
 * Below a decision, two independent axes combine into six possible
 * outcomes, not a bot/not-bot flag:
 * - A known vendor match (verification_state is one of Identity_Resolver's
 *   automatic known_* states) splits on network_match: matching the
 *   vendor's own published network data is 'verified_crawler'; claiming
 *   the identity without matching it is 'claimed_crawler_unverified' --
 *   §10's "impersonated crawlers" category, and the case worth an
 *   administrator's attention most.
 * - No vendor match splits on whether this source has actually escalated
 *   through Traffic_Block_Store's existing progressive-response ladder
 *   (throttle or worse): 'aggressive_unidentified' if so, else
 *   'unclassified' -- the overwhelming majority of ordinary, unremarkable
 *   traffic, deliberately not asserted as anything more specific than that.
 *
 * URI-pattern (the third signal §10's own exit criteria names alongside
 * identity and request-rate) is not incorporated in this first pass --
 * carried forward, see .roadmap/phase4_plan.md's Phase 4C status.
 */

declare( strict_types=1 );

namespace WP_SAM\Intelligence;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Bot_Classifier {

	private const KNOWN_STATES = array( 'known_crawler', 'known_commercial_scanner', 'known_research_scanner' );

	private const ESCALATED_STAGES = array( 'throttle', 'temporary_block', 'extended_block', 'persistent_block' );

	/**
	 * @param array<string, mixed>      $identity      A sam_scanner_identities row.
	 * @param array<string, mixed>|null $traffic_block The matching sam_traffic_blocks row for the same (ip, surface), if any.
	 */
	public function classify( array $identity, ?array $traffic_block ): string {
		$state = (string) ( $identity['verification_state'] ?? 'unknown' );

		switch ( $state ) {
			case 'customer_authorised':
				return 'admin_authorised';
			case 'explicitly_denied':
				return 'admin_denied';
			case 'previously_authorised_expired':
				return 'admin_authorisation_expired';
		}

		if ( in_array( $state, self::KNOWN_STATES, true ) ) {
			$network_match = $identity['network_match'] ?? null;
			return ( null !== $network_match && (bool) $network_match ) ? 'verified_crawler' : 'claimed_crawler_unverified';
		}

		$stage = null !== $traffic_block ? (string) ( $traffic_block['stage'] ?? 'observe' ) : 'observe';
		return in_array( $stage, self::ESCALATED_STAGES, true ) ? 'aggressive_unidentified' : 'unclassified';
	}
}
