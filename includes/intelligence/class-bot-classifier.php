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
 * Below a decision, a 'loopback' verification_state (Identity_Resolver's own
 * recognition of a request from the server's own loopback address, 127.0.0.0/8
 * or ::1 -- see its docblock) maps straight to 'loopback', ahead of the
 * known-vendor check below: this is the server calling itself, not a crawler
 * of any kind, so there's nothing to classify as verified/unverified against.
 *
 * Below that, a known vendor match (verification_state is one of
 * Identity_Resolver's automatic known_* states) splits on network_match:
 * matching the vendor's own published network data is 'verified_crawler';
 * claiming the identity without matching it is 'claimed_crawler_unverified'
 * -- §10's "impersonated crawlers" category, and the case worth an
 * administrator's attention most. A known vendor's own recent_paths is
 * never checked for enumeration below -- a search engine systematically
 * walking a site's posts is normal, expected crawler behaviour, not a
 * signal worth flagging.
 *
 * An unrecognised source (no vendor match) is classified across two
 * further signals, checked in this order:
 * - Uri_Pattern_Analyzer::is_enumerating() against this identity's
 *   Scanner_Identity_Store::recent_paths (§10's "URI-pattern" signal):
 *   'enumerating_scraper' if its last several requests show a fixed-step
 *   sequential pattern (e.g. /product/101, /product/102, /product/103) --
 *   checked first because a script walking IDs is worth flagging on its
 *   own, whether or not it has also tripped a rate limit yet.
 * - Else, whether this source has actually escalated through Traffic_
 *   Block_Store's existing progressive-response ladder (throttle or
 *   worse): 'aggressive_unidentified' if so, else 'unclassified' -- the
 *   overwhelming majority of ordinary, unremarkable traffic, deliberately
 *   not asserted as anything more specific than that.
 */

declare( strict_types=1 );

namespace WP_SAM\Intelligence;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Bot_Classifier {

	private const KNOWN_STATES = array( 'known_crawler', 'known_commercial_scanner', 'known_research_scanner' );

	private const ESCALATED_STAGES = array( 'throttle', 'temporary_block', 'extended_block', 'persistent_block' );

	private Uri_Pattern_Analyzer $uri_patterns;

	public function __construct( ?Uri_Pattern_Analyzer $uri_patterns = null ) {
		$this->uri_patterns = $uri_patterns ?? new Uri_Pattern_Analyzer();
	}

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

		if ( 'loopback' === $state ) {
			return 'loopback';
		}

		if ( in_array( $state, self::KNOWN_STATES, true ) ) {
			$network_match = $identity['network_match'] ?? null;
			return ( null !== $network_match && (bool) $network_match ) ? 'verified_crawler' : 'claimed_crawler_unverified';
		}

		$recent_paths = json_decode( (string) ( $identity['recent_paths'] ?? '' ), true );
		if ( is_array( $recent_paths ) && $this->uri_patterns->is_enumerating( $recent_paths ) ) {
			return 'enumerating_scraper';
		}

		$stage = null !== $traffic_block ? (string) ( $traffic_block['stage'] ?? 'observe' ) : 'observe';
		return in_array( $stage, self::ESCALATED_STAGES, true ) ? 'aggressive_unidentified' : 'unclassified';
	}
}
