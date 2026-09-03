<?php
/**
 * Robots.txt disallow-rule compliance (Phase 4C, .roadmap/phase3_early_
 * plan.md §10's "robots.txt behaviour" signal, second half). Robots_Txt_
 * Detector (shipped earlier) only recognises that a source examined
 * robots.txt; this checks whether a source claiming to be a known crawler
 * actually respects what it disallows.
 *
 * Deliberately scoped to sources Identity_Resolver has already recognised
 * as a known crawler/scanner vendor (verification_state is one of its
 * automatic known_* states) -- robots.txt is a voluntary convention
 * automated crawlers choose to respect; it says nothing about an ordinary
 * human visitor, who is never flagged here regardless of which path they
 * request. A claimed identity hitting a disallowed path is worth
 * attention whether or not it fetched robots.txt in this exact session --
 * most real crawlers cache it across visits rather than re-fetching every
 * time, so "did this request also fetch robots.txt" would be the wrong
 * test.
 *
 * Enforce-capable (an admin who has confirmed a specific claimed crawler
 * is genuinely non-compliant may reasonably want to act on it), but still
 * defaults to observation only.
 */

declare( strict_types=1 );

namespace WP_SAM\Intelligence\Detectors;

use WP_SAM\Intelligence\Detector;
use WP_SAM\Intelligence\Robots_Rules_Store;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Robots_Compliance_Detector extends Detector {

	private const CRAWLER_STATES = array( 'known_crawler', 'known_commercial_scanner', 'known_research_scanner' );

	private Robots_Rules_Store $rules;

	public function __construct( Robots_Rules_Store $rules ) {
		$this->rules = $rules;
	}

	public function id(): string {
		return 'robots-compliance';
	}

	public function family(): string {
		return 'robots-compliance';
	}

	public function applicable_surfaces(): array {
		return array();
	}

	public function allowed_control_actions(): array {
		return array( 'observe', 'enforce' );
	}

	public function evaluate( array $context ): ?array {
		$state = (string) ( $context['identity_verification_state'] ?? 'unknown' );
		if ( ! in_array( $state, self::CRAWLER_STATES, true ) ) {
			return null;
		}

		$path = (string) ( $context['path'] ?? '' );
		if ( ! $this->rules->is_disallowed( $path ) ) {
			return null;
		}

		return array(
			'severity'   => 'medium',
			'confidence' => 0.65,
			'detail'     => array(
				'robots_signal' => 'disallowed_path_requested',
				'description'   => 'A source recognised as a known crawler/scanner vendor requested a path this site\'s own robots.txt disallows for all crawlers.',
			),
		);
	}
}
