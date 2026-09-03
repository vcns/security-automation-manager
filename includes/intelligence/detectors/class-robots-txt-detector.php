<?php
/**
 * Recognises when a source examines robots.txt (Phase 4C, .roadmap/
 * phase4_plan.md, .roadmap/phase3_early_plan.md §10's "robots.txt
 * behaviour" signal).
 *
 * Deliberately low severity and observation-only by default: fetching
 * robots.txt before crawling is well-behaved-crawler etiquette, not
 * evidence of anything adverse -- this exists to make the *fact* of the
 * visit correlatable (by IP, against Scanner_Identity_Store and Bot_
 * Classifier) with a source's other activity, e.g. an admin noticing a
 * claimed crawler that generates hundreds of hits but never once checked
 * robots.txt.
 *
 * This is the first piece of §10's "robots.txt behaviour" signal, not the
 * whole of it -- actually checking whether a source goes on to request
 * paths robots.txt disallows needs live rule parsing and cross-request
 * correlation this increment doesn't build; carried forward, see .roadmap/
 * phase4_plan.md's Phase 4C status.
 */

declare( strict_types=1 );

namespace WP_SAM\Intelligence\Detectors;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Robots_Txt_Detector extends Pattern_Detector {

	public function id(): string {
		return 'robots-txt-visit';
	}

	public function family(): string {
		return 'robots-txt-visit';
	}

	public function applicable_surfaces(): array {
		return array();
	}

	protected function subject( array $context ): string {
		return (string) ( $context['path'] ?? '' );
	}

	protected function rules(): array {
		return array(
			array(
				'id'          => 'ROBOTS-001',
				'pattern'     => '#^/robots\.txt$#i',
				'severity'    => 'low',
				'confidence'  => 0.95,
				'description' => 'Source examined robots.txt -- typically a positive signal (a well-behaved crawler checking crawl rules before proceeding), not evidence of malicious intent.',
			),
		);
	}
}
