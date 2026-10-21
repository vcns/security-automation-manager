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

	/**
	 * Returns the stable id of the robots.txt probing detector.
	 *
	 * @return string Detector id.
	 */
	public function id(): string {
		return 'robots-txt-visit';
	}

	/**
	 * Returns the family the robots.txt probing detector belongs to.
	 *
	 * @return string Family label.
	 */
	public function family(): string {
		return 'robots-txt-visit';
	}

	/**
	 * Returns the plain-language description of the robots.txt probing detector shown in the Detectors tab.
	 *
	 * @return string Translated description.
	 */
	public function description(): string {
		return __( 'Notes when a source checks your robots.txt before crawling -- typically a good sign, not evidence of anything adverse.', 'vcns-security-automation-manager' );
	}

	/**
	 * Returns the surfaces the robots.txt probing detector runs on.
	 *
	 * @return array Surface slugs, or an empty array for every surface.
	 */
	public function applicable_surfaces(): array {
		return array();
	}

	/**
	 * Returns the request data (path) that the robots.txt probing rules are matched against.
	 *
	 * @param array $context Request context built by Request_Observer.
	 * @return string Text to match.
	 */
	protected function subject( array $context ): string {
		return (string) ( $context['path'] ?? '' );
	}

	/**
	 * Returns the robots.txt probing detection rules.
	 *
	 * @return array Rules, each with an id, pattern, severity and description.
	 */
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
