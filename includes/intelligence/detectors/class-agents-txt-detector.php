<?php
/**
 * Recognises when a source examines agents.txt (Phase 4C extension, user-
 * requested, alongside Robots_Txt_Detector's own "robots.txt behaviour"
 * signal -- see that class's own docblock for why this is a low-severity,
 * observation-only positive signal rather than evidence of anything
 * adverse).
 */

declare( strict_types=1 );

namespace WP_SAM\Intelligence\Detectors;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Agents_Txt_Detector extends Pattern_Detector {

	/**
	 * Returns the stable id of the agents.txt probing detector.
	 *
	 * @return string Detector id.
	 */
	public function id(): string {
		return 'agents-txt-visit';
	}

	/**
	 * Returns the family the agents.txt probing detector belongs to.
	 *
	 * @return string Family label.
	 */
	public function family(): string {
		return 'agents-txt-visit';
	}

	/**
	 * Returns the plain-language description of the agents.txt probing detector shown in the Detectors tab.
	 *
	 * @return string Translated description.
	 */
	public function description(): string {
		return __( 'Notes when a source checks your agents.txt before crawling -- typically a good sign, not evidence of anything adverse.', 'vcns-security-automation-manager' );
	}

	/**
	 * Returns the surfaces the agents.txt probing detector runs on.
	 *
	 * @return array Surface slugs, or an empty array for every surface.
	 */
	public function applicable_surfaces(): array {
		return array();
	}

	/**
	 * Returns the request data (path) that the agents.txt probing rules are matched against.
	 *
	 * @param array $context Request context built by Request_Observer.
	 * @return string Text to match.
	 */
	protected function subject( array $context ): string {
		return (string) ( $context['path'] ?? '' );
	}

	/**
	 * Returns the agents.txt probing detection rules.
	 *
	 * @return array Rules, each with an id, pattern, severity and description.
	 */
	protected function rules(): array {
		return array(
			array(
				'id'          => 'AGENTS-001',
				'pattern'     => '#^/agents\.txt$#i',
				'severity'    => 'low',
				'confidence'  => 0.95,
				'description' => 'Source examined agents.txt -- typically a positive signal (a well-behaved AI agent/crawler checking access rules before proceeding), not evidence of malicious intent.',
			),
		);
	}
}
