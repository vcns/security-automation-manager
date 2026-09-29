<?php
/**
 * agents.txt disallow-rule compliance (Phase 4C extension, user-requested)
 * -- the agents.txt counterpart to Robots_Compliance_Detector. Agents_Txt_
 * Detector (above) only recognises that a source examined agents.txt; this
 * checks whether a source claiming to be a known crawler actually respects
 * what it disallows. See Robots_Compliance_Detector's own docblock for the
 * full reasoning -- identical here, substituting Agents_Rules_Store.
 */

declare( strict_types=1 );

namespace WP_SAM\Intelligence\Detectors;

use WP_SAM\Intelligence\Agents_Rules_Store;
use WP_SAM\Intelligence\Detector;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Agents_Compliance_Detector extends Detector {

	private const CRAWLER_STATES = array( 'known_crawler', 'known_commercial_scanner', 'known_research_scanner' );

	private Agents_Rules_Store $rules;

	/**
	 * Constructor.
	 *
	 * @param Agents_Rules_Store $rules Agents rules store.
	 */
	public function __construct( Agents_Rules_Store $rules ) {
		$this->rules = $rules;
	}

	/**
	 * Returns the stable id of the agents.txt compliance detector.
	 *
	 * @return string Detector id.
	 */
	public function id(): string {
		return 'agents-compliance';
	}

	/**
	 * Returns the family the agents.txt compliance detector belongs to.
	 *
	 * @return string Family label.
	 */
	public function family(): string {
		return 'agents-compliance';
	}

	/**
	 * Returns the plain-language description of the agents.txt compliance detector shown in the Detectors tab.
	 *
	 * @return string Translated description.
	 */
	public function description(): string {
		return __( 'Flags a known crawler/scanner that requests a path your own agents.txt disallows for all agents.', 'vcns-security-automation-manager' );
	}

	/**
	 * Returns the surfaces the agents.txt compliance detector runs on.
	 *
	 * @return array Surface slugs, or an empty array for every surface.
	 */
	public function applicable_surfaces(): array {
		return array();
	}

	/**
	 * Returns the control actions the agents.txt compliance detector may be set to.
	 *
	 * @return array Control action keys.
	 */
	public function allowed_control_actions(): array {
		return array( 'observe', 'enforce' );
	}

	/**
	 * Flags a recognised crawler that requests a path disallowed by this site's agents.txt.
	 *
	 * @param array $context Request context built by Request_Observer.
	 * @return array|null Finding data, or null when nothing was found.
	 */
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
				'agents_signal' => 'disallowed_path_requested',
				'description'   => 'A source recognised as a known crawler/scanner vendor requested a path this site\'s own agents.txt disallows for all agents.',
			),
		);
	}
}
