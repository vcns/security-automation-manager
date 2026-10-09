<?php
/**
 * Deception and Honey Paths (Phase 3J, .roadmap/phase3_early_plan.md §15).
 *
 * rules() is built dynamically from Honeypath_Store's configured decoy
 * paths, one exact-match rule per path, rather than any hardcoded list --
 * these are administrator-chosen fake resources, not a detectable pattern
 * this codebase could know in advance. With zero configured paths (every
 * fresh install and upgrade), rules() returns an empty array and
 * Pattern_Detector::evaluate() always returns null before ever compiling a
 * pattern -- this is the entire mechanism behind "disabled by default";
 * there is no separate enable/disable flag to keep in sync.
 *
 * Only ever detects and records a Finding through the exact same Event_
 * Store path every other Pattern_Detector uses -- it never changes the
 * actual HTTP response for the request (WordPress's normal 404/route
 * handling proceeds untouched), so this can't uncontrolled-expose content
 * or actively interact with the requester, satisfying the roadmap's "no
 * active exploitation of the requester" requirement by construction.
 */

declare( strict_types=1 );

namespace WP_SAM\Intelligence\Detectors;

use WP_SAM\Intelligence\Honeypath_Store;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Honeypath_Detector extends Pattern_Detector {

	private Honeypath_Store $paths;

	/**
	 * Constructor.
	 *
	 * @param Honeypath_Store $paths Honey path store.
	 */
	public function __construct( Honeypath_Store $paths ) {
		$this->paths = $paths;
	}

	/**
	 * Returns the stable id of the honey path detector.
	 *
	 * @return string Detector id.
	 */
	public function id(): string {
		return 'honeypath';
	}

	/**
	 * Returns the family the honey path detector belongs to.
	 *
	 * @return string Family label.
	 */
	public function family(): string {
		return 'deception';
	}

	/**
	 * Returns the plain-language description of the honey path detector shown in the Detectors tab.
	 *
	 * @return string Translated description.
	 */
	public function description(): string {
		return __( 'Flags any request to one of your configured decoy paths -- no legitimate visitor should ever hit one.', 'vcns-security-automation-manager' );
	}

	/**
	 * Returns the surfaces the honey path detector runs on.
	 *
	 * @return array Surface slugs, or an empty array for every surface.
	 */
	public function applicable_surfaces(): array {
		return array();
	}

	/**
	 * Returns the request data (path) that the honey path rules are matched against.
	 *
	 * @param array $context Request context built by Request_Observer.
	 * @return string Text to match.
	 */
	protected function subject( array $context ): string {
		return (string) ( $context['path'] ?? '' );
	}

	/**
	 * Returns the honey path detection rules.
	 *
	 * @return array Rules, each with an id, pattern, severity and description.
	 */
	protected function rules(): array {
		$rules = array();

		foreach ( $this->paths->paths() as $path ) {
			$rules[] = array(
				'id'          => 'HONEY-' . substr( hash( 'sha256', $path ), 0, 12 ),
				'pattern'     => '#^' . preg_quote( $path, '#' ) . '(?:$|/)#i',
				'severity'    => 'critical',
				'confidence'  => 0.95,
				'description' => 'Request to a configured decoy path that no legitimate route ever serves.',
			);
		}

		return $rules;
	}
}
