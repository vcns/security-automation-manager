<?php
/**
 * Detects access attempts against version-control and build metadata that
 * should never be web-accessible (.roadmap/phase3_early_plan.md §11.11).
 *
 * .git/config and .git/HEAD specifically are their own, higher-severity
 * rule alongside a broader .git/ rule -- both can match the same URL
 * (e.g. /repo/.git/config), and Pattern_Detector::evaluate() reports
 * whichever is more severe, not whichever happens to run first.
 */

declare( strict_types=1 );

namespace WP_SAM\Intelligence\Detectors;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Version_Control_Artefact_Detector extends Pattern_Detector {

	/**
	 * Returns the stable id of the version control artefact detector.
	 *
	 * @return string Detector id.
	 */
	public function id(): string {
		return 'version-control-artefacts';
	}

	/**
	 * Returns the family the version control artefact detector belongs to.
	 *
	 * @return string Family label.
	 */
	public function family(): string {
		return 'version-control-artefacts';
	}

	/**
	 * Returns the plain-language description of the version control artefact detector shown in the Detectors tab.
	 *
	 * @return string Translated description.
	 */
	public function description(): string {
		return __( 'Flags requests for .git, .svn, .hg, and dependency lock files that should never be web-accessible.', 'vcns-security-automation-manager' );
	}

	/**
	 * Returns the surfaces the version control artefact detector runs on.
	 *
	 * @return array Surface slugs, or an empty array for every surface.
	 */
	public function applicable_surfaces(): array {
		return array();
	}

	/**
	 * Returns the request data (path) that the version control artefact rules are matched against.
	 *
	 * @param array $context Request context built by Request_Observer.
	 * @return string Text to match.
	 */
	protected function subject( array $context ): string {
		return (string) ( $context['path'] ?? '' );
	}

	/**
	 * Returns the version control artefact detection rules.
	 *
	 * @return array Rules, each with an id, pattern, severity and description.
	 */
	protected function rules(): array {
		return array(
			array(
				'id'          => 'VCS-001',
				'pattern'     => '#(?:^|/)\.git/(?:config|HEAD)#i',
				'severity'    => 'high',
				'confidence'  => 0.9,
				'description' => 'Git internal config/ref file -- can leak repository contents or remote credentials.',
			),
			array(
				'id'          => 'VCS-002',
				'pattern'     => '#(?:^|/)\.git/#i',
				'severity'    => 'medium',
				'confidence'  => 0.75,
				'description' => 'Git metadata directory.',
			),
			array(
				'id'          => 'VCS-003',
				'pattern'     => '#(?:^|/)\.svn/#i',
				'severity'    => 'medium',
				'confidence'  => 0.75,
				'description' => 'Subversion metadata directory.',
			),
			array(
				'id'          => 'VCS-004',
				'pattern'     => '#(?:^|/)\.hg/#i',
				'severity'    => 'medium',
				'confidence'  => 0.7,
				'description' => 'Mercurial metadata directory.',
			),
			array(
				'id'          => 'VCS-005',
				'pattern'     => '#(?:^|/)composer\.(?:lock|json)#i',
				'severity'    => 'low',
				'confidence'  => 0.6,
				'description' => 'Composer dependency metadata.',
			),
			array(
				'id'          => 'VCS-006',
				'pattern'     => '#(?:^|/)package-lock\.json#i',
				'severity'    => 'low',
				'confidence'  => 0.55,
				'description' => 'npm dependency lock file.',
			),
			array(
				'id'          => 'VCS-007',
				'pattern'     => '#(?:^|/)yarn\.lock#i',
				'severity'    => 'low',
				'confidence'  => 0.55,
				'description' => 'Yarn dependency lock file.',
			),
		);
	}
}
