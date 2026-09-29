<?php
/**
 * Detects requests for setup/installer/diagnostic pages that have no
 * business being hit repeatedly on a live site (.roadmap/phase3_early_
 * plan.md §11.10).
 *
 * wp-admin/setup-config.php and wp-admin/install.php are WordPress core's
 * own, entirely legitimate installer pages -- hit once during every fresh
 * install -- so those two rules stay low severity/confidence rather than
 * anything higher; this detector has no way to know install state.
 */

declare( strict_types=1 );

namespace WP_SAM\Intelligence\Detectors;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Setup_Install_Probe_Detector extends Pattern_Detector {

	/**
	 * Returns the stable id of the setup and install probe detector.
	 *
	 * @return string Detector id.
	 */
	public function id(): string {
		return 'setup-install-probes';
	}

	/**
	 * Returns the family the setup and install probe detector belongs to.
	 *
	 * @return string Family label.
	 */
	public function family(): string {
		return 'setup-install-probes';
	}

	/**
	 * Returns the plain-language description of the setup and install probe detector shown in the Detectors tab.
	 *
	 * @return string Translated description.
	 */
	public function description(): string {
		return __( 'Flags requests for installer, setup, and phpinfo()-style diagnostic pages.', 'vcns-security-automation-manager' );
	}

	/**
	 * Returns the surfaces the setup and install probe detector runs on.
	 *
	 * @return array Surface slugs, or an empty array for every surface.
	 */
	public function applicable_surfaces(): array {
		return array();
	}

	/**
	 * Returns the request data (path) that the setup and install probe rules are matched against.
	 *
	 * @param array $context Request context built by Request_Observer.
	 * @return string Text to match.
	 */
	protected function subject( array $context ): string {
		return (string) ( $context['path'] ?? '' );
	}

	/**
	 * Returns the setup and install probe detection rules.
	 *
	 * @return array Rules, each with an id, pattern, severity and description.
	 */
	protected function rules(): array {
		return array(
			array(
				'id'          => 'SETUP-001',
				'pattern'     => '#(?:^|/)wp-admin/setup-config\.php#i',
				'severity'    => 'low',
				'confidence'  => 0.5,
				'description' => 'WordPress core installer config step -- legitimate during a real install.',
			),
			array(
				'id'          => 'SETUP-002',
				'pattern'     => '#(?:^|/)wp-admin/install\.php#i',
				'severity'    => 'low',
				'confidence'  => 0.5,
				'description' => 'WordPress core installer -- legitimate during a real install.',
			),
			array(
				'id'          => 'SETUP-003',
				'pattern'     => '#^/install\.php$#i',
				'severity'    => 'medium',
				'confidence'  => 0.6,
				'description' => 'Root-level installer script.',
			),
			array(
				'id'          => 'SETUP-004',
				'pattern'     => '#^/setup\.php$#i',
				'severity'    => 'medium',
				'confidence'  => 0.6,
				'description' => 'Root-level setup script.',
			),
			array(
				'id'          => 'SETUP-005',
				'pattern'     => '#(?:^|/)phpinfo\.php#i',
				'severity'    => 'medium',
				'confidence'  => 0.7,
				'description' => 'Exposed phpinfo() diagnostic page.',
			),
			array(
				'id'          => 'SETUP-006',
				'pattern'     => '#^/info\.php$#i',
				'severity'    => 'medium',
				'confidence'  => 0.6,
				'description' => 'Root-level PHP info/diagnostic page.',
			),
			array(
				'id'          => 'SETUP-007',
				'pattern'     => '#^/test\.php$#i',
				'severity'    => 'low',
				'confidence'  => 0.5,
				'description' => 'Root-level test/scratch script.',
			),
		);
	}
}
