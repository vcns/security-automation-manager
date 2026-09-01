<?php
/**
 * Detects requests for other-CMS admin/install signature paths that would
 * never legitimately exist on a WordPress-only site (.roadmap/phase3_early_
 * plan.md §11.1).
 *
 * Every pattern is a high-confidence, product-specific signature file/path
 * (Joomla's administrator/manifests, Drupal's sites/default/settings.php,
 * Magento's app/etc/local.xml, and similar) rather than a generic term like
 * "admin" that would collide with WordPress's own /wp-admin/. Severity is
 * capped at medium -- the roadmap is explicit that technology mismatch
 * alone is a reconnaissance signal, not something to treat as high/critical.
 */

declare( strict_types=1 );

namespace WP_SAM\Intelligence\Detectors;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Technology_Mismatch_Detector extends Pattern_Detector {

	public function id(): string {
		return 'technology-mismatch';
	}

	public function family(): string {
		return 'technology-mismatch';
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
				'id'          => 'TM-001',
				'pattern'     => '#(?:^|/)administrator/manifests/#i',
				'severity'    => 'low',
				'confidence'  => 0.7,
				'description' => 'Joomla administrator manifest path.',
			),
			array(
				'id'          => 'TM-002',
				'pattern'     => '#(?:^|/)administrator/index\.php#i',
				'severity'    => 'low',
				'confidence'  => 0.6,
				'description' => 'Joomla administrator login path.',
			),
			array(
				'id'          => 'TM-003',
				'pattern'     => '#(?:^|/)sites/default/settings\.php#i',
				'severity'    => 'medium',
				'confidence'  => 0.85,
				'description' => 'Drupal site settings file.',
			),
			array(
				'id'          => 'TM-004',
				'pattern'     => '#(?:^|/)core/install\.php#i',
				'severity'    => 'low',
				'confidence'  => 0.6,
				'description' => 'Drupal installer path.',
			),
			array(
				'id'          => 'TM-005',
				'pattern'     => '#^/CHANGELOG\.txt$#i',
				'severity'    => 'low',
				'confidence'  => 0.55,
				'description' => 'Drupal root-level changelog (WordPress plugins ship their own at a different, non-root path, deliberately excluded).',
			),
			array(
				'id'          => 'TM-006',
				'pattern'     => '#(?:^|/)app/etc/local\.xml#i',
				'severity'    => 'medium',
				'confidence'  => 0.85,
				'description' => 'Magento local configuration file.',
			),
			array(
				'id'          => 'TM-007',
				'pattern'     => '#(?:^|/)downloader/index\.php#i',
				'severity'    => 'low',
				'confidence'  => 0.65,
				'description' => 'Magento Connect downloader.',
			),
			array(
				'id'          => 'TM-008',
				'pattern'     => '#(?:^|/)admin/Cms_Wysiwyg#i',
				'severity'    => 'medium',
				'confidence'  => 0.85,
				'description' => 'Magento admin WYSIWYG controller.',
			),
			array(
				'id'          => 'TM-009',
				'pattern'     => '#(?:^|/)typo3conf/#i',
				'severity'    => 'medium',
				'confidence'  => 0.85,
				'description' => 'TYPO3 configuration directory.',
			),
		);
	}
}
