<?php
/**
 * Detects likely attempts to retrieve secrets, credentials, or sensitive
 * configuration (.roadmap/phase3_early_plan.md §11.9).
 *
 * Every rule matches a specific, named filename/path -- never a generic
 * extension -- per the roadmap's explicit instruction not to blindly
 * classify every .json/.yaml/.conf-shaped file as malicious.
 *
 * Deliberately excludes .git/, composer/package lock files, and similar
 * build/VCS artefacts, which live in Version_Control_Artefact_Detector
 * instead -- keeps the two families non-overlapping so the same URL isn't
 * double-logged under two detectors for identical evidence. The roadmap's
 * own §11.9/§11.11 example lists genuinely overlap on .env and lock files;
 * this split is this codebase's interpretation, not something the roadmap
 * text resolves unambiguously on its own.
 */

declare( strict_types=1 );

namespace WP_SAM\Intelligence\Detectors;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Sensitive_File_Probing_Detector extends Pattern_Detector {

	/**
	 * Returns the stable id of the sensitive file probing detector.
	 *
	 * @return string Detector id.
	 */
	public function id(): string {
		return 'sensitive-files';
	}

	/**
	 * Returns the family the sensitive file probing detector belongs to.
	 *
	 * @return string Family label.
	 */
	public function family(): string {
		return 'sensitive-files';
	}

	/**
	 * Returns the plain-language description of the sensitive file probing detector shown in the Detectors tab.
	 *
	 * @return string Translated description.
	 */
	public function description(): string {
		return __( 'Flags requests for SSH keys, .env files, AWS credentials, and backup copies of wp-config.php.', 'vcns-security-automation-manager' );
	}

	/**
	 * Returns the surfaces the sensitive file probing detector runs on.
	 *
	 * @return array Surface slugs, or an empty array for every surface.
	 */
	public function applicable_surfaces(): array {
		return array();
	}

	/**
	 * Returns the request data (path) that the sensitive file probing rules are matched against.
	 *
	 * @param array $context Request context built by Request_Observer.
	 * @return string Text to match.
	 */
	protected function subject( array $context ): string {
		return (string) ( $context['path'] ?? '' );
	}

	/**
	 * Returns the sensitive file probing detection rules.
	 *
	 * @return array Rules, each with an id, pattern, severity and description.
	 */
	protected function rules(): array {
		return array(
			array(
				'id'          => 'SFILE-001',
				'pattern'     => '#(?:^|/)id_(?:rsa|dsa|ecdsa|ed25519)(?:\.pub)?#i',
				'severity'    => 'high',
				'confidence'  => 0.9,
				'description' => 'SSH private/public key file.',
			),
			array(
				'id'          => 'SFILE-002',
				'pattern'     => '#(?:^|/)\.env(?:\.[a-z0-9_-]+)?(?:$|/)#i',
				'severity'    => 'high',
				'confidence'  => 0.85,
				'description' => 'Environment/secrets file.',
			),
			array(
				'id'          => 'SFILE-003',
				'pattern'     => '#(?:^|/)\.aws/(?:credentials|config)#i',
				'severity'    => 'high',
				'confidence'  => 0.9,
				'description' => 'AWS credentials/config file.',
			),
			array(
				'id'          => 'SFILE-004',
				'pattern'     => '#(?:^|/)\.netrc#i',
				'severity'    => 'high',
				'confidence'  => 0.85,
				'description' => 'Netrc credentials file.',
			),
			array(
				'id'          => 'SFILE-005',
				'pattern'     => '#(?:^|/)\.htpasswd#i',
				'severity'    => 'high',
				'confidence'  => 0.85,
				'description' => 'Apache basic-auth password file.',
			),
			array(
				'id'          => 'SFILE-006',
				'pattern'     => '#(?:^|/)wp-config(?:\.php\.(?:bak|save|orig|old|swp)|\.php~|\.bak|\.old|\.save)$#i',
				'severity'    => 'critical',
				'confidence'  => 0.9,
				'description' => 'Backup/editor-leftover copy of wp-config.php.',
			),
		);
	}
}
