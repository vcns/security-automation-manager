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

	public function id(): string {
		return 'sensitive-files';
	}

	public function family(): string {
		return 'sensitive-files';
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
