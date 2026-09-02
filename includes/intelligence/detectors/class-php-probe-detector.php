<?php
/**
 * Detects probes for exposed PHP development/diagnostic utilities and known
 * historical vulnerable test endpoints (.roadmap/phase3_early_plan.md
 * §11.6).
 *
 * Deliberately distinct from §11.5's Script_Webshell_Probe_Detector: that
 * family matches well-known malicious *filenames* (c99.php, webshell.php,
 * ...) and the uploads-directory anomaly; this one matches specific,
 * versioned *vulnerability signatures* -- the PHPUnit eval-stdin.php remote
 * code execution path (CVE-2017-9841), the php-cgi argument-injection query
 * string (CVE-2012-1823), and similar -- and is kept separate from §11.12's
 * Vulnerability_Probe_Detector's more general admin-tool paths (phpMyAdmin,
 * Adminer, cPanel) so neither family duplicates the other's rules. Per the
 * roadmap's own note, these are "maintained as versioned intelligence
 * rather than fixed assumptions embedded permanently in code" -- see
 * ruleset_version().
 */

declare( strict_types=1 );

namespace WP_SAM\Intelligence\Detectors;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Php_Probe_Detector extends Pattern_Detector {

	public function id(): string {
		return 'php-probes';
	}

	public function family(): string {
		return 'php-probes';
	}

	public function applicable_surfaces(): array {
		return array();
	}

	protected function subject( array $context ): string {
		$path         = (string) ( $context['path'] ?? '' );
		$query_string = (string) ( $context['query_string'] ?? '' );

		return '' !== $query_string ? $path . '?' . $query_string : $path;
	}

	protected function rules(): array {
		return array(
			array(
				'id'          => 'PHPPROBE-001',
				'pattern'     => '#(?:^|/)vendor/phpunit/phpunit/(?:src/)?Util/PHP/eval-stdin\.php#i',
				'severity'    => 'critical',
				'confidence'  => 0.95,
				'description' => 'PHPUnit eval-stdin.php remote code execution path (CVE-2017-9841).',
			),
			array(
				'id'          => 'PHPPROBE-002',
				'pattern'     => '#(?:^|/)phpunit(?:/|$)#i',
				'severity'    => 'medium',
				'confidence'  => 0.6,
				'description' => 'A PHPUnit vendor path, outside the specific eval-stdin.php RCE shape above.',
			),
			array(
				'id'          => 'PHPPROBE-003',
				'pattern'     => '#(?:^|/)(?:phpinfo|php_info|info|i)\.php$#i',
				'severity'    => 'medium',
				'confidence'  => 0.6,
				'description' => 'Exposed phpinfo()-style diagnostic script.',
			),
			array(
				'id'          => 'PHPPROBE-004',
				'pattern'     => '#(?:^|/)_ignition/execute-solution#i',
				'severity'    => 'critical',
				'confidence'  => 0.9,
				'description' => 'Laravel Ignition debug-mode remote code execution path (CVE-2021-3129) -- never legitimate on a WordPress install.',
			),
			array(
				'id'          => 'PHPPROBE-005',
				'pattern'     => '#[?&]-d\s*(?:allow_url_include|auto_prepend_file)\s*=#i',
				'severity'    => 'critical',
				'confidence'  => 0.9,
				'description' => 'php-cgi argument-injection query string (CVE-2012-1823).',
			),
			array(
				'id'          => 'PHPPROBE-006',
				'pattern'     => '#(?:^|/)_profiler/#i',
				'severity'    => 'low',
				'confidence'  => 0.5,
				'description' => 'Symfony profiler/debug-toolbar path -- not a WordPress feature.',
			),
		);
	}
}
