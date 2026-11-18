<?php
/**
 * Detects probing for script-execution files and web shells
 * (.roadmap/phase3_early_plan.md §11.5).
 *
 * Deliberately does NOT match a bare script extension (.php/.cgi/.asp/...)
 * anywhere -- the roadmap is explicit that doing so would misclassify
 * ordinary WordPress traffic as malicious (wp-login.php, admin-ajax.php,
 * xmlrpc.php are all legitimate, constantly-requested .php paths). Instead:
 * (a) a curated list of filenames with no legitimate reason to exist on any
 * WordPress install, matched only at a filename boundary, and (b) any
 * script-shaped file inside wp-content/uploads/, which should never contain
 * server-executable content regardless of its name -- the anomaly signal is
 * "a script file is present in an upload directory", not the filename.
 */

declare( strict_types=1 );

namespace WP_SAM\Intelligence\Detectors;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Script_Webshell_Probe_Detector extends Pattern_Detector {

	/**
	 * Returns the stable id of the script and web shell probe detector.
	 *
	 * @return string Detector id.
	 */
	public function id(): string {
		return 'script-webshell-probes';
	}

	/**
	 * Returns the family the script and web shell probe detector belongs to.
	 *
	 * @return string Family label.
	 */
	public function family(): string {
		return 'script-webshell-probes';
	}

	/**
	 * Returns the plain-language description of the script and web shell probe detector shown in the Detectors tab.
	 *
	 * @return string Translated description.
	 */
	public function description(): string {
		return __( 'Flags known web-shell filenames and any server-executable script file sitting inside your uploads folder.', 'vcns-security-automation-manager' );
	}

	/**
	 * Returns the surfaces the script and web shell probe detector runs on.
	 *
	 * @return array Surface slugs, or an empty array for every surface.
	 */
	public function applicable_surfaces(): array {
		return array();
	}

	/**
	 * Returns the request data (path) that the script and web shell probe rules are matched against.
	 *
	 * @param array $context Request context built by Request_Observer.
	 * @return string Text to match.
	 */
	protected function subject( array $context ): string {
		return (string) ( $context['path'] ?? '' );
	}

	/**
	 * Returns the script and web shell probe detection rules.
	 *
	 * @return array Rules, each with an id, pattern, severity and description.
	 */
	protected function rules(): array {
		return array(
			array(
				'id'          => 'WSHELL-001',
				'pattern'     => '#(?:^|/)(?:c99|r57|wso|b374k|alfa)\.php[3-7]?#i',
				'severity'    => 'high',
				'confidence'  => 0.85,
				'description' => 'Filename matching a well-known web-shell toolkit.',
			),
			array(
				'id'          => 'WSHELL-002',
				'pattern'     => '#(?:^|/)webshell\.(?:php|phtml)#i',
				'severity'    => 'high',
				'confidence'  => 0.85,
				'description' => 'Filename literally named webshell.',
			),
			array(
				'id'          => 'WSHELL-003',
				'pattern'     => '#^/wp-content/uploads/.*\.(?:php[3-7]?|phtml|pl|py|cgi|asp|aspx|jsp|jsf|sh|shtm|shtml)$#i',
				'severity'    => 'critical',
				'confidence'  => 0.9,
				'description' => 'Server-executable script file requested inside the uploads directory, which should never contain one.',
			),
		);
	}
}
