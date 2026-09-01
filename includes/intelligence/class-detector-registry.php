<?php
/**
 * Registry of available request detectors.
 *
 * register_defaults() (called once from Plugin::register_detectors())
 * registers the ten deterministic detector families free and available in
 * every build (Phase 3C -- technology mismatch, command/SQL/protocol
 * injection, sensitive directories/files, setup/install probes,
 * script/web-shell probes, version-control artefacts, vulnerability
 * probes). These are core, local, free functionality -- see
 * Automation_Mode_Registry's own docblock for the same reasoning applied to
 * automation modes; only *advanced* detector packs are a possible future
 * paid tier, not this baseline set.
 *
 * Detector_Engine iterates whatever is registered here; on a registry with
 * nothing registered (a build that skips register_defaults(), or before it
 * runs), it does nothing: Request_Observer's hooks still fire, still build
 * a request context, but write zero rows to Event_Store.
 *
 * Extensions (see includes/extensions/, physically absent from the
 * WordPress.org-channel build -- see .github/workflows/wporg-deploy.yml and
 * release-package.yml) hook into the wp_sam_register_detectors action
 * (fired from Plugin::register_detectors(), after register_defaults()) to
 * add their own detector without this class, or anything else in core,
 * knowing they exist. This is the same extension-point pattern
 * Automation_Mode_Registry already uses.
 */

declare( strict_types=1 );

namespace WP_SAM\Intelligence;

use WP_SAM\Intelligence\Detectors\Command_Injection_Detector;
use WP_SAM\Intelligence\Detectors\Protocol_Injection_Detector;
use WP_SAM\Intelligence\Detectors\Script_Webshell_Probe_Detector;
use WP_SAM\Intelligence\Detectors\Sensitive_Directory_Probing_Detector;
use WP_SAM\Intelligence\Detectors\Sensitive_File_Probing_Detector;
use WP_SAM\Intelligence\Detectors\Setup_Install_Probe_Detector;
use WP_SAM\Intelligence\Detectors\Sql_Injection_Detector;
use WP_SAM\Intelligence\Detectors\Technology_Mismatch_Detector;
use WP_SAM\Intelligence\Detectors\Version_Control_Artefact_Detector;
use WP_SAM\Intelligence\Detectors\Vulnerability_Probe_Detector;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Detector_Registry {

	/** @var array<string, Detector> */
	private static array $detectors = array();

	private static bool $defaults_registered = false;

	public static function register( Detector $detector ): void {
		self::$detectors[ $detector->id() ] = $detector;
	}

	/**
	 * Registers the ten core detector families. Idempotent -- safe to call
	 * more than once (e.g. once per test).
	 */
	public static function register_defaults(): void {
		if ( self::$defaults_registered ) {
			return;
		}
		self::$defaults_registered = true;

		self::register( new Technology_Mismatch_Detector() );
		self::register( new Command_Injection_Detector() );
		self::register( new Sql_Injection_Detector() );
		self::register( new Sensitive_Directory_Probing_Detector() );
		self::register( new Sensitive_File_Probing_Detector() );
		self::register( new Setup_Install_Probe_Detector() );
		self::register( new Script_Webshell_Probe_Detector() );
		self::register( new Protocol_Injection_Detector() );
		self::register( new Version_Control_Artefact_Detector() );
		self::register( new Vulnerability_Probe_Detector() );
	}

	public static function is_registered( string $id ): bool {
		return isset( self::$detectors[ $id ] );
	}

	public static function is_available( string $id ): bool {
		return isset( self::$detectors[ $id ] ) && self::$detectors[ $id ]->is_available();
	}

	public static function get( string $id ): ?Detector {
		return self::$detectors[ $id ] ?? null;
	}

	/** @return array<string> every registered detector id. */
	public static function keys(): array {
		return array_keys( self::$detectors );
	}

	/** @return array<Detector> every registered detector, for Detector_Engine to iterate. */
	public static function all(): array {
		return array_values( self::$detectors );
	}

	/** Test-only: clears all registered state so each test starts from a clean registry. */
	public static function reset(): void {
		self::$detectors           = array();
		self::$defaults_registered = false;
	}
}
