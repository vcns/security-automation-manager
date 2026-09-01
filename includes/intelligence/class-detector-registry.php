<?php
/**
 * Registry of available request detectors.
 *
 * Ships genuinely empty in every build -- nothing in includes/ registers a
 * detector, and Phase 3B (the observation/classification skeleton) adds no
 * detector content of its own (that's Phase 3C). Detector_Engine iterates
 * whatever is registered here and, on an empty registry, does nothing:
 * Request_Observer's hooks fire, build a request context, and write zero
 * rows to Event_Store.
 *
 * Extensions (see includes/extensions/, physically absent from the
 * WordPress.org-channel build -- see .github/workflows/wporg-deploy.yml and
 * release-package.yml) hook into the wp_sam_register_detectors action
 * (fired from Plugin::register_detectors()) to add their own detector
 * without this class, or anything else in core, knowing they exist. This is
 * the same extension-point pattern Automation_Mode_Registry already uses.
 */

declare( strict_types=1 );

namespace WP_SAM\Intelligence;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Detector_Registry {

	/** @var array<string, Detector> */
	private static array $detectors = array();

	public static function register( Detector $detector ): void {
		self::$detectors[ $detector->id() ] = $detector;
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
		self::$detectors = array();
	}
}
