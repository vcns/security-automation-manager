<?php
/**
 * Registry of available CSP automation approval modes.
 *
 * register_defaults() (called once from Plugin::bootstrap()) registers the
 * three modes free and available in every build. Nothing in this class, or
 * anywhere else in includes/, has any knowledge of what -- if anything --
 * registers additional modes: extensions (see includes/extensions/,
 * physically absent from the WordPress.org-channel build -- see
 * .github/workflows/wporg-deploy.yml and release-package.yml) hook into the
 * wp_sam_register_automation_modes action (fired from Plugin::bootstrap())
 * to add their own mode, each with its own label, allowed risk tiers, and
 * optional availability check.
 *
 * This is the actual compliance boundary for a paid automation mode: a mode
 * that is never registered here does not exist anywhere in this codebase's
 * runtime behaviour for a build that never loads the extension that would
 * have registered it -- not a mode that exists but is hidden behind a flag,
 * a missing class, or an entitlement check. is_valid_mode() and
 * is_available() both return false, uniformly, for a mode nothing ever
 * registered; the rest of the codebase (Automation_Config, Decision_Engine,
 * the admin UI) never references a specific mode's identifier, label, or
 * risk tier directly -- it queries this registry generically instead.
 */

declare( strict_types=1 );

namespace WP_SAM\CSP;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Automation_Mode_Registry {

	/**
	 * @var array<string, array{label: string, allowed_risks: array<string>, availability: ?callable}>
	 */
	private static array $modes = array();

	/** @var array<string,string> legacy alias => real mode key */
	private static array $legacy_aliases = array();

	private static bool $defaults_registered = false;

	/**
	 * @param string $key Stable, lowercase mode identifier.
	 * @param string $label Human-readable label.
	 * @param array<string> $allowed_risks Risk tiers ('low'/'medium'/'high') this mode auto-approves.
	 * @param callable|null $availability_check Returns bool; null means always available (the free modes).
	 */
	public static function register( string $key, string $label, array $allowed_risks, ?callable $availability_check = null ): void {
		self::$modes[ $key ] = array(
			'label'         => $label,
			'allowed_risks' => $allowed_risks,
			'availability'  => $availability_check,
		);
	}

	public static function register_legacy_alias( string $alias, string $mode_key ): void {
		self::$legacy_aliases[ $alias ] = $mode_key;
	}

	/**
	 * Registers the free modes available in every build. Idempotent -- safe
	 * to call more than once (e.g. once per test).
	 */
	public static function register_defaults(): void {
		if ( self::$defaults_registered ) {
			return;
		}
		self::$defaults_registered = true;

		self::register( 'manual', __( 'Manual', 'vcns-security-automation-manager' ), array() );
		self::register( 'automatic_medium_high_approval', __( 'Automatic (with medium+high approvals)', 'vcns-security-automation-manager' ), array( 'low' ) );
		self::register( 'automatic_high_approval', __( 'Automatic (with high approvals only)', 'vcns-security-automation-manager' ), array( 'low', 'medium' ) );

		self::register_legacy_alias( 'conservative', 'automatic_medium_high_approval' );
		self::register_legacy_alias( 'balanced', 'automatic_high_approval' );
	}

	/** Test-only: clears all registered state so each test starts from a clean registry. */
	public static function reset(): void {
		self::$modes               = array();
		self::$legacy_aliases      = array();
		self::$defaults_registered = false;
	}

	public static function resolve_legacy_alias( string $key ): string {
		return self::$legacy_aliases[ $key ] ?? $key;
	}

	public static function is_valid_mode( string $key ): bool {
		return isset( self::$modes[ $key ] );
	}

	/** False for both an unregistered mode and a registered-but-currently-ungated-off mode (e.g. a lapsed entitlement). */
	public static function is_available( string $key ): bool {
		if ( ! isset( self::$modes[ $key ] ) ) {
			return false;
		}
		$check = self::$modes[ $key ]['availability'];
		return null === $check || true === $check();
	}

	/** @return array<string> */
	public static function allowed_risks( string $key ): array {
		return self::$modes[ $key ]['allowed_risks'] ?? array();
	}

	/** @return array<string,string> mode key => label, for every registered mode (available or not, for "requires upgrade" presentation). */
	public static function labels(): array {
		return array_map( static fn( array $mode ): string => $mode['label'], self::$modes );
	}

	/** @return array<string> every registered mode key. */
	public static function keys(): array {
		return array_keys( self::$modes );
	}
}
