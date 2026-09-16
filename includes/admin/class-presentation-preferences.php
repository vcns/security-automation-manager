<?php
/**
 * Per-WordPress-user presentation preferences for the customer-centred admin
 * experience (Change Requirement Specification: "Customer-Centred
 * Administration Experience", §5-§7).
 *
 * These preferences control ONLY how SAM presents information to the current
 * WordPress user -- wording depth, help density, and landing emphasis. They
 * are stored as user meta (scoped to one WordPress user, never site-wide) and
 * are never read by, or written from, any security-decision class. Nothing
 * in this file touches an option, a pillar profile, a policy store, or any
 * other security configuration -- see the class docblock's own boundary:
 * a presentation preference must never become a security-control decision.
 */

declare( strict_types=1 );

namespace WP_SAM\Admin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Presentation_Preferences {

	private const META_ONBOARDING_STATE = 'wp_sam_presentation_onboarding_state';
	private const META_RELATIONSHIP     = 'wp_sam_relationship';
	private const META_FAMILIARITY      = 'wp_sam_security_familiarity';
	private const META_DEPTH            = 'wp_sam_presentation_depth';
	private const META_LANDING          = 'wp_sam_landing_emphasis';

	public const ONBOARDING_STATES = array( 'completed', 'skipped' );

	public const RELATIONSHIPS = array(
		'owner_manager',
		'site_admin',
		'developer',
		'content_editor',
		'client_sites',
		'other',
	);

	public const FAMILIARITY_LEVELS = array( 'new', 'comfortable', 'experienced', 'specialist' );

	public const DEPTHS = array( 'simple', 'balanced', 'technical' );

	public const LANDING_EMPHASES = array( 'overall', 'attention', 'activity', 'protection', 'technical', 'none' );

	public const DEFAULT_DEPTH            = 'balanced';
	public const DEFAULT_LANDING_EMPHASIS = 'overall';

	/**
	 * Resolves the current preference state for a WordPress user, falling
	 * back to defaults for anything missing or not on the fixed allow-list --
	 * stored meta is never trusted as-is.
	 *
	 * @return array{onboarding_state:string,relationship:string,security_familiarity:string,presentation_depth:string,landing_emphasis:string}
	 */
	public static function get_for_user( ?int $user_id = null ): array {
		$user_id = self::resolve_user_id( $user_id );

		return array(
			'onboarding_state'     => self::normalise( get_user_meta( $user_id, self::META_ONBOARDING_STATE, true ), self::ONBOARDING_STATES, '' ),
			'relationship'         => self::normalise( get_user_meta( $user_id, self::META_RELATIONSHIP, true ), self::RELATIONSHIPS, '' ),
			'security_familiarity' => self::normalise( get_user_meta( $user_id, self::META_FAMILIARITY, true ), self::FAMILIARITY_LEVELS, '' ),
			'presentation_depth'   => self::normalise( get_user_meta( $user_id, self::META_DEPTH, true ), self::DEPTHS, self::DEFAULT_DEPTH ),
			'landing_emphasis'     => self::normalise( get_user_meta( $user_id, self::META_LANDING, true ), self::LANDING_EMPHASES, self::DEFAULT_LANDING_EMPHASIS ),
		);
	}

	public static function has_completed_onboarding( ?int $user_id = null ): bool {
		$state = self::get_for_user( $user_id )['onboarding_state'];
		return in_array( $state, self::ONBOARDING_STATES, true );
	}

	/**
	 * Persists the four Welcome/editor answers for one WordPress user.
	 * Every field is validated against its fixed allow-list; anything
	 * missing or invalid is normalised to its default rather than rejected
	 * outright, so a malformed request can never leave preferences in a
	 * partially-invalid state.
	 *
	 * @param array<string,mixed> $raw Raw request values, keyed by field name
	 *                                 (relationship, security_familiarity,
	 *                                 presentation_depth, landing_emphasis).
	 */
	public static function save_for_user( int $user_id, array $raw ): array {
		$resolved = array(
			'relationship'         => self::normalise( $raw['relationship'] ?? '', self::RELATIONSHIPS, '' ),
			'security_familiarity' => self::normalise( $raw['security_familiarity'] ?? '', self::FAMILIARITY_LEVELS, '' ),
			'presentation_depth'   => self::normalise( $raw['presentation_depth'] ?? '', self::DEPTHS, self::DEFAULT_DEPTH ),
			'landing_emphasis'     => self::normalise( $raw['landing_emphasis'] ?? '', self::LANDING_EMPHASES, self::DEFAULT_LANDING_EMPHASIS ),
		);

		update_user_meta( $user_id, self::META_ONBOARDING_STATE, 'completed' );
		update_user_meta( $user_id, self::META_RELATIONSHIP, $resolved['relationship'] );
		update_user_meta( $user_id, self::META_FAMILIARITY, $resolved['security_familiarity'] );
		update_user_meta( $user_id, self::META_DEPTH, $resolved['presentation_depth'] );
		update_user_meta( $user_id, self::META_LANDING, $resolved['landing_emphasis'] );

		return self::get_for_user( $user_id );
	}

	/**
	 * Records a "Skip for now" -- per spec §4.2, this stores only the
	 * skipped state plus the Balanced/Overall defaults. It deliberately
	 * leaves relationship and security_familiarity unset: no role or
	 * experience assumption may be made about a user who skipped.
	 */
	public static function skip_for_user( int $user_id ): array {
		update_user_meta( $user_id, self::META_ONBOARDING_STATE, 'skipped' );
		update_user_meta( $user_id, self::META_DEPTH, self::DEFAULT_DEPTH );
		update_user_meta( $user_id, self::META_LANDING, self::DEFAULT_LANDING_EMPHASIS );

		return self::get_for_user( $user_id );
	}

	/** Human-readable label for a presentation-depth value, for the small unobtrusive "Presentation: Balanced" indicator (spec §13.1). */
	public static function depth_label( string $depth ): string {
		switch ( $depth ) {
			case 'simple':
				return __( 'Simple', 'vcns-security-automation-manager' );
			case 'technical':
				return __( 'Technical', 'vcns-security-automation-manager' );
			case 'balanced':
			default:
				return __( 'Balanced', 'vcns-security-automation-manager' );
		}
	}

	private static function resolve_user_id( ?int $user_id ): int {
		return null !== $user_id ? $user_id : get_current_user_id();
	}

	/** @param string[] $allowed */
	private static function normalise( mixed $value, array $allowed, string $fallback ): string {
		$value = is_string( $value ) ? $value : '';
		return in_array( $value, $allowed, true ) ? $value : $fallback;
	}
}
