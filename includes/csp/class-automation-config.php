<?php
/**
 * Option-backed CSP automation configuration.
 */

declare( strict_types=1 );

namespace WP_SAM\CSP;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Automation_Config {

	public const MODE_MANUAL                         = 'manual';
	public const MODE_AUTOMATIC_MEDIUM_HIGH_APPROVAL = 'automatic_medium_high_approval';
	public const MODE_AUTOMATIC_HIGH_APPROVAL        = 'automatic_high_approval';
	public const SURFACES                            = array( 'frontend', 'admin', 'login', 'api' );

	/**
	 * mode defaults to automatic (high approvals only): every proposed CSP
	 * source below the high-risk threshold is auto-approved into the
	 * report-only policy on its own evidence, high-risk sources still
	 * require a human decision. This governs approval only, never
	 * enforcement -- see Activator::default_automation_config()'s longer
	 * note. max_automatic_changes_per_scan must be a positive value
	 * whenever mode isn't manual: automation_config_allows_source() in
	 * Policy_Change_Manager treats <= 0 as "automation disabled" regardless
	 * of mode, so leaving this at 0 alongside a non-manual mode would look
	 * automatic but silently approve nothing. 50 matches the cap the admin
	 * UI's number input already enforces (max="50") and what
	 * update_surface_mode() itself seeds when switching a surface onto any
	 * automatic mode.
	 */
	public const DEFAULT_SURFACE_CONFIG = array(
		'mode'                           => self::MODE_AUTOMATIC_HIGH_APPROVAL,
		'enabled_directives'             => array(),
		'excluded_directives'            => array(),
		'allowed_source_schemes'         => array( 'https' ),
		'treat_same_origin_as_low'       => true,
		'treat_known_cdn_as_low'         => false,
		'allow_wildcards'                => false,
		'allow_cleartext_http'           => false,
		'allow_browser_schemes'          => false,
		'allow_ip_literals'              => false,
		'allow_non_standard_ports'       => false,
		'approval_confidence_threshold'  => 1.0,
		'require_ai_agreement'           => false,
		'automatic_rejection_enabled'    => false,
		'max_automatic_changes_per_scan' => 50,
		'change_rate_guardrail'          => 0,
	);

	/**
	 * No Feature_Gate dependency here any more: mode availability (paid or
	 * otherwise) is entirely Automation_Mode_Registry's concern -- each
	 * registered mode carries its own availability check (see
	 * Automation_Mode_Registry::register()'s docblock). This class has no
	 * knowledge of entitlements, a payment provider, or any specific mode
	 * beyond the three free ones it defines as constants above.
	 */
	public function __construct() {}

	/** @return array<string,string> every registered mode's key => label (available or not, for "requires upgrade" presentation). */
	public static function mode_labels(): array {
		return Automation_Mode_Registry::labels();
	}

	public static function mode_label( string $mode ): string {
		$labels = self::mode_labels();
		return $labels[ $mode ] ?? $labels[ self::MODE_MANUAL ];
	}

	public function update_surface_mode( string $surface, string $mode ): array {
		$config = $this->all();
		if ( ! in_array( $surface, self::SURFACES, true ) ) {
			return $config;
		}

		$normalised_mode = $this->normalise_mode( $mode );
		$surface_config  = $config[ $surface ] ?? self::DEFAULT_SURFACE_CONFIG;

		$surface_config['mode'] = $normalised_mode;

		if ( self::MODE_MANUAL === $normalised_mode ) {
			$surface_config['max_automatic_changes_per_scan'] = 0;
		} elseif ( (int) ( $surface_config['max_automatic_changes_per_scan'] ?? 0 ) <= 0 ) {
			$surface_config['max_automatic_changes_per_scan'] = 50;
		}

		$config[ $surface ] = $this->normalise_surface( $surface_config );
		update_option( 'wp_sam_automation_config', $config );

		return $config;
	}

	public function all(): array {
		$config = get_option( 'wp_sam_automation_config', array() );
		return $this->normalise_all( is_array( $config ) ? $config : array() );
	}

	public function for_surface( string $surface ): array {
		$config = $this->all();
		return $config[ $surface ] ?? self::DEFAULT_SURFACE_CONFIG;
	}

	public function update_all( array $config ): array {
		$normalised = $this->normalise_all( $config );
		update_option( 'wp_sam_automation_config', $normalised );
		return $normalised;
	}

	public function normalise_admin_input( array $config ): array {
		return $this->normalise_all( $config );
	}

	private function normalise_all( array $config ): array {
		$normalised = array();
		foreach ( self::SURFACES as $surface ) {
			$normalised[ $surface ] = $this->normalise_surface( $config[ $surface ] ?? array() );
		}
		return $normalised;
	}

	private function normalise_surface( array $config ): array {
		$merged         = array_merge( self::DEFAULT_SURFACE_CONFIG, $config );
		$merged['mode'] = $this->normalise_mode( (string) $merged['mode'] );

		foreach ( array( 'enabled_directives', 'excluded_directives', 'allowed_source_schemes' ) as $key ) {
			$values         = is_array( $merged[ $key ] ) ? $merged[ $key ] : array();
			$merged[ $key ] = array_values(
				array_unique(
					array_filter(
						array_map(
							static fn( mixed $value ): string => strtolower( trim( sanitize_text_field( (string) $value ) ) ),
							$values
						)
					)
				)
			);
		}

		foreach ( array( 'treat_same_origin_as_low', 'treat_known_cdn_as_low', 'allow_wildcards', 'allow_cleartext_http', 'allow_browser_schemes', 'allow_ip_literals', 'allow_non_standard_ports', 'require_ai_agreement', 'automatic_rejection_enabled' ) as $key ) {
			$merged[ $key ] = (bool) $merged[ $key ];
		}

		$merged['approval_confidence_threshold']  = max( 0.0, min( 1.0, (float) $merged['approval_confidence_threshold'] ) );
		$merged['max_automatic_changes_per_scan'] = max( 0, (int) $merged['max_automatic_changes_per_scan'] );
		$merged['change_rate_guardrail']          = max( 0, (int) $merged['change_rate_guardrail'] );

		return $merged;
	}

	/**
	 * Generic against whatever Automation_Mode_Registry currently has
	 * registered -- no mode identifier beyond the three free constants
	 * above is referenced anywhere in this method. A mode string that:
	 * - resolves (via a registered legacy alias) to something never
	 *   registered at all, downgrades to MODE_MANUAL (genuinely unknown
	 *   input);
	 * - IS a registered mode but currently unavailable (a paid mode with
	 *   no active entitlement, or simply not registered in this build --
	 *   see Automation_Mode_Registry::is_available()) downgrades to
	 *   MODE_AUTOMATIC_HIGH_APPROVAL instead of manual, preserving
	 *   automation intent rather than silently disabling it -- this is the
	 *   single funnel every read/write of this option passes through, so a
	 *   lapsed entitlement or a stale option value from a build that once
	 *   had a since-removed mode registered can never leave a change
	 *   auto-applying with no review.
	 */
	private function normalise_mode( string $mode ): string {
		$mode = strtolower( trim( sanitize_text_field( $mode ) ) );
		$mode = Automation_Mode_Registry::resolve_legacy_alias( $mode );

		if ( ! Automation_Mode_Registry::is_valid_mode( $mode ) ) {
			return self::MODE_MANUAL;
		}

		if ( ! Automation_Mode_Registry::is_available( $mode ) ) {
			return self::MODE_AUTOMATIC_HIGH_APPROVAL;
		}

		return $mode;
	}
}
