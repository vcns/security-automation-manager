<?php
/**
 * Single source of truth for the 13 pillars backed by the shared
 * sam_pillar_profiles table (the nine "simple" header pillars, Reverse
 * Tabnabbing, External Scripts, Internal Script Integrity, and
 * Information Masking).
 *
 * Replaces the view-local $simple_pillars array that used to live in
 * page-overview.php -- that array had already drifted from reality once
 * (Activator::seed_default_pillar_profiles() and the Overview table
 * disagreed about which pillars exist). Content Security Policy and
 * Certificates are deliberately NOT registered here: each has its own
 * storage shape (CSP: csp_policy_profiles plus an automation axis;
 * Certificates: site-wide, not per-surface, natural-language status) that
 * would make a "uniform" resolve_status() call fictional rather than
 * genuinely shared. They stay hand-coded rows in page-overview.php, the
 * same way CSP already was before this class existed.
 */

declare( strict_types=1 );

namespace WP_SAM\Admin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use WP_SAM\Security\Cross_Origin_Embedder_Policy_Builder;
use WP_SAM\Security\Cross_Origin_Opener_Policy_Builder;
use WP_SAM\Security\Cross_Origin_Resource_Policy_Builder;
use WP_SAM\Security\Dependency_Governance_Builder;
use WP_SAM\Security\Information_Masking_Builder;
use WP_SAM\Security\Internal_Script_Integrity_Builder;
use WP_SAM\Security\Permissions_Policy_Builder;
use WP_SAM\Security\Referrer_Policy_Builder;
use WP_SAM\Security\Reverse_Tabnabbing_Builder;
use WP_SAM\Security\Strict_Transport_Security_Builder;
use WP_SAM\Security\X_Content_Type_Options_Builder;
use WP_SAM\Security\X_Frame_Options_Builder;
use WP_SAM\Security\X_Permitted_Cross_Domain_Policies_Builder;

final class Pillar_Registry {

	/**
	 * @return array<string, array{
	 *     label: string,
	 *     page: string,
	 *     tab: ?string,
	 *     mode_extractor: ?callable,
	 *     mode_status_map: array<string,string>,
	 * }> Keyed by PILLAR_KEY, pre-sorted alphabetically by label (matches
	 *     the left-nav ordering, same as the array this replaces).
	 */
	public static function pillars(): array {
		$pillars = array(
			X_Frame_Options_Builder::PILLAR_KEY            => array(
				'label'           => __( 'X-Frame-Options', 'vcns-security-automation-manager' ),
				'page'            => 'security-automation-manager-xfo',
				'tab'             => null,
				'mode_extractor'  => null,
				'mode_status_map' => array(),
			),
			X_Content_Type_Options_Builder::PILLAR_KEY     => array(
				'label'           => __( 'X-Content-Type-Options', 'vcns-security-automation-manager' ),
				'page'            => 'security-automation-manager-xcto',
				'tab'             => null,
				'mode_extractor'  => null,
				'mode_status_map' => array(),
			),
			Referrer_Policy_Builder::PILLAR_KEY            => array(
				'label'           => __( 'Referrer-Policy', 'vcns-security-automation-manager' ),
				'page'            => 'security-automation-manager-referrer-policy',
				'tab'             => null,
				'mode_extractor'  => null,
				'mode_status_map' => array(),
			),
			Information_Masking_Builder::PILLAR_KEY        => array(
				'label'           => __( 'Information Masking', 'vcns-security-automation-manager' ),
				'page'            => 'security-automation-manager-information-masking',
				'tab'             => null,
				'mode_extractor'  => null,
				'mode_status_map' => array(),
			),
			Permissions_Policy_Builder::PILLAR_KEY         => array(
				'label'           => __( 'Permissions-Policy', 'vcns-security-automation-manager' ),
				'page'            => 'security-automation-manager-permissions-policy',
				'tab'             => null,
				'mode_extractor'  => null,
				'mode_status_map' => array(),
			),
			Strict_Transport_Security_Builder::PILLAR_KEY  => array(
				'label'           => __( 'Strict-Transport-Security', 'vcns-security-automation-manager' ),
				'page'            => 'security-automation-manager-hsts',
				'tab'             => null,
				'mode_extractor'  => null,
				'mode_status_map' => array(),
			),
			Reverse_Tabnabbing_Builder::PILLAR_KEY         => array(
				'label'           => __( 'Reverse Tabnabbing Protection', 'vcns-security-automation-manager' ),
				'page'            => 'security-automation-manager-reverse-tabnabbing',
				'tab'             => null,
				'mode_extractor'  => null,
				'mode_status_map' => array(),
			),
			Dependency_Governance_Builder::PILLAR_KEY      => array(
				'label'           => __( 'External Scripts', 'vcns-security-automation-manager' ),
				'page'            => 'security-automation-manager-scripts',
				'tab'             => 'external',
				'mode_extractor'  => array( Dependency_Governance_Builder::class, 'extract_mode' ),
				'mode_status_map' => array(
					'report'  => Status_Badge::STATE_REPORT_ONLY,
					'enforce' => Status_Badge::STATE_ACTIVE,
				),
			),
			Internal_Script_Integrity_Builder::PILLAR_KEY  => array(
				'label'           => __( 'Internal Script Integrity', 'vcns-security-automation-manager' ),
				'page'            => 'security-automation-manager-scripts',
				'tab'             => 'internal',
				'mode_extractor'  => null,
				'mode_status_map' => array(),
			),
			Cross_Origin_Resource_Policy_Builder::PILLAR_KEY => array(
				'label'           => __( 'Cross-Origin-Resource-Policy', 'vcns-security-automation-manager' ),
				'page'            => 'security-automation-manager-cross-origin',
				'tab'             => 'corp',
				'mode_extractor'  => null,
				'mode_status_map' => array(),
			),
			X_Permitted_Cross_Domain_Policies_Builder::PILLAR_KEY => array(
				'label'           => __( 'X-Permitted-Cross-Domain-Policies', 'vcns-security-automation-manager' ),
				'page'            => 'security-automation-manager-cross-origin',
				'tab'             => 'xpcdp',
				'mode_extractor'  => null,
				'mode_status_map' => array(),
			),
			Cross_Origin_Opener_Policy_Builder::PILLAR_KEY => array(
				'label'           => __( 'Cross-Origin-Opener-Policy', 'vcns-security-automation-manager' ),
				'page'            => 'security-automation-manager-cross-origin',
				'tab'             => 'coop',
				'mode_extractor'  => array( Cross_Origin_Opener_Policy_Builder::class, 'extract_mode' ),
				'mode_status_map' => array(
					'disabled'    => Status_Badge::STATE_DISABLED,
					'report-only' => Status_Badge::STATE_REPORT_ONLY,
					'enforce'     => Status_Badge::STATE_ACTIVE,
				),
			),
			Cross_Origin_Embedder_Policy_Builder::PILLAR_KEY => array(
				'label'           => __( 'Cross-Origin-Embedder-Policy', 'vcns-security-automation-manager' ),
				'page'            => 'security-automation-manager-cross-origin',
				'tab'             => 'coep',
				'mode_extractor'  => array( Cross_Origin_Embedder_Policy_Builder::class, 'extract_mode' ),
				'mode_status_map' => array(
					'disabled'    => Status_Badge::STATE_DISABLED,
					'report-only' => Status_Badge::STATE_REPORT_ONLY,
					'enforce'     => Status_Badge::STATE_ACTIVE,
				),
			),
		);

		uasort(
			$pillars,
			static fn( array $a, array $b ): int => strcasecmp( $a['label'], $b['label'] )
		);

		return $pillars;
	}

	/**
	 * One query covering every registered pillar.
	 *
	 * @return array<string, array<string, array{enabled: bool, payload: string}>> pillar => surface => row.
	 */
	public static function fetch_rows(): array {
		global $wpdb;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$raw = $wpdb->get_results( "SELECT pillar, surface, enabled, payload FROM {$wpdb->prefix}sam_pillar_profiles", ARRAY_A );

		$rows = array();
		foreach ( ! empty( $raw ) ? $raw : array() as $row ) {
			$rows[ $row['pillar'] ][ $row['surface'] ] = array(
				'enabled' => ! empty( $row['enabled'] ),
				'payload' => (string) ( $row['payload'] ?? '' ),
			);
		}

		return $rows;
	}

	/**
	 * Resolves one pillar's status for one surface from an already-fetched
	 * row. Pure function -- no I/O -- so it can be called once per pillar
	 * per surface against a single batched fetch_rows() result without
	 * turning an N-pillar table into N (or 4N) queries.
	 *
	 * enabled=false always wins over a stored mode, matching the existing
	 * convention already in page-cross-origin.php's own mode <select>
	 * (only consulted once a pillar is already enabled).
	 *
	 * @param array{enabled: bool, payload: string}|null $row null = no row at all for this pillar+surface.
	 * @return array{state: string, label: string} state is one of Status_Badge::STATE_*.
	 */
	public static function resolve_status( string $pillar_key, ?array $row ): array {
		if ( null === $row ) {
			return array(
				'state' => Status_Badge::STATE_NOT_CONFIGURED,
				'label' => __( 'Not configured', 'vcns-security-automation-manager' ),
			);
		}

		if ( ! $row['enabled'] ) {
			return array(
				'state' => Status_Badge::STATE_DISABLED,
				'label' => __( 'Disabled', 'vcns-security-automation-manager' ),
			);
		}

		$pillars        = self::pillars();
		$mode_extractor = $pillars[ $pillar_key ]['mode_extractor'] ?? null;

		if ( null === $mode_extractor ) {
			return array(
				'state' => Status_Badge::STATE_ACTIVE,
				'label' => __( 'Active', 'vcns-security-automation-manager' ),
			);
		}

		$mode_status_map = $pillars[ $pillar_key ]['mode_status_map'];
		$raw_mode        = call_user_func( $mode_extractor, $row );
		$state           = $mode_status_map[ $raw_mode ] ?? Status_Badge::STATE_ACTIVE;

		$labels = array(
			Status_Badge::STATE_DISABLED    => __( 'Disabled', 'vcns-security-automation-manager' ),
			Status_Badge::STATE_REPORT_ONLY => __( 'Report-only', 'vcns-security-automation-manager' ),
			Status_Badge::STATE_ACTIVE      => __( 'Active', 'vcns-security-automation-manager' ),
		);

		return array(
			'state' => $state,
			'label' => $labels[ $state ] ?? __( 'Active', 'vcns-security-automation-manager' ),
		);
	}
}
