<?php
/**
 * Outcome-oriented protection-area status (Customer-Centred Administration
 * Experience spec §10): classifies existing, already-computed security
 * state into a small fixed vocabulary -- Protected, Learning, Monitoring,
 * Needs attention, Not in use, Unavailable -- instead of protocol/header
 * names.
 *
 * This class only classifies. Every branch below reads an existing store
 * this plugin already trusts (csp_policy_profiles, Pillar_Registry,
 * Traffic_Policy_Store, Drift_Store/Baseline_Store, Certificate_Store) and
 * never recomputes or overrides what that store already decided -- see
 * class docblock note on each *_area() method for exactly which field it
 * reads. Nothing here is a security decision.
 */

declare( strict_types=1 );

namespace WP_SAM\Admin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use WP_SAM\Certificates\Certificate_Store;
use WP_SAM\CSP\Automation_Config;
use WP_SAM\Intelligence\Baseline_Store;
use WP_SAM\Intelligence\Drift_Store;
use WP_SAM\Intelligence\Traffic_Policy_Store;
use WP_SAM\Security\Dependency_Governance_Builder;

class Protection_Status {

	public const STATE_PROTECTED       = 'protected';
	public const STATE_LEARNING        = 'learning';
	public const STATE_MONITORING      = 'monitoring';
	public const STATE_NEEDS_ATTENTION = 'needs_attention';
	public const STATE_NOT_IN_USE      = 'not_in_use';
	public const STATE_UNAVAILABLE     = 'unavailable';

	/**
	 * One row per protection area (spec §10's example table), each
	 * {area, state, summary}.
	 *
	 * @return array<int, array{area:string, state:string, summary:string}>
	 */
	public function areas(): array {
		return array(
			$this->browser_content_area(),
			$this->malicious_traffic_area(),
			$this->scripts_dependencies_area(),
			$this->configuration_integrity_area(),
			$this->tls_certificate_area(),
		);
	}

	/** Reads csp_policy_profiles.mode per surface -- the same query and mode vocabulary (disabled/report-only/enforce) already used by page-overview.php's own Overview tab. */
	private function browser_content_area(): array {
		global $wpdb;
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
		$modes = $wpdb->get_col( "SELECT mode FROM {$wpdb->prefix}csp_policy_profiles" );
		$modes = ! empty( $modes ) ? $modes : array();

		if ( in_array( 'enforce', $modes, true ) ) {
			$state   = self::STATE_PROTECTED;
			$summary = __( 'Browser security policies are active.', 'vcns-security-automation-manager' );
		} elseif ( in_array( 'report-only', $modes, true ) ) {
			$state   = self::STATE_LEARNING;
			$summary = __( 'Browser security policies are learning from report-only traffic.', 'vcns-security-automation-manager' );
		} else {
			$state   = self::STATE_NOT_IN_USE;
			$summary = __( 'Browser security policies are not configured yet.', 'vcns-security-automation-manager' );
		}

		return array(
			'area'    => __( 'Browser and content protection', 'vcns-security-automation-manager' ),
			'state'   => $state,
			'summary' => $summary,
		);
	}

	/** Reads Traffic_Policy_Store::all() -- the same store and mode vocabulary (observe/enforce) already used by the Getting Started tab's own live checklist. */
	private function malicious_traffic_area(): array {
		$policies = ( new Traffic_Policy_Store() )->all();
		$modes    = array_column( $policies, 'mode' );

		if ( empty( $policies ) ) {
			$state   = self::STATE_NOT_IN_USE;
			$summary = __( 'Traffic controls are not configured yet.', 'vcns-security-automation-manager' );
		} elseif ( in_array( 'enforce', $modes, true ) ) {
			$state   = self::STATE_PROTECTED;
			$summary = __( 'Suspicious traffic is being blocked or rate-limited.', 'vcns-security-automation-manager' );
		} else {
			$state   = self::STATE_MONITORING;
			$summary = __( 'SAM is observing traffic and evaluating threats.', 'vcns-security-automation-manager' );
		}

		return array(
			'area'    => __( 'Malicious traffic', 'vcns-security-automation-manager' ),
			'state'   => $state,
			'summary' => $summary,
		);
	}

	/**
	 * Reads Pillar_Registry's own enabled/mode state for the dependency-
	 * governance pillar (same source page-overview.php's pillar table
	 * reads) plus the unclassified-dependency count Security_Health and
	 * Action_Centre already use.
	 */
	private function scripts_dependencies_area(): array {
		$rows           = Pillar_Registry::fetch_rows();
		$pillar_key     = Dependency_Governance_Builder::PILLAR_KEY;
		$surface_rows   = $rows[ $pillar_key ] ?? array();
		$enabled_states = array();
		foreach ( Automation_Config::SURFACES as $surface ) {
			$enabled_states[] = Pillar_Registry::resolve_status( $pillar_key, $surface_rows[ $surface ] ?? null )['state'];
		}

		$any_enabled = (bool) array_filter(
			$enabled_states,
			static fn( string $state ): bool => in_array( $state, array( Status_Badge::STATE_REPORT_ONLY, Status_Badge::STATE_ACTIVE ), true )
		);

		if ( ! $any_enabled ) {
			return array(
				'area'    => __( 'Scripts and dependencies', 'vcns-security-automation-manager' ),
				'state'   => self::STATE_NOT_IN_USE,
				'summary' => __( 'Third-party and local script controls are not configured yet.', 'vcns-security-automation-manager' ),
			);
		}

		if ( $this->unclassified_dependency_count() > 0 ) {
			return array(
				'area'    => __( 'Scripts and dependencies', 'vcns-security-automation-manager' ),
				'state'   => self::STATE_NEEDS_ATTENTION,
				'summary' => __( 'Some third-party scripts have not been reviewed yet.', 'vcns-security-automation-manager' ),
			);
		}

		$any_active = in_array( Status_Badge::STATE_ACTIVE, $enabled_states, true );

		return array(
			'area'    => __( 'Scripts and dependencies', 'vcns-security-automation-manager' ),
			'state'   => $any_active ? self::STATE_PROTECTED : self::STATE_LEARNING,
			'summary' => $any_active
				? __( 'Third-party and local script integrity controls are active.', 'vcns-security-automation-manager' )
				: __( 'Third-party and local script integrity controls are learning from report-only traffic.', 'vcns-security-automation-manager' ),
		);
	}

	/** Reads Baseline_Store::get_current() and Drift_Store::all('unexplained') -- the same stores and 'unexplained' filter Security_Health's own drift row already uses. */
	private function configuration_integrity_area(): array {
		if ( null === ( new Baseline_Store() )->get_current() ) {
			return array(
				'area'    => __( 'Configuration integrity', 'vcns-security-automation-manager' ),
				'state'   => self::STATE_NOT_IN_USE,
				'summary' => __( 'No baseline has been captured yet.', 'vcns-security-automation-manager' ),
			);
		}

		$open = ( new Drift_Store() )->all( 'unexplained' );

		return array(
			'area'    => __( 'Configuration integrity', 'vcns-security-automation-manager' ),
			'state'   => empty( $open ) ? self::STATE_PROTECTED : self::STATE_NEEDS_ATTENTION,
			'summary' => empty( $open )
				? __( 'No unresolved high-risk drift is present.', 'vcns-security-automation-manager' )
				: __( 'Unexplained configuration changes are waiting for review.', 'vcns-security-automation-manager' ),
		);
	}

	/**
	 * Reads Certificate_Store's own config/latest-certificate state -- the
	 * same fields page-overview.php's own cert-status logic already reads.
	 * Deliberately does not use Certificate_Manager::last_run() (it needs
	 * three collaborators of its own to construct) -- this only needs to
	 * distinguish "not in use," "in progress," "needs attention" and
	 * "protected," not reproduce the full issuance-status page.
	 */
	private function tls_certificate_area(): array {
		$store  = new Certificate_Store();
		$config = $store->get_config();

		if ( empty( array_filter( (array) ( $config['domains'] ?? array() ) ) ) ) {
			return array(
				'area'    => __( 'TLS certificate', 'vcns-security-automation-manager' ),
				'state'   => self::STATE_NOT_IN_USE,
				'summary' => __( 'Certificate management is not configured -- your host or another service may already manage TLS for this site.', 'vcns-security-automation-manager' ),
			);
		}

		$latest = $store->latest_certificate();
		if ( null === $latest ) {
			return array(
				'area'    => __( 'TLS certificate', 'vcns-security-automation-manager' ),
				'state'   => self::STATE_LEARNING,
				'summary' => __( 'Certificate issuance has not completed yet.', 'vcns-security-automation-manager' ),
			);
		}

		$not_after = strtotime( (string) ( $latest['not_after'] ?? '' ) );
		if ( false !== $not_after && $not_after < time() ) {
			return array(
				'area'    => __( 'TLS certificate', 'vcns-security-automation-manager' ),
				'state'   => self::STATE_NEEDS_ATTENTION,
				'summary' => __( 'The certificate has expired.', 'vcns-security-automation-manager' ),
			);
		}

		return array(
			'area'    => __( 'TLS certificate', 'vcns-security-automation-manager' ),
			'state'   => self::STATE_PROTECTED,
			'summary' => __( 'A valid certificate is issued.', 'vcns-security-automation-manager' ),
		);
	}

	private function unclassified_dependency_count(): int {
		global $wpdb;
		$table = $wpdb->prefix . 'sam_dependency_inventory';
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
		return (int) $wpdb->get_var(
			$wpdb->prepare(
				// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				"SELECT COUNT(*) FROM {$table} WHERE classification = %s",
				'unclassified'
			)
		);
	}
}
