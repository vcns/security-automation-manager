<?php
/**
 * Central feature access control point.
 *
 * Features present in the WordPress.org package are available locally without
 * payment, external licensing, or remote entitlement checks.
 */

declare( strict_types=1 );

namespace WP_SAM\Modules;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Feature_Gate {

	// Features available in the shipped package without payment.
	private const FREE_FEATURES = array(
		'csp_report_only',
		'basic_scan',
		'basic_dashboard',
		'violation_endpoint',
		'manual_policy_review',
		'policy_history',
		'decision_evidence_explorer',
		'strict_dynamic',
		'trusted_types',
		'multi_surface_scan',
		'analytics_export',
	);

	// Stable product key retained for legacy compatibility helpers.
	private const PRODUCT_KEY = 'csp-automation-manager';

	/**
	 * A legacy entitlement-compatibility object, populated only by a
	 * loaded commercial-services extension (see includes/extensions/,
	 * physically absent from the WordPress.org build), or null otherwise.
	 * Typed as object, not a specific class, so this file never needs to
	 * know or reference that extension's implementing class name.
	 */
	private ?object $entitlements;

	/** In-memory cache to avoid repeated DB + transient reads per request. */
	private ?array $entitlement_cache = null;
	private bool $cache_loaded        = false;

	public function __construct( ?object $entitlements = null ) {
		$this->entitlements = $entitlements;
	}

	// ── Public API ────────────────────────────────────────────────────────────

	/**
	 * Returns true if the current site may use the given feature.
	 *
	 * Features not in FREE_FEATURES require a paid entitlement -- this falls
	 * through to is_pro(), which is always false when no entitlement source
	 * is present (every build unless a commercial-services extension has
	 * populated one -- see includes/extensions/, physically absent from
	 * the WordPress.org build), and only ever true for a site with a
	 * currently active paid entitlement.
	 */
	public function is_allowed( string $feature ): bool {
		if ( in_array( $feature, self::FREE_FEATURES, true ) ) {
			return true;
		}

		return $this->is_pro();
	}

	/**
	 * Returns the current active legacy tier, defaulting to 'free'.
	 */
	public function current_tier(): string {
		$row = $this->load_entitlement();
		return $row['tier'] ?? 'free';
	}

	/**
	 * Returns whether a legacy compatibility entitlement reports a pro tier.
	 */
	public function is_pro(): bool {
		return 'pro' === $this->current_tier();
	}

	/**
	 * Returns the legacy entitlement row, or null when none is available.
	 */
	public function get_entitlement(): ?array {
		return $this->load_entitlement();
	}

	// ── Internal ──────────────────────────────────────────────────────────────

	private function load_entitlement(): ?array {
		if ( ! $this->cache_loaded ) {
			if ( null !== $this->entitlements ) {
				$this->entitlement_cache = $this->entitlements->get_for_site( self::PRODUCT_KEY );
			}
			$this->cache_loaded = true;
		}
		return $this->entitlement_cache;
	}
}
