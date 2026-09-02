<?php
/**
 * Base contract for anything Detector_Registry can register and
 * Detector_Engine can run against a request.
 *
 * No concrete detector ships in this build -- Phase 3B is the observation
 * skeleton only (see Detector_Registry's own docblock). This class exists so
 * Phase 3C's detector families, and any extension, have a stable shape to
 * implement against without touching Detector_Engine's iteration logic.
 *
 * allowed_control_actions()/default_control_action() (Phase 4B, .roadmap/
 * phase4_plan.md -- the "allowed control actions / default action" field
 * .roadmap/phase3_early_plan.md §11's shared metadata contract specifies)
 * default to observation-only, matching every detector already shipped and
 * this plugin's default-safety posture (§30): a detector must explicitly
 * declare itself enforce-capable, an administrator must still opt in via
 * Detector_Policy_Store, and even then Traffic_Guard only actually blocks a
 * surface an administrator has separately promoted to 'enforce' -- three
 * independent opt-ins, not one. See Detector_Policy_Store's own docblock for
 * how an admin override is resolved against these two methods.
 */

declare( strict_types=1 );

namespace WP_SAM\Intelligence;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

abstract class Detector {

	/** Stable, lowercase identifier. Used as the registry key and the Finding's detector_id. */
	abstract public function id(): string;

	/** Grouping label (e.g. 'injection', 'reconnaissance') -- the Finding's detector_family. */
	abstract public function family(): string;

	/**
	 * Surfaces this detector should run on.
	 *
	 * @return array<string> Subset of 'frontend', 'admin', 'login', 'api'. An empty array means every surface.
	 */
	abstract public function applicable_surfaces(): array;

	/** True unless a paid/entitlement gate (or similar) makes this detector currently unusable. */
	public function is_available(): bool {
		return true;
	}

	/**
	 * @param array<string, mixed> $context Request context built by Request_Observer.
	 * @return array<string, mixed>|null Finding data, or null if this detector found nothing on this request.
	 */
	abstract public function evaluate( array $context ): ?array;

	/**
	 * Control actions this detector may be configured to trigger on a match,
	 * beyond recording evidence. 'observe' (evidence only) is always
	 * implicitly allowed; a subclass opts into 'enforce' (feeds Traffic_
	 * Block_Store's existing progressive-response ladder -- see Detector_
	 * Policy_Store) only when the family is reliable enough for that, per
	 * its own §11 guidance.
	 *
	 * @return array<string> Subset of Detector_Policy_Store::ACTIONS.
	 */
	public function allowed_control_actions(): array {
		return array( 'observe' );
	}

	/** Must be a member of allowed_control_actions(). */
	public function default_control_action(): string {
		return 'observe';
	}
}
