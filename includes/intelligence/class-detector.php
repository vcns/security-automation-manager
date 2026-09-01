<?php
/**
 * Base contract for anything Detector_Registry can register and
 * Detector_Engine can run against a request.
 *
 * No concrete detector ships in this build -- Phase 3B is the observation
 * skeleton only (see Detector_Registry's own docblock). This class exists so
 * Phase 3C's detector families, and any extension, have a stable shape to
 * implement against without touching Detector_Engine's iteration logic.
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
}
