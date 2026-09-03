<?php
/**
 * Explicit dependency boundary for how Policy_Builder reads its policy
 * input -- GitHub issue #170. Previously, load_profile()/load_approved_
 * hashes()/load_approved_sources() were `protected` methods on Policy_
 * Builder itself, which made a class that emits a security-sensitive
 * header into a de facto subclass extension point: any code (tests
 * included) could override how policy input is loaded just by
 * subclassing. This interface, plus Wpdb_Policy_Data_Loader's real
 * implementation, replaces that with a narrow, explicit, constructor-
 * injected collaborator -- Policy_Builder now only ever sees this
 * interface, never a wpdb call of its own, and tests get a real seam
 * (implement this interface) without widening what a subclass of
 * Policy_Builder itself can override.
 */

declare( strict_types=1 );

namespace WP_SAM\CSP;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

interface Policy_Data_Loader {

	/** @return array<string,mixed>|null the stored csp_policy_profiles row for this surface, or null if none exists. */
	public function load_profile( string $surface ): ?array;

	/** @return array<int,array<string,string>> active csp_hash_inventory rows for this surface, most-recently-seen first. */
	public function load_approved_hashes( string $surface ): array;

	/** @return array<int,array<string,string>> approved csp_source_inventory rows for this surface. */
	public function load_approved_sources( string $surface ): array;
}
