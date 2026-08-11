<?php
/**
 * Proactively checks whether pinned Subresource Integrity hashes still match
 * what the site's own frontend homepage actually serves, instead of only
 * discovering drift reactively when Dependency_Governance_Builder removes a
 * mismatched element from a real visitor's page.
 *
 * Deliberately different from -- and much safer than -- fetching a
 * third-party script and trusting whatever hash it currently returns:
 * this class never touches third-party content at all. It fetches this
 * site's own homepage (the same page a real visitor would receive) and
 * re-runs the exact same "does the live <script>/<link> tag's integrity
 * attribute still match the admin-declared expected_sri" comparison that
 * Dependency_Governance_Builder already performs on every real request in
 * enforce mode. Since this plugin never injects an integrity attribute
 * itself (see Dependency_Governance_Builder's docblock), that attribute can
 * only ever come from the site owner's own markup -- so reading it back off
 * this site's own response introduces no third-party trust problem.
 *
 * Scoped to the frontend surface only, matching Conflict_Detector's daily
 * probe: admin/login/api don't have a single representative URL that can be
 * fetched anonymously the way the homepage can.
 */

declare( strict_types=1 );

namespace WP_SAM\Security;

use WP_SAM\Modules\Audit_Log;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Dependency_Integrity_Monitor {

	private const SURFACE = 'frontend';

	private Audit_Log $audit;

	public function __construct( Audit_Log $audit ) {
		$this->audit = $audit;
	}

	// ── Bootstrap ─────────────────────────────────────────────────────────────

	public function register(): void {
		add_action( 'admin_init', array( $this, 'maybe_run_scan' ) );
	}

	/**
	 * Runs the scan at most once per day via a transient gate, same pattern
	 * as Conflict_Detector::maybe_run_probe().
	 */
	public function maybe_run_scan(): void {
		$transient_key = 'wp_sam_dependency_integrity_scan_ran';
		if ( get_transient( $transient_key ) ) {
			return;
		}
		set_transient( $transient_key, 1, DAY_IN_SECONDS );

		$this->scan_surface( self::SURFACE, get_home_url() );
	}

	// ── Scan ──────────────────────────────────────────────────────────────────

	/**
	 * Fetches $url and compares every governed element's live integrity
	 * attribute against the pinned expected_sri for its origin. Logs a
	 * warning via Audit_Log for each mismatch found.
	 *
	 * Short-circuits before any HTTP request when there is nothing pinned
	 * for this surface -- the common case for most installs, where this
	 * pillar is disabled or every origin is mutable_provider/unclassified.
	 *
	 * @return array<int,array{origin:string,resource_type:string}> Mismatches found.
	 */
	public function scan_surface( string $surface, string $url ): array {
		$pinned = $this->load_pinned( $surface );
		if ( empty( $pinned ) || ! class_exists( 'WP_HTML_Tag_Processor' ) ) {
			return array();
		}

		$response = wp_remote_get(
			$url,
			array(
				'timeout'   => 10,
				'sslverify' => true,
			)
		);
		if ( is_wp_error( $response ) || 200 !== (int) wp_remote_retrieve_response_code( $response ) ) {
			return array();
		}

		$body = wp_remote_retrieve_body( $response );
		if ( '' === $body ) {
			return array();
		}

		$mismatches = array();

		try {
			$processor = new \WP_HTML_Tag_Processor( $body );

			while ( $processor->next_tag() ) {
				$resource = Dependency_Governance_Builder::extract_governed_resource( $processor );
				if ( null === $resource ) {
					continue;
				}
				list( $resource_type, $resource_url ) = $resource;

				$origin = Dependency_Governance_Builder::normalize_origin( $resource_url );
				if ( null === $origin || Dependency_Governance_Builder::is_first_party( $origin ) ) {
					continue;
				}

				$key = $resource_type . ':' . $origin;
				if ( ! isset( $pinned[ $key ] ) ) {
					continue;
				}

				$expected  = trim( (string) $pinned[ $key ] );
				$integrity = $processor->get_attribute( 'integrity' );
				$actual    = is_string( $integrity ) ? trim( $integrity ) : '';

				if ( $actual === $expected ) {
					continue;
				}

				$mismatches[] = array(
					'origin'        => $origin,
					'resource_type' => $resource_type,
				);

				$this->audit->log(
					'dependency_integrity_monitor',
					'sri_mismatch',
					sprintf(
						"Pinned SRI hash for '%s' (%s, %s surface) no longer matches what the live page serves -- %s Review and update the pinned hash on the External Scripts page, or the enforcing element will be removed on the next real page load with enforce mode active.",
						$origin,
						$resource_type,
						$surface,
						'' === $actual
							? 'the element no longer carries an integrity attribute at all.'
							: "the element now carries a different hash ({$actual})."
					),
					'warning'
				);
			}
		} catch ( \Throwable $unused ) {
			return array();
		}

		return $mismatches;
	}

	// ── Helpers ───────────────────────────────────────────────────────────────

	/**
	 * @return array<string,string> expected_sri keyed by "resource_type:origin", for
	 *                               every immutable_pinned row on this surface.
	 */
	private function load_pinned( string $surface ): array {
		global $wpdb;
		$table = $wpdb->prefix . 'sam_dependency_inventory';
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$rows = $wpdb->get_results( $wpdb->prepare( "SELECT resource_type, origin, expected_sri FROM {$table} WHERE surface = %s AND classification = 'immutable_pinned'", $surface ), ARRAY_A );

		$by_key = array();
		foreach ( ! empty( $rows ) ? $rows : array() as $row ) {
			$expected_sri = trim( (string) ( $row['expected_sri'] ?? '' ) );
			if ( '' === $expected_sri ) {
				continue;
			}
			$by_key[ $row['resource_type'] . ':' . $row['origin'] ] = $expected_sri;
		}
		return $by_key;
	}
}
