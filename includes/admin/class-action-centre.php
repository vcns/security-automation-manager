<?php
/**
 * Action Centre aggregation (Customer-Centred Administration Experience
 * spec §11): a single, consolidated list of everything that needs the
 * administrator's attention, so a user never has to know which SAM
 * subsystem a given issue lives in.
 *
 * This class is a presentation-layer aggregator only -- it reuses existing
 * decision logic (Recommendation_Engine) and existing read-only evidence
 * (CSP pending-source review queue, unclassified dependency count) and
 * normalises them into one shape. It never evaluates new evidence, never
 * invents a recommendation the underlying engine didn't already produce,
 * and never writes anything beyond the existing dismissal path already
 * wired to Admin_UI::handle_dismiss_recommendation().
 */

declare( strict_types=1 );

namespace WP_SAM\Admin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use WP_SAM\Intelligence\Recommendation_Engine;

class Action_Centre {

	/**
	 * One authored sentence of consequence copy per recommendation key (or
	 * key prefix, for keys suffixed with a surface/pillar/detector id) --
	 * spec §11.2's "What will happen" field. Recommendation_Engine doesn't
	 * supply this field itself; this is presentation copy explaining an
	 * *existing* deterministic action, not a new decision (spec §21: "must
	 * not invent a recommendation").
	 *
	 * @var array<string,string>
	 */
	private const CONSEQUENCE_COPY = array(
		'certificate_renewal_due'       => 'Renewing now keeps this certificate valid with no gap in HTTPS coverage for the domains it covers.',
		'exception_expiring_soon'       => 'Letting this exception expire returns the affected control to its normal, fully-enforced behaviour. Extending it keeps the current temporary weakening in place.',
		'unexplained_high_risk_drift'   => 'Marking this drift as explained (or reverting it) closes the review item; it does not undo the underlying configuration change itself.',
		'csp_enforce_ready_'            => 'Enabling enforcement means browsers will begin rejecting activity that falls outside the approved policy for this surface.',
		'pillar_enforce_ready_'         => 'Enabling enforcement means this control becomes active for real traffic on this surface, instead of only being observed.',
		'detector_disabled_but_firing_' => 'Re-enabling this detector means matching activity is evaluated (and can be acted on) again; it stays silent while disabled.',
	);

	/**
	 * Normalised open items from every reused source, most-severe first
	 * (Recommendation_Engine's own risk ordering is preserved; the two
	 * additional aggregate sources are appended after it since they carry
	 * no per-item risk rating of their own).
	 *
	 * @return array<int, array{what_found:string, why_it_matters:string, recommended_action:string, what_will_happen:string, evidence_url:string, risk:string, dismissible:bool, key:?string}>
	 */
	public function items(): array {
		$items = array();

		foreach ( ( new Recommendation_Engine() )->get_recommendations() as $recommendation ) {
			$items[] = array(
				'what_found'         => (string) $recommendation['observed'],
				'why_it_matters'     => (string) $recommendation['why_it_matters'],
				'recommended_action' => (string) $recommendation['recommended_action'],
				'what_will_happen'   => $this->describe_consequence( (string) $recommendation['key'] ),
				'evidence_url'       => (string) $recommendation['cta_url'],
				'risk'               => (string) $recommendation['risk'],
				'dismissible'        => (bool) $recommendation['dismissible'],
				'key'                => (string) $recommendation['key'],
			);
		}

		$pending_sources = $this->pending_csp_source_count();
		if ( $pending_sources > 0 ) {
			$items[] = array(
				'what_found'         => sprintf(
					/* translators: %d: number of discovered content sources awaiting review */
					_n( '%d discovered content source is awaiting review.', '%d discovered content sources are awaiting review.', $pending_sources, 'vcns-security-automation-manager' ),
					$pending_sources
				),
				'why_it_matters'     => __( 'Until each discovered source is approved or rejected, it stays out of the enforced policy -- legitimate sources may be blocked once enforcement is on, and enforcement readiness stays blocked while sources sit unreviewed.', 'vcns-security-automation-manager' ),
				'recommended_action' => __( 'Review each discovered source and approve or reject it.', 'vcns-security-automation-manager' ),
				'what_will_happen'   => __( 'Approving a source adds it to the policy; rejecting one keeps it out. Either decision is recorded with a reason and can be revisited later.', 'vcns-security-automation-manager' ),
				'evidence_url'       => admin_url( 'admin.php?page=security-automation-manager-dashboard&tab=sources' ),
				'risk'               => 'medium',
				'dismissible'        => false,
				'key'                => null,
			);
		}

		$unclassified_dependencies = $this->unclassified_dependency_count();
		if ( $unclassified_dependencies > 0 ) {
			$items[] = array(
				'what_found'         => sprintf(
					/* translators: %d: number of unclassified third-party dependencies */
					_n( '%d third-party script or dependency has not been classified yet.', '%d third-party scripts or dependencies have not been classified yet.', $unclassified_dependencies, 'vcns-security-automation-manager' ),
					$unclassified_dependencies
				),
				'why_it_matters'     => __( 'An unclassified dependency has not been reviewed as expected, pinned, or flagged as suspicious -- that review is what lets SAM tell a routine update apart from an unexpected change.', 'vcns-security-automation-manager' ),
				'recommended_action' => __( 'Classify each dependency on the Scripts page.', 'vcns-security-automation-manager' ),
				'what_will_happen'   => __( 'Classifying a dependency records your decision about it; it does not change whether the script currently runs.', 'vcns-security-automation-manager' ),
				'evidence_url'       => admin_url( 'admin.php?page=security-automation-manager-scripts' ),
				'risk'               => 'low',
				'dismissible'        => false,
				'key'                => null,
			);
		}

		return $items;
	}

	public function count_open(): int {
		return count( $this->items() );
	}

	private function describe_consequence( string $key ): string {
		if ( isset( self::CONSEQUENCE_COPY[ $key ] ) ) {
			return self::CONSEQUENCE_COPY[ $key ];
		}

		foreach ( self::CONSEQUENCE_COPY as $prefix => $copy ) {
			if ( str_ends_with( $prefix, '_' ) && str_starts_with( $key, $prefix ) ) {
				return $copy;
			}
		}

		return '';
	}

	private function pending_csp_source_count(): int {
		global $wpdb;
		$table = $wpdb->prefix . 'csp_source_inventory';
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
		return (int) $wpdb->get_var(
			$wpdb->prepare(
				// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				"SELECT COUNT(*) FROM {$table} WHERE approval_state = %s",
				'pending'
			)
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
