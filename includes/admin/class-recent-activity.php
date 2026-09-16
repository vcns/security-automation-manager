<?php
/**
 * Recent-activity statistics (Customer-Centred Administration Experience
 * spec §9): a small, honestly-backed set of counts demonstrating SAM is
 * actively observing and protecting the site.
 *
 * Ships only the metrics reliably derivable from existing evidence today.
 * "Requests observed" (raw traffic volume) is deliberately omitted: no
 * store in this codebase persists total request volume -- only requests a
 * detector actually flagged are ever written anywhere (see Event_Store's
 * own class docblock) -- and spec §9.1 requires omission over fabrication:
 * "If an exact metric cannot be derived reliably from the current schema,
 * the interface shall not fabricate or estimate it."
 *
 * Every metric here documents its own exact definition (spec §9.1), and
 * none double-counts: "Detections" (not "requests" -- see Event_Store::
 * total_occurrences_since()'s own docblock for why) sums flagged activity
 * across every detector, "Blocked or rate-limited" is a current-state
 * count (not a 24h event count -- Traffic_Block_Store has no historical
 * log), and "Security changes detected" counts newly-detected drift rows,
 * not still-open ones from any time.
 */

declare( strict_types=1 );

namespace WP_SAM\Admin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use WP_SAM\Intelligence\Drift_Store;
use WP_SAM\Intelligence\Event_Store;
use WP_SAM\Intelligence\Traffic_Block_Store;

class Recent_Activity {

	private const PERIOD_HOURS = 24;

	/** @return array<int, array{label:string, value:int, definition:string}> */
	public function metrics(): array {
		return array(
			array(
				'label'      => __( 'Detections', 'vcns-security-automation-manager' ),
				'value'      => ( new Event_Store() )->total_occurrences_since( self::PERIOD_HOURS ),
				'definition' => __( 'Every detector match in the last 24 hours, across every source. One request that matches more than one detector counts once per detector, so this can exceed the number of requests involved.', 'vcns-security-automation-manager' ),
			),
			array(
				'label'      => __( 'Blocked or rate-limited', 'vcns-security-automation-manager' ),
				'value'      => count( ( new Traffic_Block_Store() )->all_active() ),
				'definition' => __( 'Sources currently blocked or rate-limited right now -- a live count, not a total over the last 24 hours.', 'vcns-security-automation-manager' ),
			),
			array(
				'label'      => __( 'Security changes detected', 'vcns-security-automation-manager' ),
				'value'      => ( new Drift_Store() )->count_detected_since( self::PERIOD_HOURS ),
				'definition' => __( 'Configuration changes newly detected against your baseline in the last 24 hours.', 'vcns-security-automation-manager' ),
			),
		);
	}

	public function period_label(): string {
		return __( 'Last 24 hours', 'vcns-security-automation-manager' );
	}
}
