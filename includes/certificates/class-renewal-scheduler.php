<?php
/**
 * Cron wiring for the certificate module.
 *
 *   - wp_sam_cert_issue        : single event scheduled by the admin
 *                                "Issue / Renew Now" button (runs the full
 *                                ACME flow off the browser request).
 *   - wp_sam_cert_renewal_check: daily; re-issues inside the 30-day window.
 *
 * wp-cron only fires on traffic, so a genuinely idle site can drift past a
 * renewal deadline. The Certificates page recommends a real system cron
 * hitting wp-cron.php; docs/certificates.md shows the one-liner.
 */

declare( strict_types=1 );

namespace WP_SAM\Certificates;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Renewal_Scheduler {

	public const ISSUE_HOOK   = 'wp_sam_cert_issue';
	public const RENEWAL_HOOK = 'wp_sam_cert_renewal_check';

	private Certificate_Manager $manager;

	public function __construct( Certificate_Manager $manager ) {
		$this->manager = $manager;
	}

	public function register(): void {
		add_action( self::ISSUE_HOOK, array( $this->manager, 'issue' ) );
		add_action( self::RENEWAL_HOOK, array( $this->manager, 'maybe_renew' ) );

		// Self-scheduling (rather than activation-time scheduling) so the
		// module heals a cleared cron table and works on sites that updated
		// in place without a deactivate/reactivate cycle.
		if ( ! wp_next_scheduled( self::RENEWAL_HOOK ) ) {
			wp_schedule_event( time() + HOUR_IN_SECONDS, 'daily', self::RENEWAL_HOOK );
		}
	}

	/** Queues a full issue run to start on the next cron spawn. */
	public function queue_issue_now(): void {
		if ( ! wp_next_scheduled( self::ISSUE_HOOK ) ) {
			wp_schedule_single_event( time(), self::ISSUE_HOOK );
		}
		// Nudge cron so "now" means seconds, not next-pageview.
		spawn_cron();
	}
}
