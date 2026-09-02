<?php
/**
 * Campaign Detection (Phase 3J, .roadmap/phase3_early_plan.md §14).
 *
 * The roadmap lists several possible correlation signals: repeated
 * identical paths, repeated payload fingerprints, common user-agents,
 * common timing, distributed source IPs, multiple cloud providers,
 * repeated detector-family matches, coordinated path sequencing. This
 * class implements exactly one of them -- distinct source IPs hitting the
 * same detector on the same surface within a time window -- because it is
 * the one signal Event_Store already has the data to answer cheaply and
 * honestly. The others would need infrastructure this build doesn't have
 * (payload fingerprint storage, ASN/provider lookup, sequencing analysis)
 * and are not implemented here rather than faked; see the roadmap's own
 * worked example ("fifty IP addresses ... making the same unusual request
 * sequence"), which this class covers the distributed-IP half of.
 *
 * scan() only ever observes, correlates, and records -- never blocks.
 * block_participants() is the one action with a real side effect, and it
 * is only ever invoked by an explicit administrator action (an admin-post
 * handler), never from scan() itself -- matching the roadmap's explicit
 * "Automatic blocking of a correlated campaign requires explicit opt-in."
 */

declare( strict_types=1 );

namespace WP_SAM\Intelligence;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Campaign_Detector {

	private const DEFAULT_WINDOW_HOURS     = 24;
	private const DEFAULT_MIN_PARTICIPANTS = 10;

	private Event_Store $events;
	private Campaign_Store $campaigns;

	public function __construct( Event_Store $events, Campaign_Store $campaigns ) {
		$this->events    = $events;
		$this->campaigns = $campaigns;
	}

	/**
	 * @return array{status:string, campaigns_detected:int}
	 */
	public function scan( int $window_hours = self::DEFAULT_WINDOW_HOURS, int $min_participants = self::DEFAULT_MIN_PARTICIPANTS ): array {
		$detected = 0;

		foreach ( $this->events->active_detector_surfaces( $window_hours ) as $combo ) {
			$detector_id = (string) $combo['detector_id'];
			$surface     = (string) $combo['surface'];

			$ips = $this->events->distinct_ips( $detector_id, $surface, $window_hours );
			if ( count( $ips ) < $min_participants ) {
				continue;
			}

			$this->campaigns->record(
				$detector_id,
				(string) $combo['detector_family'],
				$surface,
				count( $ips ),
				count( $ips )
			);
			++$detected;
		}

		return array(
			'status'             => 'scanned',
			'campaigns_detected' => $detected,
		);
	}

	/**
	 * Explicit, admin-triggered response: adds every currently-live
	 * participant IP as a permanent sam_ip_rules block (all surfaces), then
	 * marks the campaign 'blocked'. Re-queries live participants at call
	 * time rather than trusting the campaign row's own (possibly stale)
	 * participant_count.
	 */
	public function block_participants( array $campaign, int $admin_id, string $note, Ip_Rule_Store $ip_rules, int $window_hours = self::DEFAULT_WINDOW_HOURS ): int {
		$ips = $this->events->distinct_ips( (string) $campaign['detector_id'], (string) $campaign['surface'], $window_hours );

		$blocked = 0;
		foreach ( $ips as $ip ) {
			$reason = sprintf(
				/* translators: 1: detector id, 2: surface */
				__( 'Campaign block: detector %1$s on %2$s surface.', 'vcns-security-automation-manager' ),
				(string) $campaign['detector_id'],
				(string) $campaign['surface']
			);
			if ( $ip_rules->add( 'block', $ip, '', $reason, $admin_id ) ) {
				++$blocked;
			}
		}

		$this->campaigns->disposition( (int) $campaign['id'], 'blocked', $admin_id, $note );

		return $blocked;
	}
}
