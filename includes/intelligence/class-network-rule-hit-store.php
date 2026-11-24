<?php
/**
 * Records requests that an ASN or country network rule blocked, so an
 * administrator can see what the Country Block List and the ASN rules are
 * actually catching.
 *
 * Traffic_Guard answers a network-rule match with a 403 and stops the
 * request. Before schema v49 nothing kept any trace of that, so there was
 * no way to tell how much traffic a rule stopped, or whether it was
 * stopping something wanted.
 *
 * One row per UTC day, rule and address: how many of that address's
 * requests the rule blocked that day, the surface and path of the latest
 * one (never the query string), and when it was first and last seen. Rows
 * are deleted after the data-retention window by Scheduler, like request
 * events.
 */

declare( strict_types=1 );

namespace WP_SAM\Intelligence;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Network_Rule_Hit_Store {

	/** How many days, today included, the admin summaries cover. */
	public const SUMMARY_DAYS = 7;

	/** Length of the last_path column. */
	private const PATH_MAX = 255;

	/**
	 * Counts one blocked request against the rule that matched it.
	 *
	 * @param array<string, mixed> $rule    The matched Network_Rule_Store row.
	 * @param string               $ip      The blocked address.
	 * @param string               $surface Surface the request was for.
	 * @param string               $path    Request path, without the query string.
	 * @return void
	 */
	public function record( array $rule, string $ip, string $surface, string $path ): void {
		$rule_type  = (string) ( $rule['rule_type'] ?? '' );
		$rule_value = (string) ( $rule['value'] ?? '' );
		if ( '' === $rule_type || '' === $rule_value || '' === $ip ) {
			return;
		}

		global $wpdb;
		$table = $wpdb->prefix . 'sam_network_rule_hits';
		$now   = current_time( 'mysql', true );
		$path  = substr( '' !== $path ? $path : '/', 0, self::PATH_MAX );

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
		$wpdb->query(
			$wpdb->prepare(
				// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				"INSERT INTO {$table} (hit_date, rule_type, rule_value, ip, surface, last_path, hit_count, first_seen_at, last_seen_at) VALUES (%s, %s, %s, %s, %s, %s, 1, %s, %s) ON DUPLICATE KEY UPDATE hit_count = hit_count + 1, surface = %s, last_path = %s, last_seen_at = %s",
				gmdate( 'Y-m-d' ),
				$rule_type,
				$rule_value,
				$ip,
				$surface,
				$path,
				$now,
				$now,
				$surface,
				$path,
				$now
			)
		);
	}

	/**
	 * Blocked requests per rule value (country code or ASN) over the last
	 * $days days, most blocked first.
	 *
	 * @param string $rule_type 'country' or 'asn'.
	 * @param int    $days      Days to cover, today included.
	 * @return list<array{rule_value: string, requests: int, addresses: int, last_seen_at: string}>
	 */
	public function summary( string $rule_type, int $days = self::SUMMARY_DAYS ): array {
		global $wpdb;
		$table = $wpdb->prefix . 'sam_network_rule_hits';

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
		$rows = $wpdb->get_results(
			$wpdb->prepare(
				// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				"SELECT rule_value, SUM(hit_count) AS requests, COUNT(DISTINCT ip) AS addresses, MAX(last_seen_at) AS last_seen_at FROM {$table} WHERE rule_type = %s AND hit_date >= %s GROUP BY rule_value ORDER BY requests DESC, rule_value ASC",
				$rule_type,
				self::since( $days )
			),
			ARRAY_A
		);

		$summary = array();
		foreach ( is_array( $rows ) ? $rows : array() as $row ) {
			if ( ! isset( $row['rule_value'], $row['requests'] ) ) {
				continue;
			}
			$summary[] = array(
				'rule_value'   => (string) $row['rule_value'],
				'requests'     => (int) $row['requests'],
				'addresses'    => (int) ( $row['addresses'] ?? 0 ),
				'last_seen_at' => (string) ( $row['last_seen_at'] ?? '' ),
			);
		}
		return $summary;
	}

	/**
	 * The most recently blocked addresses for a rule type, latest first.
	 *
	 * @param string $rule_type 'country' or 'asn'.
	 * @param int    $limit     Maximum rows.
	 * @return list<array{rule_value: string, ip: string, surface: string, last_path: string, hit_count: int, last_seen_at: string}>
	 */
	public function recent( string $rule_type, int $limit = 20 ): array {
		global $wpdb;
		$table = $wpdb->prefix . 'sam_network_rule_hits';

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
		$rows = $wpdb->get_results(
			$wpdb->prepare(
				// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				"SELECT rule_value, ip, surface, last_path, hit_count, last_seen_at FROM {$table} WHERE rule_type = %s ORDER BY last_seen_at DESC LIMIT %d",
				$rule_type,
				max( 1, $limit )
			),
			ARRAY_A
		);

		$recent = array();
		foreach ( is_array( $rows ) ? $rows : array() as $row ) {
			if ( ! isset( $row['rule_value'], $row['ip'] ) ) {
				continue;
			}
			$recent[] = array(
				'rule_value'   => (string) $row['rule_value'],
				'ip'           => (string) $row['ip'],
				'surface'      => (string) ( $row['surface'] ?? '' ),
				'last_path'    => (string) ( $row['last_path'] ?? '' ),
				'hit_count'    => (int) ( $row['hit_count'] ?? 0 ),
				'last_seen_at' => (string) ( $row['last_seen_at'] ?? '' ),
			);
		}
		return $recent;
	}

	/**
	 * Blocked requests per rule over the last $days days, keyed
	 * "rule_type:rule_value" (e.g. "country:CN", "asn:15169").
	 *
	 * @param int $days Days to cover, today included.
	 * @return array<string, int>
	 */
	public function totals( int $days = self::SUMMARY_DAYS ): array {
		global $wpdb;
		$table = $wpdb->prefix . 'sam_network_rule_hits';

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
		$rows = $wpdb->get_results(
			$wpdb->prepare(
				// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				"SELECT rule_type, rule_value, SUM(hit_count) AS requests FROM {$table} WHERE hit_date >= %s GROUP BY rule_type, rule_value",
				self::since( $days )
			),
			ARRAY_A
		);

		$totals = array();
		foreach ( is_array( $rows ) ? $rows : array() as $row ) {
			if ( ! isset( $row['rule_type'], $row['rule_value'], $row['requests'] ) ) {
				continue;
			}
			$totals[ $row['rule_type'] . ':' . $row['rule_value'] ] = (int) $row['requests'];
		}
		return $totals;
	}

	/**
	 * Deletes rows not seen for more than $days days.
	 *
	 * @param int $days Retention window in days; 0 or less keeps everything.
	 * @return int Rows deleted.
	 */
	public function purge_older_than( int $days ): int {
		if ( $days <= 0 ) {
			return 0;
		}

		global $wpdb;
		$table = $wpdb->prefix . 'sam_network_rule_hits';

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
		$deleted = $wpdb->query(
			$wpdb->prepare(
				// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				"DELETE FROM {$table} WHERE last_seen_at < DATE_SUB(UTC_TIMESTAMP(), INTERVAL %d DAY)",
				$days
			)
		);
		return is_int( $deleted ) ? $deleted : 0;
	}

	/** First UTC date covered by a "last $days days" summary, today included. */
	private static function since( int $days ): string {
		return gmdate( 'Y-m-d', time() - ( ( max( 1, $days ) - 1 ) * DAY_IN_SECONDS ) );
	}
}
