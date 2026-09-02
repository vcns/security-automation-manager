<?php
/**
 * CRUD and refresh for sam_tor_exit_nodes: the Tor Project's own public
 * bulk exit-node list (Phase 4A, .roadmap/phase4_plan.md -- Tor Awareness,
 * .roadmap/phase3_early_plan.md §13.6).
 *
 * Deliberately built first among Geo-IP/ASN/Tor: the Tor Project publishes
 * this list at a fixed, free, unauthenticated URL -- no account, API key,
 * or licensing decision required, unlike Geo-IP (needs a chosen provider
 * and the customer's own credentials) or ASN (needs a chosen lookup
 * mechanism). See .roadmap/phase4_plan.md Phase 4A.
 *
 * refresh() replaces the table wholesale on a successful fetch (delete-all
 * then bulk-insert) rather than diffing -- the list has no per-entry
 * history worth keeping, and yesterday's node that's no longer an exit
 * relay today is just noise, not something to track drift on. A fetch
 * failure, or a suspiciously small result (a real Tor network reliably has
 * over a thousand exit relays; a mangled or truncated fetch would return
 * far fewer), leaves the existing table completely untouched -- matching
 * this build's established "a refresh failure never revokes known-good
 * data" pattern (see Intelligence\Rollback_Guard's docblock,
 * docs/remote-config-and-signing.md's failure-scenario guidance).
 */

declare( strict_types=1 );

namespace WP_SAM\Intelligence;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Tor_Exit_List_Store {

	private const LIST_URL = 'https://check.torproject.org/torbulkexitlist';

	/**
	 * Below this count, a "successful" fetch is treated as suspect (likely
	 * truncated, a maintenance page, or an unexpected response format) and
	 * rejected rather than replacing known-good data with it.
	 */
	private const MIN_PLAUSIBLE_COUNT = 100;

	public function is_exit_node( string $ip ): bool {
		if ( '' === $ip ) {
			return false;
		}

		global $wpdb;
		$table = $wpdb->prefix . 'sam_tor_exit_nodes';

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
		$found = $wpdb->get_var(
			$wpdb->prepare(
				// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				"SELECT 1 FROM {$table} WHERE ip = %s LIMIT 1",
				$ip
			)
		);

		return null !== $found;
	}

	public function count(): int {
		global $wpdb;
		$table = $wpdb->prefix . 'sam_tor_exit_nodes';
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		return (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$table}" );
	}

	public function last_refreshed_at(): ?string {
		$value = get_option( 'wp_sam_tor_list_refreshed_at', '' );
		return '' !== $value ? (string) $value : null;
	}

	public function last_fetch_status(): string {
		return (string) get_option( 'wp_sam_tor_list_last_fetch_status', '' );
	}

	/**
	 * Fetches the current bulk exit list and replaces the stored set on
	 * success. Never touches the existing table on failure.
	 *
	 * @return array{status:string, count:int, message:string}
	 */
	public function refresh(): array {
		$response = wp_remote_get(
			self::LIST_URL,
			array(
				'timeout'    => 15,
				'sslverify'  => true,
				'user-agent' => 'WordPress/' . get_bloginfo( 'version' ) . '; VCNS-Security-Automation-Manager/' . WP_SAM_VERSION . '; ' . get_bloginfo( 'url' ),
			)
		);

		if ( is_wp_error( $response ) ) {
			return $this->record_failure( 'Fetch failed: ' . $response->get_error_message() );
		}

		$code = (int) wp_remote_retrieve_response_code( $response );
		if ( 200 !== $code ) {
			return $this->record_failure( "Fetch returned HTTP {$code}." );
		}

		$body = wp_remote_retrieve_body( $response );
		$ips  = $this->parse( $body );

		if ( count( $ips ) < self::MIN_PLAUSIBLE_COUNT ) {
			return $this->record_failure(
				sprintf( 'Fetch returned only %d plausible entries -- rejected as likely truncated or malformed.', count( $ips ) )
			);
		}

		$this->replace_all( $ips );

		$now = current_time( 'mysql', true );
		update_option( 'wp_sam_tor_list_refreshed_at', $now );
		update_option( 'wp_sam_tor_list_last_fetch_status', 'success' );

		return array(
			'status'  => 'refreshed',
			'count'   => count( $ips ),
			'message' => sprintf( 'Refreshed %d exit node(s).', count( $ips ) ),
		);
	}

	/** @return array<int, string> */
	private function parse( string $body ): array {
		$lines = preg_split( '/\r\n|\r|\n/', trim( $body ) );
		if ( false === $lines ) {
			return array();
		}

		$ips = array();
		foreach ( $lines as $line ) {
			$line = trim( $line );
			if ( '' === $line || str_starts_with( $line, '#' ) ) {
				continue;
			}
			if ( false !== filter_var( $line, FILTER_VALIDATE_IP ) ) {
				$ips[] = $line;
			}
		}

		return array_values( array_unique( $ips ) );
	}

	/** @param array<int, string> $ips */
	private function replace_all( array $ips ): void {
		global $wpdb;
		$table = $wpdb->prefix . 'sam_tor_exit_nodes';

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$wpdb->query( "TRUNCATE TABLE {$table}" );

		// Chunked multi-row insert -- a single query per ~500 rows rather
		// than one query per IP, since the list runs to well over a
		// thousand entries.
		foreach ( array_chunk( $ips, 500 ) as $chunk ) {
			$placeholders = implode( ',', array_fill( 0, count( $chunk ), '(%s)' ) );
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.NotPrepared,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			$wpdb->query(
				$wpdb->prepare(
					// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared,WordPress.DB.PreparedSQLPlaceholders.UnfinishedPrepare -- $placeholders is a dynamically-built run of literal (%s) groups, one per row in $chunk; the sniff can't see the placeholder count matches count($chunk) at analysis time.
					"INSERT INTO {$table} (ip) VALUES {$placeholders}",
					...$chunk
				)
			);
		}
	}

	/** @return array{status:string, count:int, message:string} */
	private function record_failure( string $message ): array {
		update_option( 'wp_sam_tor_list_last_fetch_status', 'failed' );

		return array(
			'status'  => 'failed',
			'count'   => $this->count(),
			'message' => $message,
		);
	}
}
