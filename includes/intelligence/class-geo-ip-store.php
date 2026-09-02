<?php
/**
 * Geo-IP Controls (Phase 4A, third increment, .roadmap/phase4_plan.md,
 * .roadmap/phase3_early_plan.md §13.4).
 *
 * Entirely opt-in and bring-your-own-credentials -- unlike Tor Awareness
 * and ASN Controls (both free, no account needed), Geo-IP has no
 * free-without-a-credential option. Disabled until an administrator
 * enters their own IPinfo (https://ipinfo.io) API token; the token is
 * sealed with Certificates\Credential_Vault (the same encryption-at-rest
 * mechanism already used for DNS-01 provider tokens and certificate
 * material) and is never a shared VCNS credential -- the same "customer
 * must never hold a shared credential" principle docs/checkout-proxy-
 * design.md establishes for Stripe, applied here to a lower-severity but
 * still real API credential.
 *
 * MaxMind support is deliberately NOT implemented in this increment.
 * MaxMind's free GeoLite2 tier is a downloaded binary database (a custom
 * MMDB trie format), not a live API -- reading it correctly needs either
 * a hand-rolled binary parser (real risk of a subtly wrong implementation
 * with no test suite to lean on) or MaxMind's own `geoip2/geoip2`
 * Composer package, which would be this plugin's first production
 * dependency (today: zero, dev/test tooling only) and would need the
 * release pipeline to bundle vendor/ for the first time. Confirmed and
 * deferred as an explicit product decision, not an oversight -- IPinfo
 * ships now because it needs neither.
 *
 * Results are cached in sam_geoip_cache (30-day TTL, including a cached
 * negative result on failure) for the same reason Asn_Lookup_Store caches
 * ASN lookups: a live HTTP call is too expensive to repeat per request,
 * and IPinfo's free tier has a real monthly request quota worth not
 * burning through on repeat lookups of the same IP.
 */

declare( strict_types=1 );

namespace WP_SAM\Intelligence;

use WP_SAM\Certificates\Credential_Vault;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Geo_Ip_Store {

	private const CACHE_TTL_DAYS = 30;

	/** @var callable(string):(array|\WP_Error) Real wp_remote_get() by default; injectable so tests never make a real HTTP call. */
	private $http_get;

	public function __construct( ?callable $http_get = null ) {
		$this->http_get = $http_get ?? static fn ( string $url ) => wp_remote_get(
			$url,
			array(
				'timeout'    => 10,
				'sslverify'  => true,
				'user-agent' => 'WordPress/' . get_bloginfo( 'version' ) . '; VCNS-Security-Automation-Manager/' . WP_SAM_VERSION . '; ' . get_bloginfo( 'url' ),
			)
		);
	}

	public function is_configured(): bool {
		return '' !== $this->token();
	}

	/** @return array{country: ?string, region: ?string, city: ?string} */
	public function resolve( string $ip ): array {
		$empty = array(
			'country' => null,
			'region'  => null,
			'city'    => null,
		);

		if ( ! $this->is_configured() || '' === $ip || false === filter_var( $ip, FILTER_VALIDATE_IP ) ) {
			return $empty;
		}

		$cached = $this->cached( $ip );
		if ( null !== $cached ) {
			return $cached;
		}

		$result = $this->live_lookup( $ip );
		$this->remember( $ip, $result );

		return $result;
	}

	/**
	 * Seals and stores the administrator's own IPinfo token. An empty
	 * string clears the configuration (Geo-IP becomes inert again).
	 */
	public function save_token( string $plaintext_token ): void {
		if ( '' === trim( $plaintext_token ) ) {
			update_option( 'wp_sam_geoip_ipinfo_token', '' );
			return;
		}
		update_option( 'wp_sam_geoip_ipinfo_token', Credential_Vault::seal( trim( $plaintext_token ) ) );
	}

	/** True if a token was saved but no longer decrypts under the current vault key (e.g. wp_salt() rotated). */
	public function token_undecryptable(): bool {
		$sealed = (string) get_option( 'wp_sam_geoip_ipinfo_token', '' );
		return Credential_Vault::is_sealed_but_undecryptable( $sealed );
	}

	private function token(): string {
		$sealed = (string) get_option( 'wp_sam_geoip_ipinfo_token', '' );
		if ( '' === $sealed ) {
			return '';
		}
		return Credential_Vault::open( $sealed ) ?? '';
	}

	/** @return array{country: ?string, region: ?string, city: ?string}|null */
	private function cached( string $ip ): ?array {
		global $wpdb;
		$table = $wpdb->prefix . 'sam_geoip_cache';
		$since = gmdate( 'Y-m-d H:i:s', time() - ( self::CACHE_TTL_DAYS * DAY_IN_SECONDS ) );

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
		$row = $wpdb->get_row(
			$wpdb->prepare(
				// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				"SELECT country, region, city FROM {$table} WHERE ip = %s AND resolved_at >= %s",
				$ip,
				$since
			),
			ARRAY_A
		);

		if ( ! is_array( $row ) ) {
			return null;
		}

		return array(
			'country' => '' !== (string) $row['country'] ? (string) $row['country'] : null,
			'region'  => '' !== (string) $row['region'] ? (string) $row['region'] : null,
			'city'    => '' !== (string) $row['city'] ? (string) $row['city'] : null,
		);
	}

	/** @param array{country: ?string, region: ?string, city: ?string} $result */
	private function remember( string $ip, array $result ): void {
		global $wpdb;
		$table = $wpdb->prefix . 'sam_geoip_cache';
		$now   = current_time( 'mysql', true );

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
		$existing_id = $wpdb->get_var(
			$wpdb->prepare(
				// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				"SELECT id FROM {$table} WHERE ip = %s",
				$ip
			)
		);

		$data = array(
			'ip'          => $ip,
			'country'     => $result['country'] ?? '',
			'region'      => $result['region'] ?? '',
			'city'        => $result['city'] ?? '',
			'resolved_at' => $now,
		);

		if ( $existing_id ) {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
			$wpdb->update( $table, $data, array( 'id' => (int) $existing_id ) );
			return;
		}

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
		$wpdb->insert( $table, $data );
	}

	/** @return array{country: ?string, region: ?string, city: ?string} */
	private function live_lookup( string $ip ): array {
		$empty = array(
			'country' => null,
			'region'  => null,
			'city'    => null,
		);

		$response = ( $this->http_get )( "https://ipinfo.io/{$ip}?token=" . rawurlencode( $this->token() ) );
		if ( is_wp_error( $response ) ) {
			return $empty;
		}
		if ( 200 !== (int) wp_remote_retrieve_response_code( $response ) ) {
			return $empty;
		}

		$body = json_decode( (string) wp_remote_retrieve_body( $response ), true );
		if ( ! is_array( $body ) ) {
			return $empty;
		}

		return array(
			'country' => isset( $body['country'] ) && '' !== $body['country'] ? (string) $body['country'] : null,
			'region'  => isset( $body['region'] ) && '' !== $body['region'] ? (string) $body['region'] : null,
			'city'    => isset( $body['city'] ) && '' !== $body['city'] ? (string) $body['city'] : null,
		);
	}
}
