<?php
/**
 * Vercel DNS driver (api.vercel.com, bearer token, optional team scope).
 */

declare( strict_types=1 );

namespace WP_SAM\Certificates\Providers;

use WP_SAM\Certificates\Dns_Provider;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Provider_Vercel extends Dns_Provider {

	private const API = 'https://api.vercel.com';

	/**
	 * Returns the display name of the Vercel DNS provider.
	 *
	 * @return string Provider name.
	 */
	public static function label(): string {
		return 'Vercel DNS';
	}

	/**
	 * Describes the credentials the Vercel DNS provider needs.
	 *
	 * @return array Field definitions keyed by field key.
	 */
	public static function fields(): array {
		return array(
			'api_token' => array(
				'label' => __( 'Access token', 'vcns-security-automation-manager' ),
			),
			'team_id'   => array(
				'label'       => __( 'Team ID (blank for personal scope)', 'vcns-security-automation-manager' ),
				'secret'      => false,
				'placeholder' => 'team_...',
			),
		);
	}

	/**
	 * Adds the ACME challenge TXT record through the Vercel DNS API.
	 *
	 * @param string $fqdn  Full record name.
	 * @param string $value TXT value.
	 * @return void
	 */
	public function create_txt_record( string $fqdn, string $value ): void {
		$zone = $this->zone( $fqdn );

		$this->request(
			'POST',
			self::API . "/v2/domains/{$zone}/records" . $this->team_query(),
			$this->headers(),
			array(
				'name'  => $this->relative_name( $fqdn, $zone ),
				'type'  => 'TXT',
				'value' => $value,
				'ttl'   => 60,
			)
		);
	}

	/**
	 * Removes the ACME challenge TXT record through the Vercel DNS API.
	 *
	 * @param string $fqdn  Full record name.
	 * @param string $value TXT value.
	 * @return void
	 */
	public function delete_txt_record( string $fqdn, string $value ): void {
		$zone     = $this->zone( $fqdn );
		$relative = $this->relative_name( $fqdn, $zone );
		$list     = $this->request( 'GET', self::API . "/v4/domains/{$zone}/records?limit=100" . $this->team_query( '&' ), $this->headers() );

		foreach ( (array) ( $list['body']['records'] ?? array() ) as $record ) {
			if ( 'TXT' === ( $record['type'] ?? '' ) && ( $record['name'] ?? '' ) === $relative && ( $record['value'] ?? '' ) === $value ) {
				$this->request( 'DELETE', self::API . "/v2/domains/{$zone}/records/" . $record['id'] . $this->team_query(), $this->headers() );
			}
		}
	}

	/**
	 * Finds the Vercel DNS zone that contains a record name.
	 *
	 * @param string $fqdn Full record name.
	 * @return string Zone name or id.
	 * @throws \RuntimeException When the operation fails.
	 */
	private function zone( string $fqdn ): string {
		foreach ( $this->zone_candidates( $fqdn ) as $candidate ) {
			try {
				$this->request( 'GET', self::API . '/v5/domains/' . rawurlencode( $candidate ) . $this->team_query(), $this->headers() );
				return $candidate;
			} catch ( \RuntimeException $e ) {
				continue;
			}
		}

		throw new \RuntimeException( "Vercel: no domain found for {$fqdn}." ); // phpcs:ignore WordPress.Security.EscapeOutput.ExceptionNotEscaped -- exception message, never echoed as HTML; only logged via Audit_Log/record_run().
	}

	/**
	 * Returns the teamId query parameter when a team id is configured.
	 *
	 * @param string $sep Separator that starts the query string.
	 * @return string Query string fragment, or an empty string.
	 */
	private function team_query( string $sep = '?' ): string {
		$team = trim( $this->credential( 'team_id' ) );

		return '' !== $team ? $sep . 'teamId=' . rawurlencode( $team ) : '';
	}

	/**
	 * Builds the Vercel DNS request headers, including authentication.
	 *
	 * @return array Header map.
	 */
	private function headers(): array {
		return array( 'Authorization' => 'Bearer ' . $this->credential( 'api_token' ) );
	}
}
