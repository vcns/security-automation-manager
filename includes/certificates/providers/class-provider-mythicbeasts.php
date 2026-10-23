<?php
/**
 * Mythic Beasts driver (DNS API v2, OAuth2 client-credentials with the
 * API key ID/secret pair).
 */

declare( strict_types=1 );

namespace WP_SAM\Certificates\Providers;

use WP_SAM\Certificates\Dns_Provider;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Provider_Mythicbeasts extends Dns_Provider {

	private const API  = 'https://api.mythic-beasts.com/dns/v2';
	private const AUTH = 'https://auth.mythic-beasts.com/login';

	private ?string $token = null;

	/**
	 * Returns the display name of the Mythic Beasts provider.
	 *
	 * @return string Provider name.
	 */
	public static function label(): string {
		return 'Mythic Beasts';
	}

	/**
	 * Describes the credentials the Mythic Beasts provider needs.
	 *
	 * @return array Field definitions keyed by field key.
	 */
	public static function fields(): array {
		return array(
			'key_id' => array(
				'label'  => __( 'API key ID', 'vcns-security-automation-manager' ),
				'secret' => false,
			),
			'secret' => array(
				'label' => __( 'API secret', 'vcns-security-automation-manager' ),
			),
		);
	}

	/**
	 * Adds the ACME challenge TXT record through the Mythic Beasts API.
	 *
	 * @param string $fqdn  Full record name.
	 * @param string $value TXT value.
	 * @return void
	 */
	public function create_txt_record( string $fqdn, string $value ): void {
		$zone = $this->zone( $fqdn );

		$this->request(
			'POST',
			self::API . "/zones/{$zone}/records",
			$this->headers(),
			array(
				'records' => array(
					array(
						'host' => $this->relative_name( $fqdn, $zone ),
						'ttl'  => 60,
						'type' => 'TXT',
						'data' => $value,
					),
				),
			)
		);
	}

	/**
	 * Removes the ACME challenge TXT record through the Mythic Beasts API.
	 *
	 * @param string $fqdn  Full record name.
	 * @param string $value TXT value.
	 * @return void
	 */
	public function delete_txt_record( string $fqdn, string $value ): void {
		$zone = $this->zone( $fqdn );

		// Records endpoint supports exact-match deletion by host/type/data.
		$this->request(
			'DELETE',
			self::API . "/zones/{$zone}/records/" . rawurlencode( $this->relative_name( $fqdn, $zone ) ) . '/TXT?data=' . rawurlencode( $value ),
			$this->headers()
		);
	}

	/**
	 * Finds the Mythic Beasts zone that contains a record name.
	 *
	 * @param string $fqdn Full record name.
	 * @return string Zone name.
	 * @throws \RuntimeException When the operation fails.
	 */
	private function zone( string $fqdn ): string {
		$list  = $this->request( 'GET', self::API . '/zones', $this->headers() );
		$zones = (array) ( $list['body']['zones'] ?? array() );

		foreach ( $this->zone_candidates( $fqdn ) as $candidate ) {
			if ( in_array( $candidate, $zones, true ) ) {
				return $candidate;
			}
		}

		throw new \RuntimeException( "Mythic Beasts: no zone found for {$fqdn}." ); // phpcs:ignore WordPress.Security.EscapeOutput.ExceptionNotEscaped -- exception message, never echoed as HTML; only logged via Audit_Log/record_run().
	}

	/**
	 * Builds the Mythic Beasts request headers, fetching an access token on first use.
	 *
	 * @return array Header map.
	 * @throws \RuntimeException When the operation fails.
	 */
	private function headers(): array {
		if ( null === $this->token ) {
			$response = wp_remote_post(
				self::AUTH,
				array(
					'timeout' => 30,
					'headers' => array( 'Authorization' => $this->basic_auth( $this->credential( 'key_id' ), $this->credential( 'secret' ) ) ),
					'body'    => array( 'grant_type' => 'client_credentials' ),
				)
			);
			if ( is_wp_error( $response ) ) {
				throw new \RuntimeException( 'Mythic Beasts auth transport error: ' . $response->get_error_message() ); // phpcs:ignore WordPress.Security.EscapeOutput.ExceptionNotEscaped -- exception message, never echoed as HTML; only logged via Audit_Log/record_run().
			}
			$body        = json_decode( (string) wp_remote_retrieve_body( $response ), true );
			$this->token = (string) ( $body['access_token'] ?? '' );
			if ( '' === $this->token ) {
				throw new \RuntimeException( 'Mythic Beasts authentication failed.' );
			}
		}

		return array( 'Authorization' => 'Bearer ' . $this->token );
	}
}
