<?php
/**
 * Azure DNS driver (ARM REST API, OAuth2 client-credentials).
 *
 * Recommend a dedicated app registration granted only the "DNS Zone
 * Contributor" role on the relevant zone or resource group.
 */

declare( strict_types=1 );

namespace WP_SAM\Certificates\Providers;

use WP_SAM\Certificates\Dns_Provider;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Provider_Azure extends Dns_Provider {

	private const ARM         = 'https://management.azure.com';
	private const API_VERSION = '2018-05-01';

	private ?string $token = null;

	/**
	 * Returns the display name of the Azure DNS provider.
	 *
	 * @return string Provider name.
	 */
	public static function label(): string {
		return 'Azure DNS';
	}

	/**
	 * Describes the credentials the Azure DNS provider needs.
	 *
	 * @return array Field definitions keyed by field key.
	 */
	public static function fields(): array {
		return array(
			'tenant_id'       => array(
				'label'  => __( 'Directory (tenant) ID', 'vcns-security-automation-manager' ),
				'secret' => false,
			),
			'client_id'       => array(
				'label'  => __( 'Application (client) ID', 'vcns-security-automation-manager' ),
				'secret' => false,
			),
			'client_secret'   => array(
				'label' => __( 'Client secret', 'vcns-security-automation-manager' ),
			),
			'subscription_id' => array(
				'label'  => __( 'Subscription ID', 'vcns-security-automation-manager' ),
				'secret' => false,
			),
			'resource_group'  => array(
				'label'  => __( 'Resource group containing the DNS zone', 'vcns-security-automation-manager' ),
				'secret' => false,
			),
		);
	}

	/**
	 * Adds the ACME challenge TXT record through the Azure DNS API.
	 *
	 * @param string $fqdn  Full record name.
	 * @param string $value TXT value.
	 * @return void
	 */
	public function create_txt_record( string $fqdn, string $value ): void {
		$zone     = $this->zone( $fqdn );
		$relative = $this->relative_name( $fqdn, $zone );

		$this->request(
			'PUT',
			$this->record_url( $zone, $relative ),
			$this->headers(),
			array(
				'properties' => array(
					'TTL'        => 60,
					'TXTRecords' => array( array( 'value' => array( $value ) ) ),
				),
			)
		);
	}

	/**
	 * Removes the ACME challenge TXT record through the Azure DNS API.
	 *
	 * @param string $fqdn  Full record name.
	 * @param string $value TXT value.
	 * @return void
	 */
	public function delete_txt_record( string $fqdn, string $value ): void {
		$zone = $this->zone( $fqdn );

		$this->request( 'DELETE', $this->record_url( $zone, $this->relative_name( $fqdn, $zone ) ), $this->headers() );
	}

	/**
	 * Builds the Azure Resource Manager URL of a record set in a zone.
	 *
	 * @param string $zone     Zone name.
	 * @param string $relative Path relative to the zone.
	 * @return string The URL.
	 */
	private function record_url( string $zone, string $relative ): string {
		return self::ARM
			. '/subscriptions/' . rawurlencode( $this->credential( 'subscription_id' ) )
			. '/resourceGroups/' . rawurlencode( $this->credential( 'resource_group' ) )
			. '/providers/Microsoft.Network/dnsZones/' . rawurlencode( $zone )
			. '/TXT/' . rawurlencode( $relative )
			. '?api-version=' . self::API_VERSION;
	}

	/**
	 * Finds the Azure DNS zone that contains a record name.
	 *
	 * @param string $fqdn Full record name.
	 * @return string Zone name or id.
	 * @throws \RuntimeException When the operation fails.
	 */
	private function zone( string $fqdn ): string {
		$list = $this->request(
			'GET',
			self::ARM . '/subscriptions/' . rawurlencode( $this->credential( 'subscription_id' ) )
				. '/resourceGroups/' . rawurlencode( $this->credential( 'resource_group' ) )
				. '/providers/Microsoft.Network/dnsZones?api-version=' . self::API_VERSION,
			$this->headers()
		);

		$zones = array_column( (array) ( $list['body']['value'] ?? array() ), 'name' );
		foreach ( $this->zone_candidates( $fqdn ) as $candidate ) {
			if ( in_array( $candidate, $zones, true ) ) {
				return $candidate;
			}
		}

		throw new \RuntimeException( "Azure DNS: no zone found for {$fqdn} in the configured resource group." ); // phpcs:ignore WordPress.Security.EscapeOutput.ExceptionNotEscaped -- exception message, never echoed as HTML; only logged via Audit_Log/record_run().
	}

	/**
	 * Builds the Azure request headers, fetching an access token on first use.
	 *
	 * @return array Header map.
	 * @throws \RuntimeException When the operation fails.
	 */
	private function headers(): array {
		if ( null === $this->token ) {
			$response = wp_remote_post(
				'https://login.microsoftonline.com/' . rawurlencode( $this->credential( 'tenant_id' ) ) . '/oauth2/v2.0/token',
				array(
					'timeout' => 30,
					'body'    => array(
						'grant_type'    => 'client_credentials',
						'client_id'     => $this->credential( 'client_id' ),
						'client_secret' => $this->credential( 'client_secret' ),
						'scope'         => 'https://management.azure.com/.default',
					),
				)
			);
			if ( is_wp_error( $response ) ) {
				throw new \RuntimeException( 'Azure token transport error: ' . $response->get_error_message() ); // phpcs:ignore WordPress.Security.EscapeOutput.ExceptionNotEscaped -- exception message, never echoed as HTML; only logged via Audit_Log/record_run().
			}
			$body        = json_decode( (string) wp_remote_retrieve_body( $response ), true );
			$this->token = (string) ( $body['access_token'] ?? '' );
			if ( '' === $this->token ) {
				throw new \RuntimeException( 'Azure token request failed: ' . substr( (string) wp_remote_retrieve_body( $response ), 0, 200 ) ); // phpcs:ignore WordPress.Security.EscapeOutput.ExceptionNotEscaped -- exception message, never echoed as HTML; only logged via Audit_Log/record_run().
			}
		}

		return array( 'Authorization' => 'Bearer ' . $this->token );
	}
}
