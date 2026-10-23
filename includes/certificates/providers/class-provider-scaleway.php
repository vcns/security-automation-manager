<?php
/**
 * Scaleway Domains and DNS driver (domain/v2beta1 API, secret key).
 */

declare( strict_types=1 );

namespace WP_SAM\Certificates\Providers;

use WP_SAM\Certificates\Dns_Provider;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Provider_Scaleway extends Dns_Provider {

	private const API = 'https://api.scaleway.com/domain/v2beta1';

	/**
	 * Returns the display name of the Scaleway provider.
	 *
	 * @return string Provider name.
	 */
	public static function label(): string {
		return 'Scaleway';
	}

	/**
	 * Describes the credentials the Scaleway provider needs.
	 *
	 * @return array Field definitions keyed by field key.
	 */
	public static function fields(): array {
		return array(
			'secret_key' => array(
				'label' => __( 'API secret key', 'vcns-security-automation-manager' ),
			),
		);
	}

	/**
	 * Adds the ACME challenge TXT record through the Scaleway API.
	 *
	 * @param string $fqdn  Full record name.
	 * @param string $value TXT value.
	 * @return void
	 */
	public function create_txt_record( string $fqdn, string $value ): void {
		$zone = $this->zone( $fqdn );

		$this->request(
			'PATCH',
			self::API . '/dns-zones/' . rawurlencode( $zone ) . '/records',
			$this->headers(),
			array(
				'changes' => array(
					array(
						'add' => array(
							'records' => array(
								array(
									'name' => $this->relative_name( $fqdn, $zone ),
									'type' => 'TXT',
									'data' => '"' . $value . '"',
									'ttl'  => 60,
								),
							),
						),
					),
				),
			)
		);
	}

	/**
	 * Removes the ACME challenge TXT record through the Scaleway API.
	 *
	 * @param string $fqdn  Full record name.
	 * @param string $value TXT value.
	 * @return void
	 */
	public function delete_txt_record( string $fqdn, string $value ): void {
		$zone = $this->zone( $fqdn );

		$this->request(
			'PATCH',
			self::API . '/dns-zones/' . rawurlencode( $zone ) . '/records',
			$this->headers(),
			array(
				'changes' => array(
					array(
						'delete' => array(
							'id_fields' => array(
								'name' => $this->relative_name( $fqdn, $zone ),
								'type' => 'TXT',
								'data' => '"' . $value . '"',
							),
						),
					),
				),
			)
		);
	}

	/**
	 * Finds the Scaleway zone that contains a record name.
	 *
	 * @param string $fqdn Full record name.
	 * @return string Zone name or id.
	 * @throws \RuntimeException When the operation fails.
	 */
	private function zone( string $fqdn ): string {
		foreach ( $this->zone_candidates( $fqdn ) as $candidate ) {
			$response = $this->request( 'GET', self::API . '/dns-zones?domain=' . rawurlencode( $candidate ), $this->headers() );
			foreach ( (array) ( $response['body']['dns_zones'] ?? array() ) as $zone ) {
				$name = trim( ( $zone['subdomain'] ?? '' ) . '.' . ( $zone['domain'] ?? '' ), '.' );
				if ( $name === $candidate ) {
					return $candidate;
				}
			}
		}

		throw new \RuntimeException( "Scaleway: no DNS zone found for {$fqdn}." ); // phpcs:ignore WordPress.Security.EscapeOutput.ExceptionNotEscaped -- exception message, never echoed as HTML; only logged via Audit_Log/record_run().
	}

	/**
	 * Builds the Scaleway request headers, including authentication.
	 *
	 * @return array Header map.
	 */
	private function headers(): array {
		return array( 'X-Auth-Token' => $this->credential( 'secret_key' ) );
	}
}
