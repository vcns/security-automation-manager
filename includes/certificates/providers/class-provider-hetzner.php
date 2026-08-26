<?php
/**
 * Hetzner DNS driver (dns.hetzner.com v1, API token).
 */

declare( strict_types=1 );

namespace WP_SAM\Certificates\Providers;

use WP_SAM\Certificates\Dns_Provider;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Provider_Hetzner extends Dns_Provider {

	private const API = 'https://dns.hetzner.com/api/v1';

	public static function label(): string {
		return 'Hetzner DNS';
	}

	public static function fields(): array {
		return array(
			'api_token' => array(
				'label' => __( 'DNS API Token', 'vcns-security-automation-manager' ),
			),
		);
	}

	public function create_txt_record( string $fqdn, string $value ): void {
		$zone = $this->zone( $fqdn );

		$this->request(
			'POST',
			self::API . '/records',
			$this->headers(),
			array(
				'zone_id' => $zone['id'],
				'type'    => 'TXT',
				'name'    => $this->relative_name( $fqdn, $zone['name'] ),
				'value'   => $value,
				'ttl'     => 60,
			)
		);
	}

	public function delete_txt_record( string $fqdn, string $value ): void {
		$zone     = $this->zone( $fqdn );
		$relative = $this->relative_name( $fqdn, $zone['name'] );
		$list     = $this->request( 'GET', self::API . '/records?zone_id=' . rawurlencode( $zone['id'] ), $this->headers() );

		foreach ( (array) ( $list['body']['records'] ?? array() ) as $record ) {
			if ( 'TXT' === ( $record['type'] ?? '' ) && ( $record['name'] ?? '' ) === $relative && ( $record['value'] ?? '' ) === $value ) {
				$this->request( 'DELETE', self::API . '/records/' . $record['id'], $this->headers() );
			}
		}
	}

	/**
	 * @return array{id:string,name:string}
	 */
	private function zone( string $fqdn ): array {
		foreach ( $this->zone_candidates( $fqdn ) as $candidate ) {
			$response = $this->request( 'GET', self::API . '/zones?name=' . rawurlencode( $candidate ), $this->headers() );
			foreach ( (array) ( $response['body']['zones'] ?? array() ) as $zone ) {
				if ( ( $zone['name'] ?? '' ) === $candidate ) {
					return array(
						'id'   => (string) $zone['id'],
						'name' => $candidate,
					);
				}
			}
		}

		throw new \RuntimeException( "Hetzner: no zone found for {$fqdn}." ); // phpcs:ignore WordPress.Security.EscapeOutput.ExceptionNotEscaped -- exception message, never echoed as HTML; only logged via Audit_Log/record_run().
	}

	private function headers(): array {
		return array( 'Auth-API-Token' => $this->credential( 'api_token' ) );
	}
}
