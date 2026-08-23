<?php
/**
 * Domeneshop driver (api.domeneshop.no v0, token + secret HTTP Basic).
 */

declare( strict_types=1 );

namespace WP_SAM\Certificates\Providers;

use WP_SAM\Certificates\Dns_Provider;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Provider_Domeneshop extends Dns_Provider {

	private const API = 'https://api.domeneshop.no/v0';

	public static function label(): string {
		return 'Domeneshop';
	}

	public static function fields(): array {
		return array(
			'token'  => array(
				'label'  => __( 'API token', 'vcns-security-automation-manager' ),
				'secret' => false,
			),
			'secret' => array(
				'label' => __( 'API secret', 'vcns-security-automation-manager' ),
			),
		);
	}

	public function create_txt_record( string $fqdn, string $value ): void {
		$zone = $this->zone( $fqdn );

		$this->request(
			'POST',
			self::API . "/domains/{$zone['id']}/dns",
			$this->headers(),
			array(
				'host' => $this->relative_name( $fqdn, $zone['name'] ),
				'type' => 'TXT',
				'data' => $value,
				'ttl'  => 300,
			)
		);
	}

	public function delete_txt_record( string $fqdn, string $value ): void {
		$zone     = $this->zone( $fqdn );
		$relative = $this->relative_name( $fqdn, $zone['name'] );
		$list     = $this->request( 'GET', self::API . "/domains/{$zone['id']}/dns?type=TXT&host=" . rawurlencode( $relative ), $this->headers() );

		foreach ( (array) $list['body'] as $record ) {
			if ( is_array( $record ) && ( $record['data'] ?? '' ) === $value ) {
				$this->request( 'DELETE', self::API . "/domains/{$zone['id']}/dns/" . $record['id'], $this->headers() );
			}
		}
	}

	/**
	 * @return array{id:int,name:string}
	 */
	private function zone( string $fqdn ): array {
		foreach ( $this->zone_candidates( $fqdn ) as $candidate ) {
			$list = $this->request( 'GET', self::API . '/domains?domain=' . rawurlencode( $candidate ), $this->headers() );
			foreach ( (array) $list['body'] as $domain ) {
				if ( is_array( $domain ) && ( $domain['domain'] ?? '' ) === $candidate ) {
					return array(
						'id'   => (int) $domain['id'],
						'name' => $candidate,
					);
				}
			}
		}

		throw new \RuntimeException( "Domeneshop: no domain found for {$fqdn}." );
	}

	private function headers(): array {
		return array( 'Authorization' => $this->basic_auth( $this->credential( 'token' ), $this->credential( 'secret' ) ) );
	}
}
