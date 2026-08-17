<?php
/**
 * DNS Made Easy driver (V2.0 API, HMAC-SHA1 request signing).
 */

declare( strict_types=1 );

namespace WP_SAM\Certificates\Providers;

use WP_SAM\Certificates\Dns_Provider;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Provider_Dnsmadeeasy extends Dns_Provider {

	private const API = 'https://api.dnsmadeeasy.com/V2.0';

	public static function label(): string {
		return 'DNS Made Easy';
	}

	public static function fields(): array {
		return array(
			'api_key'    => array(
				'label' => __( 'API Key', 'security-automation-manager' ),
			),
			'secret_key' => array(
				'label' => __( 'Secret Key', 'security-automation-manager' ),
			),
		);
	}

	public function create_txt_record( string $fqdn, string $value ): void {
		$zone = $this->zone( $fqdn );

		$this->request(
			'POST',
			self::API . "/dns/managed/{$zone['id']}/records",
			$this->headers(),
			array(
				'type'        => 'TXT',
				'name'        => $this->relative_name( $fqdn, $zone['name'] ),
				'value'       => '"' . $value . '"',
				'ttl'         => 60,
				'gtdLocation' => 'DEFAULT',
			)
		);
	}

	public function delete_txt_record( string $fqdn, string $value ): void {
		$zone     = $this->zone( $fqdn );
		$relative = $this->relative_name( $fqdn, $zone['name'] );
		$list     = $this->request(
			'GET',
			self::API . "/dns/managed/{$zone['id']}/records?type=TXT&recordName=" . rawurlencode( $relative ),
			$this->headers()
		);

		foreach ( (array) ( $list['body']['data'] ?? array() ) as $record ) {
			if ( trim( (string) ( $record['value'] ?? '' ), '"' ) === $value ) {
				$this->request( 'DELETE', self::API . "/dns/managed/{$zone['id']}/records/" . $record['id'], $this->headers() );
			}
		}
	}

	/**
	 * @return array{id:int,name:string}
	 */
	private function zone( string $fqdn ): array {
		foreach ( $this->zone_candidates( $fqdn ) as $candidate ) {
			try {
				$response = $this->request( 'GET', self::API . '/dns/managed/name?domainname=' . rawurlencode( $candidate ), $this->headers() );
				if ( ! empty( $response['body']['id'] ) ) {
					return array(
						'id'   => (int) $response['body']['id'],
						'name' => $candidate,
					);
				}
			} catch ( \RuntimeException $e ) {
				continue;
			}
		}

		throw new \RuntimeException( "DNS Made Easy: no managed domain found for {$fqdn}." );
	}

	private function headers(): array {
		$date = gmdate( 'r' );

		return array(
			'x-dnsme-apiKey'      => $this->credential( 'api_key' ),
			'x-dnsme-requestDate' => $date,
			'x-dnsme-hmac'        => hash_hmac( 'sha1', $date, $this->credential( 'secret_key' ) ),
		);
	}
}
