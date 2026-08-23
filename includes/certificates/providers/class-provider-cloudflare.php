<?php
/**
 * Cloudflare DNS driver (api.cloudflare.com v4, scoped API token).
 *
 * Recommend a token scoped to Zone:DNS:Edit for only the relevant zones --
 * never a Global API Key.
 */

declare( strict_types=1 );

namespace WP_SAM\Certificates\Providers;

use WP_SAM\Certificates\Dns_Provider;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Provider_Cloudflare extends Dns_Provider {

	private const API = 'https://api.cloudflare.com/client/v4';

	public static function label(): string {
		return 'Cloudflare';
	}

	public static function fields(): array {
		return array(
			'api_token' => array(
				'label'       => __( 'API Token (scoped to Zone / DNS / Edit)', 'vcns-security-automation-manager' ),
				'placeholder' => 'cf_...',
			),
		);
	}

	public function create_txt_record( string $fqdn, string $value ): void {
		$zone_id = $this->zone_id( $fqdn );

		$this->request(
			'POST',
			self::API . "/zones/{$zone_id}/dns_records",
			$this->headers(),
			array(
				'type'    => 'TXT',
				'name'    => $fqdn,
				'content' => $value,
				'ttl'     => 60,
			)
		);
	}

	public function delete_txt_record( string $fqdn, string $value ): void {
		$zone_id = $this->zone_id( $fqdn );
		$list    = $this->request(
			'GET',
			self::API . "/zones/{$zone_id}/dns_records?type=TXT&name=" . rawurlencode( $fqdn ),
			$this->headers()
		);

		foreach ( (array) ( $list['body']['result'] ?? array() ) as $record ) {
			if ( trim( (string) ( $record['content'] ?? '' ), '"' ) === $value ) {
				$this->request( 'DELETE', self::API . "/zones/{$zone_id}/dns_records/" . $record['id'], $this->headers() );
			}
		}
	}

	private function zone_id( string $fqdn ): string {
		foreach ( $this->zone_candidates( $fqdn ) as $candidate ) {
			$response = $this->request( 'GET', self::API . '/zones?name=' . rawurlencode( $candidate ), $this->headers() );
			if ( ! empty( $response['body']['result'][0]['id'] ) ) {
				return (string) $response['body']['result'][0]['id'];
			}
		}

		throw new \RuntimeException( "Cloudflare: no zone found for {$fqdn}. Check the token's zone scope." );
	}

	private function headers(): array {
		return array( 'Authorization' => 'Bearer ' . $this->credential( 'api_token' ) );
	}
}
