<?php
/**
 * Vultr DNS driver (api.vultr.com v2, API key).
 */

declare( strict_types=1 );

namespace WP_SAM\Certificates\Providers;

use WP_SAM\Certificates\Dns_Provider;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Provider_Vultr extends Dns_Provider {

	private const API = 'https://api.vultr.com/v2';

	public static function label(): string {
		return 'Vultr';
	}

	public static function fields(): array {
		return array(
			'api_key' => array(
				'label' => __( 'API Key', 'vcns-security-automation-manager' ),
			),
		);
	}

	public function create_txt_record( string $fqdn, string $value ): void {
		$zone = $this->zone( $fqdn );

		$this->request(
			'POST',
			self::API . "/domains/{$zone}/records",
			$this->headers(),
			array(
				'type' => 'TXT',
				'name' => $this->relative_name( $fqdn, $zone ),
				'data' => '"' . $value . '"',
				'ttl'  => 120,
			)
		);
	}

	public function delete_txt_record( string $fqdn, string $value ): void {
		$zone     = $this->zone( $fqdn );
		$relative = $this->relative_name( $fqdn, $zone );
		$list     = $this->request( 'GET', self::API . "/domains/{$zone}/records?per_page=500", $this->headers() );

		foreach ( (array) ( $list['body']['records'] ?? array() ) as $record ) {
			if ( 'TXT' === ( $record['type'] ?? '' ) && ( $record['name'] ?? '' ) === $relative && trim( (string) ( $record['data'] ?? '' ), '"' ) === $value ) {
				$this->request( 'DELETE', self::API . "/domains/{$zone}/records/" . $record['id'], $this->headers() );
			}
		}
	}

	private function zone( string $fqdn ): string {
		foreach ( $this->zone_candidates( $fqdn ) as $candidate ) {
			try {
				$this->request( 'GET', self::API . '/domains/' . rawurlencode( $candidate ), $this->headers() );
				return $candidate;
			} catch ( \RuntimeException $e ) {
				continue;
			}
		}

		throw new \RuntimeException( "Vultr: no domain found for {$fqdn}." );
	}

	private function headers(): array {
		return array( 'Authorization' => 'Bearer ' . $this->credential( 'api_key' ) );
	}
}
