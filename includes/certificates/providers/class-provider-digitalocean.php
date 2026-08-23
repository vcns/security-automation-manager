<?php
/**
 * DigitalOcean DNS driver (api.digitalocean.com v2, personal access token).
 */

declare( strict_types=1 );

namespace WP_SAM\Certificates\Providers;

use WP_SAM\Certificates\Dns_Provider;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Provider_DigitalOcean extends Dns_Provider {

	private const API = 'https://api.digitalocean.com/v2';

	public static function label(): string {
		return 'DigitalOcean';
	}

	public static function fields(): array {
		return array(
			'api_token' => array(
				'label'       => __( 'Personal Access Token (write scope)', 'vcns-security-automation-manager' ),
				'placeholder' => 'dop_v1_...',
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
				'data' => $value,
				'ttl'  => 60,
			)
		);
	}

	public function delete_txt_record( string $fqdn, string $value ): void {
		$zone     = $this->zone( $fqdn );
		$relative = $this->relative_name( $fqdn, $zone );
		$list     = $this->request( 'GET', self::API . "/domains/{$zone}/records?type=TXT&per_page=200", $this->headers() );

		foreach ( (array) ( $list['body']['domain_records'] ?? array() ) as $record ) {
			if ( ( $record['name'] ?? '' ) === $relative && ( $record['data'] ?? '' ) === $value ) {
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
				continue; // 404 for this candidate; try the parent.
			}
		}

		throw new \RuntimeException( "DigitalOcean: no zone found for {$fqdn}." );
	}

	private function headers(): array {
		return array( 'Authorization' => 'Bearer ' . $this->credential( 'api_token' ) );
	}
}
