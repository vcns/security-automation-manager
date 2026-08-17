<?php
/**
 * Porkbun DNS driver (api.porkbun.com v3, API key + secret in the body).
 */

declare( strict_types=1 );

namespace WP_SAM\Certificates\Providers;

use WP_SAM\Certificates\Dns_Provider;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Provider_Porkbun extends Dns_Provider {

	private const API = 'https://api.porkbun.com/api/json/v3';

	public static function label(): string {
		return 'Porkbun';
	}

	public static function fields(): array {
		return array(
			'api_key'    => array(
				'label'       => __( 'API Key', 'security-automation-manager' ),
				'placeholder' => 'pk1_...',
			),
			'api_secret' => array(
				'label'       => __( 'Secret API Key', 'security-automation-manager' ),
				'placeholder' => 'sk1_...',
			),
		);
	}

	public function create_txt_record( string $fqdn, string $value ): void {
		$zone = $this->zone( $fqdn );

		$this->request(
			'POST',
			self::API . "/dns/create/{$zone}",
			array(),
			$this->auth(
				array(
					'type'    => 'TXT',
					'name'    => $this->relative_name( $fqdn, $zone ),
					'content' => $value,
					'ttl'     => '600',
				)
			)
		);
	}

	public function delete_txt_record( string $fqdn, string $value ): void {
		$zone     = $this->zone( $fqdn );
		$relative = $this->relative_name( $fqdn, $zone );

		$this->request(
			'POST',
			self::API . "/dns/deleteByNameType/{$zone}/TXT/" . rawurlencode( $relative ),
			array(),
			$this->auth( array() )
		);
	}

	private function zone( string $fqdn ): string {
		foreach ( $this->zone_candidates( $fqdn ) as $candidate ) {
			try {
				$this->request( 'POST', self::API . "/dns/retrieve/{$candidate}", array(), $this->auth( array() ) );
				return $candidate;
			} catch ( \RuntimeException $e ) {
				continue;
			}
		}

		throw new \RuntimeException( "Porkbun: no zone found for {$fqdn}." );
	}

	private function auth( array $body ): array {
		return array_merge(
			$body,
			array(
				'apikey'       => $this->credential( 'api_key' ),
				'secretapikey' => $this->credential( 'api_secret' ),
			)
		);
	}
}
