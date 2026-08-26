<?php
/**
 * Netlify DNS driver (api.netlify.com v1, personal access token).
 */

declare( strict_types=1 );

namespace WP_SAM\Certificates\Providers;

use WP_SAM\Certificates\Dns_Provider;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Provider_Netlify extends Dns_Provider {

	private const API = 'https://api.netlify.com/api/v1';

	public static function label(): string {
		return 'Netlify DNS';
	}

	public static function fields(): array {
		return array(
			'api_token' => array(
				'label' => __( 'Personal access token', 'vcns-security-automation-manager' ),
			),
		);
	}

	public function create_txt_record( string $fqdn, string $value ): void {
		$zone = $this->zone( $fqdn );

		$this->request(
			'POST',
			self::API . "/dns_zones/{$zone['id']}/dns_records",
			$this->headers(),
			array(
				'type'     => 'TXT',
				'hostname' => $fqdn,
				'value'    => $value,
				'ttl'      => 60,
			)
		);
	}

	public function delete_txt_record( string $fqdn, string $value ): void {
		$zone = $this->zone( $fqdn );
		$list = $this->request( 'GET', self::API . "/dns_zones/{$zone['id']}/dns_records", $this->headers() );

		foreach ( (array) $list['body'] as $record ) {
			if ( is_array( $record ) && 'TXT' === ( $record['type'] ?? '' ) && ( $record['hostname'] ?? '' ) === $fqdn && ( $record['value'] ?? '' ) === $value ) {
				$this->request( 'DELETE', self::API . "/dns_zones/{$zone['id']}/dns_records/" . $record['id'], $this->headers() );
			}
		}
	}

	/**
	 * @return array{id:string,name:string}
	 */
	private function zone( string $fqdn ): array {
		$list = $this->request( 'GET', self::API . '/dns_zones', $this->headers() );

		foreach ( $this->zone_candidates( $fqdn ) as $candidate ) {
			foreach ( (array) $list['body'] as $zone ) {
				if ( is_array( $zone ) && ( $zone['name'] ?? '' ) === $candidate ) {
					return array(
						'id'   => (string) $zone['id'],
						'name' => $candidate,
					);
				}
			}
		}

		throw new \RuntimeException( "Netlify DNS: no zone found for {$fqdn}." ); // phpcs:ignore WordPress.Security.EscapeOutput.ExceptionNotEscaped -- exception message, never echoed as HTML; only logged via Audit_Log/record_run().
	}

	private function headers(): array {
		return array( 'Authorization' => 'Bearer ' . $this->credential( 'api_token' ) );
	}
}
