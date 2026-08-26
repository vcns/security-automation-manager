<?php
/**
 * IONOS driver (developer DNS API, prefix.secret API key).
 */

declare( strict_types=1 );

namespace WP_SAM\Certificates\Providers;

use WP_SAM\Certificates\Dns_Provider;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Provider_Ionos extends Dns_Provider {

	private const API = 'https://api.hosting.ionos.com/dns/v1';

	public static function label(): string {
		return 'IONOS';
	}

	public static function fields(): array {
		return array(
			'api_key' => array(
				'label'       => __( 'API key (publicprefix.secret from the developer portal)', 'vcns-security-automation-manager' ),
				'placeholder' => 'prefix.secret',
			),
		);
	}

	public function create_txt_record( string $fqdn, string $value ): void {
		$zone = $this->zone( $fqdn );

		$this->request(
			'POST',
			self::API . "/zones/{$zone['id']}/records",
			$this->headers(),
			array(
				array(
					'name'    => $fqdn,
					'type'    => 'TXT',
					'content' => $value,
					'ttl'     => 60,
				),
			)
		);
	}

	public function delete_txt_record( string $fqdn, string $value ): void {
		$zone   = $this->zone( $fqdn );
		$detail = $this->request(
			'GET',
			self::API . "/zones/{$zone['id']}?recordName=" . rawurlencode( $fqdn ) . '&recordType=TXT',
			$this->headers()
		);

		foreach ( (array) ( $detail['body']['records'] ?? array() ) as $record ) {
			if ( trim( (string) ( $record['content'] ?? '' ), '"' ) === $value ) {
				$this->request( 'DELETE', self::API . "/zones/{$zone['id']}/records/" . $record['id'], $this->headers() );
			}
		}
	}

	/**
	 * @return array{id:string,name:string}
	 */
	private function zone( string $fqdn ): array {
		$list = $this->request( 'GET', self::API . '/zones', $this->headers() );

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

		throw new \RuntimeException( "IONOS: no zone found for {$fqdn}." ); // phpcs:ignore WordPress.Security.EscapeOutput.ExceptionNotEscaped -- exception message, never echoed as HTML; only logged via Audit_Log/record_run().
	}

	private function headers(): array {
		return array( 'X-API-Key' => $this->credential( 'api_key' ) );
	}
}
