<?php
/**
 * Linode / Akamai Connected Cloud DNS driver (api.linode.com v4).
 */

declare( strict_types=1 );

namespace WP_SAM\Certificates\Providers;

use WP_SAM\Certificates\Dns_Provider;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Provider_Linode extends Dns_Provider {

	private const API = 'https://api.linode.com/v4';

	public static function label(): string {
		return 'Linode (Akamai)';
	}

	public static function fields(): array {
		return array(
			'api_token' => array(
				'label' => __( 'Personal Access Token (Domains read/write)', 'security-automation-manager' ),
			),
		);
	}

	public function create_txt_record( string $fqdn, string $value ): void {
		$zone = $this->zone( $fqdn );

		$this->request(
			'POST',
			self::API . "/domains/{$zone['id']}/records",
			$this->headers(),
			array(
				'type'    => 'TXT',
				'name'    => $this->relative_name( $fqdn, $zone['name'] ),
				'target'  => $value,
				'ttl_sec' => 300,
			)
		);
	}

	public function delete_txt_record( string $fqdn, string $value ): void {
		$zone     = $this->zone( $fqdn );
		$relative = $this->relative_name( $fqdn, $zone['name'] );
		$list     = $this->request( 'GET', self::API . "/domains/{$zone['id']}/records?page_size=500", $this->headers() );

		foreach ( (array) ( $list['body']['data'] ?? array() ) as $record ) {
			if ( 'TXT' === ( $record['type'] ?? '' ) && ( $record['name'] ?? '' ) === $relative && ( $record['target'] ?? '' ) === $value ) {
				$this->request( 'DELETE', self::API . "/domains/{$zone['id']}/records/" . $record['id'], $this->headers() );
			}
		}
	}

	/**
	 * @return array{id:int,name:string}
	 */
	private function zone( string $fqdn ): array {
		$list = $this->request( 'GET', self::API . '/domains?page_size=500', $this->headers() );

		foreach ( $this->zone_candidates( $fqdn ) as $candidate ) {
			foreach ( (array) ( $list['body']['data'] ?? array() ) as $domain ) {
				if ( ( $domain['domain'] ?? '' ) === $candidate ) {
					return array(
						'id'   => (int) $domain['id'],
						'name' => $candidate,
					);
				}
			}
		}

		throw new \RuntimeException( "Linode: no domain found for {$fqdn}." );
	}

	private function headers(): array {
		return array( 'Authorization' => 'Bearer ' . $this->credential( 'api_token' ) );
	}
}
