<?php
/**
 * Bunny.net DNS driver (api.bunny.net, account API key).
 * TXT records use Bunny's numeric type 3.
 */

declare( strict_types=1 );

namespace WP_SAM\Certificates\Providers;

use WP_SAM\Certificates\Dns_Provider;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Provider_Bunny extends Dns_Provider {

	private const API      = 'https://api.bunny.net';
	private const TYPE_TXT = 3;

	public static function label(): string {
		return 'Bunny.net DNS';
	}

	public static function fields(): array {
		return array(
			'api_key' => array(
				'label' => __( 'Account API key', 'vcns-security-automation-manager' ),
			),
		);
	}

	public function create_txt_record( string $fqdn, string $value ): void {
		$zone = $this->zone( $fqdn );

		$this->request(
			'PUT',
			self::API . "/dnszone/{$zone['id']}/records",
			$this->headers(),
			array(
				'Type'  => self::TYPE_TXT,
				'Name'  => $this->relative_name( $fqdn, $zone['name'] ),
				'Value' => $value,
				'Ttl'   => 60,
			)
		);
	}

	public function delete_txt_record( string $fqdn, string $value ): void {
		$zone     = $this->zone( $fqdn );
		$relative = $this->relative_name( $fqdn, $zone['name'] );
		$detail   = $this->request( 'GET', self::API . '/dnszone/' . $zone['id'], $this->headers() );

		foreach ( (array) ( $detail['body']['Records'] ?? array() ) as $record ) {
			if ( self::TYPE_TXT === (int) ( $record['Type'] ?? -1 ) && ( $record['Name'] ?? '' ) === $relative && ( $record['Value'] ?? '' ) === $value ) {
				$this->request( 'DELETE', self::API . "/dnszone/{$zone['id']}/records/" . $record['Id'], $this->headers() );
			}
		}
	}

	/**
	 * @return array{id:int,name:string}
	 */
	private function zone( string $fqdn ): array {
		foreach ( $this->zone_candidates( $fqdn ) as $candidate ) {
			$list = $this->request( 'GET', self::API . '/dnszone?search=' . rawurlencode( $candidate ), $this->headers() );
			foreach ( (array) ( $list['body']['Items'] ?? array() ) as $zone ) {
				if ( ( $zone['Domain'] ?? '' ) === $candidate ) {
					return array(
						'id'   => (int) $zone['Id'],
						'name' => $candidate,
					);
				}
			}
		}

		throw new \RuntimeException( "Bunny.net: no DNS zone found for {$fqdn}." );
	}

	private function headers(): array {
		return array( 'AccessKey' => $this->credential( 'api_key' ) );
	}
}
