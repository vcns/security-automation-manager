<?php
/**
 * deSEC driver (desec.io v1 API, token auth).
 */

declare( strict_types=1 );

namespace WP_SAM\Certificates\Providers;

use WP_SAM\Certificates\Dns_Provider;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Provider_Desec extends Dns_Provider {

	private const API = 'https://desec.io/api/v1';

	public static function label(): string {
		return 'deSEC';
	}

	public static function fields(): array {
		return array(
			'api_token' => array(
				'label' => __( 'API token', 'security-automation-manager' ),
			),
		);
	}

	public function create_txt_record( string $fqdn, string $value ): void {
		$zone = $this->zone( $fqdn );

		// PUT replaces this rrset; ACME challenge names are exclusively ours.
		$this->request(
			'PUT',
			self::API . "/domains/{$zone}/rrsets/" . rawurlencode( $this->relative_name( $fqdn, $zone ) ) . '/TXT/',
			$this->headers(),
			array(
				'ttl'     => 3600, // deSEC minimum.
				'records' => array( '"' . $value . '"' ),
			)
		);
	}

	public function delete_txt_record( string $fqdn, string $value ): void {
		$zone = $this->zone( $fqdn );

		$this->request(
			'PUT',
			self::API . "/domains/{$zone}/rrsets/" . rawurlencode( $this->relative_name( $fqdn, $zone ) ) . '/TXT/',
			$this->headers(),
			array(
				'ttl'     => 3600,
				'records' => array(), // Empty record list deletes the rrset.
			)
		);
	}

	private function zone( string $fqdn ): string {
		foreach ( $this->zone_candidates( $fqdn ) as $candidate ) {
			try {
				$this->request( 'GET', self::API . '/domains/' . rawurlencode( $candidate ) . '/', $this->headers() );
				return $candidate;
			} catch ( \RuntimeException $e ) {
				continue;
			}
		}

		throw new \RuntimeException( "deSEC: no domain found for {$fqdn}." );
	}

	private function headers(): array {
		return array( 'Authorization' => 'Token ' . $this->credential( 'api_token' ) );
	}
}
