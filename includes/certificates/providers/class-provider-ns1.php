<?php
/**
 * NS1 (IBM NS1 Connect) driver (api.nsone.net v1, API key).
 */

declare( strict_types=1 );

namespace WP_SAM\Certificates\Providers;

use WP_SAM\Certificates\Dns_Provider;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Provider_Ns1 extends Dns_Provider {

	private const API = 'https://api.nsone.net/v1';

	public static function label(): string {
		return 'NS1';
	}

	public static function fields(): array {
		return array(
			'api_key' => array(
				'label' => __( 'API key', 'vcns-security-automation-manager' ),
			),
		);
	}

	public function create_txt_record( string $fqdn, string $value ): void {
		$zone = $this->zone( $fqdn );

		// PUT creates the record; ACME challenge names are exclusively ours,
		// so replacing any prior answer set is safe.
		$this->request(
			'PUT',
			self::API . "/zones/{$zone}/{$fqdn}/TXT",
			$this->headers(),
			array(
				'zone'    => $zone,
				'domain'  => $fqdn,
				'type'    => 'TXT',
				'ttl'     => 60,
				'answers' => array( array( 'answer' => array( $value ) ) ),
			)
		);
	}

	public function delete_txt_record( string $fqdn, string $value ): void {
		$zone = $this->zone( $fqdn );

		$this->request( 'DELETE', self::API . "/zones/{$zone}/{$fqdn}/TXT", $this->headers() );
	}

	private function zone( string $fqdn ): string {
		foreach ( $this->zone_candidates( $fqdn ) as $candidate ) {
			try {
				$this->request( 'GET', self::API . '/zones/' . rawurlencode( $candidate ), $this->headers() );
				return $candidate;
			} catch ( \RuntimeException $e ) {
				continue;
			}
		}

		throw new \RuntimeException( "NS1: no zone found for {$fqdn}." );
	}

	private function headers(): array {
		return array( 'X-NSONE-Key' => $this->credential( 'api_key' ) );
	}
}
