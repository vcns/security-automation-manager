<?php
/**
 * easyDNS driver (rest.easydns.net, token + key HTTP Basic).
 */

declare( strict_types=1 );

namespace WP_SAM\Certificates\Providers;

use WP_SAM\Certificates\Dns_Provider;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Provider_Easydns extends Dns_Provider {

	private const API = 'https://rest.easydns.net';

	public static function label(): string {
		return 'easyDNS';
	}

	public static function fields(): array {
		return array(
			'token' => array(
				'label'  => __( 'REST API token', 'vcns-security-automation-manager' ),
				'secret' => false,
			),
			'key'   => array(
				'label' => __( 'REST API key', 'vcns-security-automation-manager' ),
			),
		);
	}

	public function create_txt_record( string $fqdn, string $value ): void {
		$zone = $this->zone( $fqdn );

		$this->request(
			'PUT',
			self::API . "/zones/records/add/{$zone}/TXT?format=json",
			$this->headers(),
			array(
				'host'  => $this->relative_name( $fqdn, $zone ),
				'ttl'   => 60,
				'prio'  => 0,
				'rdata' => $value,
			)
		);
	}

	public function delete_txt_record( string $fqdn, string $value ): void {
		$zone     = $this->zone( $fqdn );
		$relative = $this->relative_name( $fqdn, $zone );
		$list     = $this->request( 'GET', self::API . "/zones/records/all/{$zone}?format=json", $this->headers() );

		foreach ( (array) ( $list['body']['data'] ?? array() ) as $record ) {
			if ( 'TXT' === strtoupper( (string) ( $record['type'] ?? '' ) ) && ( $record['host'] ?? '' ) === $relative && ( $record['rdata'] ?? '' ) === $value ) {
				$this->request( 'DELETE', self::API . "/zones/records/{$zone}/" . $record['id'] . '?format=json', $this->headers() );
			}
		}
	}

	private function zone( string $fqdn ): string {
		foreach ( $this->zone_candidates( $fqdn ) as $candidate ) {
			try {
				$this->request( 'GET', self::API . "/zones/records/all/{$candidate}?format=json", $this->headers() );
				return $candidate;
			} catch ( \RuntimeException $e ) {
				continue;
			}
		}

		throw new \RuntimeException( "easyDNS: no zone found for {$fqdn}." );
	}

	private function headers(): array {
		return array( 'Authorization' => $this->basic_auth( $this->credential( 'token' ), $this->credential( 'key' ) ) );
	}
}
