<?php
/**
 * Njalla driver (njal.la JSON-RPC-style API, token auth).
 */

declare( strict_types=1 );

namespace WP_SAM\Certificates\Providers;

use WP_SAM\Certificates\Dns_Provider;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Provider_Njalla extends Dns_Provider {

	private const API = 'https://njal.la/api/1/';

	public static function label(): string {
		return 'Njalla';
	}

	public static function fields(): array {
		return array(
			'api_token' => array(
				'label' => __( 'API token', 'vcns-security-automation-manager' ),
			),
		);
	}

	public function create_txt_record( string $fqdn, string $value ): void {
		$zone = $this->zone( $fqdn );

		$this->call(
			'add-record',
			array(
				'domain'  => $zone,
				'type'    => 'TXT',
				'name'    => $this->relative_name( $fqdn, $zone ),
				'content' => $value,
				'ttl'     => 60,
			)
		);
	}

	public function delete_txt_record( string $fqdn, string $value ): void {
		$zone     = $this->zone( $fqdn );
		$relative = $this->relative_name( $fqdn, $zone );
		$list     = $this->call( 'list-records', array( 'domain' => $zone ) );

		foreach ( (array) ( $list['records'] ?? array() ) as $record ) {
			if ( 'TXT' === ( $record['type'] ?? '' ) && ( $record['name'] ?? '' ) === $relative && ( $record['content'] ?? '' ) === $value ) {
				$this->call(
					'remove-record',
					array(
						'domain' => $zone,
						'id'     => (int) $record['id'],
					)
				);
			}
		}
	}

	private function zone( string $fqdn ): string {
		$list  = $this->call( 'list-domains', array() );
		$names = array_column( (array) ( $list['domains'] ?? array() ), 'name' );

		foreach ( $this->zone_candidates( $fqdn ) as $candidate ) {
			if ( in_array( $candidate, $names, true ) ) {
				return $candidate;
			}
		}

		throw new \RuntimeException( "Njalla: no domain found for {$fqdn}." );
	}

	private function call( string $method, array $params ): array {
		$body = $this->request_raw(
			'POST',
			self::API,
			array(
				'Authorization' => 'Njalla ' . $this->credential( 'api_token' ),
				'Content-Type'  => 'application/json',
			),
			(string) wp_json_encode(
				array(
					'method' => $method,
					'params' => $params,
				)
			)
		);

		$decoded = json_decode( $body, true );
		$decoded = is_array( $decoded ) ? $decoded : array();

		if ( isset( $decoded['error'] ) ) {
			throw new \RuntimeException( "Njalla {$method} failed: " . (string) wp_json_encode( $decoded['error'] ) );
		}

		return (array) ( $decoded['result'] ?? array() );
	}
}
