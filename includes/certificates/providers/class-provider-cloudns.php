<?php
/**
 * ClouDNS driver (JSON API, auth-id/sub-auth-id + password).
 */

declare( strict_types=1 );

namespace WP_SAM\Certificates\Providers;

use WP_SAM\Certificates\Dns_Provider;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Provider_Cloudns extends Dns_Provider {

	private const API = 'https://api.cloudns.net/dns';

	public static function label(): string {
		return 'ClouDNS';
	}

	public static function fields(): array {
		return array(
			'auth_id'       => array(
				'label'       => __( 'auth-id (or sub-auth-id, prefixed "sub:")', 'security-automation-manager' ),
				'secret'      => false,
				'placeholder' => '1234 or sub:1234',
			),
			'auth_password' => array(
				'label' => __( 'API password', 'security-automation-manager' ),
			),
		);
	}

	public function create_txt_record( string $fqdn, string $value ): void {
		$zone = $this->zone( $fqdn );

		$body = $this->call(
			'add-record.json',
			array(
				'domain-name' => $zone,
				'record-type' => 'TXT',
				'host'        => $this->relative_name( $fqdn, $zone ),
				'record'      => $value,
				'ttl'         => 60,
			)
		);

		if ( ! str_contains( $body, '"Success"' ) ) {
			throw new \RuntimeException( 'ClouDNS add-record failed: ' . substr( $body, 0, 200 ) );
		}
	}

	public function delete_txt_record( string $fqdn, string $value ): void {
		$zone     = $this->zone( $fqdn );
		$relative = $this->relative_name( $fqdn, $zone );
		$records  = json_decode(
			$this->call(
				'records.json',
				array(
					'domain-name' => $zone,
					'type'        => 'TXT',
					'host'        => $relative,
				)
			),
			true
		);

		foreach ( (array) $records as $id => $record ) {
			if ( is_array( $record ) && ( $record['record'] ?? '' ) === $value ) {
				$this->call(
					'delete-record.json',
					array(
						'domain-name' => $zone,
						'record-id'   => $id,
					)
				);
			}
		}
	}

	private function zone( string $fqdn ): string {
		foreach ( $this->zone_candidates( $fqdn ) as $candidate ) {
			$body = $this->call( 'get-zone-info.json', array( 'domain-name' => $candidate ) );
			if ( str_contains( $body, '"name"' ) && ! str_contains( $body, '"Failed"' ) ) {
				return $candidate;
			}
		}

		throw new \RuntimeException( "ClouDNS: no zone found for {$fqdn}." );
	}

	private function call( string $endpoint, array $params ): string {
		$auth_id = trim( $this->credential( 'auth_id' ) );
		$auth    = str_starts_with( $auth_id, 'sub:' )
			? array( 'sub-auth-id' => substr( $auth_id, 4 ) )
			: array( 'auth-id' => $auth_id );

		$query = http_build_query(
			array_merge( $auth, array( 'auth-password' => $this->credential( 'auth_password' ) ), $params )
		);

		return $this->request_raw( 'GET', self::API . "/{$endpoint}?{$query}" );
	}
}
