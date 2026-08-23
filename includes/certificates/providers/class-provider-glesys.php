<?php
/**
 * GleSYS driver (api.glesys.com JSON API, account/API-key HTTP Basic).
 */

declare( strict_types=1 );

namespace WP_SAM\Certificates\Providers;

use WP_SAM\Certificates\Dns_Provider;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Provider_Glesys extends Dns_Provider {

	private const API = 'https://api.glesys.com';

	public static function label(): string {
		return 'GleSYS';
	}

	public static function fields(): array {
		return array(
			'account' => array(
				'label'       => __( 'Account number (CL12345)', 'vcns-security-automation-manager' ),
				'secret'      => false,
				'placeholder' => 'CL12345',
			),
			'api_key' => array(
				'label' => __( 'API key', 'vcns-security-automation-manager' ),
			),
		);
	}

	public function create_txt_record( string $fqdn, string $value ): void {
		$zone = $this->zone( $fqdn );

		$this->call(
			'/domain/addrecord',
			array(
				'domainname' => $zone,
				'host'       => $this->relative_name( $fqdn, $zone ),
				'type'       => 'TXT',
				'data'       => $value,
				'ttl'        => 60,
			)
		);
	}

	public function delete_txt_record( string $fqdn, string $value ): void {
		$zone     = $this->zone( $fqdn );
		$relative = $this->relative_name( $fqdn, $zone );
		$list     = $this->call( '/domain/listrecords', array( 'domainname' => $zone ) );

		foreach ( (array) ( $list['response']['records'] ?? array() ) as $record ) {
			if ( 'TXT' === ( $record['type'] ?? '' ) && ( $record['host'] ?? '' ) === $relative && ( $record['data'] ?? '' ) === $value ) {
				$this->call( '/domain/deleterecord', array( 'recordid' => (int) $record['recordid'] ) );
			}
		}
	}

	private function zone( string $fqdn ): string {
		foreach ( $this->zone_candidates( $fqdn ) as $candidate ) {
			try {
				$this->call( '/domain/details', array( 'domainname' => $candidate ) );
				return $candidate;
			} catch ( \RuntimeException $e ) {
				continue;
			}
		}

		throw new \RuntimeException( "GleSYS: no domain found for {$fqdn}." );
	}

	private function call( string $path, array $params ): array {
		$body = $this->request_raw(
			'POST',
			self::API . $path,
			array(
				'Authorization' => $this->basic_auth( $this->credential( 'account' ), $this->credential( 'api_key' ) ),
				'Content-Type'  => 'application/json',
				'Accept'        => 'application/json',
			),
			(string) wp_json_encode( $params )
		);

		$decoded = json_decode( $body, true );

		return is_array( $decoded ) ? $decoded : array();
	}
}
