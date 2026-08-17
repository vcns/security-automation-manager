<?php
/**
 * DreamHost driver (api.dreamhost.com key-based API).
 * dns-add_record/dns-remove_record take the full record name, so no zone
 * resolution is required.
 */

declare( strict_types=1 );

namespace WP_SAM\Certificates\Providers;

use WP_SAM\Certificates\Dns_Provider;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Provider_Dreamhost extends Dns_Provider {

	private const API = 'https://api.dreamhost.com/';

	public static function label(): string {
		return 'DreamHost';
	}

	public static function fields(): array {
		return array(
			'api_key' => array(
				'label' => __( 'API key (with dns-* function access)', 'security-automation-manager' ),
			),
		);
	}

	public function create_txt_record( string $fqdn, string $value ): void {
		$this->call( 'dns-add_record', $fqdn, $value );
	}

	public function delete_txt_record( string $fqdn, string $value ): void {
		$this->call( 'dns-remove_record', $fqdn, $value );
	}

	private function call( string $cmd, string $fqdn, string $value ): void {
		$query = http_build_query(
			array(
				'key'    => $this->credential( 'api_key' ),
				'cmd'    => $cmd,
				'format' => 'json',
				'record' => $fqdn,
				'type'   => 'TXT',
				'value'  => $value,
			)
		);

		$body    = $this->request_raw( 'GET', self::API . '?' . $query );
		$decoded = json_decode( $body, true );

		if ( ! is_array( $decoded ) || 'success' !== ( $decoded['result'] ?? '' ) ) {
			$reason = is_array( $decoded ) ? (string) ( $decoded['data'] ?? 'unknown' ) : 'unparseable response';
			// Removing an already-gone record is not a failure worth aborting a renewal for.
			if ( 'dns-remove_record' === $cmd && str_contains( $reason, 'no_such_record' ) ) {
				return;
			}
			throw new \RuntimeException( "DreamHost {$cmd} failed: {$reason}" );
		}
	}
}
