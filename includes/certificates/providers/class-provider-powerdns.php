<?php
/**
 * PowerDNS Authoritative Server driver (built-in HTTP API, X-API-Key).
 *
 * Self-hosted: point api_url at the server's API endpoint, e.g.
 * http://127.0.0.1:8081. Covers any infrastructure running PowerDNS.
 */

declare( strict_types=1 );

namespace WP_SAM\Certificates\Providers;

use WP_SAM\Certificates\Dns_Provider;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Provider_Powerdns extends Dns_Provider {

	public static function label(): string {
		return 'PowerDNS (self-hosted)';
	}

	public static function fields(): array {
		return array(
			'api_url'   => array(
				'label'       => __( 'API URL (webserver address of pdns_server)', 'vcns-security-automation-manager' ),
				'secret'      => false,
				'placeholder' => 'http://127.0.0.1:8081',
			),
			'api_key'   => array(
				'label' => __( 'API key (api-key from pdns.conf)', 'vcns-security-automation-manager' ),
			),
			'server_id' => array(
				'label'       => __( 'Server ID (almost always "localhost")', 'vcns-security-automation-manager' ),
				'secret'      => false,
				'placeholder' => 'localhost',
			),
		);
	}

	public function create_txt_record( string $fqdn, string $value ): void {
		$this->patch(
			$fqdn,
			'REPLACE',
			array(
				array(
					'content'  => '"' . $value . '"',
					'disabled' => false,
				),
			)
		);
	}

	public function delete_txt_record( string $fqdn, string $value ): void {
		$this->patch( $fqdn, 'DELETE', array() );
	}

	private function patch( string $fqdn, string $changetype, array $records ): void {
		$zone  = $this->zone( $fqdn );
		$rrset = array(
			'name'       => $fqdn . '.',
			'type'       => 'TXT',
			'changetype' => $changetype,
		);
		if ( 'REPLACE' === $changetype ) {
			$rrset['ttl']     = 60;
			$rrset['records'] = $records;
		}

		$this->request(
			'PATCH',
			$this->base() . '/zones/' . rawurlencode( $zone ),
			$this->headers(),
			array( 'rrsets' => array( $rrset ) )
		);
	}

	private function zone( string $fqdn ): string {
		$list  = $this->request( 'GET', $this->base() . '/zones', $this->headers() );
		$zones = array_map(
			static fn( array $z ): string => rtrim( (string) ( $z['name'] ?? '' ), '.' ),
			(array) ( $list['body'] ?? array() )
		);

		foreach ( $this->zone_candidates( $fqdn ) as $candidate ) {
			if ( in_array( $candidate, $zones, true ) ) {
				return $candidate . '.';
			}
		}

		throw new \RuntimeException( "PowerDNS: no zone found for {$fqdn}." ); // phpcs:ignore WordPress.Security.EscapeOutput.ExceptionNotEscaped -- exception message, never echoed as HTML; only logged via Audit_Log/record_run().
	}

	private function base(): string {
		$server = trim( $this->credential( 'server_id' ) );

		return rtrim( $this->credential( 'api_url' ), '/' ) . '/api/v1/servers/' . rawurlencode( '' !== $server ? $server : 'localhost' );
	}

	private function headers(): array {
		return array( 'X-API-Key' => $this->credential( 'api_key' ) );
	}
}
