<?php
/**
 * netcup driver (CCP JSON webservice, customer number + API key/password).
 * updateDnsRecords with deleterecord=true removes entries; the record set
 * is otherwise merged server-side, so no read-modify-write risk.
 */

declare( strict_types=1 );

namespace WP_SAM\Certificates\Providers;

use WP_SAM\Certificates\Dns_Provider;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Provider_Netcup extends Dns_Provider {

	private const API = 'https://ccp.netcup.net/run/webservice/servers/endpoint.php?JSON';

	private ?string $session = null;

	public static function label(): string {
		return 'netcup';
	}

	public static function fields(): array {
		return array(
			'customer_number' => array(
				'label'  => __( 'Customer number', 'vcns-security-automation-manager' ),
				'secret' => false,
			),
			'api_key'         => array(
				'label' => __( 'API key', 'vcns-security-automation-manager' ),
			),
			'api_password'    => array(
				'label' => __( 'API password', 'vcns-security-automation-manager' ),
			),
		);
	}

	public function create_txt_record( string $fqdn, string $value ): void {
		$zone = $this->zone( $fqdn );

		$this->update_records(
			$zone,
			array(
				array(
					'hostname'    => $this->relative_name( $fqdn, $zone ),
					'type'        => 'TXT',
					'destination' => $value,
				),
			)
		);
	}

	public function delete_txt_record( string $fqdn, string $value ): void {
		$zone     = $this->zone( $fqdn );
		$relative = $this->relative_name( $fqdn, $zone );
		$info     = $this->call( 'infoDnsRecords', array( 'domainname' => $zone ) );

		foreach ( (array) ( $info['responsedata']['dnsrecords'] ?? array() ) as $record ) {
			if ( 'TXT' === ( $record['type'] ?? '' ) && ( $record['hostname'] ?? '' ) === $relative && ( $record['destination'] ?? '' ) === $value ) {
				$this->update_records(
					$zone,
					array(
						array(
							'id'           => (string) $record['id'],
							'hostname'     => $relative,
							'type'         => 'TXT',
							'destination'  => $value,
							'deleterecord' => true,
						),
					)
				);
			}
		}
	}

	private function update_records( string $zone, array $records ): void {
		$this->call(
			'updateDnsRecords',
			array(
				'domainname'   => $zone,
				'dnsrecordset' => array( 'dnsrecords' => $records ),
			)
		);
	}

	private function zone( string $fqdn ): string {
		foreach ( $this->zone_candidates( $fqdn ) as $candidate ) {
			try {
				$this->call( 'infoDnsZone', array( 'domainname' => $candidate ) );
				return $candidate;
			} catch ( \RuntimeException $e ) {
				continue;
			}
		}

		throw new \RuntimeException( "netcup: no DNS zone found for {$fqdn}." );
	}

	private function call( string $action, array $params ): array {
		if ( null === $this->session && 'login' !== $action ) {
			$login         = $this->call(
				'login',
				array(
					'apikey'         => $this->credential( 'api_key' ),
					'apipassword'    => $this->credential( 'api_password' ),
					'customernumber' => $this->credential( 'customer_number' ),
				)
			);
			$this->session = (string) ( $login['responsedata']['apisessionid'] ?? '' );
			if ( '' === $this->session ) {
				throw new \RuntimeException( 'netcup login failed.' );
			}
		}

		$request_params = array_merge(
			array(
				'customernumber' => $this->credential( 'customer_number' ),
				'apikey'         => $this->credential( 'api_key' ),
			),
			null !== $this->session && 'login' !== $action ? array( 'apisessionid' => $this->session ) : array(),
			$params
		);

		$body = $this->request_raw(
			'POST',
			self::API,
			array( 'Content-Type' => 'application/json' ),
			(string) wp_json_encode(
				array(
					'action' => $action,
					'param'  => $request_params,
				)
			)
		);

		$decoded = json_decode( $body, true );
		$decoded = is_array( $decoded ) ? $decoded : array();

		if ( 'success' !== strtolower( (string) ( $decoded['status'] ?? '' ) ) ) {
			throw new \RuntimeException( "netcup {$action} failed: " . (string) ( $decoded['longmessage'] ?? $decoded['shortmessage'] ?? 'unknown' ) );
		}

		return $decoded;
	}
}
