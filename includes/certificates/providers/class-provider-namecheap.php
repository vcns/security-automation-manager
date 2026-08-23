<?php
/**
 * Namecheap driver (XML API, key + whitelisted IP).
 *
 * Namecheap's setHosts call REPLACES the entire host list, so this driver
 * does a read-modify-write: fetch every existing host, append/remove the
 * challenge TXT, and write the full set back. If getHosts fails, nothing is
 * ever written -- a partial read must never wipe a zone.
 *
 * Requirements Namecheap imposes: API access enabled on the account and this
 * server's public IP whitelisted (Profile > Tools > API Access).
 */

declare( strict_types=1 );

namespace WP_SAM\Certificates\Providers;

use WP_SAM\Certificates\Dns_Provider;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Provider_Namecheap extends Dns_Provider {

	private const API = 'https://api.namecheap.com/xml.response';

	public static function label(): string {
		return 'Namecheap';
	}

	public static function fields(): array {
		return array(
			'api_user'  => array(
				'label'  => __( 'API user (usually the account username)', 'vcns-security-automation-manager' ),
				'secret' => false,
			),
			'api_key'   => array(
				'label' => __( 'API key', 'vcns-security-automation-manager' ),
			),
			'client_ip' => array(
				'label'       => __( 'This server\'s public IP (must be whitelisted at Namecheap)', 'vcns-security-automation-manager' ),
				'secret'      => false,
				'placeholder' => '203.0.113.10',
			),
		);
	}

	public function create_txt_record( string $fqdn, string $value ): void {
		$this->modify_hosts(
			$fqdn,
			static function ( array $hosts, string $relative ) use ( $value ): array {
				$hosts[] = array(
					'Name'    => $relative,
					'Type'    => 'TXT',
					'Address' => $value,
					'TTL'     => '60',
				);
				return $hosts;
			}
		);
	}

	public function delete_txt_record( string $fqdn, string $value ): void {
		$this->modify_hosts(
			$fqdn,
			static function ( array $hosts, string $relative ) use ( $value ): array {
				return array_values(
					array_filter(
						$hosts,
						static fn( array $h ): bool => ! ( 'TXT' === $h['Type'] && $h['Name'] === $relative && $h['Address'] === $value )
					)
				);
			}
		);
	}

	/**
	 * @param callable(array,string):array $mutate Receives (hosts, relative name), returns new hosts.
	 */
	private function modify_hosts( string $fqdn, callable $mutate ): void {
		$zone = $this->zone( $fqdn );

		$labels = explode( '.', $zone );
		$sld    = array_shift( $labels );
		$tld    = implode( '.', $labels );

		$body = $this->call(
			'namecheap.domains.dns.getHosts',
			array(
				'SLD' => $sld,
				'TLD' => $tld,
			)
		);
		if ( ! str_contains( $body, 'Status="OK"' ) ) {
			throw new \RuntimeException( 'Namecheap getHosts failed; refusing to write (setHosts replaces the whole zone). ' . $this->error_from( $body ) );
		}

		$hosts = array();
		if ( preg_match_all( '#<host\s([^>]+)/?>#i', $body, $matches ) ) {
			foreach ( $matches[1] as $attrs ) {
				$host = array();
				if ( preg_match_all( '#(\w+)="([^"]*)"#', $attrs, $pairs, PREG_SET_ORDER ) ) {
					foreach ( $pairs as $pair ) {
						$host[ $pair[1] ] = html_entity_decode( $pair[2], ENT_QUOTES | ENT_XML1 );
					}
				}
				if ( isset( $host['Name'], $host['Type'], $host['Address'] ) ) {
					$hosts[] = $host;
				}
			}
		}

		$hosts = $mutate( $hosts, $this->relative_name( $fqdn, $zone ) );

		$params = array(
			'SLD' => $sld,
			'TLD' => $tld,
		);
		$index  = 1;
		foreach ( $hosts as $host ) {
			$params[ "HostName{$index}" ]   = $host['Name'];
			$params[ "RecordType{$index}" ] = $host['Type'];
			$params[ "Address{$index}" ]    = $host['Address'];
			$params[ "TTL{$index}" ]        = $host['TTL'] ?? '1800';
			if ( 'MX' === $host['Type'] && isset( $host['MXPref'] ) ) {
				$params[ "MXPref{$index}" ] = $host['MXPref'];
			}
			++$index;
		}

		$result = $this->call( 'namecheap.domains.dns.setHosts', $params, 'POST' );
		if ( ! str_contains( $result, 'IsSuccess="true"' ) ) {
			throw new \RuntimeException( 'Namecheap setHosts failed: ' . $this->error_from( $result ) );
		}
	}

	private function zone( string $fqdn ): string {
		// Namecheap-registered zones are registrable domains (SLD.TLD); pick
		// the candidate that getHosts accepts.
		foreach ( $this->zone_candidates( $fqdn ) as $candidate ) {
			$labels = explode( '.', $candidate );
			if ( count( $labels ) < 2 ) {
				continue;
			}
			$sld  = array_shift( $labels );
			$body = $this->call(
				'namecheap.domains.dns.getHosts',
				array(
					'SLD' => $sld,
					'TLD' => implode( '.', $labels ),
				)
			);
			if ( str_contains( $body, 'Status="OK"' ) ) {
				return $candidate;
			}
		}

		throw new \RuntimeException( "Namecheap: no manageable domain found for {$fqdn}." );
	}

	private function call( string $command, array $params, string $method = 'GET' ): string {
		$query = array_merge(
			array(
				'ApiUser'  => $this->credential( 'api_user' ),
				'ApiKey'   => $this->credential( 'api_key' ),
				'UserName' => $this->credential( 'api_user' ),
				'Command'  => $command,
				'ClientIp' => $this->credential( 'client_ip' ),
			),
			$params
		);

		if ( 'POST' === $method ) {
			return $this->request_raw( 'POST', self::API, array( 'Content-Type' => 'application/x-www-form-urlencoded' ), http_build_query( $query ) );
		}

		return $this->request_raw( 'GET', self::API . '?' . http_build_query( $query ) );
	}

	private function error_from( string $body ): string {
		preg_match( '#<Error[^>]*>([^<]*)</Error>#', $body, $error );

		return $error[1] ?? 'unknown error';
	}
}
