<?php
/**
 * Alibaba Cloud DNS (AliDNS) driver (RPC API with HMAC-SHA1 signatures).
 */

declare( strict_types=1 );

namespace WP_SAM\Certificates\Providers;

use WP_SAM\Certificates\Dns_Provider;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Provider_Alidns extends Dns_Provider {

	private const API = 'https://alidns.aliyuncs.com/';

	public static function label(): string {
		return 'Alibaba Cloud DNS';
	}

	public static function fields(): array {
		return array(
			'access_key_id'     => array(
				'label'  => __( 'AccessKey ID', 'vcns-security-automation-manager' ),
				'secret' => false,
			),
			'access_key_secret' => array(
				'label' => __( 'AccessKey Secret', 'vcns-security-automation-manager' ),
			),
		);
	}

	public function create_txt_record( string $fqdn, string $value ): void {
		$zone = $this->zone( $fqdn );

		$this->call(
			'AddDomainRecord',
			array(
				'DomainName' => $zone,
				'RR'         => $this->relative_name( $fqdn, $zone ),
				'Type'       => 'TXT',
				'Value'      => $value,
				'TTL'        => '600', // AliDNS free-tier minimum.
			)
		);
	}

	public function delete_txt_record( string $fqdn, string $value ): void {
		$zone     = $this->zone( $fqdn );
		$relative = $this->relative_name( $fqdn, $zone );
		$list     = $this->call(
			'DescribeDomainRecords',
			array(
				'DomainName'  => $zone,
				'RRKeyWord'   => $relative,
				'TypeKeyWord' => 'TXT',
			)
		);

		foreach ( (array) ( $list['DomainRecords']['Record'] ?? array() ) as $record ) {
			if ( ( $record['RR'] ?? '' ) === $relative && ( $record['Value'] ?? '' ) === $value ) {
				$this->call( 'DeleteDomainRecord', array( 'RecordId' => (string) $record['RecordId'] ) );
			}
		}
	}

	private function zone( string $fqdn ): string {
		$info = $this->call( 'GetMainDomainName', array( 'InputString' => $fqdn ) );
		$zone = (string) ( $info['DomainName'] ?? '' );

		if ( '' === $zone ) {
			throw new \RuntimeException( "Alibaba Cloud DNS: unable to resolve the zone for {$fqdn}." );
		}

		return $zone;
	}

	private function call( string $action, array $params ): array {
		$query = array_merge(
			array(
				'Action'           => $action,
				'Format'           => 'JSON',
				'Version'          => '2015-01-09',
				'AccessKeyId'      => $this->credential( 'access_key_id' ),
				'SignatureMethod'  => 'HMAC-SHA1',
				'SignatureVersion' => '1.0',
				'SignatureNonce'   => bin2hex( random_bytes( 16 ) ),
				'Timestamp'        => gmdate( 'Y-m-d\TH:i:s\Z' ),
			),
			$params
		);

		ksort( $query );
		$canonical = array();
		foreach ( $query as $key => $val ) {
			$canonical[] = $this->percent_encode( (string) $key ) . '=' . $this->percent_encode( (string) $val );
		}
		$string_to_sign     = 'GET&%2F&' . $this->percent_encode( implode( '&', $canonical ) );
		$query['Signature'] = base64_encode( hash_hmac( 'sha1', $string_to_sign, $this->credential( 'access_key_secret' ) . '&', true ) );

		$body    = $this->request_raw( 'GET', self::API . '?' . http_build_query( $query ) );
		$decoded = json_decode( $body, true );

		return is_array( $decoded ) ? $decoded : array();
	}

	private function percent_encode( string $value ): string {
		return str_replace( array( '+', '*', '%7E' ), array( '%20', '%2A', '~' ), rawurlencode( $value ) );
	}
}
