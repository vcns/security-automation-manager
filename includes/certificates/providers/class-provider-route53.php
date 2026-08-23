<?php
/**
 * AWS Route 53 driver (SigV4-signed XML API, 2013-04-01).
 *
 * Recommend an IAM user/role limited to route53:ChangeResourceRecordSets,
 * route53:ListHostedZonesByName, and route53:GetChange.
 */

declare( strict_types=1 );

namespace WP_SAM\Certificates\Providers;

use WP_SAM\Certificates\Dns_Provider;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Provider_Route53 extends Dns_Provider {

	private const HOST    = 'route53.amazonaws.com';
	private const SERVICE = 'route53';
	private const REGION  = 'us-east-1'; // Route 53 is a global service signed against us-east-1.

	public static function label(): string {
		return 'AWS Route 53';
	}

	public static function fields(): array {
		return array(
			'access_key_id'     => array(
				'label'  => __( 'Access Key ID', 'vcns-security-automation-manager' ),
				'secret' => false,
			),
			'secret_access_key' => array(
				'label' => __( 'Secret Access Key', 'vcns-security-automation-manager' ),
			),
		);
	}

	public function create_txt_record( string $fqdn, string $value ): void {
		$this->change( $fqdn, $value, 'UPSERT' );
	}

	public function delete_txt_record( string $fqdn, string $value ): void {
		$this->change( $fqdn, $value, 'DELETE' );
	}

	private function change( string $fqdn, string $value, string $action ): void {
		$zone_id = $this->zone_id( $fqdn );

		$xml = '<?xml version="1.0" encoding="UTF-8"?>'
			. '<ChangeResourceRecordSetsRequest xmlns="https://route53.amazonaws.com/doc/2013-04-01/"><ChangeBatch><Changes><Change>'
			. '<Action>' . $action . '</Action>'
			. '<ResourceRecordSet>'
			. '<Name>' . esc_html( $fqdn ) . '.</Name>'
			. '<Type>TXT</Type><TTL>60</TTL>'
			. '<ResourceRecords><ResourceRecord><Value>&quot;' . esc_html( $value ) . '&quot;</Value></ResourceRecord></ResourceRecords>'
			. '</ResourceRecordSet>'
			. '</Change></Changes></ChangeBatch></ChangeResourceRecordSetsRequest>';

		$this->signed_request( 'POST', "/2013-04-01/hostedzone/{$zone_id}/rrset/", '', $xml );
	}

	private function zone_id( string $fqdn ): string {
		foreach ( $this->zone_candidates( $fqdn ) as $candidate ) {
			$body = $this->signed_request( 'GET', '/2013-04-01/hostedzonesbyname', 'dnsname=' . rawurlencode( $candidate . '.' ) . '&maxitems=1' );
			if ( preg_match( '#<Name>' . preg_quote( $candidate, '#' ) . '\.</Name>.*?<Id>/hostedzone/([A-Z0-9]+)</Id>#s', $body, $m )
				|| preg_match( '#<Id>/hostedzone/([A-Z0-9]+)</Id>.*?<Name>' . preg_quote( $candidate, '#' ) . '\.</Name>#s', $body, $m ) ) {
				return $m[1];
			}
		}

		throw new \RuntimeException( "Route 53: no hosted zone found for {$fqdn}." );
	}

	/**
	 * Minimal AWS Signature Version 4 over the Route 53 REST API.
	 */
	private function signed_request( string $method, string $path, string $query, string $body = '' ): string {
		$now        = gmdate( 'Ymd\THis\Z' );
		$date       = substr( $now, 0, 8 );
		$body_hash  = hash( 'sha256', $body );
		$headers    = array(
			'host'                 => self::HOST,
			'x-amz-content-sha256' => $body_hash,
			'x-amz-date'           => $now,
		);
		$signed_set = implode( ';', array_keys( $headers ) );

		$canonical = implode(
			"\n",
			array(
				$method,
				$path,
				$query,
				implode( "\n", array_map( static fn( $k, $v ) => "{$k}:{$v}", array_keys( $headers ), $headers ) ) . "\n",
				$signed_set,
				$body_hash,
			)
		);

		$scope          = "{$date}/" . self::REGION . '/' . self::SERVICE . '/aws4_request';
		$string_to_sign = "AWS4-HMAC-SHA256\n{$now}\n{$scope}\n" . hash( 'sha256', $canonical );

		$k_date    = hash_hmac( 'sha256', $date, 'AWS4' . $this->credential( 'secret_access_key' ), true );
		$k_region  = hash_hmac( 'sha256', self::REGION, $k_date, true );
		$k_service = hash_hmac( 'sha256', self::SERVICE, $k_region, true );
		$k_signing = hash_hmac( 'sha256', 'aws4_request', $k_service, true );
		$signature = hash_hmac( 'sha256', $string_to_sign, $k_signing );

		$authorization = 'AWS4-HMAC-SHA256 Credential=' . $this->credential( 'access_key_id' ) . "/{$scope}, SignedHeaders={$signed_set}, Signature={$signature}";

		return $this->request_raw(
			$method,
			'https://' . self::HOST . $path . ( '' !== $query ? "?{$query}" : '' ),
			array(
				'X-Amz-Content-Sha256' => $body_hash,
				'X-Amz-Date'           => $now,
				'Authorization'        => $authorization,
				'Content-Type'         => 'text/xml',
			),
			'' !== $body ? $body : null
		);
	}
}
