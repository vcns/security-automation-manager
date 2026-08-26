<?php
/**
 * Dynu driver (api.dynu.com v2, API key). getroot resolves the zone
 * server-side, which spares the label-walk guesswork.
 */

declare( strict_types=1 );

namespace WP_SAM\Certificates\Providers;

use WP_SAM\Certificates\Dns_Provider;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Provider_Dynu extends Dns_Provider {

	private const API = 'https://api.dynu.com/v2';

	public static function label(): string {
		return 'Dynu';
	}

	public static function fields(): array {
		return array(
			'api_key' => array(
				'label' => __( 'API key', 'vcns-security-automation-manager' ),
			),
		);
	}

	public function create_txt_record( string $fqdn, string $value ): void {
		$zone = $this->zone( $fqdn );

		$this->request(
			'POST',
			self::API . "/dns/{$zone['id']}/record",
			$this->headers(),
			array(
				'nodeName'   => $zone['node'],
				'recordType' => 'TXT',
				'textData'   => $value,
				'state'      => true,
				'ttl'        => 60,
			)
		);
	}

	public function delete_txt_record( string $fqdn, string $value ): void {
		$zone = $this->zone( $fqdn );
		$list = $this->request( 'GET', self::API . "/dns/{$zone['id']}/record", $this->headers() );

		foreach ( (array) ( $list['body']['dnsRecords'] ?? array() ) as $record ) {
			if ( 'TXT' === ( $record['recordType'] ?? '' ) && ( $record['nodeName'] ?? '' ) === $zone['node'] && ( $record['textData'] ?? '' ) === $value ) {
				$this->request( 'DELETE', self::API . "/dns/{$zone['id']}/record/" . $record['id'], $this->headers() );
			}
		}
	}

	/**
	 * @return array{id:int,node:string}
	 */
	private function zone( string $fqdn ): array {
		$root = $this->request( 'GET', self::API . '/dns/getroot/' . rawurlencode( $fqdn ), $this->headers() );

		$id = (int) ( $root['body']['id'] ?? 0 );
		if ( 0 === $id ) {
			throw new \RuntimeException( "Dynu: no root domain found for {$fqdn}." ); // phpcs:ignore WordPress.Security.EscapeOutput.ExceptionNotEscaped -- exception message, never echoed as HTML; only logged via Audit_Log/record_run().
		}

		return array(
			'id'   => $id,
			'node' => (string) ( $root['body']['node'] ?? '' ),
		);
	}

	private function headers(): array {
		return array( 'API-Key' => $this->credential( 'api_key' ) );
	}
}
