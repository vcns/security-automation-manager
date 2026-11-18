<?php
/**
 * NameSilo driver (XML API v1, API key).
 */

declare( strict_types=1 );

namespace WP_SAM\Certificates\Providers;

use WP_SAM\Certificates\Dns_Provider;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Provider_Namesilo extends Dns_Provider {

	private const API = 'https://www.namesilo.com/api';

	/**
	 * Returns the display name of the NameSilo provider.
	 *
	 * @return string Provider name.
	 */
	public static function label(): string {
		return 'NameSilo';
	}

	/**
	 * Describes the credentials the NameSilo provider needs.
	 *
	 * @return array Field definitions keyed by field key.
	 */
	public static function fields(): array {
		return array(
			'api_key' => array(
				'label' => __( 'API Key', 'vcns-security-automation-manager' ),
			),
		);
	}

	/**
	 * Adds the ACME challenge TXT record through the NameSilo API.
	 *
	 * @param string $fqdn  Full record name.
	 * @param string $value TXT value.
	 * @return void
	 */
	public function create_txt_record( string $fqdn, string $value ): void {
		$zone = $this->zone( $fqdn );

		$body = $this->call(
			'dnsAddRecord',
			array(
				'domain'  => $zone,
				'rrtype'  => 'TXT',
				'rrhost'  => $this->relative_name( $fqdn, $zone ),
				'rrvalue' => $value,
				'rrttl'   => '3600', // NameSilo minimum.
			)
		);

		$this->assert_success( $body, 'dnsAddRecord' );
	}

	/**
	 * Removes the ACME challenge TXT record through the NameSilo API.
	 *
	 * @param string $fqdn  Full record name.
	 * @param string $value TXT value.
	 * @return void
	 */
	public function delete_txt_record( string $fqdn, string $value ): void {
		$zone = $this->zone( $fqdn );
		$list = $this->call( 'dnsListRecords', array( 'domain' => $zone ) );

		if ( preg_match_all( '#<resource_record>.*?</resource_record>#s', $list, $records ) ) {
			foreach ( $records[0] as $record ) {
				if ( str_contains( $record, '<type>TXT</type>' )
					&& str_contains( $record, '<host>' . $fqdn . '</host>' )
					&& str_contains( $record, '<value>' . $value . '</value>' )
					&& preg_match( '#<record_id>([^<]+)</record_id>#', $record, $id ) ) {
					$this->call(
						'dnsDeleteRecord',
						array(
							'domain' => $zone,
							'rrid'   => $id[1],
						)
					);
				}
			}
		}
	}

	/**
	 * Finds the NameSilo zone that contains a record name.
	 *
	 * @param string $fqdn Full record name.
	 * @return string Zone name or id.
	 * @throws \RuntimeException When the operation fails.
	 */
	private function zone( string $fqdn ): string {
		foreach ( $this->zone_candidates( $fqdn ) as $candidate ) {
			$body = $this->call( 'getDomainInfo', array( 'domain' => $candidate ) );
			if ( str_contains( $body, '<code>300</code>' ) ) {
				return $candidate;
			}
		}

		throw new \RuntimeException( "NameSilo: no domain found for {$fqdn}." ); // phpcs:ignore WordPress.Security.EscapeOutput.ExceptionNotEscaped -- exception message, never echoed as HTML; only logged via Audit_Log/record_run().
	}

	/**
	 * Sends a request to the NameSilo API.
	 *
	 * @param string $operation API operation name.
	 * @param array  $params    Operation parameters.
	 * @return string Response body.
	 */
	private function call( string $operation, array $params ): string {
		$query = http_build_query(
			array_merge(
				array(
					'version' => '1',
					'type'    => 'xml',
					'key'     => $this->credential( 'api_key' ),
				),
				$params
			)
		);

		return $this->request_raw( 'GET', self::API . "/{$operation}?{$query}" );
	}

	/**
	 * Throws when a NameSilo response does not report success.
	 *
	 * @param string $body      Response body.
	 * @param string $operation API operation name.
	 * @return void
	 * @throws \RuntimeException When the operation fails.
	 */
	private function assert_success( string $body, string $operation ): void {
		if ( ! str_contains( $body, '<code>300</code>' ) ) {
			preg_match( '#<detail>([^<]*)</detail>#', $body, $detail );
			throw new \RuntimeException( "NameSilo {$operation} failed: " . ( $detail[1] ?? 'unknown error' ) ); // phpcs:ignore WordPress.Security.EscapeOutput.ExceptionNotEscaped -- exception message, never echoed as HTML; only logged via Audit_Log/record_run().
		}
	}
}
