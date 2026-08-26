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

	public static function label(): string {
		return 'NameSilo';
	}

	public static function fields(): array {
		return array(
			'api_key' => array(
				'label' => __( 'API Key', 'vcns-security-automation-manager' ),
			),
		);
	}

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

	private function zone( string $fqdn ): string {
		foreach ( $this->zone_candidates( $fqdn ) as $candidate ) {
			$body = $this->call( 'getDomainInfo', array( 'domain' => $candidate ) );
			if ( str_contains( $body, '<code>300</code>' ) ) {
				return $candidate;
			}
		}

		throw new \RuntimeException( "NameSilo: no domain found for {$fqdn}." ); // phpcs:ignore WordPress.Security.EscapeOutput.ExceptionNotEscaped -- exception message, never echoed as HTML; only logged via Audit_Log/record_run().
	}

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

	private function assert_success( string $body, string $operation ): void {
		if ( ! str_contains( $body, '<code>300</code>' ) ) {
			preg_match( '#<detail>([^<]*)</detail>#', $body, $detail );
			throw new \RuntimeException( "NameSilo {$operation} failed: " . ( $detail[1] ?? 'unknown error' ) ); // phpcs:ignore WordPress.Security.EscapeOutput.ExceptionNotEscaped -- exception message, never echoed as HTML; only logged via Audit_Log/record_run().
		}
	}
}
