<?php
/**
 * DNSPod driver (dnsapi.cn, login-token auth). Covers Tencent-managed
 * DNSPod zones (common for .cn and Chinese-hosted domains).
 */

declare( strict_types=1 );

namespace WP_SAM\Certificates\Providers;

use WP_SAM\Certificates\Dns_Provider;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Provider_Dnspod extends Dns_Provider {

	private const API = 'https://dnsapi.cn';

	/**
	 * Returns the display name of the DNSPod provider.
	 *
	 * @return string Provider name.
	 */
	public static function label(): string {
		return 'DNSPod';
	}

	/**
	 * Describes the credentials the DNSPod provider needs.
	 *
	 * @return array Field definitions keyed by field key.
	 */
	public static function fields(): array {
		return array(
			'token_id' => array(
				'label'  => __( 'Token ID', 'vcns-security-automation-manager' ),
				'secret' => false,
			),
			'token'    => array(
				'label' => __( 'Token', 'vcns-security-automation-manager' ),
			),
		);
	}

	/**
	 * Adds the ACME challenge TXT record through the DNSPod API.
	 *
	 * @param string $fqdn  Full record name.
	 * @param string $value TXT value.
	 * @return void
	 * @throws \RuntimeException When the operation fails.
	 */
	public function create_txt_record( string $fqdn, string $value ): void {
		$zone = $this->zone( $fqdn );

		$body = $this->call(
			'Record.Create',
			array(
				'domain'      => $zone,
				'sub_domain'  => $this->relative_name( $fqdn, $zone ),
				'record_type' => 'TXT',
				'record_line' => '默认',
				'value'       => $value,
				'ttl'         => 600,
			)
		);

		if ( '1' !== (string) ( $body['status']['code'] ?? '' ) ) {
			throw new \RuntimeException( 'DNSPod Record.Create failed: ' . (string) ( $body['status']['message'] ?? 'unknown' ) ); // phpcs:ignore WordPress.Security.EscapeOutput.ExceptionNotEscaped -- exception message, never echoed as HTML; only logged via Audit_Log/record_run().
		}
	}

	/**
	 * Removes the ACME challenge TXT record through the DNSPod API.
	 *
	 * @param string $fqdn  Full record name.
	 * @param string $value TXT value.
	 * @return void
	 */
	public function delete_txt_record( string $fqdn, string $value ): void {
		$zone     = $this->zone( $fqdn );
		$relative = $this->relative_name( $fqdn, $zone );
		$list     = $this->call(
			'Record.List',
			array(
				'domain'      => $zone,
				'sub_domain'  => $relative,
				'record_type' => 'TXT',
			)
		);

		foreach ( (array) ( $list['records'] ?? array() ) as $record ) {
			if ( ( $record['value'] ?? '' ) === $value ) {
				$this->call(
					'Record.Remove',
					array(
						'domain'    => $zone,
						'record_id' => (string) $record['id'],
					)
				);
			}
		}
	}

	/**
	 * Finds the DNSPod zone that contains a record name.
	 *
	 * @param string $fqdn Full record name.
	 * @return string Zone name or id.
	 * @throws \RuntimeException When the operation fails.
	 */
	private function zone( string $fqdn ): string {
		foreach ( $this->zone_candidates( $fqdn ) as $candidate ) {
			$body = $this->call( 'Domain.Info', array( 'domain' => $candidate ) );
			if ( '1' === (string) ( $body['status']['code'] ?? '' ) ) {
				return $candidate;
			}
		}

		throw new \RuntimeException( "DNSPod: no domain found for {$fqdn}." ); // phpcs:ignore WordPress.Security.EscapeOutput.ExceptionNotEscaped -- exception message, never echoed as HTML; only logged via Audit_Log/record_run().
	}

	/**
	 * Sends a request to the DNSPod API.
	 *
	 * @param string $action API action name.
	 * @param array  $params Request parameters.
	 * @return array Decoded response.
	 */
	private function call( string $action, array $params ): array {
		$body = $this->request_raw(
			'POST',
			self::API . '/' . $action,
			array( 'Content-Type' => 'application/x-www-form-urlencoded' ),
			http_build_query(
				array_merge(
					array(
						'login_token' => $this->credential( 'token_id' ) . ',' . $this->credential( 'token' ),
						'format'      => 'json',
						'lang'        => 'en',
					),
					$params
				)
			)
		);

		$decoded = json_decode( $body, true );

		return is_array( $decoded ) ? $decoded : array();
	}
}
