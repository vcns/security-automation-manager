<?php
/**
 * GleSYS driver (api.glesys.com JSON API, account/API-key HTTP Basic).
 */

declare( strict_types=1 );

namespace WP_SAM\Certificates\Providers;

use WP_SAM\Certificates\Dns_Provider;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Provider_Glesys extends Dns_Provider {

	private const API = 'https://api.glesys.com';

	/**
	 * Returns the display name of the GleSYS provider.
	 *
	 * @return string Provider name.
	 */
	public static function label(): string {
		return 'GleSYS';
	}

	/**
	 * Describes the credentials the GleSYS provider needs.
	 *
	 * @return array Field definitions keyed by field key.
	 */
	public static function fields(): array {
		return array(
			'account' => array(
				'label'       => __( 'Account number (CL12345)', 'vcns-security-automation-manager' ),
				'secret'      => false,
				'placeholder' => 'CL12345',
			),
			'api_key' => array(
				'label' => __( 'API key', 'vcns-security-automation-manager' ),
			),
		);
	}

	/**
	 * Adds the ACME challenge TXT record through the GleSYS API.
	 *
	 * @param string $fqdn  Full record name.
	 * @param string $value TXT value.
	 * @return void
	 */
	public function create_txt_record( string $fqdn, string $value ): void {
		$zone = $this->zone( $fqdn );

		$this->call(
			'/domain/addrecord',
			array(
				'domainname' => $zone,
				'host'       => $this->relative_name( $fqdn, $zone ),
				'type'       => 'TXT',
				'data'       => $value,
				'ttl'        => 60,
			)
		);
	}

	/**
	 * Removes the ACME challenge TXT record through the GleSYS API.
	 *
	 * @param string $fqdn  Full record name.
	 * @param string $value TXT value.
	 * @return void
	 */
	public function delete_txt_record( string $fqdn, string $value ): void {
		$zone     = $this->zone( $fqdn );
		$relative = $this->relative_name( $fqdn, $zone );
		$list     = $this->call( '/domain/listrecords', array( 'domainname' => $zone ) );

		foreach ( (array) ( $list['response']['records'] ?? array() ) as $record ) {
			if ( 'TXT' === ( $record['type'] ?? '' ) && ( $record['host'] ?? '' ) === $relative && ( $record['data'] ?? '' ) === $value ) {
				$this->call( '/domain/deleterecord', array( 'recordid' => (int) $record['recordid'] ) );
			}
		}
	}

	/**
	 * Finds the GleSYS zone that contains a record name.
	 *
	 * @param string $fqdn Full record name.
	 * @return string Zone name or id.
	 * @throws \RuntimeException When the operation fails.
	 */
	private function zone( string $fqdn ): string {
		foreach ( $this->zone_candidates( $fqdn ) as $candidate ) {
			try {
				$this->call( '/domain/details', array( 'domainname' => $candidate ) );
				return $candidate;
			} catch ( \RuntimeException $e ) {
				continue;
			}
		}

		throw new \RuntimeException( "GleSYS: no domain found for {$fqdn}." ); // phpcs:ignore WordPress.Security.EscapeOutput.ExceptionNotEscaped -- exception message, never echoed as HTML; only logged via Audit_Log/record_run().
	}

	/**
	 * Sends a request to the GleSYS API.
	 *
	 * @param string $path   API path.
	 * @param array  $params Request parameters.
	 * @return array Decoded response.
	 */
	private function call( string $path, array $params ): array {
		$body = $this->request_raw(
			'POST',
			self::API . $path,
			array(
				'Authorization' => $this->basic_auth( $this->credential( 'account' ), $this->credential( 'api_key' ) ),
				'Content-Type'  => 'application/json',
				'Accept'        => 'application/json',
			),
			(string) wp_json_encode( $params )
		);

		$decoded = json_decode( $body, true );

		return is_array( $decoded ) ? $decoded : array();
	}
}
