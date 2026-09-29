<?php
/**
 * DreamHost driver (api.dreamhost.com key-based API).
 * dns-add_record/dns-remove_record take the full record name, so no zone
 * resolution is required.
 */

declare( strict_types=1 );

namespace WP_SAM\Certificates\Providers;

use WP_SAM\Certificates\Dns_Provider;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Provider_Dreamhost extends Dns_Provider {

	private const API = 'https://api.dreamhost.com/';

	/**
	 * Returns the display name of the DreamHost provider.
	 *
	 * @return string Provider name.
	 */
	public static function label(): string {
		return 'DreamHost';
	}

	/**
	 * Describes the credentials the DreamHost provider needs.
	 *
	 * @return array Field definitions keyed by field key.
	 */
	public static function fields(): array {
		return array(
			'api_key' => array(
				'label' => __( 'API key (with dns-* function access)', 'vcns-security-automation-manager' ),
			),
		);
	}

	/**
	 * Adds the ACME challenge TXT record through the DreamHost API.
	 *
	 * @param string $fqdn  Full record name.
	 * @param string $value TXT value.
	 * @return void
	 */
	public function create_txt_record( string $fqdn, string $value ): void {
		$this->call( 'dns-add_record', $fqdn, $value );
	}

	/**
	 * Removes the ACME challenge TXT record through the DreamHost API.
	 *
	 * @param string $fqdn  Full record name.
	 * @param string $value TXT value.
	 * @return void
	 */
	public function delete_txt_record( string $fqdn, string $value ): void {
		$this->call( 'dns-remove_record', $fqdn, $value );
	}

	/**
	 * Sends a record command to the DreamHost API.
	 *
	 * @param string $cmd   API command.
	 * @param string $fqdn  Full record name.
	 * @param string $value TXT value.
	 * @return void
	 * @throws \RuntimeException When the operation fails.
	 */
	private function call( string $cmd, string $fqdn, string $value ): void {
		$query = http_build_query(
			array(
				'key'    => $this->credential( 'api_key' ),
				'cmd'    => $cmd,
				'format' => 'json',
				'record' => $fqdn,
				'type'   => 'TXT',
				'value'  => $value,
			)
		);

		$body    = $this->request_raw( 'GET', self::API . '?' . $query );
		$decoded = json_decode( $body, true );

		if ( ! is_array( $decoded ) || 'success' !== ( $decoded['result'] ?? '' ) ) {
			$reason = is_array( $decoded ) ? (string) ( $decoded['data'] ?? 'unknown' ) : 'unparseable response';
			// Removing an already-gone record is not a failure worth aborting a renewal for.
			if ( 'dns-remove_record' === $cmd && str_contains( $reason, 'no_such_record' ) ) {
				return;
			}
			throw new \RuntimeException( "DreamHost {$cmd} failed: {$reason}" ); // phpcs:ignore WordPress.Security.EscapeOutput.ExceptionNotEscaped -- exception message, never echoed as HTML; only logged via Audit_Log/record_run().
		}
	}
}
