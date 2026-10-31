<?php
/**
 * Gandi LiveDNS driver (api.gandi.net v5, personal access token).
 */

declare( strict_types=1 );

namespace WP_SAM\Certificates\Providers;

use WP_SAM\Certificates\Dns_Provider;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Provider_Gandi extends Dns_Provider {

	private const API = 'https://api.gandi.net/v5/livedns';

	/**
	 * Returns the display name of the Gandi (LiveDNS) provider.
	 *
	 * @return string Provider name.
	 */
	public static function label(): string {
		return 'Gandi (LiveDNS)';
	}

	/**
	 * Describes the credentials the Gandi (LiveDNS) provider needs.
	 *
	 * @return array Field definitions keyed by field key.
	 */
	public static function fields(): array {
		return array(
			'api_token' => array(
				'label'       => __( 'Personal Access Token', 'vcns-security-automation-manager' ),
				'placeholder' => 'pat-...',
			),
		);
	}

	/**
	 * Adds the ACME challenge TXT record through the Gandi (LiveDNS) API.
	 *
	 * @param string $fqdn  Full record name.
	 * @param string $value TXT value.
	 * @return void
	 */
	public function create_txt_record( string $fqdn, string $value ): void {
		$zone     = $this->zone( $fqdn );
		$relative = $this->relative_name( $fqdn, $zone );

		// PUT replaces the rrset; ACME challenge names are exclusively ours, so
		// replacement semantics are safe here.
		$this->request(
			'PUT',
			self::API . "/domains/{$zone}/records/" . rawurlencode( $relative ) . '/TXT',
			$this->headers(),
			array(
				'rrset_ttl'    => 300,
				'rrset_values' => array( '"' . $value . '"' ),
			)
		);
	}

	/**
	 * Removes the ACME challenge TXT record through the Gandi (LiveDNS) API.
	 *
	 * @param string $fqdn  Full record name.
	 * @param string $value TXT value.
	 * @return void
	 */
	public function delete_txt_record( string $fqdn, string $value ): void {
		$zone     = $this->zone( $fqdn );
		$relative = $this->relative_name( $fqdn, $zone );

		$this->request(
			'DELETE',
			self::API . "/domains/{$zone}/records/" . rawurlencode( $relative ) . '/TXT',
			$this->headers()
		);
	}

	/**
	 * Finds the Gandi (LiveDNS) zone that contains a record name.
	 *
	 * @param string $fqdn Full record name.
	 * @return string Zone name or id.
	 * @throws \RuntimeException When the operation fails.
	 */
	private function zone( string $fqdn ): string {
		foreach ( $this->zone_candidates( $fqdn ) as $candidate ) {
			try {
				$this->request( 'GET', self::API . '/domains/' . rawurlencode( $candidate ), $this->headers() );
				return $candidate;
			} catch ( \RuntimeException $e ) {
				continue;
			}
		}

		throw new \RuntimeException( "Gandi: no LiveDNS zone found for {$fqdn}." ); // phpcs:ignore WordPress.Security.EscapeOutput.ExceptionNotEscaped -- exception message, never echoed as HTML; only logged via Audit_Log/record_run().
	}

	/**
	 * Builds the Gandi (LiveDNS) request headers, including authentication.
	 *
	 * @return array Header map.
	 */
	private function headers(): array {
		return array( 'Authorization' => 'Bearer ' . $this->credential( 'api_token' ) );
	}
}
