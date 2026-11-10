<?php
/**
 * GoDaddy DNS driver (api.godaddy.com v1, API key + secret).
 *
 * Note GoDaddy's DELETE removes every TXT record at the name; ACME challenge
 * names (_acme-challenge.*) are exclusively ours, so that is acceptable.
 */

declare( strict_types=1 );

namespace WP_SAM\Certificates\Providers;

use WP_SAM\Certificates\Dns_Provider;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Provider_GoDaddy extends Dns_Provider {

	private const API = 'https://api.godaddy.com/v1';

	/**
	 * Returns the display name of the GoDaddy provider.
	 *
	 * @return string Provider name.
	 */
	public static function label(): string {
		return 'GoDaddy';
	}

	/**
	 * Describes the credentials the GoDaddy provider needs.
	 *
	 * @return array Field definitions keyed by field key.
	 */
	public static function fields(): array {
		return array(
			'api_key'    => array(
				'label' => __( 'API Key', 'vcns-security-automation-manager' ),
			),
			'api_secret' => array(
				'label' => __( 'API Secret', 'vcns-security-automation-manager' ),
			),
		);
	}

	/**
	 * Adds the ACME challenge TXT record through the GoDaddy API.
	 *
	 * @param string $fqdn  Full record name.
	 * @param string $value TXT value.
	 * @return void
	 */
	public function create_txt_record( string $fqdn, string $value ): void {
		$zone     = $this->zone( $fqdn );
		$relative = $this->relative_name( $fqdn, $zone );

		$this->request(
			'PATCH',
			self::API . "/domains/{$zone}/records",
			$this->headers(),
			array(
				array(
					'type' => 'TXT',
					'name' => $relative,
					'data' => $value,
					'ttl'  => 600, // GoDaddy's minimum.
				),
			)
		);
	}

	/**
	 * Removes the ACME challenge TXT record through the GoDaddy API.
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
			self::API . "/domains/{$zone}/records/TXT/" . rawurlencode( $relative ),
			$this->headers()
		);
	}

	/**
	 * Finds the GoDaddy zone that contains a record name.
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

		throw new \RuntimeException( "GoDaddy: no domain found for {$fqdn}." ); // phpcs:ignore WordPress.Security.EscapeOutput.ExceptionNotEscaped -- exception message, never echoed as HTML; only logged via Audit_Log/record_run().
	}

	/**
	 * Builds the GoDaddy request headers, including authentication.
	 *
	 * @return array Header map.
	 */
	private function headers(): array {
		return array(
			'Authorization' => 'sso-key ' . $this->credential( 'api_key' ) . ':' . $this->credential( 'api_secret' ),
		);
	}
}
