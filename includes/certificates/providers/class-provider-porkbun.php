<?php
/**
 * Porkbun DNS driver (api.porkbun.com v3, API key + secret in the body).
 */

declare( strict_types=1 );

namespace WP_SAM\Certificates\Providers;

use WP_SAM\Certificates\Dns_Provider;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Provider_Porkbun extends Dns_Provider {

	private const API = 'https://api.porkbun.com/api/json/v3';

	/**
	 * Returns the display name of the Porkbun provider.
	 *
	 * @return string Provider name.
	 */
	public static function label(): string {
		return 'Porkbun';
	}

	/**
	 * Describes the credentials the Porkbun provider needs.
	 *
	 * @return array Field definitions keyed by field key.
	 */
	public static function fields(): array {
		return array(
			'api_key'    => array(
				'label'       => __( 'API Key', 'vcns-security-automation-manager' ),
				'placeholder' => 'pk1_...',
			),
			'api_secret' => array(
				'label'       => __( 'Secret API Key', 'vcns-security-automation-manager' ),
				'placeholder' => 'sk1_...',
			),
		);
	}

	/**
	 * Adds the ACME challenge TXT record through the Porkbun API.
	 *
	 * @param string $fqdn  Full record name.
	 * @param string $value TXT value.
	 * @return void
	 */
	public function create_txt_record( string $fqdn, string $value ): void {
		$zone = $this->zone( $fqdn );

		$this->request(
			'POST',
			self::API . "/dns/create/{$zone}",
			array(),
			$this->auth(
				array(
					'type'    => 'TXT',
					'name'    => $this->relative_name( $fqdn, $zone ),
					'content' => $value,
					'ttl'     => '600',
				)
			)
		);
	}

	/**
	 * Removes the ACME challenge TXT record through the Porkbun API.
	 *
	 * @param string $fqdn  Full record name.
	 * @param string $value TXT value.
	 * @return void
	 */
	public function delete_txt_record( string $fqdn, string $value ): void {
		$zone     = $this->zone( $fqdn );
		$relative = $this->relative_name( $fqdn, $zone );

		$this->request(
			'POST',
			self::API . "/dns/deleteByNameType/{$zone}/TXT/" . rawurlencode( $relative ),
			array(),
			$this->auth( array() )
		);
	}

	/**
	 * Finds the Porkbun zone that contains a record name.
	 *
	 * @param string $fqdn Full record name.
	 * @return string Zone name or id.
	 * @throws \RuntimeException When the operation fails.
	 */
	private function zone( string $fqdn ): string {
		foreach ( $this->zone_candidates( $fqdn ) as $candidate ) {
			try {
				$this->request( 'POST', self::API . "/dns/retrieve/{$candidate}", array(), $this->auth( array() ) );
				return $candidate;
			} catch ( \RuntimeException $e ) {
				continue;
			}
		}

		throw new \RuntimeException( "Porkbun: no zone found for {$fqdn}." ); // phpcs:ignore WordPress.Security.EscapeOutput.ExceptionNotEscaped -- exception message, never echoed as HTML; only logged via Audit_Log/record_run().
	}

	/**
	 * Adds the API key and secret to a request body.
	 *
	 * @param array $body Request body.
	 * @return array Request body with the credentials.
	 */
	private function auth( array $body ): array {
		return array_merge(
			$body,
			array(
				'apikey'       => $this->credential( 'api_key' ),
				'secretapikey' => $this->credential( 'api_secret' ),
			)
		);
	}
}
