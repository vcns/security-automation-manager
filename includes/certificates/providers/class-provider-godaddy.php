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

	public static function label(): string {
		return 'GoDaddy';
	}

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

	public function delete_txt_record( string $fqdn, string $value ): void {
		$zone     = $this->zone( $fqdn );
		$relative = $this->relative_name( $fqdn, $zone );

		$this->request(
			'DELETE',
			self::API . "/domains/{$zone}/records/TXT/" . rawurlencode( $relative ),
			$this->headers()
		);
	}

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

	private function headers(): array {
		return array(
			'Authorization' => 'sso-key ' . $this->credential( 'api_key' ) . ':' . $this->credential( 'api_secret' ),
		);
	}
}
