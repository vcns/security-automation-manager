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

	public static function label(): string {
		return 'Gandi (LiveDNS)';
	}

	public static function fields(): array {
		return array(
			'api_token' => array(
				'label'       => __( 'Personal Access Token', 'security-automation-manager' ),
				'placeholder' => 'pat-...',
			),
		);
	}

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

	public function delete_txt_record( string $fqdn, string $value ): void {
		$zone     = $this->zone( $fqdn );
		$relative = $this->relative_name( $fqdn, $zone );

		$this->request(
			'DELETE',
			self::API . "/domains/{$zone}/records/" . rawurlencode( $relative ) . '/TXT',
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

		throw new \RuntimeException( "Gandi: no LiveDNS zone found for {$fqdn}." );
	}

	private function headers(): array {
		return array( 'Authorization' => 'Bearer ' . $this->credential( 'api_token' ) );
	}
}
