<?php
/**
 * acme-dns driver (github.com/joohoi/acme-dns) -- the universal answer for
 * providers without an API.
 *
 * One-time setup: register against an acme-dns server (self-hosted or a
 * trusted instance), then create a single CNAME at your real provider:
 *
 *   _acme-challenge.example.com  CNAME  <fulldomain from registration>
 *
 * From then on every challenge is fulfilled via the acme-dns API and the
 * real DNS provider never needs API access at all. Works with any provider
 * on the planet, which is why it ships as a first-class driver here.
 */

declare( strict_types=1 );

namespace WP_SAM\Certificates\Providers;

use WP_SAM\Certificates\Dns_Provider;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Provider_Acmedns extends Dns_Provider {

	public static function label(): string {
		return 'acme-dns (works with any provider via CNAME delegation)';
	}

	public static function fields(): array {
		return array(
			'server_url' => array(
				'label'       => __( 'acme-dns server URL', 'vcns-security-automation-manager' ),
				'secret'      => false,
				'placeholder' => 'https://auth.acme-dns.io',
			),
			'username'   => array(
				'label' => __( 'Username (from /register)', 'vcns-security-automation-manager' ),
			),
			'password'   => array(
				'label' => __( 'Password (from /register)', 'vcns-security-automation-manager' ),
			),
			'subdomain'  => array(
				'label'       => __( 'Subdomain (from /register)', 'vcns-security-automation-manager' ),
				'secret'      => false,
				'placeholder' => 'd420c923-bbd7-4056-ab64-c3ca54c9b3cf',
			),
		);
	}

	public function create_txt_record( string $fqdn, string $value ): void {
		$body = $this->request_raw(
			'POST',
			rtrim( $this->credential( 'server_url' ), '/' ) . '/update',
			array(
				'X-Api-User'   => $this->credential( 'username' ),
				'X-Api-Key'    => $this->credential( 'password' ),
				'Content-Type' => 'application/json',
			),
			(string) wp_json_encode(
				array(
					'subdomain' => $this->credential( 'subdomain' ),
					'txt'       => $value,
				)
			)
		);

		$decoded = json_decode( $body, true );
		if ( ! is_array( $decoded ) || ( $decoded['txt'] ?? '' ) !== $value ) {
			throw new \RuntimeException( 'acme-dns update failed: ' . substr( $body, 0, 200 ) );
		}
	}

	public function delete_txt_record( string $fqdn, string $value ): void {
		// acme-dns keeps a rolling window of the last two TXT values and has
		// no delete endpoint; old values age out on the next update.
	}
}
