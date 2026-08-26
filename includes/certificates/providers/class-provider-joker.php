<?php
/**
 * Joker.com driver (svc.joker.com TXT replace endpoint -- Joker's documented
 * ACME mechanism, using per-zone Dynamic DNS credentials).
 *
 * Enable "Dynamic DNS" for the zone in Joker's DNS editor to obtain the
 * username/password pair; they are valid only for _acme-challenge labels.
 */

declare( strict_types=1 );

namespace WP_SAM\Certificates\Providers;

use WP_SAM\Certificates\Dns_Provider;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Provider_Joker extends Dns_Provider {

	private const API = 'https://svc.joker.com/nic/replace';

	public static function label(): string {
		return 'Joker.com';
	}

	public static function fields(): array {
		return array(
			'zone'     => array(
				'label'       => __( 'Zone (the registered domain)', 'vcns-security-automation-manager' ),
				'secret'      => false,
				'placeholder' => 'example.com',
			),
			'username' => array(
				'label' => __( 'Dynamic DNS username', 'vcns-security-automation-manager' ),
			),
			'password' => array(
				'label' => __( 'Dynamic DNS password', 'vcns-security-automation-manager' ),
			),
		);
	}

	public function create_txt_record( string $fqdn, string $value ): void {
		$this->replace( $fqdn, $value );
	}

	public function delete_txt_record( string $fqdn, string $value ): void {
		// Joker's replace endpoint clears the label when given an empty value.
		$this->replace( $fqdn, '' );
	}

	private function replace( string $fqdn, string $value ): void {
		$zone  = rtrim( trim( $this->credential( 'zone' ) ), '.' );
		$label = $fqdn === $zone ? '_acme-challenge' : $this->relative_name( $fqdn, $zone );

		$body = $this->request_raw(
			'POST',
			self::API,
			array( 'Content-Type' => 'application/x-www-form-urlencoded' ),
			http_build_query(
				array(
					'username' => $this->credential( 'username' ),
					'password' => $this->credential( 'password' ),
					'zone'     => $zone,
					'label'    => $label,
					'type'     => 'TXT',
					'value'    => $value,
				)
			)
		);

		if ( ! str_contains( $body, 'good' ) && ! str_contains( $body, 'OK' ) ) {
			throw new \RuntimeException( 'Joker.com TXT replace failed: ' . substr( trim( $body ), 0, 200 ) ); // phpcs:ignore WordPress.Security.EscapeOutput.ExceptionNotEscaped -- exception message, never echoed as HTML; only logged via Audit_Log/record_run().
		}
	}
}
