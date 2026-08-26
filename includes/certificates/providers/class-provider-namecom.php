<?php
/**
 * Name.com driver (api.name.com v4, username + API token, HTTP Basic).
 */

declare( strict_types=1 );

namespace WP_SAM\Certificates\Providers;

use WP_SAM\Certificates\Dns_Provider;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Provider_Namecom extends Dns_Provider {

	private const API = 'https://api.name.com/v4';

	public static function label(): string {
		return 'Name.com';
	}

	public static function fields(): array {
		return array(
			'username'  => array(
				'label'  => __( 'Account username', 'vcns-security-automation-manager' ),
				'secret' => false,
			),
			'api_token' => array(
				'label' => __( 'API token', 'vcns-security-automation-manager' ),
			),
		);
	}

	public function create_txt_record( string $fqdn, string $value ): void {
		$zone = $this->zone( $fqdn );

		$this->request(
			'POST',
			self::API . "/domains/{$zone}/records",
			$this->headers(),
			array(
				'host'   => $this->relative_name( $fqdn, $zone ),
				'type'   => 'TXT',
				'answer' => $value,
				'ttl'    => 300, // Name.com minimum.
			)
		);
	}

	public function delete_txt_record( string $fqdn, string $value ): void {
		$zone     = $this->zone( $fqdn );
		$relative = $this->relative_name( $fqdn, $zone );
		$list     = $this->request( 'GET', self::API . "/domains/{$zone}/records", $this->headers() );

		foreach ( (array) ( $list['body']['records'] ?? array() ) as $record ) {
			if ( 'TXT' === ( $record['type'] ?? '' ) && ( $record['host'] ?? '' ) === $relative && ( $record['answer'] ?? '' ) === $value ) {
				$this->request( 'DELETE', self::API . "/domains/{$zone}/records/" . $record['id'], $this->headers() );
			}
		}
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

		throw new \RuntimeException( "Name.com: no domain found for {$fqdn}." ); // phpcs:ignore WordPress.Security.EscapeOutput.ExceptionNotEscaped -- exception message, never echoed as HTML; only logged via Audit_Log/record_run().
	}

	private function headers(): array {
		return array( 'Authorization' => $this->basic_auth( $this->credential( 'username' ), $this->credential( 'api_token' ) ) );
	}
}
