<?php
/**
 * DNSimple driver (api.dnsimple.com v2, account access token).
 */

declare( strict_types=1 );

namespace WP_SAM\Certificates\Providers;

use WP_SAM\Certificates\Dns_Provider;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Provider_Dnsimple extends Dns_Provider {

	private const API = 'https://api.dnsimple.com/v2';

	private ?string $account_id = null;

	public static function label(): string {
		return 'DNSimple';
	}

	public static function fields(): array {
		return array(
			'api_token' => array(
				'label' => __( 'Account access token', 'vcns-security-automation-manager' ),
			),
		);
	}

	public function create_txt_record( string $fqdn, string $value ): void {
		$zone = $this->zone( $fqdn );

		$this->request(
			'POST',
			self::API . '/' . $this->account() . "/zones/{$zone}/records",
			$this->headers(),
			array(
				'name'    => $this->relative_name( $fqdn, $zone ),
				'type'    => 'TXT',
				'content' => $value,
				'ttl'     => 60,
			)
		);
	}

	public function delete_txt_record( string $fqdn, string $value ): void {
		$zone     = $this->zone( $fqdn );
		$relative = $this->relative_name( $fqdn, $zone );
		$list     = $this->request(
			'GET',
			self::API . '/' . $this->account() . "/zones/{$zone}/records?type=TXT&name=" . rawurlencode( $relative ),
			$this->headers()
		);

		foreach ( (array) ( $list['body']['data'] ?? array() ) as $record ) {
			if ( trim( (string) ( $record['content'] ?? '' ), '"' ) === $value ) {
				$this->request( 'DELETE', self::API . '/' . $this->account() . "/zones/{$zone}/records/" . $record['id'], $this->headers() );
			}
		}
	}

	private function account(): string {
		if ( null === $this->account_id ) {
			$who              = $this->request( 'GET', self::API . '/whoami', $this->headers() );
			$this->account_id = (string) ( $who['body']['data']['account']['id'] ?? '' );
			if ( '' === $this->account_id ) {
				throw new \RuntimeException( 'DNSimple: token is not an account token (no account in whoami).' );
			}
		}

		return $this->account_id;
	}

	private function zone( string $fqdn ): string {
		foreach ( $this->zone_candidates( $fqdn ) as $candidate ) {
			try {
				$this->request( 'GET', self::API . '/' . $this->account() . '/zones/' . rawurlencode( $candidate ), $this->headers() );
				return $candidate;
			} catch ( \RuntimeException $e ) {
				continue;
			}
		}

		throw new \RuntimeException( "DNSimple: no zone found for {$fqdn}." ); // phpcs:ignore WordPress.Security.EscapeOutput.ExceptionNotEscaped -- exception message, never echoed as HTML; only logged via Audit_Log/record_run().
	}

	private function headers(): array {
		return array( 'Authorization' => 'Bearer ' . $this->credential( 'api_token' ) );
	}
}
