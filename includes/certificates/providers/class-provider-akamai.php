<?php
/**
 * Akamai Edge DNS driver (Config DNS v2 API, EdgeGrid EG1-HMAC-SHA256 auth).
 */

declare( strict_types=1 );

namespace WP_SAM\Certificates\Providers;

use WP_SAM\Certificates\Dns_Provider;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Provider_Akamai extends Dns_Provider {

	/**
	 * Returns the display name of the Akamai Edge DNS provider.
	 *
	 * @return string Provider name.
	 */
	public static function label(): string {
		return 'Akamai Edge DNS';
	}

	/**
	 * Describes the credentials the Akamai Edge DNS provider needs.
	 *
	 * @return array Field definitions keyed by field key.
	 */
	public static function fields(): array {
		return array(
			'host'          => array(
				'label'       => __( 'API host (from the .edgerc credential set)', 'vcns-security-automation-manager' ),
				'secret'      => false,
				'placeholder' => 'akab-xxxx.luna.akamaiapis.net',
			),
			'client_token'  => array(
				'label' => __( 'Client token', 'vcns-security-automation-manager' ),
			),
			'client_secret' => array(
				'label' => __( 'Client secret', 'vcns-security-automation-manager' ),
			),
			'access_token'  => array(
				'label' => __( 'Access token', 'vcns-security-automation-manager' ),
			),
		);
	}

	/**
	 * Adds the ACME challenge TXT record through the Akamai Edge DNS API.
	 *
	 * @param string $fqdn  Full record name.
	 * @param string $value TXT value.
	 * @return void
	 */
	public function create_txt_record( string $fqdn, string $value ): void {
		$zone = $this->zone( $fqdn );

		// PUT upserts the recordset; ACME names are exclusively ours.
		$this->signed(
			'PUT',
			"/config-dns/v2/zones/{$zone}/names/{$fqdn}/types/TXT",
			(string) wp_json_encode(
				array(
					'name'  => $fqdn,
					'type'  => 'TXT',
					'ttl'   => 60,
					'rdata' => array( '"' . $value . '"' ),
				)
			)
		);
	}

	/**
	 * Removes the ACME challenge TXT record through the Akamai Edge DNS API.
	 *
	 * @param string $fqdn  Full record name.
	 * @param string $value TXT value.
	 * @return void
	 */
	public function delete_txt_record( string $fqdn, string $value ): void {
		$zone = $this->zone( $fqdn );

		$this->signed( 'DELETE', "/config-dns/v2/zones/{$zone}/names/{$fqdn}/types/TXT" );
	}

	/**
	 * Finds the Akamai zone that contains a record name.
	 *
	 * @param string $fqdn Full record name.
	 * @return string Zone name.
	 * @throws \RuntimeException When the operation fails.
	 */
	private function zone( string $fqdn ): string {
		foreach ( $this->zone_candidates( $fqdn ) as $candidate ) {
			try {
				$this->signed( 'GET', '/config-dns/v2/zones/' . rawurlencode( $candidate ) );
				return $candidate;
			} catch ( \RuntimeException $e ) {
				continue;
			}
		}

		throw new \RuntimeException( "Akamai Edge DNS: no zone found for {$fqdn}." ); // phpcs:ignore WordPress.Security.EscapeOutput.ExceptionNotEscaped -- exception message, never echoed as HTML; only logged via Audit_Log/record_run().
	}

	/**
	 * Sends an EdgeGrid-signed request to the Akamai API.
	 *
	 * @param string $method HTTP method.
	 * @param string $path   API path.
	 * @param string $body   Request body.
	 * @return string Response body.
	 */
	private function signed( string $method, string $path, string $body = '' ): string {
		$host      = trim( $this->credential( 'host' ) );
		$timestamp = gmdate( 'Ymd\TH:i:sO' ); // EdgeGrid format: 20260817T12:00:00+0000.
		$timestamp = substr( $timestamp, 0, -5 ) . '+0000';
		$nonce     = wp_generate_uuid4();

		$auth_prefix = 'EG1-HMAC-SHA256 '
			. 'client_token=' . $this->credential( 'client_token' ) . ';'
			. 'access_token=' . $this->credential( 'access_token' ) . ';'
			. 'timestamp=' . $timestamp . ';'
			. 'nonce=' . $nonce . ';';

		$body_hash = '' !== $body && 'POST' === $method
			? base64_encode( hash( 'sha256', $body, true ) )
			: ( '' !== $body && 'PUT' === $method ? base64_encode( hash( 'sha256', $body, true ) ) : '' );

		$data_to_sign = implode(
			"\t",
			array( $method, 'https', $host, $path, '', $body_hash, $auth_prefix )
		);

		$signing_key = base64_encode( hash_hmac( 'sha256', $timestamp, $this->credential( 'client_secret' ), true ) );
		$signature   = base64_encode( hash_hmac( 'sha256', $data_to_sign, base64_decode( $signing_key ), true ) );

		return $this->request_raw(
			$method,
			'https://' . $host . $path,
			array(
				'Authorization' => $auth_prefix . 'signature=' . $signature,
				'Content-Type'  => 'application/json',
			),
			'' !== $body ? $body : null
		);
	}
}
