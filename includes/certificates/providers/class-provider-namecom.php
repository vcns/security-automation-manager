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

	/**
	 * Returns the display name of the Name.com provider.
	 *
	 * @return string Provider name.
	 */
	public static function label(): string {
		return 'Name.com';
	}

	/**
	 * Describes the credentials the Name.com provider needs.
	 *
	 * @return array Field definitions keyed by field key.
	 */
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

	/**
	 * Adds the ACME challenge TXT record through the Name.com API.
	 *
	 * @param string $fqdn  Full record name.
	 * @param string $value TXT value.
	 * @return void
	 */
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

	/**
	 * Removes the ACME challenge TXT record through the Name.com API.
	 *
	 * @param string $fqdn  Full record name.
	 * @param string $value TXT value.
	 * @return void
	 */
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

	/**
	 * Finds the Name.com zone that contains a record name.
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

		throw new \RuntimeException( "Name.com: no domain found for {$fqdn}." ); // phpcs:ignore WordPress.Security.EscapeOutput.ExceptionNotEscaped -- exception message, never echoed as HTML; only logged via Audit_Log/record_run().
	}

	/**
	 * Builds the Name.com request headers, including authentication.
	 *
	 * @return array Header map.
	 */
	private function headers(): array {
		return array( 'Authorization' => $this->basic_auth( $this->credential( 'username' ), $this->credential( 'api_token' ) ) );
	}
}
