<?php
/**
 * OVH driver (application key/secret + consumer key, time-drift-corrected
 * request signatures). Endpoint selectable for EU/CA/US regions.
 */

declare( strict_types=1 );

namespace WP_SAM\Certificates\Providers;

use WP_SAM\Certificates\Dns_Provider;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Provider_Ovh extends Dns_Provider {

	private const ENDPOINTS = array(
		'ovh-eu' => 'https://eu.api.ovh.com/1.0',
		'ovh-ca' => 'https://ca.api.ovh.com/1.0',
		'ovh-us' => 'https://api.us.ovhcloud.com/1.0',
	);

	private ?int $time_delta = null;

	public static function label(): string {
		return 'OVH';
	}

	public static function fields(): array {
		return array(
			'endpoint'           => array(
				'label'       => __( 'Endpoint (ovh-eu, ovh-ca, or ovh-us)', 'vcns-security-automation-manager' ),
				'secret'      => false,
				'placeholder' => 'ovh-eu',
			),
			'application_key'    => array(
				'label' => __( 'Application key', 'vcns-security-automation-manager' ),
			),
			'application_secret' => array(
				'label' => __( 'Application secret', 'vcns-security-automation-manager' ),
			),
			'consumer_key'       => array(
				'label' => __( 'Consumer key', 'vcns-security-automation-manager' ),
			),
		);
	}

	public function create_txt_record( string $fqdn, string $value ): void {
		$zone = $this->zone( $fqdn );

		$this->signed(
			'POST',
			"/domain/zone/{$zone}/record",
			array(
				'fieldType' => 'TXT',
				'subDomain' => $this->relative_name( $fqdn, $zone ),
				'target'    => $value,
				'ttl'       => 60,
			)
		);
		$this->signed( 'POST', "/domain/zone/{$zone}/refresh" );
	}

	public function delete_txt_record( string $fqdn, string $value ): void {
		$zone     = $this->zone( $fqdn );
		$relative = $this->relative_name( $fqdn, $zone );
		$ids      = json_decode( $this->signed( 'GET', "/domain/zone/{$zone}/record?fieldType=TXT&subDomain=" . rawurlencode( $relative ) ), true );

		foreach ( (array) $ids as $id ) {
			$record = json_decode( $this->signed( 'GET', "/domain/zone/{$zone}/record/" . (int) $id ), true );
			if ( is_array( $record ) && ( $record['target'] ?? '' ) === $value ) {
				$this->signed( 'DELETE', "/domain/zone/{$zone}/record/" . (int) $id );
			}
		}
		$this->signed( 'POST', "/domain/zone/{$zone}/refresh" );
	}

	private function zone( string $fqdn ): string {
		$zones = json_decode( $this->signed( 'GET', '/domain/zone' ), true );
		$zones = is_array( $zones ) ? $zones : array();

		foreach ( $this->zone_candidates( $fqdn ) as $candidate ) {
			if ( in_array( $candidate, $zones, true ) ) {
				return $candidate;
			}
		}

		throw new \RuntimeException( "OVH: no zone found for {$fqdn}." ); // phpcs:ignore WordPress.Security.EscapeOutput.ExceptionNotEscaped -- exception message, never echoed as HTML; only logged via Audit_Log/record_run().
	}

	private function endpoint(): string {
		$key = strtolower( trim( $this->credential( 'endpoint' ) ) );

		return self::ENDPOINTS[ $key ] ?? self::ENDPOINTS['ovh-eu'];
	}

	private function signed( string $method, string $path, ?array $body = null ): string {
		$url       = $this->endpoint() . $path;
		$body_json = null === $body ? '' : (string) wp_json_encode( $body );

		if ( null === $this->time_delta ) {
			$remote           = (int) trim( $this->request_raw( 'GET', $this->endpoint() . '/auth/time' ) );
			$this->time_delta = $remote > 0 ? $remote - time() : 0;
		}
		$now = time() + $this->time_delta;

		$signature = '$1$' . sha1(
			implode(
				'+',
				array(
					$this->credential( 'application_secret' ),
					$this->credential( 'consumer_key' ),
					$method,
					$url,
					$body_json,
					$now,
				)
			)
		);

		return $this->request_raw(
			$method,
			$url,
			array(
				'X-Ovh-Application' => $this->credential( 'application_key' ),
				'X-Ovh-Consumer'    => $this->credential( 'consumer_key' ),
				'X-Ovh-Timestamp'   => (string) $now,
				'X-Ovh-Signature'   => $signature,
				'Content-Type'      => 'application/json',
			),
			'' !== $body_json ? $body_json : null
		);
	}
}
