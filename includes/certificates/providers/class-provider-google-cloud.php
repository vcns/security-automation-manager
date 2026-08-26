<?php
/**
 * Google Cloud DNS driver (Cloud DNS v1 API, service-account JWT auth).
 *
 * Recommend a dedicated service account holding only the "DNS Administrator"
 * role. Paste the full JSON key file; it is encrypted at rest.
 */

declare( strict_types=1 );

namespace WP_SAM\Certificates\Providers;

use WP_SAM\Certificates\Acme_Crypto;
use WP_SAM\Certificates\Dns_Provider;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Provider_Google_Cloud extends Dns_Provider {

	private const API   = 'https://dns.googleapis.com/dns/v1';
	private const SCOPE = 'https://www.googleapis.com/auth/ndev.clouddns.readwrite';

	private ?string $token = null;

	public static function label(): string {
		return 'Google Cloud DNS';
	}

	public static function fields(): array {
		return array(
			'service_account_json' => array(
				'label'    => __( 'Service account key (paste the full JSON file)', 'vcns-security-automation-manager' ),
				'textarea' => true,
			),
		);
	}

	public function create_txt_record( string $fqdn, string $value ): void {
		$zone = $this->zone( $fqdn );

		$this->request(
			'POST',
			self::API . '/projects/' . rawurlencode( $this->project() ) . '/managedZones/' . rawurlencode( $zone ) . '/changes',
			$this->headers(),
			array(
				'additions' => array(
					array(
						'name'    => $fqdn . '.',
						'type'    => 'TXT',
						'ttl'     => 60,
						'rrdatas' => array( '"' . $value . '"' ),
					),
				),
			)
		);
	}

	public function delete_txt_record( string $fqdn, string $value ): void {
		$zone = $this->zone( $fqdn );

		// Cloud DNS deletions must match the existing rrset exactly.
		$existing = $this->request(
			'GET',
			self::API . '/projects/' . rawurlencode( $this->project() ) . '/managedZones/' . rawurlencode( $zone )
				. '/rrsets?type=TXT&name=' . rawurlencode( $fqdn . '.' ),
			$this->headers()
		);

		foreach ( (array) ( $existing['body']['rrsets'] ?? array() ) as $rrset ) {
			$this->request(
				'POST',
				self::API . '/projects/' . rawurlencode( $this->project() ) . '/managedZones/' . rawurlencode( $zone ) . '/changes',
				$this->headers(),
				array( 'deletions' => array( $rrset ) )
			);
		}
	}

	private function zone( string $fqdn ): string {
		foreach ( $this->zone_candidates( $fqdn ) as $candidate ) {
			$response = $this->request(
				'GET',
				self::API . '/projects/' . rawurlencode( $this->project() ) . '/managedZones?dnsName=' . rawurlencode( $candidate . '.' ),
				$this->headers()
			);
			if ( ! empty( $response['body']['managedZones'][0]['name'] ) ) {
				return (string) $response['body']['managedZones'][0]['name'];
			}
		}

		throw new \RuntimeException( "Google Cloud DNS: no managed zone found for {$fqdn}." ); // phpcs:ignore WordPress.Security.EscapeOutput.ExceptionNotEscaped -- exception message, never echoed as HTML; only logged via Audit_Log/record_run().
	}

	private function key(): array {
		$key = json_decode( $this->credential( 'service_account_json' ), true );
		if ( ! is_array( $key ) || empty( $key['client_email'] ) || empty( $key['private_key'] ) ) {
			throw new \RuntimeException( 'Google Cloud DNS: the service account JSON is missing client_email/private_key.' );
		}

		return $key;
	}

	private function project(): string {
		return (string) ( $this->key()['project_id'] ?? '' );
	}

	private function headers(): array {
		if ( null === $this->token ) {
			$key    = $this->key();
			$now    = time();
			$header = Acme_Crypto::base64url(
				(string) wp_json_encode(
					array(
						'alg' => 'RS256',
						'typ' => 'JWT',
					)
				)
			);
			$claims = Acme_Crypto::base64url(
				(string) wp_json_encode(
					array(
						'iss'   => $key['client_email'],
						'scope' => self::SCOPE,
						'aud'   => 'https://oauth2.googleapis.com/token',
						'iat'   => $now,
						'exp'   => $now + 3600,
					)
				)
			);

			$jwt = $header . '.' . $claims . '.' . Acme_Crypto::base64url( Acme_Crypto::sign( $header . '.' . $claims, (string) $key['private_key'] ) );

			$response = wp_remote_post(
				'https://oauth2.googleapis.com/token',
				array(
					'timeout' => 30,
					'body'    => array(
						'grant_type' => 'urn:ietf:params:oauth:grant-type:jwt-bearer',
						'assertion'  => $jwt,
					),
				)
			);
			if ( is_wp_error( $response ) ) {
				throw new \RuntimeException( 'Google token transport error: ' . $response->get_error_message() ); // phpcs:ignore WordPress.Security.EscapeOutput.ExceptionNotEscaped -- exception message, never echoed as HTML; only logged via Audit_Log/record_run().
			}
			$body        = json_decode( (string) wp_remote_retrieve_body( $response ), true );
			$this->token = (string) ( $body['access_token'] ?? '' );
			if ( '' === $this->token ) {
				throw new \RuntimeException( 'Google token request failed: ' . substr( (string) wp_remote_retrieve_body( $response ), 0, 200 ) ); // phpcs:ignore WordPress.Security.EscapeOutput.ExceptionNotEscaped -- exception message, never echoed as HTML; only logged via Audit_Log/record_run().
			}
		}

		return array( 'Authorization' => 'Bearer ' . $this->token );
	}
}
