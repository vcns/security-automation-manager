<?php
/**
 * INWX driver (JSON-RPC api.domrobot.com, session-cookie auth).
 * Accounts with two-factor login enabled cannot authenticate over the API
 * this way; use a dedicated API sub-account without 2FA.
 */

declare( strict_types=1 );

namespace WP_SAM\Certificates\Providers;

use WP_SAM\Certificates\Dns_Provider;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Provider_Inwx extends Dns_Provider {

	private const API = 'https://api.domrobot.com/jsonrpc/';

	private ?string $cookie = null;

	public static function label(): string {
		return 'INWX';
	}

	public static function fields(): array {
		return array(
			'username' => array(
				'label'  => __( 'Username', 'security-automation-manager' ),
				'secret' => false,
			),
			'password' => array(
				'label' => __( 'Password', 'security-automation-manager' ),
			),
		);
	}

	public function create_txt_record( string $fqdn, string $value ): void {
		$zone = $this->zone( $fqdn );

		$this->rpc(
			'nameserver.createRecord',
			array(
				'domain'  => $zone,
				'name'    => $fqdn,
				'type'    => 'TXT',
				'content' => $value,
				'ttl'     => 300,
			)
		);
	}

	public function delete_txt_record( string $fqdn, string $value ): void {
		$zone = $this->zone( $fqdn );
		$info = $this->rpc(
			'nameserver.info',
			array(
				'domain' => $zone,
				'name'   => $fqdn,
				'type'   => 'TXT',
			)
		);

		foreach ( (array) ( $info['resData']['record'] ?? array() ) as $record ) {
			if ( ( $record['content'] ?? '' ) === $value ) {
				$this->rpc( 'nameserver.deleteRecord', array( 'id' => (int) $record['id'] ) );
			}
		}
	}

	private function zone( string $fqdn ): string {
		foreach ( $this->zone_candidates( $fqdn ) as $candidate ) {
			$info = $this->rpc( 'nameserver.info', array( 'domain' => $candidate ), true );
			if ( 1000 === (int) ( $info['code'] ?? 0 ) ) {
				return $candidate;
			}
		}

		throw new \RuntimeException( "INWX: no zone found for {$fqdn}." );
	}

	private function rpc( string $method, array $params, bool $allow_failure = false ): array {
		if ( null === $this->cookie && 'account.login' !== $method ) {
			$this->login();
		}

		$headers = array( 'Content-Type' => 'application/json' );
		if ( null !== $this->cookie ) {
			$headers['Cookie'] = $this->cookie;
		}

		$response = wp_remote_post(
			self::API,
			array(
				'timeout' => 30,
				'headers' => $headers,
				'body'    => (string) wp_json_encode(
					array(
						'method' => $method,
						'params' => $params,
					)
				),
			)
		);
		if ( is_wp_error( $response ) ) {
			throw new \RuntimeException( 'INWX transport error: ' . $response->get_error_message() );
		}

		$set_cookie = wp_remote_retrieve_header( $response, 'set-cookie' );
		if ( ! empty( $set_cookie ) ) {
			$raw          = is_array( $set_cookie ) ? implode( '; ', $set_cookie ) : (string) $set_cookie;
			$this->cookie = trim( explode( ';', $raw )[0] );
		}

		$body = json_decode( (string) wp_remote_retrieve_body( $response ), true );
		$body = is_array( $body ) ? $body : array();
		$code = (int) ( $body['code'] ?? 0 );

		if ( ! $allow_failure && ( $code < 1000 || $code >= 2000 ) ) {
			throw new \RuntimeException( "INWX {$method} failed (code {$code}): " . (string) ( $body['msg'] ?? 'unknown' ) );
		}

		return $body;
	}

	private function login(): void {
		$this->cookie = ''; // Sentinel so login itself does not recurse.
		$this->rpc(
			'account.login',
			array(
				'user' => $this->credential( 'username' ),
				'pass' => $this->credential( 'password' ),
			)
		);
	}
}
