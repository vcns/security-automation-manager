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

	/**
	 * Returns the display name of the INWX provider.
	 *
	 * @return string Provider name.
	 */
	public static function label(): string {
		return 'INWX';
	}

	/**
	 * Describes the credentials the INWX provider needs.
	 *
	 * @return array Field definitions keyed by field key.
	 */
	public static function fields(): array {
		return array(
			'username' => array(
				'label'  => __( 'Username', 'vcns-security-automation-manager' ),
				'secret' => false,
			),
			'password' => array(
				'label' => __( 'Password', 'vcns-security-automation-manager' ),
			),
		);
	}

	/**
	 * Adds the ACME challenge TXT record through the INWX API.
	 *
	 * @param string $fqdn  Full record name.
	 * @param string $value TXT value.
	 * @return void
	 */
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

	/**
	 * Removes the ACME challenge TXT record through the INWX API.
	 *
	 * @param string $fqdn  Full record name.
	 * @param string $value TXT value.
	 * @return void
	 */
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

	/**
	 * Finds the INWX zone that contains a record name.
	 *
	 * @param string $fqdn Full record name.
	 * @return string Zone name or id.
	 * @throws \RuntimeException When the operation fails.
	 */
	private function zone( string $fqdn ): string {
		foreach ( $this->zone_candidates( $fqdn ) as $candidate ) {
			$info = $this->rpc( 'nameserver.info', array( 'domain' => $candidate ), true );
			if ( 1000 === (int) ( $info['code'] ?? 0 ) ) {
				return $candidate;
			}
		}

		throw new \RuntimeException( "INWX: no zone found for {$fqdn}." ); // phpcs:ignore WordPress.Security.EscapeOutput.ExceptionNotEscaped -- exception message, never echoed as HTML; only logged via Audit_Log/record_run().
	}

	/**
	 * Calls a method of the INWX XML-RPC API, logging in first when needed.
	 *
	 * @param string $method        API method name.
	 * @param array  $params        Method parameters.
	 * @param bool   $allow_failure Whether a failed call is returned instead of throwing an exception.
	 * @return array Decoded response.
	 * @throws \RuntimeException When the operation fails.
	 */
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
			throw new \RuntimeException( 'INWX transport error: ' . $response->get_error_message() ); // phpcs:ignore WordPress.Security.EscapeOutput.ExceptionNotEscaped -- exception message, never echoed as HTML; only logged via Audit_Log/record_run().
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
			throw new \RuntimeException( "INWX {$method} failed (code {$code}): " . (string) ( $body['msg'] ?? 'unknown' ) ); // phpcs:ignore WordPress.Security.EscapeOutput.ExceptionNotEscaped -- exception message, never echoed as HTML; only logged via Audit_Log/record_run().
		}

		return $body;
	}

	/**
	 * Logs in to the INWX API and keeps the session cookie.
	 *
	 * @return void
	 */
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
