<?php
/**
 * Minimal ACME v2 (RFC 8555) client over wp_remote_*.
 *
 * Speaks to Let's Encrypt (or any RFC 8555 directory) entirely from PHP:
 * directory discovery, nonce handling, JWS-signed requests (ES256/RS256),
 * account registration, order lifecycle, challenge responses, finalize, and
 * certificate download. No shell-outs, no daemons -- deliberately compatible
 * with shared hosting.
 *
 * Note ACME v1 is not implemented and never will be: Let's Encrypt switched
 * its v1 endpoints off in June 2021. The "HTTP fallback" lives inside v2 as
 * the http-01 challenge type (see Challenge_Http).
 */

declare( strict_types=1 );

namespace WP_SAM\Certificates;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Acme_Client {

	public const DIRECTORY_PRODUCTION = 'https://acme-v02.api.letsencrypt.org/directory';
	public const DIRECTORY_STAGING    = 'https://acme-staging-v02.api.letsencrypt.org/directory';

	private string $directory_url;
	private string $account_key_pem;
	private ?array $directory = null;
	private ?string $nonce    = null;

	/** Account URL ("kid") once registered/looked-up. */
	private ?string $kid = null;

	public function __construct( string $directory_url, string $account_key_pem ) {
		$this->directory_url   = $directory_url;
		$this->account_key_pem = $account_key_pem;
	}

	// ── Account ───────────────────────────────────────────────────────────────

	/**
	 * Registers (or retrieves) the ACME account for the current key.
	 *
	 * @param string $contact_email Optional contact for expiry mails from the CA.
	 * @return string The account URL (JWS "kid" for subsequent requests).
	 */
	public function register_account( string $contact_email = '' ): string {
		$payload = array( 'termsOfServiceAgreed' => true );
		if ( '' !== $contact_email ) {
			$payload['contact'] = array( 'mailto:' . $contact_email );
		}

		$response = $this->signed_request( $this->dir( 'newAccount' ), $payload, false );
		$status   = (int) wp_remote_retrieve_response_code( $response );
		if ( ! in_array( $status, array( 200, 201 ), true ) ) {
			throw new \RuntimeException( 'ACME account registration failed: ' . $this->error_detail( $response ) );
		}

		$this->kid = (string) wp_remote_retrieve_header( $response, 'location' );
		if ( '' === $this->kid ) {
			throw new \RuntimeException( 'ACME newAccount response had no Location header.' );
		}

		return $this->kid;
	}

	public function set_kid( string $kid ): void {
		$this->kid = $kid;
	}

	public function thumbprint(): string {
		return Acme_Crypto::thumbprint( Acme_Crypto::jwk( $this->account_key_pem ) );
	}

	// ── Order lifecycle ───────────────────────────────────────────────────────

	/**
	 * Creates a new order for the given domains.
	 *
	 * @return array{url:string, body:array} Order URL and decoded body.
	 */
	public function new_order( array $domains ): array {
		$identifiers = array_map(
			static fn( string $d ): array => array(
				'type'  => 'dns',
				'value' => $d,
			),
			array_values( $domains )
		);

		$response = $this->signed_request( $this->dir( 'newOrder' ), array( 'identifiers' => $identifiers ) );
		$status   = (int) wp_remote_retrieve_response_code( $response );
		if ( 201 !== $status ) {
			throw new \RuntimeException( 'ACME newOrder failed: ' . $this->error_detail( $response ) );
		}

		return array(
			'url'  => (string) wp_remote_retrieve_header( $response, 'location' ),
			'body' => $this->json( $response ),
		);
	}

	/**
	 * POST-as-GET fetch of any ACME resource (order, authorization, challenge).
	 */
	public function fetch( string $url ): array {
		$response = $this->signed_request( $url, null );
		$status   = (int) wp_remote_retrieve_response_code( $response );
		if ( $status >= 400 ) {
			throw new \RuntimeException( 'ACME fetch failed for ' . $url . ': ' . $this->error_detail( $response ) );
		}

		return $this->json( $response );
	}

	/**
	 * Tells the CA a challenge is ready to be validated.
	 */
	public function respond_challenge( string $challenge_url ): array {
		$response = $this->signed_request( $challenge_url, new \stdClass() );
		$status   = (int) wp_remote_retrieve_response_code( $response );
		if ( $status >= 400 ) {
			throw new \RuntimeException( 'ACME challenge response failed: ' . $this->error_detail( $response ) );
		}

		return $this->json( $response );
	}

	/**
	 * Submits the CSR for a ready order.
	 */
	public function finalize( string $finalize_url, string $csr_der ): array {
		$response = $this->signed_request(
			$finalize_url,
			array( 'csr' => Acme_Crypto::base64url( $csr_der ) )
		);
		$status   = (int) wp_remote_retrieve_response_code( $response );
		if ( $status >= 400 ) {
			throw new \RuntimeException( 'ACME finalize failed: ' . $this->error_detail( $response ) );
		}

		return $this->json( $response );
	}

	/**
	 * Downloads the issued certificate chain (PEM).
	 */
	public function download_certificate( string $certificate_url ): string {
		$response = $this->signed_request( $certificate_url, null );
		$status   = (int) wp_remote_retrieve_response_code( $response );
		if ( 200 !== $status ) {
			throw new \RuntimeException( 'ACME certificate download failed: ' . $this->error_detail( $response ) );
		}

		return (string) wp_remote_retrieve_body( $response );
	}

	// ── JWS transport ─────────────────────────────────────────────────────────

	/**
	 * Performs a JWS-signed POST (or POST-as-GET when $payload is null).
	 *
	 * @param string            $url     Target URL.
	 * @param array|object|null $payload null = POST-as-GET (empty payload string).
	 * @param bool              $use_kid false only for newAccount, which must embed the full JWK.
	 * @return array wp_remote_post() response array.
	 */
	public function signed_request( string $url, $payload, bool $use_kid = true ): array {
		$attempt = 0;
		do {
			$protected = array(
				'alg'   => Acme_Crypto::alg( $this->account_key_pem ),
				'nonce' => $this->take_nonce(),
				'url'   => $url,
			);
			if ( $use_kid && null !== $this->kid ) {
				$protected['kid'] = $this->kid;
			} else {
				$protected['jwk'] = Acme_Crypto::jwk( $this->account_key_pem );
			}

			$protected_b64 = Acme_Crypto::base64url( (string) wp_json_encode( $protected ) );
			$payload_b64   = null === $payload ? '' : Acme_Crypto::base64url( (string) wp_json_encode( $payload ) );
			$signature     = Acme_Crypto::sign( $protected_b64 . '.' . $payload_b64, $this->account_key_pem );

			$response = wp_remote_post(
				$url,
				array(
					'timeout' => 30,
					'headers' => array( 'Content-Type' => 'application/jose+json' ),
					'body'    => (string) wp_json_encode(
						array(
							'protected' => $protected_b64,
							'payload'   => $payload_b64,
							'signature' => Acme_Crypto::base64url( $signature ),
						)
					),
				)
			);

			if ( is_wp_error( $response ) ) {
				throw new \RuntimeException( 'ACME request transport error: ' . $response->get_error_message() );
			}

			$this->store_nonce( $response );

			// RFC 8555 §6.5: a badNonce rejection must be retried with the fresh
			// nonce the error response itself carries.
			$is_bad_nonce = 400 === (int) wp_remote_retrieve_response_code( $response )
				&& str_contains( (string) wp_remote_retrieve_body( $response ), 'urn:ietf:params:acme:error:badNonce' );

			++$attempt;
		} while ( $is_bad_nonce && $attempt < 3 );

		return $response;
	}

	// ── Internals ─────────────────────────────────────────────────────────────

	private function dir( string $key ): string {
		if ( null === $this->directory ) {
			$response = wp_remote_get( $this->directory_url, array( 'timeout' => 30 ) );
			if ( is_wp_error( $response ) ) {
				throw new \RuntimeException( 'Unable to fetch ACME directory: ' . $response->get_error_message() );
			}
			$this->directory = $this->json( $response );
		}

		if ( empty( $this->directory[ $key ] ) ) {
			throw new \RuntimeException( "ACME directory is missing '{$key}'." );
		}

		return (string) $this->directory[ $key ];
	}

	private function take_nonce(): string {
		if ( null !== $this->nonce ) {
			$nonce       = $this->nonce;
			$this->nonce = null;
			return $nonce;
		}

		$response = wp_remote_head( $this->dir( 'newNonce' ), array( 'timeout' => 30 ) );
		if ( is_wp_error( $response ) ) {
			throw new \RuntimeException( 'Unable to fetch ACME nonce: ' . $response->get_error_message() );
		}

		$nonce = (string) wp_remote_retrieve_header( $response, 'replay-nonce' );
		if ( '' === $nonce ) {
			throw new \RuntimeException( 'ACME newNonce returned no Replay-Nonce header.' );
		}

		return $nonce;
	}

	private function store_nonce( array $response ): void {
		$nonce = (string) wp_remote_retrieve_header( $response, 'replay-nonce' );
		if ( '' !== $nonce ) {
			$this->nonce = $nonce;
		}
	}

	private function json( array $response ): array {
		$decoded = json_decode( (string) wp_remote_retrieve_body( $response ), true );
		return is_array( $decoded ) ? $decoded : array();
	}

	private function error_detail( array $response ): string {
		$status = (int) wp_remote_retrieve_response_code( $response );
		$body   = $this->json( $response );
		$detail = isset( $body['detail'] ) ? (string) $body['detail'] : substr( (string) wp_remote_retrieve_body( $response ), 0, 200 );

		return "HTTP {$status}: {$detail}";
	}
}
