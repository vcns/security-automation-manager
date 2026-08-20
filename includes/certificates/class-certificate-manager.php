<?php
/**
 * Orchestrates the full issue/renew flow:
 *
 *   account -> order -> per-authorization challenge (dns-01 via the
 *   configured provider, http-01 otherwise) -> propagation wait ->
 *   validation poll -> finalize with CSR -> download -> store -> deploy.
 *
 * Runs synchronously inside a cron invocation (wp_sam_cert_issue single
 * event or the daily renewal check); the admin "Issue / Renew Now" button
 * schedules that event rather than blocking the browser, because dns-01
 * propagation waits are measured in minutes on some providers.
 */

declare( strict_types=1 );

namespace WP_SAM\Certificates;

use WP_SAM\Modules\Audit_Log;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Certificate_Manager {

	private const STATUS_OPTION = 'wp_sam_cert_last_run';

	/** Seconds to wait for DNS propagation before asking the CA to validate. */
	private const DNS_SETTLE_SECONDS = 30;

	/** Maximum polls (10s apart) for authorization/order state transitions. */
	private const MAX_POLLS = 18;

	private Certificate_Store $store;
	private Challenge_Http $http_challenge;
	private Deployer $deployer;
	private Audit_Log $audit;

	public function __construct( Certificate_Store $store, Challenge_Http $http_challenge, Deployer $deployer, Audit_Log $audit ) {
		$this->store          = $store;
		$this->http_challenge = $http_challenge;
		$this->deployer       = $deployer;
		$this->audit          = $audit;
	}

	// ── Testability seams ────────────────────────────────────────────────────
	//
	// poll()'s loop bound/interval, the DNS-settle wait, and DNS-provider
	// resolution are the only places this class's own real-time waiting and
	// static-registry lookup live. Each is behind a small protected method a
	// test subclass can override, purely so a test can make the real timeout
	// and cleanup-on-failure paths fast and provider-controllable -- none of
	// these change what production does; the constants below are still what
	// every call site uses by default. See test/unit/CertificateManagerTest.php.

	/** @return int Maximum poll attempts before giving up. Production: 18. */
	protected function poll_max_attempts(): int {
		return self::MAX_POLLS;
	}

	/** Waits between two poll attempts. Production: sleep( 10 ) seconds. */
	protected function wait_between_polls(): void {
		sleep( 10 );
	}

	/** Waits for DNS propagation after creating a challenge TXT record. Production: sleep( 30 ) seconds. */
	protected function wait_for_dns_settle(): void {
		sleep( self::DNS_SETTLE_SECONDS );
	}

	/** Resolves the configured DNS provider. Production: the real Dns_Provider registry. */
	protected function resolve_dns_provider( string $slug, array $credentials ): ?Dns_Provider {
		return Dns_Provider::make( $slug, $credentials );
	}

	// ── Public API ────────────────────────────────────────────────────────────

	/**
	 * Issues (or renews) the configured certificate. Records the outcome in
	 * the wp_sam_cert_last_run option and the audit log; never throws.
	 */
	public function issue(): void {
		$config  = $this->store->get_config();
		$domains = array_values( array_filter( array_map( 'trim', (array) $config['domains'] ) ) );

		if ( empty( $domains ) ) {
			$this->record_run( 'failed', 'No domains configured.' );
			return;
		}

		if ( function_exists( 'set_time_limit' ) ) {
			set_time_limit( 600 ); // phpcs:ignore Squiz.PHP.DiscouragedFunctions.Discouraged -- long-running ACME flow in cron context.
		}

		$environment = $config['staging'] ? 'staging' : 'production';
		$this->record_run( 'running', 'Order started for ' . implode( ', ', $domains ) . " ({$environment})." );

		try {
			$this->run_order( $config, $domains, $environment );
			$this->record_run( 'success', 'Certificate issued for ' . implode( ', ', $domains ) . " ({$environment})." );
			$this->audit->log( 'certificates', 'cert_issued', 'Certificate issued for ' . implode( ', ', $domains ) . " via ACME ({$environment}).", 'info' );
		} catch ( \Throwable $e ) {
			$this->record_run( 'failed', $e->getMessage() );
			$this->audit->log( 'certificates', 'cert_issue_failed', 'Certificate order failed: ' . $e->getMessage(), 'error' );
		}
	}

	/**
	 * Daily renewal check: re-issues when inside the renewal window. Staging
	 * certificates are never auto-renewed -- staging exists for configuration
	 * testing, not continuity.
	 */
	public function maybe_renew(): void {
		$config = $this->store->get_config();
		if ( $config['staging'] || empty( $config['domains'] ) ) {
			return;
		}

		if ( $this->store->renewal_due() ) {
			$this->audit->log( 'certificates', 'cert_renewal_started', 'Certificate is inside the 30-day renewal window; starting renewal.', 'info' );
			$this->issue();
		}
	}

	/**
	 * @return array{status:string,detail:string,at:string}
	 */
	public function last_run(): array {
		$run = get_option( self::STATUS_OPTION, array() );

		return array(
			'status' => (string) ( $run['status'] ?? 'never' ),
			'detail' => (string) ( $run['detail'] ?? '' ),
			'at'     => (string) ( $run['at'] ?? '' ),
		);
	}

	// ── Order flow ────────────────────────────────────────────────────────────

	private function run_order( array $config, array $domains, string $environment ): void {
		$directory = $config['staging'] ? Acme_Client::DIRECTORY_STAGING : Acme_Client::DIRECTORY_PRODUCTION;
		$account   = $this->store->get_account( $environment );
		$client    = new Acme_Client( $directory, $account['key_pem'] );

		if ( '' !== $account['kid'] ) {
			$client->set_kid( $account['kid'] );
		} else {
			$kid = $client->register_account( (string) $config['contact_email'] );
			$this->store->save_account_kid( $environment, $kid );
		}

		$order = $client->new_order( $domains );

		foreach ( (array) ( $order['body']['authorizations'] ?? array() ) as $authz_url ) {
			$this->satisfy_authorization( $client, $config, (string) $authz_url );
		}

		// Wait for the order to become ready, finalize, then wait for issuance.
		$order_body = $this->poll(
			fn(): array => $client->fetch( $order['url'] ),
			static fn( array $body ): bool => in_array( (string) ( $body['status'] ?? '' ), array( 'ready', 'valid' ), true ),
			'order did not become ready'
		);

		$custom_key = trim( (string) ( $config['custom_key_pem'] ?? '' ) );
		if ( '' !== $custom_key ) {
			if ( false === openssl_pkey_get_private( $custom_key ) ) {
				throw new \RuntimeException( 'The supplied private key could not be loaded. Paste a valid, unencrypted PEM private key (BEGIN PRIVATE KEY / BEGIN EC PRIVATE KEY / BEGIN RSA PRIVATE KEY), or clear it to let the plugin generate one.' );
			}
			$cert_key = $custom_key;
		} else {
			$cert_key = Acme_Crypto::generate_key( (string) $config['key_type'] );
		}
		if ( 'ready' === ( $order_body['status'] ?? '' ) ) {
			$subject = array(
				'organization'        => (string) ( $config['organization'] ?? '' ),
				'organizational_unit' => (string) ( $config['organizational_unit'] ?? '' ),
				'country'             => (string) ( $config['country'] ?? '' ),
				'state'               => (string) ( $config['state'] ?? '' ),
				'locality'            => (string) ( $config['locality'] ?? '' ),
			);
			$client->finalize( (string) $order_body['finalize'], Acme_Crypto::csr_der( $domains, $cert_key, $subject ) );
		}

		$order_body = $this->poll(
			fn(): array => $client->fetch( $order['url'] ),
			static fn( array $body ): bool => 'valid' === (string) ( $body['status'] ?? '' ),
			'order did not reach valid after finalize'
		);

		$fullchain = $client->download_certificate( (string) $order_body['certificate'] );
		$this->store->insert_certificate( $domains, $cert_key, $fullchain, $environment );

		$this->deployer->deploy( $config, $domains[0], $cert_key, $fullchain );
	}

	private function satisfy_authorization( Acme_Client $client, array $config, string $authz_url ): void {
		$authz  = $client->fetch( $authz_url );
		$domain = (string) ( $authz['identifier']['value'] ?? '' );

		if ( 'valid' === ( $authz['status'] ?? '' ) ) {
			return; // Cached authorization from a recent order.
		}

		$wildcard  = ! empty( $authz['wildcard'] );
		$use_dns   = 'dns-01' === $config['challenge'] && '' !== $config['provider'];
		$challenge = null;
		foreach ( (array) ( $authz['challenges'] ?? array() ) as $candidate ) {
			if ( ( $use_dns || $wildcard ) && 'dns-01' === ( $candidate['type'] ?? '' ) ) {
				$challenge = $candidate;
				break;
			}
			if ( ! $use_dns && ! $wildcard && 'http-01' === ( $candidate['type'] ?? '' ) ) {
				$challenge = $candidate;
				break;
			}
		}

		if ( null === $challenge ) {
			throw new \RuntimeException( "No usable challenge offered for {$domain}. Wildcards require a DNS provider (dns-01)." );
		}

		$token    = (string) $challenge['token'];
		$key_auth = $token . '.' . $client->thumbprint();

		if ( 'dns-01' === $challenge['type'] ) {
			$provider = $this->resolve_dns_provider( (string) $config['provider'], (array) $config['dns_credentials'] );
			if ( null === $provider ) {
				throw new \RuntimeException( 'Configured DNS provider is not available: ' . (string) $config['provider'] );
			}

			$record_fqdn  = '_acme-challenge.' . ltrim( $domain, '*.' );
			$record_value = Acme_Crypto::base64url( hash( 'sha256', $key_auth, true ) );

			$provider->create_txt_record( $record_fqdn, $record_value );
			try {
				$this->wait_for_dns_settle(); // Propagation head start before the CA queries.
				$this->validate_challenge( $client, (string) $challenge['url'], $authz_url, $domain );
			} finally {
				try {
					$provider->delete_txt_record( $record_fqdn, $record_value );
				} catch ( \Throwable $cleanup_error ) { // phpcs:ignore Generic.CodeAnalysis.EmptyStatement.DetectedCatch
					// Cleanup failure must not mask the validation outcome; a
					// stale TXT record is cosmetic.
				}
			}
			return;
		}

		$this->http_challenge->put_token( $token, $key_auth );
		try {
			$this->validate_challenge( $client, (string) $challenge['url'], $authz_url, $domain );
		} finally {
			$this->http_challenge->delete_token( $token );
		}
	}

	private function validate_challenge( Acme_Client $client, string $challenge_url, string $authz_url, string $domain ): void {
		$client->respond_challenge( $challenge_url );

		$this->poll(
			fn(): array => $client->fetch( $authz_url ),
			static function ( array $body ): bool {
				$status = (string) ( $body['status'] ?? '' );
				if ( 'invalid' === $status ) {
					$error = (string) ( $body['challenges'][0]['error']['detail'] ?? 'challenge became invalid' );
					throw new \RuntimeException( $error );
				}
				return 'valid' === $status;
			},
			"validation for {$domain} timed out"
		);
	}

	/**
	 * Polls $fetch until $done returns true. $done may throw to abort early.
	 */
	private function poll( callable $fetch, callable $done, string $timeout_message ): array {
		$max_attempts = $this->poll_max_attempts();
		for ( $i = 0; $i < $max_attempts; $i++ ) {
			$body = $fetch();
			if ( $done( $body ) ) {
				return $body;
			}
			$this->wait_between_polls();
		}

		throw new \RuntimeException( 'ACME polling timed out: ' . $timeout_message );
	}

	private function record_run( string $status, string $detail ): void {
		update_option(
			self::STATUS_OPTION,
			array(
				'status' => $status,
				'detail' => substr( $detail, 0, 500 ),
				'at'     => current_time( 'mysql', true ),
			),
			false
		);
	}
}
