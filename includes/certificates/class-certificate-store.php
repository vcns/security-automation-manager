<?php
/**
 * Persistence for the certificate module.
 *
 * Configuration lives in the wp_sam_cert_config option with every secret
 * field sealed by Credential_Vault before it is written. Issued certificates
 * live in the sam_certificates table; the private key column is sealed too,
 * so neither a database dump nor a stray phpMyAdmin session yields usable
 * key material.
 */

declare( strict_types=1 );

namespace WP_SAM\Certificates;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Certificate_Store {

	public const CONFIG_OPTION      = 'wp_sam_cert_config';
	public const ACCOUNT_KEY_OPTION = 'wp_sam_acme_account_keys';

	/** Config fields that must always be stored sealed. */
	private const SECRET_FIELDS = array( 'dns_credentials', 'cpanel_token', 'custom_key_pem' );

	// ── Configuration ─────────────────────────────────────────────────────────

	/**
	 * @return array{
	 *   domains:array<int,string>, contact_email:string, provider:string,
	 *   challenge:string, key_type:string, staging:bool, deployment:string,
	 *   export_path:string, cpanel_host:string, cpanel_user:string,
	 *   cpanel_token:string, dns_credentials:array<string,string>
	 * }
	 */
	public function get_config(): array {
		$defaults = array(
			'domains'             => array(),
			'contact_email'       => '',
			'provider'            => '',
			'challenge'           => 'dns-01',
			'key_type'            => 'ec-256',
			'staging'             => true,
			'deployment'          => 'download',
			'export_path'         => '',
			'cpanel_host'         => '',
			'cpanel_user'         => '',
			'cpanel_token'        => '',
			'dns_credentials'     => array(),
			// CSR subject (distinguished name) parts. DV CAs such as Let's
			// Encrypt ignore these in the issued certificate; they are
			// included in the CSR for organisations whose workflows or CAs
			// consume them.
			'organization'        => '',
			'organizational_unit' => '',
			'country'             => '',
			'state'               => '',
			'locality'            => '',
			// Optional bring-your-own certificate private key (PEM). When set,
			// orders use it instead of generating a key -- for hosts where
			// ext/openssl key generation misbehaves, or organisations that
			// must control key material.
			'custom_key_pem'      => '',
		);

		$stored = get_option( self::CONFIG_OPTION, array() );
		$config = array_merge( $defaults, is_array( $stored ) ? $stored : array() );

		// Unseal secrets for use. Values that fail authentication (vault key
		// rotated, tampered row) come back empty rather than as ciphertext.
		$config['cpanel_token']   = (string) ( Credential_Vault::open( (string) $config['cpanel_token'] ) ?? '' );
		$config['custom_key_pem'] = (string) ( Credential_Vault::open( (string) $config['custom_key_pem'] ) ?? '' );

		$credentials = array();
		foreach ( (array) $config['dns_credentials'] as $key => $sealed ) {
			$credentials[ (string) $key ] = (string) ( Credential_Vault::open( (string) $sealed ) ?? '' );
		}
		$config['dns_credentials'] = $credentials;

		return $config;
	}

	/**
	 * Persists configuration, sealing secret fields. Secret values that are
	 * empty strings mean "keep the stored value" so settings forms can render
	 * placeholder-only password fields.
	 */
	public function save_config( array $config ): void {
		$stored = get_option( self::CONFIG_OPTION, array() );
		$stored = is_array( $stored ) ? $stored : array();

		foreach ( self::SECRET_FIELDS as $field ) {
			if ( 'dns_credentials' === $field ) {
				$sealed = array();
				foreach ( (array) ( $config['dns_credentials'] ?? array() ) as $key => $value ) {
					$value = (string) $value;
					if ( '' === $value && isset( $stored['dns_credentials'][ $key ] ) ) {
						$sealed[ $key ] = (string) $stored['dns_credentials'][ $key ]; // Unchanged.
					} elseif ( '' !== $value ) {
						$sealed[ $key ] = Credential_Vault::seal( $value );
					}
				}
				$config['dns_credentials'] = $sealed;
				continue;
			}

			// null is an explicit "clear this secret"; '' means "keep stored".
			if ( array_key_exists( $field, $config ) && null === $config[ $field ] ) {
				$config[ $field ] = '';
				continue;
			}

			$value = (string) ( $config[ $field ] ?? '' );
			if ( '' === $value && isset( $stored[ $field ] ) ) {
				$config[ $field ] = (string) $stored[ $field ];
			} elseif ( '' !== $value ) {
				$config[ $field ] = Credential_Vault::seal( $value );
			}
		}

		update_option( self::CONFIG_OPTION, $config, false );
	}

	// ── ACME account keys ─────────────────────────────────────────────────────

	/**
	 * Returns (creating on first use) the account key for an environment.
	 *
	 * @param string $environment 'staging' or 'production'. Separate keys --
	 *                            Let's Encrypt accounts do not span directories.
	 * @return array{key_pem:string, kid:string}
	 */
	public function get_account( string $environment ): array {
		$accounts = get_option( self::ACCOUNT_KEY_OPTION, array() );
		$accounts = is_array( $accounts ) ? $accounts : array();

		if ( ! empty( $accounts[ $environment ]['key_pem'] ) ) {
			$pem = Credential_Vault::open( (string) $accounts[ $environment ]['key_pem'] );
			if ( null !== $pem && '' !== $pem ) {
				return array(
					'key_pem' => $pem,
					'kid'     => (string) ( $accounts[ $environment ]['kid'] ?? '' ),
				);
			}
		}

		$pem                      = Acme_Crypto::generate_key( 'ec-256' );
		$accounts[ $environment ] = array(
			'key_pem' => Credential_Vault::seal( $pem ),
			'kid'     => '',
		);
		update_option( self::ACCOUNT_KEY_OPTION, $accounts, false );

		return array(
			'key_pem' => $pem,
			'kid'     => '',
		);
	}

	public function save_account_kid( string $environment, string $kid ): void {
		$accounts = get_option( self::ACCOUNT_KEY_OPTION, array() );
		$accounts = is_array( $accounts ) ? $accounts : array();

		if ( isset( $accounts[ $environment ] ) ) {
			$accounts[ $environment ]['kid'] = $kid;
			update_option( self::ACCOUNT_KEY_OPTION, $accounts, false );
		}
	}

	// ── Certificates table ────────────────────────────────────────────────────

	/**
	 * Records an issued certificate. The private key is sealed before write.
	 *
	 * @return int Row ID.
	 */
	public function insert_certificate( array $domains, string $key_pem, string $fullchain_pem, string $environment ): int {
		global $wpdb;

		$parsed     = openssl_x509_parse( $fullchain_pem );
		$not_before = isset( $parsed['validFrom_time_t'] ) ? gmdate( 'Y-m-d H:i:s', (int) $parsed['validFrom_time_t'] ) : null;
		$not_after  = isset( $parsed['validTo_time_t'] ) ? gmdate( 'Y-m-d H:i:s', (int) $parsed['validTo_time_t'] ) : null;
		$now        = current_time( 'mysql', true );

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
		$wpdb->insert(
			$wpdb->prefix . 'sam_certificates',
			array(
				'domains'       => (string) wp_json_encode( array_values( $domains ) ),
				'environment'   => $environment,
				'status'        => 'issued',
				'key_pem'       => Credential_Vault::seal( $key_pem ),
				'fullchain_pem' => $fullchain_pem,
				'not_before'    => $not_before,
				'not_after'     => $not_after,
				'created_at'    => $now,
				'updated_at'    => $now,
			),
			array( '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s' )
		);

		return (int) $wpdb->insert_id;
	}

	/**
	 * Latest issued certificate row (unsealed key), or null.
	 *
	 * @return array|null
	 */
	public function latest_certificate( ?string $environment = null ): ?array {
		global $wpdb;

		$sql  = "SELECT * FROM {$wpdb->prefix}sam_certificates WHERE status = 'issued'";
		$args = array();
		if ( null !== $environment ) {
			$sql   .= ' AND environment = %s';
			$args[] = $environment;
		}
		$sql .= ' ORDER BY id DESC LIMIT 1';

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.NotPrepared -- interpolation is the table prefix; placeholders prepared below; key material must never enter the object cache.
		$row = $wpdb->get_row( empty( $args ) ? $sql : $wpdb->prepare( $sql, ...$args ), ARRAY_A );
		if ( ! is_array( $row ) ) {
			return null;
		}

		$domains        = json_decode( (string) $row['domains'], true );
		$row['key_pem'] = (string) ( Credential_Vault::open( (string) $row['key_pem'] ) ?? '' );
		$row['domains'] = is_array( $domains ) ? $domains : array();

		return $row;
	}

	/**
	 * True when the newest issued production certificate expires within the
	 * renewal window (or none exists).
	 */
	public function renewal_due( int $window_days = 30 ): bool {
		$latest = $this->latest_certificate( 'production' );
		if ( null === $latest || empty( $latest['not_after'] ) ) {
			return true;
		}

		return strtotime( (string) $latest['not_after'] . ' UTC' ) - time() < $window_days * DAY_IN_SECONDS;
	}
}
