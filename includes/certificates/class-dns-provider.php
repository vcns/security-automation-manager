<?php
/**
 * Base class and registry for DNS providers used by dns-01 challenges.
 *
 * Each provider is a thin authenticated REST wrapper exposing exactly what
 * ACME needs: create a TXT record, delete it afterwards. Zone resolution is
 * shared here -- given _acme-challenge.www.example.co.uk, walk the label
 * chain (www.example.co.uk, example.co.uk, co.uk) against the provider's
 * zone list and pick the longest match.
 *
 * Third parties can register additional providers through the
 * 'wp_sam_dns_providers' filter (slug => fully-qualified class name).
 */

declare( strict_types=1 );

namespace WP_SAM\Certificates;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

abstract class Dns_Provider {

	/** @var array<string,string> Decrypted credential map, keyed by field key. */
	protected array $credentials;

	public function __construct( array $credentials ) {
		$this->credentials = $credentials;
	}

	/** Human-readable provider name for the GUI dropdown. */
	abstract public static function label(): string;

	/**
	 * Credential fields the GUI must collect.
	 *
	 * Each entry may set 'secret' => false to render a plain text input
	 * (endpoints, usernames, zone names) instead of a password field, and
	 * 'textarea' => true for multi-line values (service-account JSON). All
	 * values are sealed at rest regardless of input type.
	 *
	 * @return array<string,array{label:string,placeholder?:string,secret?:bool,textarea?:bool}> keyed by field key.
	 */
	abstract public static function fields(): array;

	/**
	 * Creates a TXT record. Implementations must tolerate the record name
	 * already existing (add another value or replace their own).
	 *
	 * @param string $fqdn  Full record name, e.g. _acme-challenge.example.com.
	 * @param string $value TXT value (the base64url challenge digest).
	 */
	abstract public function create_txt_record( string $fqdn, string $value ): void;

	/**
	 * Removes the TXT record created by create_txt_record().
	 */
	abstract public function delete_txt_record( string $fqdn, string $value ): void;

	// ── Registry ──────────────────────────────────────────────────────────────

	/**
	 * @return array<string,class-string<Dns_Provider>> slug => class.
	 */
	public static function providers(): array {
		$builtin = array(
			'acmedns'      => Providers\Provider_Acmedns::class,
			'akamai'       => Providers\Provider_Akamai::class,
			'alidns'       => Providers\Provider_Alidns::class,
			'azure'        => Providers\Provider_Azure::class,
			'bunny'        => Providers\Provider_Bunny::class,
			'cloudflare'   => Providers\Provider_Cloudflare::class,
			'cloudns'      => Providers\Provider_Cloudns::class,
			'desec'        => Providers\Provider_Desec::class,
			'digitalocean' => Providers\Provider_DigitalOcean::class,
			'dnsimple'     => Providers\Provider_Dnsimple::class,
			'dnsmadeeasy'  => Providers\Provider_Dnsmadeeasy::class,
			'dnspod'       => Providers\Provider_Dnspod::class,
			'domeneshop'   => Providers\Provider_Domeneshop::class,
			'dreamhost'    => Providers\Provider_Dreamhost::class,
			'dynu'         => Providers\Provider_Dynu::class,
			'easydns'      => Providers\Provider_Easydns::class,
			'gandi'        => Providers\Provider_Gandi::class,
			'glesys'       => Providers\Provider_Glesys::class,
			'godaddy'      => Providers\Provider_GoDaddy::class,
			'googlecloud'  => Providers\Provider_Google_Cloud::class,
			'hetzner'      => Providers\Provider_Hetzner::class,
			'inwx'         => Providers\Provider_Inwx::class,
			'ionos'        => Providers\Provider_Ionos::class,
			'joker'        => Providers\Provider_Joker::class,
			'linode'       => Providers\Provider_Linode::class,
			'mythicbeasts' => Providers\Provider_Mythicbeasts::class,
			'namecheap'    => Providers\Provider_Namecheap::class,
			'namecom'      => Providers\Provider_Namecom::class,
			'namesilo'     => Providers\Provider_Namesilo::class,
			'netcup'       => Providers\Provider_Netcup::class,
			'netlify'      => Providers\Provider_Netlify::class,
			'njalla'       => Providers\Provider_Njalla::class,
			'ns1'          => Providers\Provider_Ns1::class,
			'ovh'          => Providers\Provider_Ovh::class,
			'porkbun'      => Providers\Provider_Porkbun::class,
			'powerdns'     => Providers\Provider_Powerdns::class,
			'rfc2136'      => Providers\Provider_Rfc2136::class,
			'route53'      => Providers\Provider_Route53::class,
			'scaleway'     => Providers\Provider_Scaleway::class,
			'vercel'       => Providers\Provider_Vercel::class,
			'vultr'        => Providers\Provider_Vultr::class,
		);

		/**
		 * Filters the available DNS providers for dns-01 challenges.
		 *
		 * @param array<string,string> $builtin slug => class extending Dns_Provider.
		 */
		$providers = apply_filters( 'wp_sam_dns_providers', $builtin );

		return array_filter(
			is_array( $providers ) ? $providers : $builtin,
			static fn( $provider_class ): bool => is_string( $provider_class ) && is_subclass_of( $provider_class, self::class )
		);
	}

	public static function make( string $slug, array $credentials ): ?Dns_Provider {
		$providers = self::providers();
		if ( ! isset( $providers[ $slug ] ) ) {
			return null;
		}

		$class = $providers[ $slug ];

		return new $class( $credentials );
	}

	// ── Shared helpers ────────────────────────────────────────────────────────

	/**
	 * Candidate zones for an FQDN, longest first:
	 * _acme-challenge.www.example.co.uk => [ '_acme-challenge.www.example.co.uk',
	 * 'www.example.co.uk', 'example.co.uk', 'co.uk' ].
	 *
	 * @return array<int,string>
	 */
	protected function zone_candidates( string $fqdn ): array {
		$labels     = explode( '.', rtrim( $fqdn, '.' ) );
		$candidates = array();
		$count      = count( $labels );

		for ( $i = 0; $i < $count - 1; $i++ ) {
			$candidates[] = implode( '.', array_slice( $labels, $i ) );
		}

		return $candidates;
	}

	/**
	 * Relative record name within a zone: _acme-challenge.www for zone
	 * example.co.uk and fqdn _acme-challenge.www.example.co.uk.
	 */
	protected function relative_name( string $fqdn, string $zone ): string {
		if ( $fqdn === $zone ) {
			return '@';
		}

		return substr( $fqdn, 0, - ( strlen( $zone ) + 1 ) );
	}

	/**
	 * JSON request helper. Throws on transport errors and >=400 responses.
	 *
	 * @return array{status:int,body:array}
	 */
	protected function request( string $method, string $url, array $headers = array(), $body = null ): array {
		$args = array(
			'method'  => $method,
			'timeout' => 30,
			'headers' => array_merge( array( 'Content-Type' => 'application/json' ), $headers ),
		);
		if ( null !== $body ) {
			$args['body'] = (string) wp_json_encode( $body );
		}

		$response = wp_remote_request( $url, $args );
		if ( is_wp_error( $response ) ) {
			throw new \RuntimeException( static::label() . ' API transport error: ' . $response->get_error_message() ); // phpcs:ignore WordPress.Security.EscapeOutput.ExceptionNotEscaped -- exception message, never echoed as HTML; only logged via Audit_Log/record_run().
		}

		$status  = (int) wp_remote_retrieve_response_code( $response );
		$decoded = json_decode( (string) wp_remote_retrieve_body( $response ), true );

		if ( $status >= 400 ) {
			throw new \RuntimeException(
				static::label() . " API error (HTTP {$status}): " . substr( (string) wp_remote_retrieve_body( $response ), 0, 200 ) // phpcs:ignore WordPress.Security.EscapeOutput.ExceptionNotEscaped -- exception message, never echoed as HTML; only logged via Audit_Log/record_run().
			);
		}

		return array(
			'status' => $status,
			'body'   => is_array( $decoded ) ? $decoded : array(),
		);
	}

	protected function credential( string $key ): string {
		return isset( $this->credentials[ $key ] ) ? (string) $this->credentials[ $key ] : '';
	}

	protected function basic_auth( string $user, string $password ): string {
		return 'Basic ' . base64_encode( $user . ':' . $password );
	}

	/**
	 * Raw (non-JSON) request helper for providers speaking XML or
	 * form-encoded protocols. Returns the body; throws on transport errors
	 * and >=400 statuses.
	 */
	protected function request_raw( string $method, string $url, array $headers = array(), ?string $body = null ): string {
		$args = array(
			'method'  => $method,
			'timeout' => 30,
			'headers' => $headers,
		);
		if ( null !== $body ) {
			$args['body'] = $body;
		}

		$response = wp_remote_request( $url, $args );
		if ( is_wp_error( $response ) ) {
			throw new \RuntimeException( static::label() . ' API transport error: ' . $response->get_error_message() ); // phpcs:ignore WordPress.Security.EscapeOutput.ExceptionNotEscaped -- exception message, never echoed as HTML; only logged via Audit_Log/record_run().
		}

		$status = (int) wp_remote_retrieve_response_code( $response );
		if ( $status >= 400 ) {
			throw new \RuntimeException(
				static::label() . " API error (HTTP {$status}): " . substr( (string) wp_remote_retrieve_body( $response ), 0, 200 ) // phpcs:ignore WordPress.Security.EscapeOutput.ExceptionNotEscaped -- exception message, never echoed as HTML; only logged via Audit_Log/record_run().
			);
		}

		return (string) wp_remote_retrieve_body( $response );
	}
}
