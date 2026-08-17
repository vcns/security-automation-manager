<?php
/**
 * Unit tests for WP_SAM\Certificates\Dns_Provider registry and shared helpers.
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;
use WP_SAM\Certificates\Dns_Provider;

class DnsProviderTest extends TestCase {

	private function make_probe(): Dns_Provider {
		return new class( array() ) extends Dns_Provider {
			public static function label(): string {
				return 'Probe';
			}
			public static function fields(): array {
				return array();
			}
			public function create_txt_record( string $fqdn, string $value ): void {}
			public function delete_txt_record( string $fqdn, string $value ): void {}
			public function probe_zone_candidates( string $fqdn ): array {
				return $this->zone_candidates( $fqdn );
			}
			public function probe_relative_name( string $fqdn, string $zone ): string {
				return $this->relative_name( $fqdn, $zone );
			}
		};
	}

	public function test_registry_contains_builtin_providers_with_valid_classes(): void {
		$providers = Dns_Provider::providers();

		$expected = array(
			'acmedns', 'akamai', 'alidns', 'azure', 'bunny', 'cloudflare', 'cloudns',
			'desec', 'digitalocean', 'dnsimple', 'dnsmadeeasy', 'dnspod', 'domeneshop',
			'dreamhost', 'dynu', 'easydns', 'gandi', 'glesys', 'godaddy', 'googlecloud',
			'hetzner', 'inwx', 'ionos', 'joker', 'linode', 'mythicbeasts', 'namecheap',
			'namecom', 'namesilo', 'netcup', 'netlify', 'njalla', 'ns1', 'ovh',
			'porkbun', 'powerdns', 'rfc2136', 'route53', 'scaleway', 'vercel', 'vultr',
		);

		$this->assertCount( 41, $expected );
		foreach ( $expected as $slug ) {
			$this->assertArrayHasKey( $slug, $providers );
			$this->assertTrue( is_subclass_of( $providers[ $slug ], Dns_Provider::class ) );
			$this->assertNotSame( '', $providers[ $slug ]::label() );
		}
	}

	public function test_every_provider_is_instantiable_with_empty_credentials(): void {
		foreach ( Dns_Provider::providers() as $slug => $class ) {
			$this->assertInstanceOf( Dns_Provider::class, Dns_Provider::make( $slug, array() ), "{$slug} failed to instantiate" );
		}
	}

	public function test_make_returns_null_for_unknown_slug(): void {
		$this->assertNull( Dns_Provider::make( 'not-a-provider', array() ) );
		$this->assertInstanceOf( Dns_Provider::class, Dns_Provider::make( 'cloudflare', array( 'api_token' => 'x' ) ) );
	}

	public function test_zone_candidates_walk_the_label_chain_longest_first(): void {
		$this->assertSame(
			array(
				'_acme-challenge.www.example.co.uk',
				'www.example.co.uk',
				'example.co.uk',
				'co.uk',
			),
			$this->make_probe()->probe_zone_candidates( '_acme-challenge.www.example.co.uk' )
		);
	}

	public function test_relative_name_strips_zone_suffix(): void {
		$probe = $this->make_probe();

		$this->assertSame( '_acme-challenge.www', $probe->probe_relative_name( '_acme-challenge.www.example.com', 'example.com' ) );
		$this->assertSame( '@', $probe->probe_relative_name( 'example.com', 'example.com' ) );
	}

	public function test_every_builtin_provider_declares_credential_fields(): void {
		foreach ( Dns_Provider::providers() as $class ) {
			foreach ( $class::fields() as $key => $field ) {
				$this->assertIsString( $key );
				$this->assertArrayHasKey( 'label', $field );
			}
		}
	}
}
