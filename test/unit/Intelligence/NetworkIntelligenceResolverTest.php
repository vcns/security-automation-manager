<?php
/**
 * Unit tests for WP_SAM\Intelligence\Network_Intelligence_Resolver.
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;
use WP_SAM\Intelligence\Network_Intelligence_Resolver;
use WP_SAM\Intelligence\Tor_Exit_List_Store;

class NetworkIntelligenceResolverTest extends TestCase {

	protected function setUp(): void {
		wp_test_reset_globals();
	}

	public function test_resolve_returns_false_for_empty_ip_without_querying(): void {
		$resolver = new Network_Intelligence_Resolver( new Tor_Exit_List_Store() );

		$result = $resolver->resolve( '' );

		$this->assertSame( array( 'is_tor_exit' => false ), $result );
		$this->assertNull( $GLOBALS['_wpdb_last_operation'] ?? null );
	}

	public function test_resolve_reports_a_known_exit_node(): void {
		$GLOBALS['_wpdb_get_var'] = '1';
		$resolver                 = new Network_Intelligence_Resolver( new Tor_Exit_List_Store() );

		$result = $resolver->resolve( '203.0.113.42' );

		$this->assertTrue( $result['is_tor_exit'] );
	}

	public function test_resolve_reports_a_non_exit_ip(): void {
		$GLOBALS['_wpdb_get_var'] = null;
		$resolver                 = new Network_Intelligence_Resolver( new Tor_Exit_List_Store() );

		$result = $resolver->resolve( '203.0.113.42' );

		$this->assertFalse( $result['is_tor_exit'] );
	}
}
