<?php
/**
 * Unit tests for WP_SAM\Intelligence\Well_Known_File_Server.
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;
use WP_SAM\Intelligence\Well_Known_File_Server;
use WP_SAM\Intelligence\Well_Known_File_Store;

/** Records what maybe_serve() would send instead of sending it. */
class Recording_Well_Known_File_Server extends Well_Known_File_Server {

	public ?int $status = null;

	/** @var array<int, string> */
	public array $headers = array();

	public ?string $body = null;

	public bool $terminated = false;

	protected function emit_status( int $status ): void {
		$this->status = $status;
	}

	protected function emit_header( string $header ): void {
		$this->headers[] = $header;
	}

	protected function emit_body( string $body ): void {
		$this->body = $body;
	}

	protected function terminate(): void {
		$this->terminated = true;
	}
}

class WellKnownFileServerTest extends TestCase {

	protected function setUp(): void {
		wp_test_reset_globals();
	}

	protected function tearDown(): void {
		unset( $_SERVER['REQUEST_URI'], $_SERVER['REQUEST_METHOD'] );
	}

	public function test_register_runs_the_robots_filter_last_and_answers_early_in_parse_request(): void {
		( new Well_Known_File_Server() )->register();

		$this->assertSame( PHP_INT_MAX, $GLOBALS['_wp_actions']['robots_txt'][0][1] );
		$this->assertSame( 0, $GLOBALS['_wp_actions']['parse_request'][0][1] );
	}

	public function test_resolve_returns_nothing_until_a_version_is_saved(): void {
		$this->assertNull( ( new Well_Known_File_Server() )->resolve( '/ads.txt' ) );
	}

	public function test_resolve_returns_the_saved_version_at_each_of_its_paths(): void {
		$store = new Well_Known_File_Store();
		$store->save( 'ads', "placeholder.example.com, placeholder, DIRECT, placeholder\n", 1 );
		$store->save( 'security', "Contact: mailto:a@example.com\n", 1 );
		$server = new Well_Known_File_Server( $store );

		$this->assertSame( "placeholder.example.com, placeholder, DIRECT, placeholder\n", $server->resolve( '/ads.txt' ) );
		$this->assertSame( "Contact: mailto:a@example.com\n", $server->resolve( '/.well-known/security.txt' ) );
		$this->assertSame( "Contact: mailto:a@example.com\n", $server->resolve( '/security.txt' ) );
		$this->assertNull( $server->resolve( '/humans.txt' ) );
		$this->assertNull( $server->resolve( '/blog/ads.txt' ) );
	}

	public function test_resolve_leaves_robots_txt_to_wordpress_core(): void {
		$store = new Well_Known_File_Store();
		$store->save( 'robots', "User-agent: *\nDisallow:\n", 1 );

		$this->assertNull( ( new Well_Known_File_Server( $store ) )->resolve( '/robots.txt' ) );
	}

	public function test_robots_filter_replaces_cores_output_with_the_saved_version(): void {
		$store = new Well_Known_File_Store();
		$server = new Well_Known_File_Server( $store );
		$core   = "User-agent: *\nDisallow: /wp-admin/\n";

		$this->assertSame( $core, $server->filter_robots_txt( $core ) );

		$store->save( 'robots', "User-agent: GPTBot\nDisallow: /\n", 1 );

		$this->assertSame( "User-agent: GPTBot\nDisallow: /\n", $server->filter_robots_txt( $core ) );
	}

	public function test_maybe_serve_sends_a_saved_file_as_plain_text_and_ends_the_request(): void {
		$store = new Well_Known_File_Store();
		$store->save( 'humans', "/* TEAM */\nSite: Example\n", 1 );
		$server                    = new Recording_Well_Known_File_Server( $store );
		$_SERVER['REQUEST_URI']    = '/humans.txt?ref=x';
		$_SERVER['REQUEST_METHOD'] = 'GET';

		$server->maybe_serve();

		$this->assertSame( 200, $server->status );
		$this->assertContains( 'Content-Type: text/plain; charset=utf-8', $server->headers );
		$this->assertContains( 'X-Content-Type-Options: nosniff', $server->headers );
		$this->assertSame( "/* TEAM */\nSite: Example\n", $server->body );
		$this->assertTrue( $server->terminated );
	}

	public function test_maybe_serve_sends_no_body_for_head(): void {
		$store = new Well_Known_File_Store();
		$store->save( 'humans', "Site: Example\n", 1 );
		$server                    = new Recording_Well_Known_File_Server( $store );
		$_SERVER['REQUEST_URI']    = '/humans.txt';
		$_SERVER['REQUEST_METHOD'] = 'HEAD';

		$server->maybe_serve();

		$this->assertSame( 200, $server->status );
		$this->assertNull( $server->body );
		$this->assertTrue( $server->terminated );
	}

	public function test_maybe_serve_lets_wordpress_carry_on_otherwise(): void {
		$store = new Well_Known_File_Store();
		$store->save( 'humans', "Site: Example\n", 1 );
		$server = new Recording_Well_Known_File_Server( $store );

		$_SERVER['REQUEST_URI']    = '/humans.txt';
		$_SERVER['REQUEST_METHOD'] = 'POST';
		$server->maybe_serve();

		$_SERVER['REQUEST_URI']    = '/ads.txt';
		$_SERVER['REQUEST_METHOD'] = 'GET';
		$server->maybe_serve();

		$this->assertNull( $server->status );
		$this->assertFalse( $server->terminated );
	}
}
