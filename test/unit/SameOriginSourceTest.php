<?php
/**
 * Unit tests for WP_SAM\CSP\Same_Origin_Source: which blocked files on the
 * site's own host may be proposed as exact-path script and worker sources,
 * and the source expression the policy builder emits for them.
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;
use WP_SAM\CSP\Same_Origin_Source;

class SameOriginSourceTest extends TestCase {

	protected function setUp(): void {
		wp_test_reset_globals();
	}

	public function test_a_blocked_gateway_script_becomes_an_exact_path_candidate(): void {
		$candidate = Same_Origin_Source::candidate( 'script-src-elem', 'https://example.com/gtm/gtm.js?id=G-TEST123' );

		$this->assertSame(
			array(
				'directive' => 'script-src-elem',
				'uri'       => 'https://example.com/gtm/gtm.js?id=G-TEST123',
				'scheme'    => 'self',
				'host'      => '/gtm/gtm.js',
			),
			$candidate
		);
	}

	public function test_workers_are_proposable_too(): void {
		$this->assertSame( '/sw.js', Same_Origin_Source::candidate( 'worker-src', 'https://example.com/sw.js' )['host'] );
	}

	public function test_directives_that_default_to_self_are_not_proposable(): void {
		foreach ( array( 'img-src', 'connect-src', 'font-src', 'frame-src', 'style-src-elem' ) as $directive ) {
			$this->assertNull( Same_Origin_Source::candidate( $directive, 'https://example.com/gtm/gtm.js' ), $directive );
		}
	}

	public function test_path_case_is_kept_because_csp_paths_are_case_sensitive(): void {
		$this->assertSame( '/Theme/JS/App.min.js', Same_Origin_Source::proposable_path( '/Theme/JS/App.min.js' ) );
	}

	/**
	 * @dataProvider refused_paths
	 */
	public function test_paths_that_would_reopen_a_script_hole_are_refused( string $path, string $query ): void {
		$this->assertNull( Same_Origin_Source::proposable_path( $path, $query ) );
	}

	public static function refused_paths(): array {
		return array(
			'site root'                => array( '/', '' ),
			'a directory'              => array( '/gtm/', 'id=G-TEST123' ),
			'REST API'                 => array( '/wp-json/wp/v2/users', '' ),
			'REST API in a subfolder'  => array( '/blog/wp-json/wp/v2/users', '' ),
			'REST via rest_route'      => array( '/index.js', 'rest_route=/wp/v2/users' ),
			'JSONP callback'           => array( '/feed.js', '_jsonp=alert' ),
			'callback parameter'       => array( '/feed.js', 'callback=alert' ),
			'PHP endpoint'             => array( '/wp-admin/admin-ajax.php', 'action=x' ),
			'PHP endpoint, any case'   => array( '/Script.PHP', '' ),
			'uploads directory'        => array( '/wp-content/uploads/2026/11/evil.js', '' ),
			'percent-encoded'          => array( '/wp%2Djson/wp/v2/users', '' ),
			'dot segment'              => array( '/gtm/../wp-json/x', '' ),
			'protocol-relative'        => array( '//evil.example/x.js', '' ),
			'header-breaking ;'        => array( '/a.js;script-src', '' ),
			'header-breaking ,'        => array( '/a.js,b.js', '' ),
			'quote'                    => array( "/a'.js", '' ),
			'not a path'               => array( 'gtm.js', '' ),
			'too long'                 => array( '/' . str_repeat( 'a', 255 ) . '.js', '' ),
		);
	}

	public function test_a_refused_url_gives_no_candidate(): void {
		$this->assertNull( Same_Origin_Source::candidate( 'script-src-elem', 'https://example.com/wp-json/wp/v2/users?_jsonp=alert' ) );
	}

	public function test_expression_is_this_sites_origin_plus_the_path_never_self(): void {
		$this->assertSame( 'https://example.com/gtm/gtm.js', Same_Origin_Source::expression( '/gtm/gtm.js' ) );
	}

	public function test_expression_is_empty_for_a_stored_path_that_may_not_be_emitted(): void {
		$this->assertSame( '', Same_Origin_Source::expression( '/wp-json/wp/v2/users' ) );
		$this->assertSame( '', Same_Origin_Source::expression( "/a.js; script-src 'unsafe-inline'" ) );
	}

	public function test_label_names_the_path_as_this_site(): void {
		$this->assertSame( 'This site: /gtm/gtm.js', Same_Origin_Source::label( '/gtm/gtm.js' ) );
	}
}
