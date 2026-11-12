<?php
/**
 * Unit tests for WP_SAM\CSP\Discovery.
 *
 * Focused on get_crawl_urls(), tested via reflection since it's private,
 * and on which surfaces/URLs run_scan() actually crawls.
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;
use WP_SAM\CSP\Csp_Surfaces;
use WP_SAM\CSP\Discovery;
use WP_SAM\CSP\Policy_Change_Manager;
use WP_SAM\Modules\Audit_Log;
use WP_SAM\Modules\Feature_Gate;

class DiscoveryTest extends TestCase {

	private Discovery $discovery;

	/** @var Audit_Log&\PHPUnit\Framework\MockObject\MockObject */
	private $audit;

	protected function setUp(): void {
		wp_test_reset_globals();

		$this->audit     = $this->createMock( Audit_Log::class );
		$gate            = $this->createMock( Feature_Gate::class );
		$policy_changes  = $this->createMock( Policy_Change_Manager::class );
		$this->discovery = new Discovery( $this->audit, $gate, $policy_changes );
	}

	// ── crawl_url() ───────────────────────────────────────────────────────────

	public function test_crawl_url_logs_a_403_as_blocked_at_info(): void {
		// A firewall or login protection refusing an anonymous crawl is not
		// a fault worth a wp-admin warning notice.
		$GLOBALS['_wp_remote_get_response'] = array(
			'response' => array( 'code' => 403 ),
			'body'     => '',
		);
		$this->audit->expects( $this->once() )
			->method( 'log' )
			->with(
				'discovery',
				'crawl_blocked',
				'HTTP 403 for https://example.com/wp-login.php: the request was refused, likely by a firewall or login protection, so this page was not crawled.',
				'info'
			);

		$result = $this->discovery->crawl_url( 'https://example.com/wp-login.php', 'login' );

		$this->assertSame( array( 'added' => 0, 'updated' => 0 ), $result );
	}

	public function test_crawl_url_does_not_follow_a_redirect_to_another_host(): void {
		$GLOBALS['_wp_remote_get_response_queue'] = array(
			array(
				'response' => array( 'code' => 301 ),
				'headers'  => array( 'location' => 'https://production.example.org/' ),
				'body'     => '',
			),
			array(
				'response' => array( 'code' => 200 ),
				'body'     => '<script src="https://cdn.production.example.org/app.js"></script>',
			),
		);
		$this->audit->expects( $this->once() )
			->method( 'log' )
			->with(
				'discovery',
				'crawl_redirected_offsite',
				$this->logicalAnd(
					$this->stringContains( 'https://example.com/ redirected away from this site (HTTP 301)' ),
					$this->logicalNot( $this->stringContains( 'production.example.org' ) )
				),
				'warning'
			);

		$result = $this->discovery->crawl_url( 'https://example.com/', 'frontend' );

		$this->assertSame( array( 'added' => 0, 'updated' => 0 ), $result );
		$this->assertCount( 1, $GLOBALS['_wp_remote_get_requests'] );
		$this->assertSame( 0, $GLOBALS['_wp_remote_get_requests'][0]['args']['redirection'] );
	}

	public function test_crawl_url_still_logs_other_http_errors_as_crawl_http_error(): void {
		$GLOBALS['_wp_remote_get_response'] = array(
			'response' => array( 'code' => 500 ),
			'body'     => '',
		);
		$this->audit->expects( $this->once() )
			->method( 'log' )
			->with( 'discovery', 'crawl_http_error', 'HTTP 500 for https://example.com/.', 'warning' );

		$this->discovery->crawl_url( 'https://example.com/', 'frontend' );
	}

	public function test_admin_surface_has_no_crawl_targets(): void {
		// An anonymous wp_remote_get() to wp-admin never sees real admin
		// content -- WordPress redirects a logged-out request to
		// wp-login.php, and it has been observed to trigger a fatal error on
		// some hosts/security plugins for a bot-like request there. The
		// 'admin' surface must not be crawled anonymously.
		$this->assertSame( [], $this->get_crawl_urls( 'admin' ) );
	}

	public function test_unknown_surface_has_no_crawl_targets(): void {
		$this->assertSame( [], $this->get_crawl_urls( 'not-a-real-surface' ) );
	}

	public function test_api_surface_has_no_crawl_targets(): void {
		// The REST API isn't a CSP surface (Csp_Surfaces): no CSP is ever
		// sent on a REST response, and JSON has no subresources to discover.
		$this->assertSame( [], $this->get_crawl_urls( 'api' ) );
	}

	public function test_multi_surface_scan_crawls_only_csp_surfaces_and_never_the_rest_api(): void {
		$gate = $this->createMock( Feature_Gate::class );
		$gate->method( 'is_allowed' )->willReturnCallback( static fn( string $feature ): bool => 'multi_surface_scan' === $feature );

		$discovery = new class( $this->audit, $gate, $this->createMock( Policy_Change_Manager::class ) ) extends Discovery {
			/** @var array<int, array{0: string, 1: string}> */
			public array $crawled = [];

			public function crawl_url( string $url, string $surface ): array {
				$this->crawled[] = [ $url, $surface ];
				return [ 'added' => 0, 'updated' => 0 ];
			}
		};

		$discovery->run_scan();

		$this->assertNotEmpty( $discovery->crawled );
		foreach ( $discovery->crawled as [ $url, $surface ] ) {
			$this->assertContains( $surface, Csp_Surfaces::ALL );
			$this->assertNotSame( rest_url(), $url );
			$this->assertStringNotContainsString( '/wp-json', $url );
		}
		$this->assertSame(
			[ [ 'https://example.com/', 'frontend' ], [ 'https://example.com/wp-login.php', 'login' ] ],
			$discovery->crawled
		);
	}

	/**
	 * Calls the private get_crawl_urls() method via reflection.
	 *
	 * @return array<int,string>
	 */
	private function get_crawl_urls( string $surface ): array {
		$ref = new ReflectionMethod( $this->discovery, 'get_crawl_urls' );
		$ref->setAccessible( true );
		return $ref->invoke( $this->discovery, $surface );
	}
}
